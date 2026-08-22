"""Database access with SQLite by default and optional PostgreSQL support."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Iterable

from core.settings import get_settings


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE = DATA_DIR / "shadowtrap.db"  # Backwards-compatible public constant.


class DatabaseConnection:
    """Normalize SQLite and psycopg's small API differences."""

    def __init__(self, connection: Any, backend: str):
        self._connection = connection
        self.backend = backend

    def _statement(self, statement: str) -> str:
        return statement.replace("?", "%s") if self.backend == "postgres" else statement

    def execute(self, statement: str, parameters: Iterable[Any] = ()) -> Any:
        return self._connection.execute(self._statement(statement), tuple(parameters))

    def executemany(self, statement: str, parameters: Iterable[Iterable[Any]]) -> Any:
        return self._connection.executemany(self._statement(statement), parameters)

    def executescript(self, script: str) -> None:
        if self.backend == "sqlite":
            self._connection.executescript(script)
            return
        for statement in (part.strip() for part in script.split(";") if part.strip()):
            self._connection.execute(statement)

    def commit(self) -> None:
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()


def _open_connection() -> DatabaseConnection:
    settings = get_settings()
    if settings.database_url.startswith("sqlite:///"):
        database_path = Path(settings.database_url.removeprefix("sqlite:///"))
        database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return DatabaseConnection(connection, "sqlite")

    if settings.database_url.startswith(("postgres://", "postgresql://")):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as error:  # pragma: no cover - depends on deployment choice
            raise RuntimeError("PostgreSQL requires the optional psycopg dependency") from error
        return DatabaseConnection(psycopg.connect(settings.database_url, row_factory=dict_row), "postgres")

    raise RuntimeError("DATABASE_URL must use sqlite:/// or postgresql://")


def _schema(backend: str) -> str:
    if backend == "postgres":
        return """
        CREATE TABLE IF NOT EXISTS attacks (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            timestamp TEXT NOT NULL,
            service TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            source_port INTEGER,
            username TEXT,
            password TEXT,
            event TEXT NOT NULL,
            metadata TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_attacks_source_ip_timestamp ON attacks (source_ip, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_attacks_service_timestamp ON attacks (service, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_attacks_event ON attacks (event);
        CREATE TABLE IF NOT EXISTS alerts (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            classification TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            payload TEXT NOT NULL,
            delivery_status TEXT NOT NULL DEFAULT 'created'
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_source_ip_timestamp ON alerts (source_ip, timestamp DESC);
        """
    return """
    CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        service TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        source_port INTEGER,
        username TEXT,
        password TEXT,
        event TEXT NOT NULL,
        metadata TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_attacks_source_ip_timestamp ON attacks (source_ip, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_attacks_service_timestamp ON attacks (service, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_attacks_event ON attacks (event);
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        classification TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        severity TEXT NOT NULL,
        payload TEXT NOT NULL,
        delivery_status TEXT NOT NULL DEFAULT 'created'
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_source_ip_timestamp ON alerts (source_ip, timestamp DESC);
    """


def initialize_database() -> None:
    connection = _open_connection()
    try:
        connection.executescript(_schema(connection.backend))
        connection.commit()
    finally:
        connection.close()


def get_connection() -> DatabaseConnection:
    connection = _open_connection()
    try:
        connection.executescript(_schema(connection.backend))
        connection.commit()
        return connection
    except Exception:
        connection.close()
        raise


def purge_events_older_than(days: int) -> int:
    """Apply an explicit retention policy; no events are deleted implicitly."""
    from datetime import datetime, timedelta, timezone

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    connection = get_connection()
    try:
        cursor = connection.execute("DELETE FROM attacks WHERE timestamp < ?", (cutoff,))
        connection.commit()
        return cursor.rowcount
    finally:
        connection.close()
