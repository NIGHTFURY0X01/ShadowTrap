"""Validated event ingestion for all ShadowTrap collection services."""

from __future__ import annotations

import json
import logging
from typing import Any

from core.database import get_connection
from core.utils import json_safe, utc_now, validate_ip


LOGGER = logging.getLogger("shadowtrap.events")
VALID_SERVICES = {"http", "ssh"}
MAX_METADATA_BYTES = 16_384


def _bounded_text(value: str | None, field: str, limit: int = 256) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if len(normalized) > limit:
        raise ValueError(f"{field} exceeds the {limit}-character limit")
    return normalized or None


def log_attack(
    service: str,
    source_ip: str,
    source_port: int | None = None,
    username: str | None = None,
    password: str | None = None,
    event: str = "unknown",
    metadata: dict[str, Any] | None = None,
) -> int | None:
    """Store a normalized event and optionally evaluate an alert.

    This function never prints credentials. Callers may retain captured values in
    the protected database, but public API responses redact them by default.
    """
    normalized_service = service.lower().strip()
    if normalized_service not in VALID_SERVICES:
        raise ValueError(f"Unsupported service: {service}")
    if source_port is not None and not 0 < int(source_port) <= 65_535:
        raise ValueError("source_port must be between 1 and 65535")

    event = _bounded_text(event, "event", 100) or "unknown"
    safe_metadata = json_safe(metadata or {})
    metadata_json = json.dumps(safe_metadata, ensure_ascii=False, separators=(",", ":"))
    if len(metadata_json.encode("utf-8")) > MAX_METADATA_BYTES:
        raise ValueError("metadata exceeds the 16 KiB limit")

    timestamp = utc_now()
    connection = get_connection()
    try:
        cursor = connection.execute(
            """
            INSERT INTO attacks (
                timestamp, service, source_ip, source_port, username,
                password, event, metadata
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                normalized_service,
                validate_ip(source_ip),
                int(source_port) if source_port is not None else None,
                _bounded_text(username, "username"),
                _bounded_text(password, "password"),
                event,
                metadata_json,
            ),
        )
        connection.commit()
        attack_id = getattr(cursor, "lastrowid", None)
    finally:
        connection.close()

    LOGGER.info("event=%s service=%s source_ip=%s", event, normalized_service, source_ip)
    # Alerting is isolated so an unavailable notifier can never prevent capture.
    try:
        from core.alerting import maybe_create_alert

        maybe_create_alert(validate_ip(source_ip))
    except Exception:  # pragma: no cover - defensive boundary around optional alerting
        LOGGER.exception("Alert evaluation failed for source_ip=%s", source_ip)
    return attack_id
