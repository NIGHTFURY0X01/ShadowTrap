"""Runtime configuration for ShadowTrap.

Environment variables take precedence over the checked-in ``config.yaml`` file.
Keeping configuration here makes every entrypoint (CLI, API, and honeypots) use
the same database and safety settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _load_yaml_config() -> dict[str, Any]:
    """Load the optional local YAML configuration without making it mandatory."""
    config_path = Path(os.getenv("SHADOWTRAP_CONFIG", PROJECT_ROOT / "config.yaml"))
    if not config_path.exists():
        return {}

    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        return {}

    with config_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _nested(config: dict[str, Any], section: str, key: str, default: Any = None) -> Any:
    return config.get(section, {}).get(key, default) if isinstance(config.get(section), dict) else default


def _value(name: str, configured: Any, default: Any) -> Any:
    return os.getenv(name, configured if configured is not None else default)


def _project_path(value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


@dataclass(frozen=True)
class Settings:
    database_url: str
    api_host: str
    api_port: int
    http_host: str
    http_port: int
    ssh_host: str
    ssh_port: int
    api_key: str | None
    cors_origins: tuple[str, ...]
    high_risk_threshold: int
    critical_risk_threshold: int
    alerting_enabled: bool
    alert_webhook_url: str | None
    alert_dedupe_seconds: int
    retention_days: int
    log_level: str

    @property
    def database_path(self) -> Path | None:
        """Return an SQLite path when SQLite is the configured backend."""
        if not self.database_url.startswith("sqlite:///"):
            return None
        return Path(self.database_url.removeprefix("sqlite:///"))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    config = _load_yaml_config()
    database_path = _value(
        "SHADOWTRAP_DATABASE_PATH",
        _nested(config, "database", "path"),
        "data/shadowtrap.db",
    )
    database_url = _value(
        "SHADOWTRAP_DATABASE_URL",
        _nested(config, "database", "url"),
        f"sqlite:///{_project_path(str(database_path))}",
    )
    cors_value = _value("SHADOWTRAP_CORS_ORIGINS", _nested(config, "api", "cors_origins"), "*")
    if isinstance(cors_value, list):
        cors_origins = tuple(str(value) for value in cors_value)
    else:
        cors_origins = tuple(value.strip() for value in str(cors_value).split(",") if value.strip())

    return Settings(
        database_url=str(database_url),
        api_host=str(_value("SHADOWTRAP_API_HOST", _nested(config, "api", "host"), "127.0.0.1")),
        api_port=int(_value("SHADOWTRAP_API_PORT", _nested(config, "api", "port"), 8000)),
        http_host=str(_value("SHADOWTRAP_HTTP_HOST", _nested(config, "honeypots", "http_host"), "127.0.0.1")),
        http_port=int(_value("SHADOWTRAP_HTTP_PORT", _nested(config, "honeypots", "http_port"), 8080)),
        ssh_host=str(_value("SHADOWTRAP_SSH_HOST", _nested(config, "honeypots", "ssh_host"), "127.0.0.1")),
        ssh_port=int(_value("SHADOWTRAP_SSH_PORT", _nested(config, "honeypots", "ssh_port"), 2222)),
        api_key=os.getenv("SHADOWTRAP_API_KEY") or _nested(config, "security", "api_key"),
        cors_origins=cors_origins or ("*",),
        high_risk_threshold=int(_value("SHADOWTRAP_RISK_THRESHOLD_HIGH", _nested(config, "risk", "high_threshold"), 70)),
        critical_risk_threshold=int(_value("SHADOWTRAP_RISK_THRESHOLD_CRITICAL", _nested(config, "risk", "critical_threshold"), 85)),
        alerting_enabled=_as_bool(_value("SHADOWTRAP_ALERTING_ENABLED", _nested(config, "alerting", "enabled"), False)),
        alert_webhook_url=os.getenv("SHADOWTRAP_ALERT_WEBHOOK_URL") or _nested(config, "alerting", "webhook_url"),
        alert_dedupe_seconds=int(_value("SHADOWTRAP_ALERT_DEDUPE_SECONDS", _nested(config, "alerting", "dedupe_seconds"), 300)),
        retention_days=int(_value("SHADOWTRAP_RETENTION_DAYS", _nested(config, "database", "retention_days"), 90)),
        log_level=str(_value("SHADOWTRAP_LOG_LEVEL", _nested(config, "logging", "level"), "INFO")).upper(),
    )


def reload_settings() -> Settings:
    """Clear the configuration cache; useful for tests and long-running tooling."""
    get_settings.cache_clear()
    return get_settings()
