"""Small dependency-free helpers shared by the intelligence pipeline."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any


def parse_timestamp(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp.astimezone(timezone.utc)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_ip(value: str) -> str:
    """Validate IP input early so it is never interpolated into SQL or logs."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise ValueError("A valid IPv4 or IPv6 address is required") from error


def redact(value: str | None, visible: int = 2) -> str | None:
    if value is None:
        return None
    if not value:
        return ""
    if len(value) <= visible:
        return "*" * len(value)
    return f"{value[:visible]}{'*' * min(8, len(value) - visible)}"


def json_safe(value: Any) -> Any:
    """Conservatively coerce arbitrary metadata into JSON-safe primitives."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    return str(value)
