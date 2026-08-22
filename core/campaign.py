"""Campaign correlation across SSH and HTTP events from one attacker."""

from __future__ import annotations

from collections import Counter
from typing import Any

from core.database import get_connection
from core.utils import validate_ip


def detect_campaign(source_ip: str) -> dict[str, Any] | None:
    normalized_ip = validate_ip(source_ip)
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT service, username, password, timestamp, event
            FROM attacks WHERE source_ip = ? ORDER BY timestamp ASC
            """,
            (normalized_ip,),
        ).fetchall()
    finally:
        connection.close()
    if not rows:
        return None

    records = [dict(row) for row in rows]
    usernames = [row["username"] for row in records if row["username"]]
    passwords = [row["password"] for row in records if row["password"]]
    credentials = [(row["username"], row["password"]) for row in records if row["username"] and row["password"]]
    services = [row["service"] for row in records]
    service_counter = Counter(services)
    has_http_probe = any(row["service"] == "http" and row["event"] == "http_request" for row in records)
    has_auth = any(row["event"] == "authentication_attempt" for row in records)

    if len(set(services)) >= 2:
        pattern, confidence = "MULTI_SERVICE_ATTACK", 90
    elif has_auth and len(credentials) >= 5:
        pattern, confidence = "CREDENTIAL_SPRAY", 80
    elif len(records) >= 5:
        pattern, confidence = "REPEATED_AUTHENTICATION", 70
    elif has_http_probe:
        pattern, confidence = "HTTP_RECONNAISSANCE", 55
    else:
        pattern, confidence = "LOW_VOLUME_ACTIVITY", 35

    username_counter = Counter(usernames)
    password_counter = Counter(passwords)
    return {
        "source_ip": normalized_ip,
        "attempts": len(records),
        "unique_credentials": len(set(credentials)),
        "unique_usernames": len(set(usernames)),
        "unique_passwords": len(set(passwords)),
        "services": dict(service_counter),
        "top_username": username_counter.most_common(1)[0][0] if username_counter else None,
        "top_password": password_counter.most_common(1)[0][0] if password_counter else None,
        "top_service": service_counter.most_common(1)[0][0] if service_counter else None,
        "pattern": pattern,
        "classification": pattern,
        "campaign_detected": pattern in {"MULTI_SERVICE_ATTACK", "CREDENTIAL_SPRAY", "REPEATED_AUTHENTICATION"},
        "confidence": confidence,
    }
