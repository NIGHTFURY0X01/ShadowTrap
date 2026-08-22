"""Credential-focused intelligence without exposing values by default in the API."""

from __future__ import annotations

from collections import Counter
from typing import Any

from core.database import get_connection
from core.utils import validate_ip


def analyze_credentials(source_ip: str) -> dict[str, Any] | None:
    normalized_ip = validate_ip(source_ip)
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT username, password, service FROM attacks WHERE source_ip = ?",
            (normalized_ip,),
        ).fetchall()
    finally:
        connection.close()
    if not rows:
        return None

    records = [dict(row) for row in rows]
    usernames = [record["username"] for record in records if record["username"]]
    passwords = [record["password"] for record in records if record["password"]]
    credentials = [(record["username"], record["password"]) for record in records if record["username"] and record["password"]]
    username_counter = Counter(usernames)
    password_counter = Counter(passwords)
    credential_counter = Counter(credentials)
    repeated = [
        {"username": username, "password": password, "attempts": count}
        for (username, password), count in credential_counter.most_common()
        if count > 1
    ]
    return {
        "source_ip": normalized_ip,
        "attempts": len(records),
        "unique_usernames": len(set(usernames)),
        "unique_passwords": len(set(passwords)),
        "top_usernames": username_counter.most_common(5),
        "top_passwords": password_counter.most_common(5),
        "repeated_credentials": repeated,
        "username_spray": len(set(usernames)) >= 3,
        "password_reuse": len(passwords) > len(set(passwords)),
        "credential_stuffing": len(credentials) >= 5 and len(set(credentials)) >= 4,
    }
