"""Cross-service behavioural analysis for one source IP."""

from __future__ import annotations

from collections import Counter
from typing import Any

from core.database import get_connection
from core.risk import score_general, severity_for
from core.utils import parse_timestamp, validate_ip


BRUTE_FORCE_ATTEMPTS = 10
BRUTE_FORCE_WINDOW = 60


def get_ip_attempts(source_ip: str) -> list[dict[str, Any]]:
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT id, timestamp, service, source_ip, source_port, username,
                   password, event, metadata
            FROM attacks WHERE source_ip = ? ORDER BY timestamp ASC, id ASC
            """,
            (validate_ip(source_ip),),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def calculate_risk_score(
    attempts: int,
    unique_usernames: int,
    unique_passwords: int,
    time_window_seconds: float | None,
) -> int:
    """Backward-compatible public scoring helper."""
    return score_general(
        attempts=attempts,
        unique_usernames=unique_usernames,
        unique_passwords=unique_passwords,
        time_window_seconds=time_window_seconds,
    )


def classify_attack(attempts: int, time_window_seconds: float | None) -> str:
    if attempts >= BRUTE_FORCE_ATTEMPTS and time_window_seconds is not None and time_window_seconds <= BRUTE_FORCE_WINDOW:
        return "BRUTE_FORCE"
    if attempts >= 3:
        return "SUSPICIOUS"
    return "PROBE"


def calculate_severity(risk_score: int) -> str:
    return severity_for(risk_score)


def calculate_time_window(attacks: list[dict[str, Any]]) -> float | None:
    if len(attacks) < 2:
        return 0.0 if attacks else None
    timestamps = sorted(parse_timestamp(attack["timestamp"]) for attack in attacks)
    return (timestamps[-1] - timestamps[0]).total_seconds()


def analyze_ip(source_ip: str) -> dict[str, Any] | None:
    normalized_ip = validate_ip(source_ip)
    attacks = get_ip_attempts(normalized_ip)
    if not attacks:
        return None

    usernames = [attack["username"] for attack in attacks if attack["username"]]
    passwords = [attack["password"] for attack in attacks if attack["password"]]
    services = [attack["service"] for attack in attacks if attack["service"]]
    username_counts = Counter(usernames)
    password_counts = Counter(passwords)
    service_counts = Counter(services)
    time_window_seconds = calculate_time_window(attacks)
    attempts = len(attacks)
    unique_usernames = len(set(usernames))
    unique_passwords = len(set(passwords))
    risk_score = calculate_risk_score(attempts, unique_usernames, unique_passwords, time_window_seconds)

    return {
        "source_ip": normalized_ip,
        "attempts": attempts,
        "unique_usernames": unique_usernames,
        "unique_passwords": unique_passwords,
        "unique_services": len(set(services)),
        "service_counts": dict(service_counts),
        "event_counts": dict(Counter(attack["event"] for attack in attacks)),
        "top_username": username_counts.most_common(1)[0][0] if username_counts else None,
        "top_password": password_counts.most_common(1)[0][0] if password_counts else None,
        "top_service": service_counts.most_common(1)[0][0] if service_counts else None,
        "first_seen": attacks[0]["timestamp"],
        "last_seen": attacks[-1]["timestamp"],
        "time_window_seconds": time_window_seconds,
        "classification": classify_attack(attempts, time_window_seconds),
        "risk_score": risk_score,
        "severity": calculate_severity(risk_score),
    }
