"""HTTP-specific analysis and deterministic detection output."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from core.database import get_connection
from core.detection import detect_http_behaviors
from core.risk import score_http, severity_for
from core.utils import parse_timestamp, validate_ip


def _metadata(raw: str | None) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def analyze_http_ip(source_ip: str) -> dict[str, Any] | None:
    normalized_ip = validate_ip(source_ip)
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT id, timestamp, source_ip, source_port, username, password,
                   event, metadata FROM attacks
            WHERE source_ip = ? AND service = 'http' ORDER BY timestamp ASC, id ASC
            """,
            (normalized_ip,),
        ).fetchall()
    finally:
        connection.close()
    if not rows:
        return None

    records = [dict(row) for row in rows]
    indicators: list[dict[str, Any]] = []
    paths: list[str] = []
    user_agents: list[str] = []
    usernames = [row["username"] for row in records if row["username"]]
    passwords = [row["password"] for row in records if row["password"]]
    for row in records:
        meta = _metadata(row["metadata"])
        path = meta.get("path")
        if path:
            paths.append(path)
        if meta.get("user_agent"):
            user_agents.append(meta["user_agent"])
        indicators.append({
            "event": row["event"],
            "path": path,
            "request_category": meta.get("request_category", "normal"),
            "suspicious_path": bool(meta.get("suspicious_path")),
            "user_agent": meta.get("user_agent", ""),
        })

    detection = detect_http_behaviors(indicators)
    auth_attempts = sum(row["event"] == "authentication_attempt" for row in records)
    suspicious_paths = sum(item["suspicious_path"] for item in indicators)
    scanner_detected = bool(detection["scanner_detected"])
    brute_force_detected = bool(detection["brute_force_detected"])
    if brute_force_detected:
        classification = "HTTP_BRUTE_FORCE"
    elif scanner_detected:
        classification = "HTTP_SCANNER"
    elif auth_attempts:
        classification = "HTTP_AUTH_ATTACK"
    elif suspicious_paths:
        classification = "HTTP_SUSPICIOUS_ACTIVITY"
    else:
        classification = "HTTP_RECONNAISSANCE"
    risk_score = score_http(
        authentication_attempts=auth_attempts,
        suspicious_paths=suspicious_paths,
        scanner_detected=scanner_detected,
        brute_force_detected=brute_force_detected,
    )
    timestamps = [parse_timestamp(record["timestamp"]) for record in records]
    username_counts = Counter(usernames)
    password_counts = Counter(passwords)
    path_counts = Counter(paths)
    user_agent_counts = Counter(user_agents)
    return {
        "source_ip": normalized_ip,
        "attempts": len(records),
        "http_requests": sum(row["event"] == "http_request" for row in records),
        "authentication_attempts": auth_attempts,
        "unique_usernames": len(set(usernames)),
        "unique_passwords": len(set(passwords)),
        "unique_paths": len(set(paths)),
        "suspicious_paths": suspicious_paths,
        "top_username": username_counts.most_common(1)[0][0] if username_counts else "-",
        "top_password": password_counts.most_common(1)[0][0] if password_counts else "-",
        "top_paths": path_counts.most_common(5),
        "top_user_agents": user_agent_counts.most_common(5),
        "request_categories": detection["category_counts"],
        "scanner_detected": scanner_detected,
        "brute_force_detected": brute_force_detected,
        "scanner_evidence": detection["scanner_evidence"],
        "first_seen": min(timestamps).isoformat(),
        "last_seen": max(timestamps).isoformat(),
        "classification": classification,
        "risk_score": risk_score,
        "severity": severity_for(risk_score),
    }
