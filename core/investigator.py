"""One-stop IP investigation and an event timeline for the dashboard/API."""

from __future__ import annotations

import json
from typing import Any

from core.analyzer import analyze_ip
from core.campaign import detect_campaign
from core.credentials import analyze_credentials
from core.database import get_connection
from core.http_analyzer import analyze_http_ip
from core.risk import score_combined, severity_for
from core.utils import validate_ip


def timeline_for_ip(source_ip: str, limit: int = 250) -> list[dict[str, Any]]:
    normalized_ip = validate_ip(source_ip)
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT id, timestamp, service, source_ip, source_port, username,
                   event, metadata FROM attacks WHERE source_ip = ?
            ORDER BY timestamp ASC, id ASC LIMIT ?
            """,
            (normalized_ip, max(1, min(limit, 500))),
        ).fetchall()
    finally:
        connection.close()
    events: list[dict[str, Any]] = []
    for row in rows:
        event = dict(row)
        try:
            metadata = json.loads(event.pop("metadata") or "{}")
        except (json.JSONDecodeError, TypeError):
            metadata = {}
        event["path"] = metadata.get("path")
        event["method"] = metadata.get("method")
        event["request_category"] = metadata.get("request_category")
        event["suspicious_path"] = bool(metadata.get("suspicious_path"))
        events.append(event)
    return events


def investigate_ip(source_ip: str) -> dict[str, Any] | None:
    normalized_ip = validate_ip(source_ip)
    general = analyze_ip(normalized_ip)
    if not general:
        return None
    http = analyze_http_ip(normalized_ip)
    credentials = analyze_credentials(normalized_ip)
    campaign = detect_campaign(normalized_ip)
    scores = [general["risk_score"]]
    if http:
        scores.append(http["risk_score"])
    service_count = general["unique_services"]
    campaign_detected = bool(campaign and campaign["campaign_detected"])
    risk_score = score_combined(scores, service_count, campaign_detected)
    if campaign and campaign["classification"] == "MULTI_SERVICE_ATTACK":
        classification = "MULTI_SERVICE_ATTACK"
    elif http and http["risk_score"] >= general["risk_score"]:
        classification = http["classification"]
    else:
        classification = general["classification"]
    evidence = []
    if http and http["scanner_detected"]:
        evidence.append("HTTP scanner behaviour")
    if http and http["brute_force_detected"]:
        evidence.append("Repeated HTTP authentication attempts")
    if credentials and credentials["password_reuse"]:
        evidence.append("Password reuse")
    if service_count >= 2:
        evidence.append("Activity across multiple honeypot services")
    return {
        "source_ip": normalized_ip,
        "risk_score": risk_score,
        "severity": severity_for(risk_score),
        "classification": classification,
        "evidence": evidence,
        "general": general,
        "http": http,
        "credentials": credentials,
        "campaign": campaign,
        "timeline_count": len(timeline_for_ip(normalized_ip)),
    }
