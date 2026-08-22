"""Opt-in critical-event alerting with database-backed deduplication."""

from __future__ import annotations

import json
import logging
import threading
from datetime import timedelta
from urllib.request import Request, urlopen

from core.database import get_connection
from core.investigator import investigate_ip
from core.settings import get_settings
from core.utils import parse_timestamp, utc_now


LOGGER = logging.getLogger("shadowtrap.alerting")


def _send_webhook(url: str, payload: dict[str, object]) -> None:
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "ShadowTrap/1.0"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=3) as response:  # nosec B310 - user-controlled opt-in webhook
            LOGGER.info("Alert webhook delivered with status=%s", response.status)
    except Exception:
        LOGGER.exception("Alert webhook delivery failed")


def maybe_create_alert(source_ip: str) -> dict[str, object] | None:
    settings = get_settings()
    if not settings.alerting_enabled:
        return None
    investigation = investigate_ip(source_ip)
    if not investigation or investigation["risk_score"] < settings.critical_risk_threshold:
        return None

    connection = get_connection()
    try:
        latest = connection.execute(
            "SELECT timestamp FROM alerts WHERE source_ip = ? AND classification = ? ORDER BY timestamp DESC LIMIT 1",
            (source_ip, investigation["classification"]),
        ).fetchone()
        if latest and parse_timestamp(latest["timestamp"]) > parse_timestamp(utc_now()) - timedelta(seconds=settings.alert_dedupe_seconds):
            return None
        payload: dict[str, object] = {
            "type": "shadowtrap.critical_alert",
            "timestamp": utc_now(),
            "source_ip": source_ip,
            "risk_score": investigation["risk_score"],
            "severity": investigation["severity"],
            "classification": investigation["classification"],
            "evidence": investigation["evidence"],
        }
        connection.execute(
            """INSERT INTO alerts (timestamp, source_ip, classification, risk_score, severity, payload, delivery_status)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (payload["timestamp"], source_ip, payload["classification"], payload["risk_score"], payload["severity"], json.dumps(payload), "created"),
        )
        connection.commit()
    finally:
        connection.close()

    LOGGER.warning("CRITICAL alert: source_ip=%s classification=%s score=%s", source_ip, payload["classification"], payload["risk_score"])
    if settings.alert_webhook_url:
        threading.Thread(target=_send_webhook, args=(settings.alert_webhook_url, payload), daemon=True).start()
    return payload
