"""Read-only intelligence API for ShadowTrap."""

from __future__ import annotations

import hmac
import json
from collections import Counter
from typing import Any, Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import PlainTextResponse

from api.schemas import AttackList, AttackRecord, StatsResponse
from core.analyzer import analyze_ip
from core.campaign import detect_campaign
from core.credentials import analyze_credentials
from core.database import get_connection
from core.http_analyzer import analyze_http_ip
from core.investigator import investigate_ip, timeline_for_ip
from core.settings import get_settings
from core.utils import redact, validate_ip


router = APIRouter(prefix="/api", tags=["intelligence"])


def require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    """Enforce API-key access only when the deployment has configured a key."""
    configured_key = get_settings().api_key
    if configured_key and (not x_api_key or not hmac.compare_digest(x_api_key, configured_key)):
        raise HTTPException(status_code=401, detail="A valid X-API-Key header is required")


def _valid_ip(ip: str) -> str:
    try:
        return validate_ip(ip)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


def _parse_metadata(value: str | None) -> dict[str, Any]:
    try:
        data = json.loads(value or "{}")
        if not isinstance(data, dict):
            return {}
    except (json.JSONDecodeError, TypeError):
        return {}
    # Do not expose complete headers, queries, or any future raw request fields.
    public_fields = ("method", "path", "request_category", "suspicious_path", "user_agent", "content_length")
    return {field: data[field] for field in public_fields if field in data}


def _attack_record(row: Any, include_sensitive: bool) -> dict[str, Any]:
    attack = dict(row)
    attack["metadata"] = _parse_metadata(attack.get("metadata"))
    if not include_sensitive:
        attack["password"] = redact(attack.get("password"))
    return attack


def _sensitive_access_requested(include_sensitive: bool, x_api_key: str | None) -> bool:
    if not include_sensitive:
        return False
    configured_key = get_settings().api_key
    if not configured_key or not x_api_key or not hmac.compare_digest(x_api_key, configured_key):
        raise HTTPException(status_code=403, detail="Sensitive fields require a configured, valid API key")
    return True


def _redact_analysis(result: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of an analysis tree with all captured passwords masked."""
    safe = json.loads(json.dumps(result))

    def redact_password_fields(value: Any) -> None:
        if not isinstance(value, dict):
            return
        if "top_password" in value:
            value["top_password"] = redact(value["top_password"])
        if "top_passwords" in value:
            value["top_passwords"] = [[redact(item[0]), item[1]] for item in value["top_passwords"]]
        for repeated in value.get("repeated_credentials", []):
            repeated["password"] = redact(repeated.get("password"))
        for nested in value.values():
            if isinstance(nested, dict):
                redact_password_fields(nested)

    redact_password_fields(safe)
    return safe


@router.get("/health", dependencies=[Depends(require_api_key)])
def health() -> dict[str, str]:
    settings = get_settings()
    connection = get_connection()
    try:
        connection.execute("SELECT 1").fetchone()
    finally:
        connection.close()
    return {"status": "ok", "service": "shadowtrap-api", "version": "1.1.0", "database": "postgresql" if settings.database_path is None else "sqlite"}


@router.get("/stats", response_model=StatsResponse, dependencies=[Depends(require_api_key)])
def stats() -> dict[str, Any]:
    connection = get_connection()
    try:
        rows = connection.execute("SELECT service, event, metadata FROM attacks").fetchall()
    finally:
        connection.close()
    records = [dict(row) for row in rows]
    service_counts = Counter(record["service"] for record in records)
    suspicious_requests = 0
    for record in records:
        metadata = _parse_metadata(record.get("metadata"))
        suspicious_requests += bool(metadata.get("suspicious_path"))
    unique_ips_connection = get_connection()
    try:
        unique_ips = unique_ips_connection.execute("SELECT COUNT(DISTINCT source_ip) AS count FROM attacks").fetchone()["count"]
    finally:
        unique_ips_connection.close()
    return {
        "total_attacks": len(records),
        "unique_ips": unique_ips,
        "ssh_attacks": service_counts.get("ssh", 0),
        "http_attacks": service_counts.get("http", 0),
        "authentication_attempts": sum(record["event"] == "authentication_attempt" for record in records),
        "suspicious_requests": suspicious_requests,
        "services": dict(service_counts),
    }


@router.get("/attacks", response_model=AttackList, dependencies=[Depends(require_api_key)])
def attacks(
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    service: Annotated[str | None, Query(pattern="^(http|ssh)$")] = None,
    source_ip: str | None = None,
    event: Annotated[str | None, Query(max_length=100)] = None,
    include_sensitive: bool = False,
    x_api_key: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    sensitive = _sensitive_access_requested(include_sensitive, x_api_key)
    clauses: list[str] = []
    parameters: list[Any] = []
    if service:
        clauses.append("service = ?")
        parameters.append(service)
    if source_ip:
        clauses.append("source_ip = ?")
        parameters.append(_valid_ip(source_ip))
    if event:
        clauses.append("event = ?")
        parameters.append(event)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    parameters.append(limit)
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT id, timestamp, service, source_ip, source_port, username, password, event, metadata "
            f"FROM attacks{where} ORDER BY timestamp DESC, id DESC LIMIT ?",
            parameters,
        ).fetchall()
    finally:
        connection.close()
    return {"count": len(rows), "attacks": [_attack_record(row, sensitive) for row in rows]}


@router.get("/attacks/{ip}", dependencies=[Depends(require_api_key)])
def attack_analysis(ip: str) -> dict[str, Any]:
    result = analyze_ip(_valid_ip(ip))
    if not result:
        raise HTTPException(status_code=404, detail="No attacks found for this IP")
    return _redact_analysis(result)


@router.get("/investigate/{ip}", dependencies=[Depends(require_api_key)])
def ip_investigation(ip: str) -> dict[str, Any]:
    result = investigate_ip(_valid_ip(ip))
    if not result:
        raise HTTPException(status_code=404, detail="No attacks found for this IP")
    return _redact_analysis(result)


@router.get("/timeline/{ip}", dependencies=[Depends(require_api_key)])
def attack_timeline(ip: str, limit: Annotated[int, Query(ge=1, le=500)] = 250) -> dict[str, Any]:
    normalized_ip = _valid_ip(ip)
    events = timeline_for_ip(normalized_ip, limit)
    if not events:
        raise HTTPException(status_code=404, detail="No attacks found for this IP")
    for event in events:
        event["username"] = redact(event.get("username"))
    return {"source_ip": normalized_ip, "count": len(events), "events": events}


@router.get("/campaign/{ip}", dependencies=[Depends(require_api_key)])
def campaign_analysis(ip: str) -> dict[str, Any]:
    result = detect_campaign(_valid_ip(ip))
    if not result:
        raise HTTPException(status_code=404, detail="No campaign found for this IP")
    return _redact_analysis(result)


@router.get("/credentials/{ip}", dependencies=[Depends(require_api_key)])
def credential_analysis(ip: str, include_sensitive: bool = False, x_api_key: Annotated[str | None, Header()] = None) -> dict[str, Any]:
    result = analyze_credentials(_valid_ip(ip))
    if not result:
        raise HTTPException(status_code=404, detail="No credential activity found for this IP")
    if not _sensitive_access_requested(include_sensitive, x_api_key):
        result["top_passwords"] = [(redact(password), count) for password, count in result["top_passwords"]]
        for item in result["repeated_credentials"]:
            item["password"] = redact(item["password"])
    return result


@router.get("/http/{ip}", dependencies=[Depends(require_api_key)])
def http_analysis(ip: str) -> dict[str, Any]:
    result = analyze_http_ip(_valid_ip(ip))
    if not result:
        raise HTTPException(status_code=404, detail="No HTTP attacks found for this IP")
    return _redact_analysis(result)


@router.get("/alerts", dependencies=[Depends(require_api_key)])
def alerts(limit: Annotated[int, Query(ge=1, le=100)] = 50) -> dict[str, Any]:
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT id, timestamp, source_ip, classification, risk_score, severity, delivery_status FROM alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        connection.close()
    return {"count": len(rows), "alerts": [dict(row) for row in rows]}


@router.get("/metrics", response_class=PlainTextResponse, dependencies=[Depends(require_api_key)])
def metrics() -> str:
    values = stats()
    lines = ["# HELP shadowtrap_attacks_total Total collected honeypot events", "# TYPE shadowtrap_attacks_total gauge"]
    lines.append(f"shadowtrap_attacks_total {values['total_attacks']}")
    lines.extend(["# HELP shadowtrap_unique_ips Unique attacker IPs", "# TYPE shadowtrap_unique_ips gauge", f"shadowtrap_unique_ips {values['unique_ips']}"])
    for service, count in values["services"].items():
        lines.append(f'shadowtrap_service_events{{service="{service}"}} {count}')
    return "\n".join(lines) + "\n"
