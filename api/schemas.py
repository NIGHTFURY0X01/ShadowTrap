"""Response contracts for API consumers and the generated OpenAPI document."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AttackRecord(BaseModel):
    id: int
    timestamp: str
    service: str
    source_ip: str
    source_port: int | None = None
    username: str | None = None
    password: str | None = None
    event: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackList(BaseModel):
    count: int
    attacks: list[AttackRecord]


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str


class StatsResponse(BaseModel):
    total_attacks: int
    unique_ips: int
    ssh_attacks: int
    http_attacks: int
    authentication_attempts: int
    suspicious_requests: int
    services: dict[str, int]
