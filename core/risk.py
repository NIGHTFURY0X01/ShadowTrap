"""Deterministic risk scoring used by every analysis endpoint."""

from __future__ import annotations

from typing import Iterable

from core.settings import get_settings


def severity_for(score: int) -> str:
    settings = get_settings()
    if score >= settings.critical_risk_threshold:
        return "CRITICAL"
    if score >= settings.high_risk_threshold:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def score_general(*, attempts: int, unique_usernames: int, unique_passwords: int, time_window_seconds: float | None) -> int:
    score = 0
    if attempts >= 5:
        score += 25
    if attempts >= 10:
        score += 15
    if unique_usernames >= 3:
        score += 15
    if unique_passwords >= 5:
        score += 20
    if time_window_seconds is not None and attempts >= 5 and time_window_seconds <= 60:
        score += 25
    return min(score, 100)


def score_http(*, authentication_attempts: int, suspicious_paths: int, scanner_detected: bool, brute_force_detected: bool) -> int:
    # The top-level behaviours intentionally dominate one-off indicators.
    if brute_force_detected:
        return 90
    if scanner_detected:
        return 70
    if authentication_attempts:
        return 60
    if suspicious_paths:
        return 50
    return 30


def score_combined(scores: Iterable[int], service_count: int, campaign_detected: bool) -> int:
    score = max(scores, default=0)
    if service_count >= 2:
        score += 10
    if campaign_detected:
        score += 5
    return min(score, 100)
