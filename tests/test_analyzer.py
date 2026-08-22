from core.analyzer import (
    calculate_risk_score,
    calculate_severity,
    classify_attack,
)


def test_brute_force_classification():
    result = classify_attack(
        attempts=10,
        time_window_seconds=20,
    )

    assert result == "BRUTE_FORCE"


def test_suspicious_classification():
    result = classify_attack(
        attempts=3,
        time_window_seconds=120,
    )

    assert result == "SUSPICIOUS"


def test_probe_classification():
    result = classify_attack(
        attempts=1,
        time_window_seconds=None,
    )

    assert result == "PROBE"


def test_high_risk_score():
    score = calculate_risk_score(
        attempts=20,
        unique_usernames=5,
        unique_passwords=10,
        time_window_seconds=5,
    )

    assert score >= 80


def test_low_risk_score():
    score = calculate_risk_score(
        attempts=1,
        unique_usernames=1,
        unique_passwords=1,
        time_window_seconds=None,
    )

    assert score == 0


def test_critical_severity():
    assert calculate_severity(90) == "CRITICAL"


def test_high_severity():
    assert calculate_severity(70) == "HIGH"


def test_medium_severity():
    assert calculate_severity(40) == "MEDIUM"


def test_low_severity():
    assert calculate_severity(10) == "LOW"