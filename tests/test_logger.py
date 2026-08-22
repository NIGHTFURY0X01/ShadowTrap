import pytest

from core.analyzer import analyze_ip
from core.logger import log_attack


def test_logger_stores_a_valid_normalized_event():
    log_attack(
        service="http",
        source_ip="192.0.2.20",
        source_port=42000,
        username="admin",
        password="not-shown-in-api",
        event="authentication_attempt",
        metadata={"path": "/login", "suspicious_path": True},
    )

    result = analyze_ip("192.0.2.20")

    assert result is not None
    assert result["attempts"] == 1
    assert result["top_username"] == "admin"


@pytest.mark.parametrize(
    ("service", "source_ip"),
    [("smtp", "192.0.2.20"), ("http", "not-an-ip")],
)
def test_logger_rejects_invalid_event_identity(service, source_ip):
    with pytest.raises(ValueError):
        log_attack(service=service, source_ip=source_ip)
