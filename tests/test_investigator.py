from core.investigator import investigate_ip, timeline_for_ip
from core.logger import log_attack


def test_investigation_correlates_multi_service_activity():
    log_attack("http", "203.0.113.55", 50001, event="http_request", metadata={"path": "/phpmyadmin", "suspicious_path": True, "request_category": "phpmyadmin"})
    log_attack("ssh", "203.0.113.55", 50002, "root", "demo", "authentication_attempt")

    result = investigate_ip("203.0.113.55")
    timeline = timeline_for_ip("203.0.113.55")

    assert result is not None
    assert result["classification"] == "MULTI_SERVICE_ATTACK"
    assert result["general"]["unique_services"] == 2
    assert [event["service"] for event in timeline] == ["http", "ssh"]
