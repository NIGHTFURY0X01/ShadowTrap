from fastapi.testclient import TestClient

from api.main import app
from core.logger import log_attack
from core.settings import reload_settings


def test_api_exposes_stats_redacted_events_and_investigation(monkeypatch):
    monkeypatch.delenv("SHADOWTRAP_API_KEY", raising=False)
    reload_settings()
    log_attack(
        "http",
        "198.51.100.44",
        44444,
        "admin",
        "super-secret",
        "authentication_attempt",
        {"method": "POST", "path": "/login", "suspicious_path": True, "request_category": "login"},
    )

    with TestClient(app) as client:
        root = client.get("/")
        stats = client.get("/api/stats")
        attacks = client.get("/api/attacks")
        investigation = client.get("/api/investigate/198.51.100.44")
        timeline = client.get("/api/timeline/198.51.100.44")

    assert root.status_code == 200
    assert stats.json()["total_attacks"] == 1
    assert attacks.json()["attacks"][0]["password"] != "super-secret"
    assert attacks.json()["attacks"][0]["metadata"]["path"] == "/login"
    assert investigation.json()["source_ip"] == "198.51.100.44"
    assert timeline.json()["count"] == 1


def test_api_rejects_bad_ip_addresses():
    with TestClient(app) as client:
        response = client.get("/api/investigate/not-an-ip")

    assert response.status_code == 422


def test_api_key_protects_routes_when_configured(monkeypatch):
    monkeypatch.setenv("SHADOWTRAP_API_KEY", "test-only-key")
    reload_settings()
    try:
        with TestClient(app) as client:
            denied = client.get("/api/stats")
            allowed = client.get("/api/stats", headers={"X-API-Key": "test-only-key"})
            sensitive = client.get("/api/attacks?include_sensitive=true", headers={"X-API-Key": "test-only-key"})
        assert denied.status_code == 401
        assert allowed.status_code == 200
        assert sensitive.status_code == 200
    finally:
        monkeypatch.delenv("SHADOWTRAP_API_KEY", raising=False)
        reload_settings()
