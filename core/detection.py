"""Pure detection rules for normalized HTTP honeypot events."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable
from urllib.parse import unquote


SUSPICIOUS_PATHS: dict[str, str] = {
    "/admin": "admin_panel",
    "/login": "login",
    "/wp-admin": "wordpress_admin",
    "/wp-login.php": "wordpress_login",
    "/phpmyadmin": "phpmyadmin",
    "/administrator": "administrator",
    "/manager/html": "tomcat_manager",
    "/.env": "environment_file",
    "/config.php": "config_file",
    "/server-status": "server_status",
    "/.git/config": "git_config",
    "/cgi-bin/": "cgi_probe",
}
SCANNER_USER_AGENTS = ("nikto", "nmap", "masscan", "sqlmap", "gobuster", "dirbuster", "zgrab", "curl/")


def normalize_path(path: str | None) -> str:
    raw = unquote(path or "/").split("?", 1)[0]
    normalized = "/" + "/".join(part for part in raw.split("/") if part and part not in {".", ".."})
    return normalized.lower() if normalized != "/" else "/"


def classify_path(path: str | None) -> tuple[bool, str]:
    normalized = normalize_path(path)
    if normalized in SUSPICIOUS_PATHS:
        return True, SUSPICIOUS_PATHS[normalized]
    for candidate, category in SUSPICIOUS_PATHS.items():
        if candidate.endswith("/") and normalized.startswith(candidate):
            return True, category
    return False, "normal"


def is_scanner_user_agent(user_agent: str | None) -> bool:
    normalized = (user_agent or "").lower()
    return any(signature in normalized for signature in SCANNER_USER_AGENTS)


def detect_http_behaviors(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    event_list = list(events)
    categories = [event.get("request_category", "normal") for event in event_list]
    suspicious = [event for event in event_list if event.get("suspicious_path")]
    user_agent_scanner = any(is_scanner_user_agent(event.get("user_agent")) for event in event_list)
    distinct_probe_categories = len({category for category in categories if category != "normal"})
    distinct_paths = len({event.get("path") for event in event_list if event.get("path")})
    authentication_attempts = sum(event.get("event") == "authentication_attempt" for event in event_list)
    scanner_detected = user_agent_scanner or distinct_probe_categories >= 2 or (len(suspicious) >= 4 and distinct_paths >= 3)
    brute_force_detected = authentication_attempts >= 3
    return {
        "scanner_detected": scanner_detected,
        "brute_force_detected": brute_force_detected,
        "scanner_evidence": {
            "scanner_user_agent": user_agent_scanner,
            "distinct_probe_categories": distinct_probe_categories,
            "distinct_paths": distinct_paths,
        },
        "category_counts": dict(Counter(categories)),
    }
