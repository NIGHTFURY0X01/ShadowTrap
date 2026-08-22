"""ShadowTrap command-line entrypoint."""

from __future__ import annotations

import argparse
import json
import logging
import os
from typing import Any

from core.analyzer import analyze_ip
from core.campaign import detect_campaign
from core.credentials import analyze_credentials
from core.database import initialize_database, purge_events_older_than
from core.http_analyzer import analyze_http_ip
from core.investigator import investigate_ip, timeline_for_ip
from core.settings import get_settings, reload_settings
from core.utils import redact
from services.http_honeypot import start_http_honeypot
from services.ssh_honeypot import start_ssh_honeypot


def _safe_result(result: dict[str, Any], show_sensitive: bool) -> dict[str, Any]:
    if show_sensitive:
        return result
    # Serialize/deserialize to make a narrow, non-mutating copy for CLI output.
    safe = json.loads(json.dumps(result))
    def redact_password_fields(value: Any) -> None:
        if not isinstance(value, dict):
            return
        if "top_password" in value:
            value["top_password"] = redact(value["top_password"])
        if "top_passwords" in value:
            value["top_passwords"] = [[redact(item[0]), item[1]] for item in value["top_passwords"]]
        for item in value.get("repeated_credentials", []):
            item["password"] = redact(item.get("password"))
        for nested in value.values():
            if isinstance(nested, dict):
                redact_password_fields(nested)

    redact_password_fields(safe)
    return safe


def _print_result(result: dict[str, Any] | list[dict[str, Any]] | None, as_json: bool, show_sensitive: bool) -> None:
    if result is None:
        print("No matching events found.")
        return
    safe = _safe_result(result, show_sensitive) if isinstance(result, dict) else result
    if as_json:
        print(json.dumps(safe, indent=2, ensure_ascii=False, default=str))
        return
    if isinstance(safe, list):
        for event in safe:
            print(f"{event['timestamp']}  {event['service'].upper():<4}  {event['event']:<24} {event.get('path') or '-'}")
        return
    for key, value in safe.items():
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        print(f"{key.replace('_', ' ').title():<24} {value}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ShadowTrap honeypot attack-intelligence platform")
    parser.add_argument(
        "command",
        choices=("init", "ssh", "http", "api", "analyze", "campaign", "credentials", "http-analyze", "investigate", "timeline", "purge"),
        help="Action to run",
    )
    parser.add_argument("--host", help="Listening address for a service")
    parser.add_argument("--port", type=int, help="Listening port for a service")
    parser.add_argument("--ip", help="IPv4 or IPv6 address to investigate")
    parser.add_argument("--limit", type=int, default=100, help="Timeline event limit (1-500)")
    parser.add_argument("--config", help="Optional YAML configuration file")
    parser.add_argument("--json", action="store_true", help="Render investigation output as JSON")
    parser.add_argument("--show-sensitive", action="store_true", help="Show captured passwords in local CLI output")
    parser.add_argument("--confirm", action="store_true", help="Confirm a retention purge")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.config:
        os.environ["SHADOWTRAP_CONFIG"] = args.config
        reload_settings()
    settings = get_settings()
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    initialize_database()

    if args.command == "init":
        print(f"Database initialized: {settings.database_url}")
        return
    if args.command == "ssh":
        start_ssh_honeypot(args.host or settings.ssh_host, args.port or settings.ssh_port)
        return
    if args.command == "http":
        start_http_honeypot(args.host or settings.http_host, args.port or settings.http_port)
        return
    if args.command == "api":
        try:
            import uvicorn
        except ImportError as error:
            parser.error("API runtime is missing. Run: python -m pip install -r requirements.txt")
            raise error  # Unreachable, keeps type checkers satisfied.
        uvicorn.run("api.main:app", host=args.host or settings.api_host, port=args.port or settings.api_port, reload=False)
        return
    if args.command == "purge":
        if not args.confirm:
            parser.error("purge is destructive; rerun with --confirm")
        print(f"Purged {purge_events_older_than(settings.retention_days)} events older than {settings.retention_days} days.")
        return
    if not args.ip:
        parser.error(f"the {args.command} command requires --ip")
    if args.command == "analyze":
        result: Any = analyze_ip(args.ip)
    elif args.command == "campaign":
        result = detect_campaign(args.ip)
    elif args.command == "credentials":
        result = analyze_credentials(args.ip)
    elif args.command == "http-analyze":
        result = analyze_http_ip(args.ip)
    elif args.command == "investigate":
        result = investigate_ip(args.ip)
    else:
        result = timeline_for_ip(args.ip, max(1, min(args.limit, 500)))
    _print_result(result, args.json, args.show_sensitive)


if __name__ == "__main__":
    main()
