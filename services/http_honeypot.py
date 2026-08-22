"""A deliberately low-interaction HTTP honeypot.

It captures reconnaissance and login attempts, but it never executes submitted
content or proxies requests to another system.
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from core.detection import SUSPICIOUS_PATHS, classify_path, normalize_path
from core.logger import log_attack


LOGGER = logging.getLogger("shadowtrap.http")
MAX_BODY_BYTES = 16_384
LOGIN_PATHS = {"/admin", "/login", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/administrator"}


class HTTPHoneypotHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.58"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        # BaseHTTPRequestHandler's default logs untrusted request URLs to stderr.
        LOGGER.debug("%s - %s", self.client_address[0], format % args)

    def get_client_info(self) -> dict[str, Any]:
        return {"ip": self.client_address[0], "port": self.client_address[1]}

    def get_request_info(self) -> dict[str, Any]:
        parsed_url = urlparse(self.path)
        path = normalize_path(parsed_url.path)
        suspicious_path, request_category = classify_path(path)
        content_length = self.headers.get("Content-Length", "0")
        try:
            parsed_length = max(0, int(content_length))
        except ValueError:
            parsed_length = 0
        return {
            "method": self.command,
            "path": path,
            "query": parsed_url.query[:2_048],
            "user_agent": self.headers.get("User-Agent", "-")[:512],
            "referer": self.headers.get("Referer", "-")[:1_024],
            "host": self.headers.get("Host", "-")[:255],
            "content_type": self.headers.get("Content-Type", "-")[:255],
            "content_length": parsed_length,
            "suspicious_path": suspicious_path,
            "request_category": request_category,
        }

    def _send_html(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def record_request(self, event: str, username: str | None = None, password: str | None = None) -> None:
        client = self.get_client_info()
        log_attack(
            service="http",
            source_ip=client["ip"],
            source_port=client["port"],
            username=username,
            password=password,
            event=event,
            metadata=self.get_request_info(),
        )

    @staticmethod
    def _login_form() -> str:
        return """<!doctype html><html><head><title>Administrator Login</title></head>
        <body><h2>Administrator Login</h2><form method='post' action='/login'>
        <label>Username <input name='username' autocomplete='username'></label><br>
        <label>Password <input type='password' name='password' autocomplete='current-password'></label><br>
        <button type='submit'>Login</button></form></body></html>"""

    def _handle_get(self) -> None:
        path = normalize_path(urlparse(self.path).path)
        self.record_request("http_request")
        if path == "/":
            self._send_html(200, "<!doctype html><html><head><title>Apache2 Ubuntu Default Page</title></head><body><h1>It works!</h1><p>Apache HTTP Server</p></body></html>")
        elif path in LOGIN_PATHS:
            self._send_html(200, self._login_form())
        elif path == "/server-status":
            self._send_html(403, "<!doctype html><title>403 Forbidden</title><h1>Forbidden</h1>")
        else:
            self._send_html(404, "<!doctype html><title>404 Not Found</title><h1>Not Found</h1>")

    def do_GET(self) -> None:
        self._handle_get()

    def do_HEAD(self) -> None:
        self._handle_get()

    def do_OPTIONS(self) -> None:
        self.record_request("http_request")
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _read_form(self) -> tuple[str | None, str | None] | None:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError:
            self._send_json(400, {"detail": "Invalid Content-Length"})
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"detail": "Request body too large"})
            return None
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        content_type = self.headers.get("Content-Type", "").lower()
        if "application/json" in content_type:
            try:
                data = json.loads(raw_body)
            except json.JSONDecodeError:
                data = {}
            if not isinstance(data, dict):
                data = {}
            username, password = data.get("username"), data.get("password")
        else:
            form = parse_qs(raw_body, keep_blank_values=True)
            username, password = form.get("username", [None])[0], form.get("password", [None])[0]
        return (str(username)[:256] if username is not None else None, str(password)[:256] if password is not None else None)

    def do_POST(self) -> None:
        credentials = self._read_form()
        if credentials is None:
            return
        username, password = credentials
        self.record_request("authentication_attempt", username=username, password=password)
        self._send_html(401, "<!doctype html><title>Authentication Failed</title><h2>Invalid username or password</h2>")


def start_http_honeypot(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), HTTPHoneypotHandler)
    server.daemon_threads = True
    LOGGER.info("HTTP honeypot listening on %s:%s", host, port)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        LOGGER.info("HTTP honeypot stopped")
    finally:
        server.server_close()
