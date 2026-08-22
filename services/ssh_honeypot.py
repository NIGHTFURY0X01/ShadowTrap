"""A low-interaction SSH honeypot that records attempts and runs no commands."""

from __future__ import annotations

import hashlib
import logging
import socket
import threading
from pathlib import Path
from typing import Any

try:
    import paramiko
except ImportError:  # pragma: no cover - exercised only without optional runtime dependency
    paramiko = None  # type: ignore[assignment]

from core.logger import log_attack
from core.settings import get_settings


LOGGER = logging.getLogger("shadowtrap.ssh")


def _host_key() -> Any:
    if paramiko is None:
        raise RuntimeError("SSH honeypot requires Paramiko. Install requirements.txt first.")
    key_path = Path(get_settings().database_path or Path("data"))
    key_path = key_path.parent / "ssh_honeypot_host_key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        return paramiko.RSAKey.from_private_key_file(str(key_path))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    try:
        key_path.chmod(0o600)
    except OSError:
        pass
    return key


class HoneypotServer(paramiko.ServerInterface if paramiko else object):
    def __init__(self, client_ip: str, client_port: int):
        self.client_ip = client_ip
        self.client_port = client_port

    def check_auth_password(self, username: str, password: str) -> int:
        log_attack("ssh", self.client_ip, self.client_port, username, password, "authentication_attempt")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: Any) -> int:
        fingerprint = hashlib.sha256(key.asbytes()).hexdigest()[:32]
        log_attack("ssh", self.client_ip, self.client_port, username, None, "public_key_attempt", {
            "key_type": key.get_name(), "key_fingerprint_sha256": fingerprint,
        })
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel: Any, command: bytes) -> bool:
        log_attack("ssh", self.client_ip, self.client_port, event="command_attempt", metadata={
            "command": command.decode("utf-8", errors="replace")[:1_024],
        })
        return False

    def check_channel_shell_request(self, channel: Any) -> bool:
        log_attack("ssh", self.client_ip, self.client_port, event="shell_request")
        return False


def handle_client(client_socket: socket.socket, client_address: tuple[str, int], host_key: Any | None = None) -> None:
    if paramiko is None:
        client_socket.close()
        return
    client_ip, client_port = client_address
    transport = paramiko.Transport(client_socket)
    transport.banner_timeout = 10
    transport.auth_timeout = 10
    transport.add_server_key(host_key or _host_key())
    try:
        log_attack("ssh", client_ip, client_port, event="connection_attempt")
        transport.start_server(server=HoneypotServer(client_ip, client_port))
        channel = transport.accept(10)
        if channel is not None:
            channel.close()
    except Exception as error:
        LOGGER.debug("SSH connection from %s:%s ended: %s", client_ip, client_port, error)
    finally:
        transport.close()
        client_socket.close()


def start_ssh_honeypot(host: str = "127.0.0.1", port: int = 2222) -> None:
    if paramiko is None:
        raise RuntimeError("SSH honeypot requires Paramiko. Install requirements.txt first.")
    host_key = _host_key()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(100)
        server_socket.settimeout(1.0)
        LOGGER.info("SSH honeypot listening on %s:%s", host, port)
        try:
            while True:
                try:
                    client_socket, client_address = server_socket.accept()
                except TimeoutError:
                    continue
                thread = threading.Thread(target=handle_client, args=(client_socket, client_address, host_key), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            LOGGER.info("SSH honeypot stopped")
