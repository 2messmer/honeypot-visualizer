"""ssh_honeypot.py — decoy SSH server. Identical to v1."""
from __future__ import annotations
import socket
import threading

import paramiko

from app.capture.event_bus import HoneypotEvent, bus

BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"


class _ServerInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str):
        super().__init__()
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        bus.publish(HoneypotEvent(
            service="ssh", ip=self.client_ip, username=username, password=password,
            raw_text=f"password-auth username={username} password={password}",
            technique_tags={"CRED_STUFFING"},
        ))
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        fingerprint = key.get_fingerprint().hex()
        bus.publish(HoneypotEvent(
            service="ssh", ip=self.client_ip, username=username, password=None,
            raw_text=f"pubkey-auth username={username} fingerprint={fingerprint}",
        ))
        return paramiko.AUTH_FAILED


def _handle_client(client_sock, client_addr, host_key):
    client_ip = client_addr[0]
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = BANNER
        transport.add_server_key(host_key)
        server = _ServerInterface(client_ip)
        try:
            transport.start_server(server=server)
        except (paramiko.SSHException, EOFError, ConnectionResetError):
            return
        chan = transport.accept(timeout=5)
        if chan:
            chan.close()
    except Exception:
        pass
    finally:
        try:
            transport.close()
        except Exception:
            pass


class SshHoneypot:
    def __init__(self, host: str = "0.0.0.0", port: int = 2222):
        self.host = host
        self.port = port
        self._host_key = paramiko.RSAKey.generate(2048)
        self._sock: socket.socket | None = None
        self._running = False

    @property
    def is_running(self):
        return self._running

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, client_addr = self._sock.accept()
            except OSError:
                break
            threading.Thread(
                target=_handle_client,
                args=(client_sock, client_addr, self._host_key),
                daemon=True,
            ).start()

    def start(self):
        if self._running:
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(100)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None
