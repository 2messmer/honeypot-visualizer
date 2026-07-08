"""
http_honeypot.py
------------------
A minimal decoy HTTP server. It answers every request with a plausible
(but generic, non-branded) placeholder page and logs full request
details as a HoneypotEvent — method, path, query, headers, User-Agent,
and body for POST/PUT.

This is a DEFENSIVE / RESEARCH tool: it never executes anything an
attacker sends, never grants real access to anything, and never serves
real credentials or real system information. Only run it on a machine
and network you own or are explicitly authorized to monitor.
"""

from __future__ import annotations
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.capture.event_bus import HoneypotEvent, bus
from app.intel import signatures

BANNER_SERVER_HEADER = "nginx/1.18.0 (Ubuntu)"  # generic, widely-deployed banner — not a real fingerprint of this app


def _fake_body_for(path: str) -> tuple[int, str, str]:
    """Returns (status_code, content_type, body) — deliberately generic/harmless."""
    lower = path.lower()
    if ".env" in lower:
        return 404, "text/plain", "Not Found"
    if "wp-login" in lower or "admin" in lower:
        return 200, "text/html", (
            "<html><head><title>Sign in</title></head><body>"
            "<h2>Administration</h2><form method='post'>"
            "<input name='username' placeholder='Username'><br>"
            "<input name='password' type='password' placeholder='Password'><br>"
            "<button type='submit'>Sign in</button></form></body></html>"
        )
    if "phpmyadmin" in lower:
        return 200, "text/html", "<html><body><h3>phpMyAdmin</h3><p>Please log in.</p></body></html>"
    if "actuator" in lower:
        return 200, "application/json", '{"status":"UP"}'
    if path == "/" or path == "":
        return 200, "text/html", "<html><body><h1>It works!</h1></body></html>"
    return 404, "text/plain", "Not Found"


class _Handler(BaseHTTPRequestHandler):
    server_version = BANNER_SERVER_HEADER
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # silence default stderr logging; we log via the event bus instead

    def _handle(self, method: str):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body_bytes = self.rfile.read(length) if length else b""
        body_text = body_bytes.decode("utf-8", errors="replace")
        path = self.path
        user_agent = self.headers.get("User-Agent", "")
        raw_text = f"{method} {path} {body_text}".strip()

        bus.publish(HoneypotEvent(
            service="http",
            ip=self.client_address[0],
            path=path.split("?")[0],
            method=method,
            raw_text=raw_text,
            user_agent=user_agent,
        ))

        status, content_type, body = _fake_body_for(path)
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_HEAD(self):
        self._handle("HEAD")


class HttpHoneypot:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.is_running:
            return
        self._server = ThreadingHTTPServer((self.host, self.port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        self._server = None
        self._thread = None
