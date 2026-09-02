"""http_honeypot.py — decoy HTTP server. Identical to v1."""
from __future__ import annotations
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.capture.event_bus import HoneypotEvent, bus
from app.intel.signatures import classify_techniques

BANNER_SERVER_HEADER = "nginx/1.18.0 (Ubuntu)"


def _fake_body_for(path: str) -> tuple[int, str, str]:
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
        return 200, "text/html", "<html><body><h3>phpMyAdmin</h3></body></html>"
    if "actuator" in lower:
        return 200, "application/json", '{"status":"UP"}'
    if path in ("/", ""):
        return 200, "text/html", "<html><body><h1>It works!</h1></body></html>"
    return 404, "text/plain", "Not Found"


class _Handler(BaseHTTPRequestHandler):
    server_version = BANNER_SERVER_HEADER
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _handle(self, method: str):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body_bytes = self.rfile.read(length) if length else b""
        body_text = body_bytes.decode("utf-8", errors="replace")
        path = self.path
        user_agent = self.headers.get("User-Agent", "")
        raw_text = f"{method} {path} {body_text}".strip()
        tags = classify_techniques(raw_text)

        bus.publish(HoneypotEvent(
            service="http", ip=self.client_address[0],
            path=path.split("?")[0], method=method,
            raw_text=raw_text, user_agent=user_agent,
            technique_tags=tags,
        ))

        status, content_type, body = _fake_body_for(path)
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_PUT(self):  self._handle("PUT")
    def do_HEAD(self): self._handle("HEAD")


class HttpHoneypot:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.is_running:
            return
        self._server = ThreadingHTTPServer((self.host, self.port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        self._server = None
        self._thread = None
