"""
Run with:  python tests/test_honeypot_core.py
(or:       python -m pytest tests/ -v)

Covers the custom scoring algorithm, the offline bearing function, SQLite
persistence, and full end-to-end socket tests of both honeypots using
real client libraries (urllib for HTTP, paramiko for SSH) over loopback.
"""

import sys
import os
import socket
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib.request
import urllib.error
import paramiko

from app.intel.scoring import ThreatRegistry
from app.intel.geolocate import offline_bearing, is_public_ip
from app.intel import signatures
from app.capture.event_bus import HoneypotEvent, bus
from app.capture.event_store import EventStore
from app.capture.http_honeypot import HttpHoneypot
from app.capture.ssh_honeypot import SshHoneypot


def test_benign_vs_aggressive_bdi_separation():
    reg = ThreatRegistry()
    benign = reg.get_or_create("203.0.113.10")
    benign.register_event(service="http", path="/", raw_text="/")

    aggressive = reg.get_or_create("198.51.100.77")
    for path in ["/admin", "/.env", "/wp-login.php", "/phpmyadmin/", "/.git/config"]:
        aggressive.register_event(service="http", path=path, raw_text=path + " union select ../../etc/passwd")
    for u, p in [("root", "root"), ("admin", "admin"), ("root", "123456"), ("test", "test")]:
        aggressive.register_event(service="ssh", username=u, password=p)

    assert benign.bdi() < 20
    assert aggressive.bdi() > 60
    assert aggressive.tier() in ("HIGH", "CRITICAL")


def test_offline_bearing_is_deterministic_and_spread_out():
    assert offline_bearing("8.8.8.8") == offline_bearing("8.8.8.8")
    bearings = {offline_bearing(f"10.0.0.{i}") for i in range(20)}
    assert len(bearings) > 10  # different IPs should mostly land on different bearings


def test_is_public_ip():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("192.168.1.5") is False
    assert is_public_ip("127.0.0.1") is False


def test_signature_matching():
    assert signatures.matches_bait_path("/wp-login.php")
    assert signatures.suspicious_score("' UNION SELECT * FROM users -- ../etc/passwd") > 0.5
    assert signatures.suspicious_score("hello world") == 0.0
    assert signatures.is_common_credential_pair("root", "toor")
    assert not signatures.is_common_credential_pair("bob", "correcthorsebatterystaple")


def test_event_store_roundtrip():
    db_path = Path("/tmp/test_honeypot_events.db")
    if db_path.exists():
        db_path.unlink()
    store = EventStore(db_path=db_path)
    store.save(HoneypotEvent(service="http", ip="1.2.3.4", path="/admin", method="GET"))
    store.save(HoneypotEvent(service="ssh", ip="5.6.7.8", username="root", password="root"))
    assert store.count() == 2
    recent = store.recent(10)
    assert recent[0]["service"] == "ssh"
    store.clear()
    assert store.count() == 0
    db_path.unlink()


def test_http_honeypot_end_to_end():
    hp = HttpHoneypot(host="127.0.0.1", port=8199)
    hp.start()
    time.sleep(0.3)
    try:
        r = urllib.request.urlopen("http://127.0.0.1:8199/wp-login.php", timeout=2)
        assert r.status == 200
        try:
            urllib.request.urlopen("http://127.0.0.1:8199/.env", timeout=2)
            assert False, "expected HTTPError 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404
        time.sleep(0.2)
        events = bus.drain()
        paths = {e.path for e in events}
        assert "/wp-login.php" in paths
        assert "/.env" in paths
    finally:
        hp.stop()


def test_ssh_honeypot_end_to_end():
    hp = SshHoneypot(host="127.0.0.1", port=2299)
    hp.start()
    time.sleep(0.3)
    try:
        sock = socket.create_connection(("127.0.0.1", 2299), timeout=3)
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=5)
            auth_rejected = False
            try:
                transport.auth_password("root", "toor")
            except paramiko.AuthenticationException:
                auth_rejected = True
            assert auth_rejected, "the honeypot must NEVER grant real authentication"
        finally:
            transport.close()
        time.sleep(0.3)
        events = bus.drain()
        assert any(e.service == "ssh" and e.username == "root" and e.password == "toor" for e in events)
    finally:
        hp.stop()


if __name__ == "__main__":
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print(f"PASS  {t.__name__}")
    print(f"\n{passed}/{len(tests)} tests passed.")
