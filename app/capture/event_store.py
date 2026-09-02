"""event_store.py v2 — adds count_for_ip() for historical persistence scoring."""
from __future__ import annotations
import sqlite3
import threading
from pathlib import Path

from app.capture.event_bus import HoneypotEvent

DB_PATH = Path(__file__).resolve().parent.parent.parent / "honeypot_events_v2.db"
_lock = threading.Lock()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            ip TEXT NOT NULL,
            path TEXT,
            method TEXT,
            username TEXT,
            password TEXT,
            raw_text TEXT,
            user_agent TEXT,
            timestamp REAL NOT NULL,
            technique_tags TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON events(ip)")
    conn.commit()
    return conn


class EventStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._conn = _connect(db_path)

    def save(self, event: HoneypotEvent):
        tags_str = ",".join(sorted(event.technique_tags)) if event.technique_tags else ""
        with _lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO events
                   (event_id,service,ip,path,method,username,password,raw_text,user_agent,timestamp,technique_tags)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (event.event_id, event.service, event.ip, event.path, event.method,
                 event.username, event.password, event.raw_text, event.user_agent,
                 event.timestamp, tags_str),
            )
            self._conn.commit()

    def count_for_ip(self, ip: str) -> int:
        """Returns historical event count for this IP (for persistence scoring)."""
        with _lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM events WHERE ip=?", (ip,))
            return cur.fetchone()[0]

    def recent(self, limit: int = 200) -> list[dict]:
        with _lock:
            cur = self._conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            columns = [d[0] for d in cur.description]
            return [dict(zip(columns, row)) for row in cur.fetchall()]

    def count(self) -> int:
        with _lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM events")
            return cur.fetchone()[0]

    def clear(self):
        with _lock:
            self._conn.execute("DELETE FROM events")
            self._conn.commit()
