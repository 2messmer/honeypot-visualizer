"""
event_bus.py
Thread-safe bridge between honeypot listener threads and the Flet UI.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import queue
import time
import itertools

_id_counter = itertools.count(1)


@dataclass
class HoneypotEvent:
    service: str
    ip: str
    path: str = ""
    method: str = ""
    username: str = None
    password: str = None
    raw_text: str = ""
    user_agent: str = ""
    timestamp: float = field(default_factory=time.time)
    event_id: int = field(default_factory=lambda: next(_id_counter))
    technique_tags: set = field(default_factory=set)


class EventBus:
    def __init__(self):
        self._queue: "queue.Queue[HoneypotEvent]" = queue.Queue()

    def publish(self, event: HoneypotEvent):
        self._queue.put_nowait(event)

    def drain(self, max_items: int = 200) -> list[HoneypotEvent]:
        items = []
        for _ in range(max_items):
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return items


bus = EventBus()
