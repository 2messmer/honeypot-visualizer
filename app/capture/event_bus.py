"""
event_bus.py
-------------
A minimal thread-safe bridge between the honeypot listener threads
(which block on socket I/O) and the Flet UI (which must only touch its
controls from its own asyncio loop).

Producers (the HTTP/SSH honeypot threads, or the attack simulator) call
`bus.publish(event)` from any thread. The UI runs a single asyncio
consumer loop (see main.py) that drains the queue with
`bus.drain()` and applies the events to its controls — the only code
that ever touches Flet controls runs on the UI's own loop.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import queue
import time
import itertools

_id_counter = itertools.count(1)


@dataclass
class HoneypotEvent:
    service: str                 # "http" or "ssh"
    ip: str
    path: str = ""
    method: str = ""
    username: str = None
    password: str = None
    raw_text: str = ""
    user_agent: str = ""
    timestamp: float = field(default_factory=time.time)
    event_id: int = field(default_factory=lambda: next(_id_counter))


class EventBus:
    def __init__(self):
        self._queue: "queue.Queue[HoneypotEvent]" = queue.Queue()

    def publish(self, event: HoneypotEvent):
        self._queue.put_nowait(event)

    def drain(self, max_items: int = 200) -> list[HoneypotEvent]:
        """Non-blocking: returns and removes up to `max_items` pending events."""
        items = []
        for _ in range(max_items):
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return items


# One shared bus for the whole process (single-user desktop app).
bus = EventBus()
