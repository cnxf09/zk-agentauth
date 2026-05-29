"""Broadcast SSE channel for Service UI Agent monitoring."""
from __future__ import annotations
import threading
import time
from queue import Queue
from collections import deque


class Feed:
    def __init__(self, history: int = 50):
        self._lock = threading.Lock()
        self._history: deque = deque(maxlen=history)
        self._subs: list[Queue] = []

    def publish(self, kind: str, **payload):
        ev = {"kind": kind, "ts": time.time(), **payload}
        with self._lock:
            self._history.append(ev)
            for q in list(self._subs):
                q.put(ev)

    def subscribe(self) -> Queue:
        q: Queue = Queue()
        with self._lock:
            for ev in list(self._history):
                q.put(ev)
            self._subs.append(q)
        return q

    def unsubscribe(self, q: Queue):
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def history(self) -> list:
        with self._lock:
            return list(self._history)


FEED = Feed()
