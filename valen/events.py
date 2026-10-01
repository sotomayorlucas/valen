"""In-process activity bus for the team server (operator collaboration).

Every mutating action publishes an event; connected operators receive them over
Server-Sent Events (``GET /api/events``), so the UI shows a live activity feed
across the team. The bus is intentionally in-memory: the durable record is the
``runs`` table (history) + the engagement itself.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from typing import Any, Dict, List, Optional


class EventBus:
    def __init__(self, history: int = 200) -> None:
        self._subs: List["queue.Queue[Dict[str, Any]]"] = []
        self._lock = threading.Lock()
        self._history: List[Dict[str, Any]] = []
        self._history_max = history

    def subscribe(self) -> "queue.Queue[Dict[str, Any]]":
        q: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: "queue.Queue[Dict[str, Any]]") -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def publish(self, kind: str, summary: str = "", **fields: Any) -> Dict[str, Any]:
        event = {"ts": time.time(), "kind": kind, "summary": summary, **fields}
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._history_max:
                self._history = self._history[-self._history_max:]
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:  # pragma: no cover - subscriber too slow
                pass
        return event

    def recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history[-limit:])

    @staticmethod
    def sse_format(event: Dict[str, Any], event_id: Optional[int] = None) -> str:
        """Serialize one event as an SSE frame."""
        head = f"id: {event_id}\n" if event_id is not None else ""
        return f"{head}data: {json.dumps(event)}\n\n"
