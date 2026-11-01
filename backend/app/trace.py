"""In-memory trace store with replay + live subscription (feeds SSE)."""
import asyncio
import time
from dataclasses import asdict, dataclass, field
from typing import Any

TERMINAL = {("run", "completed"), ("run", "failed")}


@dataclass
class TraceEvent:
    run_id: str
    seq: int
    ts: float
    kind: str          # run | tool_call | llm_call | finding | policy
    name: str
    data: dict[str, Any] = field(default_factory=dict)


class TraceStore:
    def __init__(self) -> None:
        self._events: dict[str, list[TraceEvent]] = {}
        self._subs: dict[str, list[asyncio.Queue]] = {}

    def emit(self, run_id: str, kind: str, name: str, **data: Any) -> TraceEvent:
        events = self._events.setdefault(run_id, [])
        ev = TraceEvent(run_id, len(events), time.time(), kind, name, data)
        events.append(ev)
        for q in self._subs.get(run_id, []):
            q.put_nowait(ev)
        return ev

    def history(self, run_id: str) -> list[dict]:
        return [asdict(e) for e in self._events.get(run_id, [])]

    def subscribe(self, run_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subs.setdefault(run_id, []).append(q)
        return q

    def unsubscribe(self, run_id: str, q: asyncio.Queue) -> None:
        if q in self._subs.get(run_id, []):
            self._subs[run_id].remove(q)

    @staticmethod
    def is_terminal(ev: dict) -> bool:
        return (ev["kind"], ev["name"]) in TERMINAL