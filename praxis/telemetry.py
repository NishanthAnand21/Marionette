"""In-process event bus + sink.

Targets emit; the runner and detection assertions consume.  The data structure
is a list plus subscriber callbacks -- a technique run is short-lived, so
anything that needs a real queue can subscribe and forward.

Two things it is *not* naive about:

* **Thread safety.**  The engine gives every target its own collector, so the
  common path is uncontended.  But an adapter is free to observe from a
  background thread (an MCP stderr drain, a streaming client), and the
  ``mark()`` / ``since()`` pair that bounds a technique's assertion window
  must not interleave with an append from one of those threads.  A single
  re-entrant lock makes the window honest for the cost of an uncontended
  acquire.

* **Growth.**  A technique with a runaway loop emits until the run ends.
  ``max_events`` caps retention, and the count of what was dropped is kept so
  a report can say so out loud -- see :meth:`emit` for why the cap refuses to
  drop events out of a live assertion window.
"""

from __future__ import annotations

import threading
from typing import Callable

from .schema import AgentEvent, write_jsonl

Subscriber = Callable[[AgentEvent], None]

# 0 / None means unbounded, which is the default: capping by default would
# change existing verdicts, and a cap is an operator decision about a long
# fleet run, not something a technique should discover by surprise.
UNBOUNDED = 0


class Collector:
    def __init__(self, run_id: str | None = None,
                 max_events: int = UNBOUNDED) -> None:
        self.run_id = run_id
        self.events: list[AgentEvent] = []
        self.dropped = 0            # events discarded by the cap, ever
        self.max_events = max(0, int(max_events or 0))
        self._subscribers: list[Subscriber] = []
        self._technique_id: str | None = None
        self._floor = 0             # oldest index still retained (see _trim)
        self._lock = threading.RLock()

    # -- production ---------------------------------------------------------
    def bind_technique(self, technique_id: str | None) -> None:
        """Stamp subsequent events with the technique that provoked them."""
        with self._lock:
            self._technique_id = technique_id

    def emit(self, event: AgentEvent) -> AgentEvent:
        with self._lock:
            if event.run_id is None:
                event.run_id = self.run_id
            if event.technique_id is None:
                event.technique_id = self._technique_id
            self.events.append(event)
            self._trim()
            subs = tuple(self._subscribers)
        # Subscribers run outside the lock: a sink that re-enters the collector
        # or blocks on I/O must not stall every other emitter.
        for sub in subs:
            sub(event)
        return event

    def _trim(self) -> None:
        """Drop the oldest events once over the cap, and remember how many.

        Truncation is from the *front*, never the back, because assertions are
        evaluated over the tail of the stream (``since(mark)``): dropping the
        newest events would silently change a verdict, while dropping the
        oldest can only shrink a window that has already been counted.  The
        drop is still recorded, and ``since()`` reports a window that starts at
        the retention floor, so nothing is quietly pretended away.
        """
        if not self.max_events:
            return
        excess = len(self.events) - self.max_events
        if excess > 0:
            del self.events[:excess]
            self.dropped += excess
            self._floor += excess

    def subscribe(self, fn: Subscriber) -> None:
        with self._lock:
            self._subscribers.append(fn)

    # -- consumption --------------------------------------------------------
    def since(self, index: int) -> list[AgentEvent]:
        """Events emitted after ``index``, a mark from :meth:`mark`.

        Marks are absolute emit counts, so they stay valid across truncation:
        a mark older than the retention floor clamps to the floor rather than
        slicing the wrong window.
        """
        with self._lock:
            return self.events[max(0, index - self._floor):]

    def mark(self) -> int:
        with self._lock:
            return self._floor + len(self.events)

    def of_type(self, event_type: str) -> list[AgentEvent]:
        with self._lock:
            return [e for e in self.events if e.type == event_type]

    def save(self, path: str) -> int:
        with self._lock:
            snapshot = list(self.events)
        return write_jsonl(snapshot, path)

    def __len__(self) -> int:
        with self._lock:
            return len(self.events)
