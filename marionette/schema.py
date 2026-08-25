"""Normalized agent security event schema.

The research gap this closes: observability vendors (LangSmith, Phoenix,
AgentOps) emit rich traces with no threat model, and there is no shared
schema for tool-call / memory-write / delegation / authority events.  Without
a schema, no detection content is portable between two agent deployments.

The shape here is deliberately OCSF-flavoured (``ts``/``class``/``actor``/
``severity`` envelope + typed ``data`` payload) so it can be mapped onto an
OCSF ``Application Activity`` extension later without reworking producers.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable


# --- event classes -----------------------------------------------------------
# Kept as plain strings so technique YAML can name them without importing us.

PROMPT = "agent.prompt"
TOOL_LIST = "agent.tool.list"
TOOL_CALL = "agent.tool.call"
TOOL_RESULT = "agent.tool.result"
MEMORY_READ = "agent.memory.read"
MEMORY_WRITE = "agent.memory.write"
DELEGATION = "agent.delegation"
AUTHORITY = "agent.authority"
TARGET_SNAPSHOT = "target.snapshot"
TECHNIQUE_START = "marionette.technique.start"
TECHNIQUE_END = "marionette.technique.end"

EVENT_CLASSES = frozenset({
    PROMPT, TOOL_LIST, TOOL_CALL, TOOL_RESULT, MEMORY_READ, MEMORY_WRITE,
    DELEGATION, AUTHORITY, TARGET_SNAPSHOT, TECHNIQUE_START, TECHNIQUE_END,
})

SEVERITIES = ("informational", "low", "medium", "high", "critical")


@dataclass
class AgentEvent:
    """One observable thing an agent did.

    ``principal`` is the identity the action is *ultimately* on behalf of, and
    ``authority`` is the effective scope set at the moment of the call.  Those
    two fields are what make confused-deputy conditions expressible at all:
    without them an event stream cannot distinguish "the user asked for this"
    from "a web page the agent read asked for this".
    """

    type: str
    ts: float = field(default_factory=time.time)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    run_id: str | None = None
    technique_id: str | None = None

    actor: str | None = None          # which agent / session
    target: str | None = None         # which server / endpoint
    tool_name: str | None = None
    principal: str | None = None      # whose authority is being exercised
    authority: list[str] = field(default_factory=list)
    provenance: str | None = None     # where the instruction came from
    severity: str = "informational"
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in EVENT_CLASSES:
            raise ValueError(f"unknown event class: {self.type!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity!r}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, default=str)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AgentEvent":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in raw.items() if k in known})


def write_jsonl(events: Iterable[AgentEvent], path: str) -> int:
    n = 0
    # newline="": JSONL is line-framed, so a Windows \r\n translation would
    # end every record with a carriage return the reader has to strip.
    with open(path, "w", encoding="utf-8", newline="") as fh:
        for ev in events:
            fh.write(ev.to_json() + "\n")
            n += 1
    return n


def read_jsonl(path: str) -> list[AgentEvent]:
    out: list[AgentEvent] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(AgentEvent.from_dict(json.loads(line)))
    return out
