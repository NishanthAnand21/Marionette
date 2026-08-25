"""Target adapter layer.

A *target* is anything a technique can be executed against: an MCP server, an
agent framework's loop, or a mock.  Techniques are written against this
interface only, so a technique authored for MCP runs unchanged against a
LangGraph agent the day someone writes that adapter.

Adapters are responsible for emitting normalized :mod:`praxis.schema` events
for everything they observe.  That is the whole point: the schema is produced
at the adapter boundary, not bolted on afterwards.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Callable

from ..errors import UnsupportedCapability
from ..schema import AgentEvent, TOOL_CALL, TOOL_LIST, TOOL_RESULT, PROMPT
from ..telemetry import Collector

# Re-exported: adapters and the runner import it from here.
__all__ = ["UnsupportedCapability", "ToolSpec", "ToolResult", "Target",
           "register", "build", "available"]


@dataclass
class ToolSpec:
    """A tool as the target advertises it.

    ``description`` is the security-relevant field — it is model-facing
    instruction text, and it is what rug pulls mutate.
    """

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }


@dataclass
class ToolResult:
    ok: bool
    content: Any = None
    error: str | None = None


class Target(abc.ABC):
    """Base adapter."""

    kind: str = "abstract"
    capabilities: frozenset[str] = frozenset()

    def __init__(self, name: str, collector: Collector | None = None) -> None:
        self.name = name
        self.collector = collector or Collector()

    # -- lifecycle ----------------------------------------------------------
    def connect(self) -> None:  # pragma: no cover - default no-op
        return None

    def close(self) -> None:  # pragma: no cover - default no-op
        return None

    def __enter__(self) -> "Target":
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        # Always tears down, including when the body raised.
        self.close()

    def health(self) -> tuple[bool, str | None]:
        """Is this target alive and answering? ``(ok, reason_if_not)``."""
        return True, None

    # -- capability surface -------------------------------------------------
    @abc.abstractmethod
    def list_tools(self) -> list[ToolSpec]:
        ...

    @abc.abstractmethod
    def call_tool(self, tool: str, args: dict[str, Any]) -> ToolResult:
        ...

    def send_prompt(self, text: str, provenance: str = "user") -> str:
        raise UnsupportedCapability(
            f"target {self.name!r} ({self.kind}) cannot accept prompts"
        )

    def reset(self) -> None:
        """Return the target to its initial state between techniques.

        The engine reuses one connection for every technique (that is the
        speed win), which would otherwise let one technique's mutations --
        granted authority, a shadowed tool, poisoned memory -- change the
        result of the next one. Adapters that cannot reset a remote system
        leave this a no-op; isolation is then the operator's problem, not a
        silent correctness bug.
        """
        return None

    def require(self, capability: str) -> None:
        if capability not in self.capabilities:
            raise UnsupportedCapability(
                f"target {self.name!r} ({self.kind}) lacks capability "
                f"{capability!r}; has {sorted(self.capabilities)}"
            )

    # -- emission helpers ---------------------------------------------------
    def _emit(self, **kwargs: Any) -> AgentEvent:
        kwargs.setdefault("target", self.name)
        return self.collector.emit(AgentEvent(**kwargs))

    def emit_tool_list(self, tools: list[ToolSpec]) -> None:
        self._emit(
            type=TOOL_LIST,
            data={"tools": [t.to_dict() for t in tools], "count": len(tools)},
        )

    def emit_tool_call(
        self,
        tool: str,
        args: dict[str, Any],
        principal: str | None = None,
        authority: list[str] | None = None,
        provenance: str = "user",
    ) -> None:
        self._emit(
            type=TOOL_CALL,
            tool_name=tool,
            principal=principal,
            authority=list(authority or []),
            provenance=provenance,
            data={"arguments": args},
        )

    def emit_tool_result(self, tool: str, result: ToolResult) -> None:
        self._emit(
            type=TOOL_RESULT,
            tool_name=tool,
            severity="informational" if result.ok else "low",
            data={"ok": result.ok, "content": result.content, "error": result.error},
        )

    def emit_prompt(self, text: str, provenance: str) -> None:
        self._emit(type=PROMPT, provenance=provenance, data={"text": text})


# --- registry ----------------------------------------------------------------

_REGISTRY: dict[str, Callable[..., Target]] = {}


def register(kind: str) -> Callable[[type[Target]], type[Target]]:
    def deco(cls: type[Target]) -> type[Target]:
        cls.kind = kind
        _REGISTRY[kind] = cls
        return cls

    return deco


def build(kind: str, **kwargs: Any) -> Target:
    if kind not in _REGISTRY:
        raise KeyError(f"no target adapter registered for {kind!r}; "
                       f"have {sorted(_REGISTRY)}")
    return _REGISTRY[kind](**kwargs)


def available() -> list[str]:
    return sorted(_REGISTRY)


def registry() -> dict[str, type[Target]]:
    """Public read-only view of the adapter registry.

    Exposed so tooling (the validator, docs generation) can introspect adapter
    capabilities without reaching into module privates.
    """
    return dict(_REGISTRY)


def known_capabilities() -> frozenset[str]:
    """Union of the capabilities every registered adapter exposes."""
    caps: set[str] = set()
    for cls in _REGISTRY.values():
        caps |= set(getattr(cls, "capabilities", frozenset()))
    return frozenset(caps)
