"""The execute -> observe -> assert loop."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .detection import AssertionResult
from .errors import MarionetteError
from .errors import UnsupportedCapability as UnsupportedCapabilityError
from .schema import AgentEvent, TECHNIQUE_START, TECHNIQUE_END
from .targets.base import Target, UnsupportedCapability
from .technique import Step, Technique


# Status is the single field the CLI, JSON report and exit code all key off.
# `executed`/`passed` are kept for back-compat with existing callers.
PASS, FAIL, SKIP, ERROR = "pass", "fail", "skip", "error"


@dataclass
class TechniqueResult:
    technique_id: str
    name: str
    status: str
    executed: bool
    passed: bool
    skipped_reason: str | None = None
    duration_ms: float = 0.0
    assertions: list[AssertionResult] = field(default_factory=list)
    event_count: int = 0
    error: str | None = None
    error_detail: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id, "name": self.name,
            "status": self.status, "executed": self.executed, "passed": self.passed,
            "skipped_reason": self.skipped_reason,
            "duration_ms": round(self.duration_ms, 2),
            "assertions": [a.to_dict() for a in self.assertions],
            "event_count": self.event_count, "error": self.error,
            "error_detail": self.error_detail,
        }


def _dispatch(target: Target, step: Step) -> None:
    a = step.args
    if step.action == "list_tools":
        target.list_tools()
    elif step.action == "call_tool":
        target.call_tool(a["tool"], a.get("args", {}))
    elif step.action == "send_prompt":
        target.send_prompt(a.get("text", ""), a.get("provenance", "user"))
    elif step.action == "grant":
        target.grant(a["authority"])           # type: ignore[attr-defined]
    elif step.action == "mem_write":
        target.mem_write(a["key"], a["value"],  # type: ignore[attr-defined]
                         a.get("provenance", "user"))
    elif step.action == "mem_read":
        target.mem_read(a["key"])               # type: ignore[attr-defined]
    elif step.action == "set_description":
        target.set_description(a["tool"], a["description"])  # type: ignore[attr-defined]
    elif step.action == "snapshot":
        target.list_tools()
    # --- registry / prompt / supply chain ---------------------------------
    elif step.action == "add_tool":
        target.add_tool(a["name"], a.get("description", ""),   # type: ignore[attr-defined]
                        a.get("input_schema"), a.get("returns"))
    elif step.action == "remove_tool":
        target.remove_tool(a["name"])           # type: ignore[attr-defined]
    elif step.action == "set_system_prompt":
        target.set_system_prompt(a.get("text", ""),  # type: ignore[attr-defined]
                                 a.get("append", False),
                                 a.get("provenance", "user"))
    elif step.action == "load_artifact":
        target.load_artifact(a["name"], a.get("path", ""),   # type: ignore[attr-defined]
                             a.get("trusted", False), a.get("payload", ""),
                             a.get("kind", "model"))
    # --- retrieval ---------------------------------------------------------
    elif step.action == "rag_index":
        target.rag_index(a["doc_id"], a.get("content", ""),  # type: ignore[attr-defined]
                         a.get("provenance", "untrusted"))
    elif step.action == "rag_query":
        target.rag_query(a.get("query", ""), a.get("top_k", 3))  # type: ignore[attr-defined]
    # --- multi-agent / identity -------------------------------------------
    elif step.action == "delegate":
        target.delegate(a["agent"], a.get("task", ""),   # type: ignore[attr-defined]
                        a.get("carry_authority", True), a.get("response", ""))
    elif step.action == "set_identity":
        target.set_identity(a["principal"])     # type: ignore[attr-defined]
    # --- environment / authority ------------------------------------------
    elif step.action == "env_set":
        target.env_set(a["key"], a["value"])    # type: ignore[attr-defined]
    elif step.action == "env_read":
        target.env_read(a["key"])               # type: ignore[attr-defined]
    elif step.action == "revoke":
        target.revoke(a["authority"])           # type: ignore[attr-defined]


def _err_detail(exc: BaseException) -> dict[str, Any] | None:
    """Structured error payload, but only for our own typed errors."""
    return exc.to_dict() if isinstance(exc, MarionetteError) else None


def run_technique(technique: Technique, target: Target,
                  run_id: str | None = None) -> TechniqueResult:
    run_id = run_id or uuid.uuid4().hex[:12]
    col = target.collector
    col.run_id = run_id

    missing = [c for c in technique.requires if c not in target.capabilities]
    if missing:
        return TechniqueResult(
            technique.id, technique.name, status=SKIP, executed=False,
            passed=False,
            skipped_reason=f"target lacks capabilities: {missing}")

    col.bind_technique(technique.id)
    mark = col.mark()
    col.emit(AgentEvent(type=TECHNIQUE_START, target=target.name,
                        technique_id=technique.id, data={"name": technique.name}))
    t0 = time.perf_counter()
    error = None
    detail = None
    try:
        for step in technique.steps:
            _dispatch(target, step)
    except (UnsupportedCapability, UnsupportedCapabilityError) as exc:
        # A capability gap discovered mid-run is still a skip, not a failure:
        # the technique never got the chance to prove anything.
        col.bind_technique(None)
        return TechniqueResult(technique.id, technique.name, status=SKIP,
                               executed=False, passed=False,
                               skipped_reason=str(exc),
                               error_detail=_err_detail(exc))
    except Exception as exc:  # noqa: BLE001
        error = str(exc)
        detail = _err_detail(exc)
    dt = (time.perf_counter() - t0) * 1000
    col.emit(AgentEvent(type=TECHNIQUE_END, target=target.name,
                        technique_id=technique.id))
    col.bind_technique(None)

    window = col.since(mark)
    results = [a.evaluate(window) for a in technique.assertions]
    if error is not None:
        status = ERROR
    elif not results:
        # No assertions means the technique can never fail — an authoring bug
        # that would otherwise masquerade as a green run. Be loud about it.
        status = ERROR
        error = "technique defines no assertions; it can never fail"
    elif all(r.passed for r in results):
        status = PASS
    else:
        status = FAIL
    return TechniqueResult(
        technique.id, technique.name, status=status, executed=True,
        passed=status == PASS, duration_ms=dt, assertions=results,
        event_count=len(window), error=error, error_detail=detail)
