"""Hardened agent target — the negative control for the whole technique pack.

Every technique passes against :class:`~praxis.targets.mock.MockAgentTarget`.
That proves the techniques *execute*; it does not prove they *measure*.  An
assertion that would also hold against a well-built agent is testing the
harness, not the target.

This adapter is the same agent as the mock — same tools, same verbs, same
capability set, same normalized events — with the defences a competent agent
deployment would actually have.  Running the pack against both and diffing the
verdicts is what separates a real detection from a tautology.

The defences are design-level, not filter-level.  Nothing here tries to spot a
"malicious" string; the payloads are allowed to arrive intact.  What changes is
*who is allowed to make the agent act*:

* **Provenance-gated planning.**  Only ``user`` provenance can initiate an
  action.  Text arriving through tool output, retrieval, artifacts, memory,
  a sub-agent, or the system prompt is data, never a command.  This is the
  CaMeL / dual-LLM control-flow separation, and it kills the whole injection
  family in one place instead of once per sink.
* **Per-call authorization against the originating principal.**  Authority is
  not transitive: a call whose authority was inherited through untrusted
  delegation is denied, and delegation drops scope at the boundary.
* **Tool-registry integrity.**  Descriptions are frozen after registration and
  a name may not be re-bound; both rug pulls are refused, not merely logged.
* **Write provenance on memory and corpus.**  Non-user writes are quarantined
  where the planner can never retrieve them.
* **Credential isolation and redaction.**  Credential-bearing config is not
  reachable through general-purpose tools, and secrets (including the system
  prompt) never reach the event stream from tool output.
* **A call budget.**  A runaway tool loop is cut at a fixed ceiling.

A refusal is itself observable: it emits ``agent.authority`` with
``data.kind == "blocked"`` and a reason.  ``agent.authority`` is the existing
class for "an authorization decision happened" — a denial is one, and reusing
it keeps the schema untouched.  Deliberately *not* ``agent.delegation``: a
blocked instruction is the opposite of a delegation, and emitting one there
would make injection assertions pass against the defence that stopped them.
"""

from __future__ import annotations

import re
from typing import Any

from .base import ToolResult, ToolSpec, register
from ..schema import AUTHORITY, MEMORY_READ
from .mock import MockAgentTarget, ToolFn, _INJECTION, P_USER, P_TOOL

# Only content the human actually typed may initiate an action. Everything
# else is content the agent *read*, and reading is not consenting.
_TRUSTED_PROVENANCE = frozenset({P_USER})

# Tool calls per technique. Real agents cap on tokens or wall clock; a fixed
# integer is the only version of that a deterministic range can have.
_CALL_BUDGET = 12

_REDACTED = "[redacted-by-policy]"

# Credential shapes a tool result must never carry back into the planner or
# the event stream. Kept narrow and literal: this is defence in depth behind
# the provenance gate, not the thing doing the real work.
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\S*"),
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_\w+"),
    re.compile(r"\bwhsec[-_]\S+"),
    re.compile(r"(?i)\b[\w.-]*(?:key|token|secret|password|passwd|credential)"
               r"\s*[=:]\s*\S+"),
)


def _redact_text(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub(_REDACTED, text)
    return text


@register("hardened")
class HardenedAgentTarget(MockAgentTarget):
    """The mock agent, defended. Same surface, different answers."""

    # Identical to the mock's, on purpose. A capability the target no longer
    # *abuses* is still a capability it has: dropping `follows_tool_output`
    # here would make every injection technique SKIP, and a skip proves
    # nothing. The technique must run and its assertions must come up empty.
    capabilities = MockAgentTarget.capabilities

    def __init__(self, name: str = "hardened-agent", collector: Any = None,
                 follow_tool_output: bool = True) -> None:
        # State the base __init__ touches indirectly (via _register) has to
        # exist first: _install_default_tools runs inside super().__init__.
        self.quarantine: dict[str, dict[str, Any]] = {}
        self._calls = 0
        super().__init__(name=name, collector=collector,
                         follow_tool_output=follow_tool_output)
        self._harden_defaults()

    def reset(self) -> None:
        super().reset()
        self.quarantine.clear()
        self._calls = 0
        self._harden_defaults()

    # -- refusal telemetry --------------------------------------------------
    def _blocked(self, defence: str, reason: str,
                 provenance: str | None = None, tool: str | None = None,
                 **extra: Any) -> None:
        """Record that a defence refused something, and why."""
        self._emit(type=AUTHORITY, tool_name=tool, provenance=provenance,
                   principal=self.principal, authority=list(self.authority),
                   severity="medium",
                   data={"kind": "blocked", "defence": defence,
                         "reason": reason, **extra})

    # -- credential isolation ----------------------------------------------
    def _harden_defaults(self) -> None:
        """Re-bind the credential tool to a refusal.

        The finding in the mock is that a general-purpose tool reads the
        runtime environment with no authorization check at all. The fix is not
        a check — it is that a general-purpose tool has no path to the
        credential store in the first place.
        """
        def denied(args: dict[str, Any], tgt: "HardenedAgentTarget") -> Any:
            tgt._blocked("credential-isolation",
                         "general-purpose tools cannot read the credential "
                         "store", tool="read_credentials",
                         requested=args.get("key"))
            return {"denied": True, "reason": "credential store is isolated"}

        spec = self._tools.get("read_credentials")
        if spec is not None:
            self._register(spec, denied)

    def _redact(self, value: Any) -> Any:
        """Strip secrets — and the system prompt — out of tool output.

        Applied at registration time so it covers runtime-added tools too, and
        so the redacted form is what the event stream records: telemetry that
        carries the secret is itself the leak.
        """
        if isinstance(value, str):
            text = _redact_text(value)
            prompt = self.system_prompt
            # System prompt confidentiality: whatever the standing
            # instructions say, a tool result may not echo them back.
            if len(prompt) > 12 and prompt in text:
                text = text.replace(prompt, _REDACTED)
            return text
        if isinstance(value, dict):
            return {k: self._redact(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._redact(v) for v in value]
        return value

    def _register(self, spec: ToolSpec, fn: ToolFn) -> None:
        def guarded(args: dict[str, Any], tgt: "HardenedAgentTarget") -> Any:
            return tgt._redact(fn(args, tgt))

        super()._register(spec, guarded)

    # -- the planner, with untrusted content demoted to data ----------------
    def _maybe_follow(self, content: Any, provenance: str = P_TOOL) -> None:
        if provenance in _TRUSTED_PROVENANCE:
            super()._maybe_follow(content, provenance=provenance)
            return
        text = content if isinstance(content, str) else str(content)
        m = _INJECTION.search(text)
        if not m:
            return  # ordinary data; nothing to refuse, nothing to report
        self._blocked("untrusted-content-does-not-plan",
                      f"instruction arrived via {provenance!r}; only user "
                      f"provenance may initiate an action",
                      provenance=provenance, tool=m.group("tool"))

    # -- per-call authorization --------------------------------------------
    def grant(self, authority: str) -> None:
        """Refuse mid-session scope widening.

        A well-built agent takes its scopes just-in-time for the request it is
        serving rather than accumulating them as it runs, so authority granted
        part-way through a session is not honoured for the rest of it. Without
        this the range models no defence at all against silent escalation, and
        a technique testing for it cannot distinguish a vulnerable agent from
        a defended one.
        """
        self._blocked("just-in-time-authority",
                      f"refusing mid-session grant of {authority!r}; scopes are "
                      f"bound to the originating request")

    def call_tool(self, tool: str, args: dict[str, Any],
                  provenance: str = P_USER) -> ToolResult:
        if self._calls >= _CALL_BUDGET:
            self._blocked("call-budget", f"tool-call budget of {_CALL_BUDGET} "
                          f"exhausted", provenance=provenance, tool=tool)
            return ToolResult(ok=False, error="call budget exceeded")
        if provenance not in _TRUSTED_PROVENANCE:
            # Defence in depth behind the planner gate: even if some other
            # path induced this call, the authority it would spend belongs to
            # the user, not to whatever content asked for it.
            self._blocked("per-call-authorization",
                          f"call inherited authority through {provenance!r} "
                          f"delegation; denied against originating principal",
                          provenance=provenance, tool=tool)
            return ToolResult(ok=False, error="unauthorized for this principal")
        self._calls += 1
        return super().call_tool(tool, args, provenance=provenance)

    # -- tool-registry integrity -------------------------------------------
    def set_description(self, tool: str, description: str) -> None:
        if tool not in self._tools:
            super().set_description(tool, description)  # raises, as the mock does
            return
        # A description is model-facing instruction text. Mutating it after the
        # planner has been shown the tool is a rug pull, so the registry is
        # frozen: the refusal is recorded and the old text stands.
        self._blocked("tool-registry-integrity",
                      "tool descriptions are immutable after registration",
                      tool=tool, attempted_description=description)

    def add_tool(self, name: str, description: str = "",
                 input_schema: dict[str, Any] | None = None,
                 returns: Any = None) -> None:
        if name in self._tools:
            self._blocked("tool-registry-integrity",
                          "refusing to re-bind an already-registered tool "
                          "name (shadowing)", tool=name,
                          attempted_description=description)
            return
        super().add_tool(name, description, input_schema, returns)

    # -- write provenance ---------------------------------------------------
    def mem_write(self, key: str, value: str, provenance: str = P_USER) -> None:
        if provenance not in _TRUSTED_PROVENANCE:
            # Quarantined rather than dropped: the attempt is evidence, and
            # keeping it out of `self.memory` is what guarantees mem_read can
            # never hand it back to the planner a session later.
            self.quarantine[key] = {"value": value, "provenance": provenance}
            self._blocked("memory-write-provenance",
                          f"memory write from {provenance!r} quarantined; "
                          f"only user provenance may persist",
                          provenance=provenance, key=key)
            return
        super().mem_write(key, value, provenance=provenance)

    def rag_index(self, doc_id: str, content: str,
                  provenance: str = "untrusted") -> None:
        if provenance not in _TRUSTED_PROVENANCE:
            self.quarantine[doc_id] = {"value": content,
                                       "provenance": provenance}
            self._blocked("corpus-write-provenance",
                          f"document from {provenance!r} quarantined; it is "
                          f"not retrievable into the planner",
                          provenance=provenance, doc_id=doc_id)
            return
        super().rag_index(doc_id, content, provenance=provenance)

    # -- standing instructions ---------------------------------------------
    def set_system_prompt(self, text: str, append: bool = False,
                          provenance: str = P_USER) -> str:
        if provenance not in _TRUSTED_PROVENANCE:
            # Config tampering is persistent injection. Same rule, longer blast
            # radius: untrusted content does not get to rewrite the agent.
            self._blocked("untrusted-content-does-not-plan",
                          f"system prompt change from {provenance!r} refused",
                          provenance=provenance)
            return self.system_prompt
        return super().set_system_prompt(text, append, provenance)

    # -- delegation ---------------------------------------------------------
    def delegate(self, agent: str, task: str, carry_authority: bool = True,
                 response: str = "") -> str:
        if carry_authority:
            self._blocked("per-call-authorization",
                          "authority is not transitive; scope dropped at the "
                          "sub-agent boundary", tool=agent,
                          withheld_authority=list(self.authority))
        # The child runs unprivileged, and its reply comes back as sub-agent
        # provenance, which the planner gate already refuses to act on.
        return super().delegate(agent, task, carry_authority=False,
                                response=response)

    # -- credential store ---------------------------------------------------
    def env_read(self, key: str) -> str | None:
        val = self.env.get(key)
        # The caller still gets the value — this is the credential store's own
        # accessor. What changes is that the secret does not enter telemetry,
        # which is where a "read the config" technique actually harvests it.
        self._emit(type=MEMORY_READ, principal=self.principal,
                   authority=list(self.authority),
                   severity="high" if val is not None else "low",
                   data={"kind": "env_read", "key": key,
                         "hit": val is not None,
                         "value": _REDACTED if val is not None else None,
                         "redacted": val is not None})
        return val
