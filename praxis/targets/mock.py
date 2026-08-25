"""Mock agent target — an in-process agent loop with a memory store.

This is what makes Praxis runnable, testable, and CI-able with zero external
processes.  It models the things real agent frameworks share and that attacks
exploit: a *mutable* tool registry, a system prompt, a retrieval corpus, a
memory store, loadable artifacts, sub-agents, an environment holding secrets,
and a naive planner that will follow instructions embedded in any of the
untrusted content that reaches it.

Every one of those untrusted sinks funnels into the same planner, tagged with
a distinct ``provenance`` — that is what lets a detection assertion say "the
agent obeyed the *retrieval corpus*" rather than merely "the agent obeyed
something".

It is intentionally vulnerable.  That is the point of a range.  It is also
intentionally deterministic: no randomness, no network, no filesystem.  A
technique that passes today must pass identically in CI a year from now.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from ..errors import UnsupportedCapability
from .base import Target, ToolResult, ToolSpec, register
from ..schema import (AgentEvent, MEMORY_READ, MEMORY_WRITE, DELEGATION,
                      AUTHORITY, PROMPT, TOOL_LIST, TOOL_CALL, TOOL_RESULT)

ToolFn = Callable[[dict[str, Any], "MockAgentTarget"], Any]

# Matches an instruction an injected payload might smuggle through tool output.
_INJECTION = re.compile(r"(?:SYSTEM|IMPORTANT|INSTRUCTION)\s*:\s*call\s+"
                        r"(?P<tool>[\w.-]+)(?:\s+with\s+(?P<args>.+))?",
                        re.IGNORECASE)

# Provenance labels. These are a public contract: techniques assert on them to
# distinguish *which* untrusted channel got the agent to act.
P_USER = "user"
P_TOOL = "tool-output"
P_RAG = "rag-retrieval"
P_ARTIFACT = "artifact"
P_MEMORY = "memory"
P_SUBAGENT = "sub-agent"
P_SYSTEM_PROMPT = "system-prompt"

# A followed instruction can itself return an instruction. Real agents loop
# until a token budget stops them; we stop at a fixed depth so a technique can
# never hang CI.
_MAX_FOLLOW_DEPTH = 4


@register("mock")
class MockAgentTarget(Target):
    """A deliberately naive agent with tools, memory, and a gullible planner."""

    # One label per verb, so `requires:` in a technique gates precisely and a
    # target that genuinely cannot do a thing (MCP) SKIPs instead of erroring.
    capabilities = frozenset(
        {"list_tools", "call_tool", "prompt", "memory", "delegation",
         "snapshot", "follows_tool_output", "grant", "set_description",
         "add_tool", "remove_tool", "set_system_prompt", "load_artifact",
         "rag_index", "rag_query", "delegate", "set_identity",
         "env_set", "env_read", "revoke"}
    )

    def __init__(self, name: str = "mock-agent", collector: Any = None,
                 follow_tool_output: bool = True) -> None:
        super().__init__(name=name, collector=collector)
        self._tools: dict[str, ToolSpec] = {}
        self._impl: dict[str, ToolFn] = {}
        self.memory: dict[str, str] = {}
        self.corpus: list[dict[str, Any]] = []
        self.artifacts: list[dict[str, Any]] = []
        self.env: dict[str, str] = {}
        self.system_prompt = "You are a helpful assistant."
        self.principal = "user"
        self.authority = ["read:public"]
        self.follow_tool_output = follow_tool_output
        self._follow_depth = 0
        self._install_default_tools()

    def reset(self) -> None:
        """Restore the range to a pristine agent: no poison, no leftovers."""
        self._tools.clear()
        self._impl.clear()
        self.memory.clear()
        self.corpus.clear()
        self.artifacts.clear()
        self.env.clear()
        self.system_prompt = "You are a helpful assistant."
        self.principal = "user"
        self.authority = ["read:public"]
        self._follow_depth = 0
        self._install_default_tools()

    # -- tool registry ------------------------------------------------------
    def _register(self, spec: ToolSpec, fn: ToolFn) -> None:
        """Bind a tool without emitting — used for the built-in tool set."""
        self._tools[spec.name] = spec
        self._impl[spec.name] = fn

    def add_tool(self, name: str, description: str = "",
                 input_schema: dict[str, Any] | None = None,
                 returns: Any = None) -> None:
        """Register a tool at runtime, possibly shadowing an existing name.

        Shadowing is the interesting case: a name the planner already trusts
        now resolves to attacker-supplied behaviour, and nothing in the tool
        list says so except that the description changed.
        """
        shadowed = name in self._tools
        # A runtime-added tool returns exactly what its author declared, so an
        # attacker-registered tool can hand the planner an instruction.
        canned = returns if returns is not None else f"{name} executed"

        def dynamic(args: dict[str, Any], tgt: "MockAgentTarget") -> Any:
            return args.get("_content", canned)

        self._register(ToolSpec(name, description, input_schema or {}), dynamic)
        self._emit(type=TOOL_LIST, tool_name=name,
                   severity="high" if shadowed else "medium",
                   data={"kind": "tool_added", "tool": name,
                         "description": description, "shadowed": shadowed,
                         "tools": [t.to_dict() for t in self._tools.values()],
                         "count": len(self._tools)})

    def remove_tool(self, name: str) -> None:
        """Deregister a tool — the inverse of :meth:`add_tool`."""
        if name not in self._tools:
            raise UnsupportedCapability(
                f"target {self.name!r} has no tool {name!r} to remove; "
                f"has {sorted(self._tools)}",
                hint="check the `name` arg in the technique step")
        self._tools.pop(name)
        self._impl.pop(name, None)
        self._emit(type=TOOL_LIST, tool_name=name, severity="medium",
                   data={"kind": "tool_removed", "tool": name,
                         "tools": [t.to_dict() for t in self._tools.values()],
                         "count": len(self._tools)})

    def set_description(self, tool: str, description: str) -> None:
        """Mutate a live tool description — models an MCP rug pull."""
        if tool not in self._tools:
            raise UnsupportedCapability(
                f"target {self.name!r} has no tool {tool!r} to re-describe; "
                f"has {sorted(self._tools)}",
                hint="check the `tool` name in the technique step")
        self._tools[tool].description = description

    def _install_default_tools(self) -> None:
        def read_public(args, tgt):
            return f"public record: {args.get('key', '')}"

        def read_secret(args, tgt):
            tgt.require("call_tool")
            if "read:secret" not in tgt.authority:
                return {"denied": True, "reason": "insufficient authority"}
            return {"secret": "FLAG{praxis-confused-deputy}"}

        def fetch_url(args, tgt):
            # The untrusted-content sink: returns attacker-controlled text.
            return args.get("_content", f"<html>content of {args.get('url','')}</html>")

        def send_email(args, tgt):
            return {"sent_to": args.get("to"), "body": args.get("body", "")}

        def read_credentials(args, tgt):
            # Credential access straight off the runtime environment — no
            # authority check, which is the whole finding.
            key = args.get("key")
            if key:
                return {"key": key, "value": tgt.env.get(key)}
            return {"env": dict(tgt.env)}

        def read_file(args, tgt):
            # No real filesystem: `_content` is the range's stand-in so a
            # technique stays reproducible on any machine.
            return args.get("_content", f"contents of {args.get('path', '')}")

        def http_post(args, tgt):
            # The outbound sink. Nothing leaves the process; the event is the
            # artifact a detection is written against.
            return {"posted_to": args.get("url"), "body": args.get("body", "")}

        def exec_code(args, tgt):
            # Deliberately does NOT evaluate anything — the security-relevant
            # fact is that the agent was willing to, and that is in the event.
            return {"executed": args.get("code", ""), "exit_code": 0}

        self._register(ToolSpec("read_public", "Read a public record by key.",
                                {"type": "object", "properties": {"key": {"type": "string"}}}),
                       read_public)
        self._register(ToolSpec("read_secret", "Read a privileged secret. Requires read:secret.",
                                {"type": "object", "properties": {}}),
                       read_secret)
        self._register(ToolSpec("fetch_url", "Fetch a URL and return its contents.",
                                {"type": "object", "properties": {"url": {"type": "string"}}}),
                       fetch_url)
        self._register(ToolSpec("send_email", "Send an email.",
                                {"type": "object", "properties": {
                                    "to": {"type": "string"}, "body": {"type": "string"}}}),
                       send_email)
        self._register(ToolSpec("read_credentials",
                                "Read secrets from the agent's environment.",
                                {"type": "object", "properties": {"key": {"type": "string"}}}),
                       read_credentials)
        self._register(ToolSpec("read_file", "Read a file from local disk.",
                                {"type": "object", "properties": {"path": {"type": "string"}}}),
                       read_file)
        self._register(ToolSpec("http_post", "POST a body to an arbitrary URL.",
                                {"type": "object", "properties": {
                                    "url": {"type": "string"}, "body": {"type": "string"}}}),
                       http_post)
        self._register(ToolSpec("exec_code", "Execute a code snippet in the agent sandbox.",
                                {"type": "object", "properties": {"code": {"type": "string"}}}),
                       exec_code)

    # -- capability surface -------------------------------------------------
    def list_tools(self) -> list[ToolSpec]:
        tools = list(self._tools.values())
        self.emit_tool_list(tools)
        return tools

    def call_tool(self, tool: str, args: dict[str, Any],
                  provenance: str = P_USER) -> ToolResult:
        if tool not in self._impl:
            res = ToolResult(ok=False, error=f"no such tool: {tool}")
            self.emit_tool_call(tool, args, self.principal, self.authority, provenance)
            self.emit_tool_result(tool, res)
            return res
        self.emit_tool_call(tool, args, self.principal, self.authority, provenance)
        try:
            content = self._impl[tool](args, self)
            res = ToolResult(ok=True, content=content)
        except Exception as exc:  # noqa: BLE001 - surfaced as a tool error
            res = ToolResult(ok=False, error=str(exc))
        self.emit_tool_result(tool, res)
        # Indirect prompt injection: the planner scans tool output for orders.
        if res.ok and self.follow_tool_output:
            self._maybe_follow(res.content)
        return res

    def send_prompt(self, text: str, provenance: str = P_USER) -> str:
        self.emit_prompt(text, provenance)
        self._maybe_follow(text, provenance=provenance)
        return "ok"

    def set_system_prompt(self, text: str, append: bool = False,
                          provenance: str = P_USER) -> str:
        """Replace or extend the agent's standing instructions.

        Tampering here outlives any single turn, so it is the persistence
        analogue of prompt injection rather than a one-shot.
        """
        self.system_prompt = (self.system_prompt + "\n" + text) if append else text
        self._emit(type=PROMPT, provenance=provenance, severity="high",
                   principal=self.principal,
                   data={"kind": "system_prompt", "append": append,
                         "text": text, "system_prompt": self.system_prompt})
        # Standing instructions are still instructions — the planner reads them.
        self._maybe_follow(text, provenance=P_SYSTEM_PROMPT)
        return self.system_prompt

    # -- authority / identity ----------------------------------------------
    def grant(self, authority: str) -> None:
        self.authority = sorted(set(self.authority) | {authority})
        self._emit(type=AUTHORITY, principal=self.principal,
                   authority=self.authority,
                   data={"kind": "grant", "granted": authority})

    def revoke(self, authority: str) -> None:
        """Drop a scope. Exists so techniques can prove revocation *took*."""
        had = authority in self.authority
        self.authority = [a for a in self.authority if a != authority]
        self._emit(type=AUTHORITY, principal=self.principal,
                   authority=self.authority,
                   data={"kind": "revoke", "revoked": authority,
                         "was_held": had})

    def set_identity(self, principal: str) -> None:
        """Swap the acting principal without re-deriving authority.

        That decoupling is the bug: the scopes granted to the old identity
        stay attached to the new one.
        """
        previous, self.principal = self.principal, principal
        self._emit(type=AUTHORITY, principal=principal,
                   authority=self.authority, severity="high",
                   data={"kind": "identity_change", "previous": previous,
                         "principal": principal,
                         "authority_carried": list(self.authority)})

    # -- environment (credential store) -------------------------------------
    def env_set(self, key: str, value: str) -> None:
        self._emit(type=MEMORY_WRITE, provenance=P_USER,
                   data={"kind": "env_set", "key": key,
                         "value_len": len(value)})
        self.env[key] = value

    def env_read(self, key: str) -> str | None:
        val = self.env.get(key)
        # Reading a secret out of the runtime environment is the technique, so
        # it is high even when it succeeds legitimately.
        self._emit(type=MEMORY_READ, principal=self.principal,
                   authority=self.authority,
                   severity="high" if val is not None else "low",
                   data={"kind": "env_read", "key": key,
                         "hit": val is not None, "value": val})
        return val

    # -- memory -------------------------------------------------------------
    def mem_write(self, key: str, value: str, provenance: str = P_USER) -> None:
        self._emit(type=MEMORY_WRITE, provenance=provenance,
                   data={"kind": "memory", "key": key, "value": value})
        self.memory[key] = value

    def mem_read(self, key: str) -> str | None:
        val = self.memory.get(key)
        self._emit(type=MEMORY_READ,
                   data={"kind": "memory", "key": key, "hit": val is not None})
        # Recalled memory is fed back to the planner verbatim — that is what
        # turns a poisoned write into a live action a session later.
        if val is not None:
            self._maybe_follow(val, provenance=P_MEMORY)
        return val

    # -- retrieval corpus ---------------------------------------------------
    def rag_index(self, doc_id: str, content: str,
                  provenance: str = "untrusted") -> None:
        """Add a document to the corpus. `provenance` is the doc's origin."""
        self.corpus = [d for d in self.corpus if d["doc_id"] != doc_id]
        self.corpus.append({"doc_id": doc_id, "content": content,
                            "provenance": provenance})
        self._emit(type=MEMORY_WRITE, provenance=provenance,
                   data={"kind": "rag_index", "doc_id": doc_id,
                         "content": content, "corpus_size": len(self.corpus)})

    def rag_query(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        """Retrieve and hand the results straight to the planner.

        Substring matching, insertion-ordered — a real ranker would be
        non-deterministic and a range cannot afford that.
        """
        q = query.lower()
        hits = [d for d in self.corpus
                if not q or q in d["content"].lower() or q in d["doc_id"].lower()]
        hits = hits[:top_k]
        self._emit(type=MEMORY_READ, principal=self.principal,
                   data={"kind": "rag_query", "query": query,
                         "hit_count": len(hits), "results": hits})
        # The RAG-poisoning sink: retrieved text is context, and this planner
        # cannot tell context from command.
        for doc in hits:
            self._maybe_follow(doc["content"], provenance=P_RAG)
        return hits

    # -- artifacts (supply chain) -------------------------------------------
    def load_artifact(self, name: str, path: str = "", trusted: bool = False,
                      payload: str = "", kind: str = "model") -> dict[str, Any]:
        """Load a model / skill / plugin artifact.

        Nothing is deserialized for real; the finding is that an untrusted
        artifact's embedded payload reaches the planner with the same
        authority as a first-party instruction.
        """
        art = {"name": name, "path": path, "trusted": bool(trusted),
               "artifact_kind": kind, "has_payload": bool(payload)}
        self.artifacts.append(art)
        self._emit(type=TOOL_CALL, tool_name=name, principal=self.principal,
                   authority=self.authority,
                   provenance=P_ARTIFACT if not trusted else P_USER,
                   severity="informational" if trusted else "high",
                   data={"kind": "artifact_load", **art})
        self._emit(type=TOOL_RESULT, tool_name=name,
                   severity="informational" if trusted else "high",
                   data={"kind": "artifact_payload", "name": name,
                         "trusted": bool(trusted), "payload": payload})
        if payload:
            self._maybe_follow(payload, provenance=P_ARTIFACT)
        return art

    # -- delegation (A2A) ---------------------------------------------------
    def delegate(self, agent: str, task: str, carry_authority: bool = True,
                 response: str = "") -> str:
        """Hand a task to a sub-agent, optionally passing our authority along.

        `carry_authority=True` is the transitive-authority bug; the sub-agent's
        reply is untrusted content that flows back into our own planner, which
        is the transitive-injection bug.
        """
        carried = list(self.authority) if carry_authority else []
        self._emit(type=DELEGATION, tool_name=agent, principal=self.principal,
                   authority=carried, provenance=P_USER,
                   severity="high" if carry_authority else "medium",
                   data={"kind": "delegate", "sub_agent": agent, "task": task,
                         "carried_authority": carried,
                         "authority_dropped": not carry_authority})
        reply = response or f"{agent} completed: {task}"
        self._emit(type=TOOL_RESULT, tool_name=agent, provenance=P_SUBAGENT,
                   data={"kind": "sub_agent_response", "sub_agent": agent,
                         "content": reply})
        self._maybe_follow(reply, provenance=P_SUBAGENT)
        return reply

    # -- the gullible planner ----------------------------------------------
    def _maybe_follow(self, content: Any, provenance: str = P_TOOL) -> None:
        text = content if isinstance(content, str) else str(content)
        m = _INJECTION.search(text)
        if not m:
            return
        if self._follow_depth >= _MAX_FOLLOW_DEPTH:
            return
        tool = m.group("tool")
        raw_args = m.group("args") or ""
        args: dict[str, Any] = {}
        for pair in re.findall(r"(\w+)=([^\s,]+)", raw_args):
            args[pair[0]] = pair[1]
        self.collector.emit(AgentEvent(
            type=DELEGATION, target=self.name, tool_name=tool,
            provenance=provenance, severity="high",
            principal=self.principal, authority=list(self.authority),
            data={"reason": "planner followed instruction from untrusted content",
                  "kind": "planner_follow", "args": args}))
        if tool in self._impl:
            self._follow_depth += 1
            try:
                self.call_tool(tool, args, provenance=provenance)
            finally:
                self._follow_depth -= 1
