"""Callable adapter — the bridge to arbitrary agent frameworks.

Marionette must be able to point at a LangGraph graph, a CrewAI crew, or someone's
bespoke while-loop, without taking a dependency on any of them.  So the
dependency is inverted: the *user* writes a tiny shim object, and names it with
a dotted import path::

    marionette run --target callable --command "myapp.agents:build_target"

The path may name either an adapter object/class (instantiated with no args if
it is a class or a zero-arg factory) or a factory function returning one.

The duck-typed protocol — implement only what your agent can actually do::

    class MyAgentAdapter:
        # Optional. Inferred from which methods exist if omitted.
        capabilities = {"list_tools", "call_tool", "prompt"}

        def list_tools(self) -> list[dict]:
            # [{"name": str, "description": str, "input_schema": dict}, ...]
            # A bare list[str] of names is also accepted.

        def call_tool(self, name: str, args: dict) -> dict:
            # {"ok": bool, "content": Any, "error": str | None}
            # Any other return value is treated as successful content.

        def send_prompt(self, text: str, provenance: str) -> str:
            # Drive one turn of the agent; return what it said.

        def connect(self) / def close(self) / def reset(self)
        def health(self) -> tuple[bool, str | None]

Everything except ``list_tools``/``call_tool`` is optional, and *absence is not
a crash*: a missing method degrades to :class:`UnsupportedCapability`, which the
runner reports as SKIP.  A technique that needs prompts against an agent that
cannot take them is an honest "not applicable", not a red test.

The shim is imported and executed in-process, so it is code the operator is
trusting exactly as much as their own; the dotted path is never taken from a
target's own responses.
"""

from __future__ import annotations

import importlib
from typing import Any

from ..errors import TargetConnectError, UnsupportedCapability
from .base import Target, ToolResult, ToolSpec, register

# The methods we probe for, and the capability each one implies.
_METHOD_CAPS = {
    "list_tools": "list_tools",
    "call_tool": "call_tool",
    "send_prompt": "prompt",
}


def load_object(path: str) -> Any:
    """Import ``pkg.mod:attr`` (or ``pkg.mod.attr``) and return the attribute.

    Every failure mode is one error the user can act on, naming the path they
    typed — an ImportError traceback from three frames inside their own package
    is not a usable diagnostic.
    """
    if not path or not isinstance(path, str):
        raise TargetConnectError(
            "callable target requires a dotted import path",
            hint='e.g. --command "myapp.agents:build_target"')
    if ":" in path:
        mod_name, _, attr = path.partition(":")
    elif "." in path:
        mod_name, _, attr = path.rpartition(".")
    else:
        raise TargetConnectError(
            f"callable target path {path!r} names no attribute",
            hint='use "module:attribute", e.g. "myapp.agents:build_target"')
    try:
        mod = importlib.import_module(mod_name)
    except Exception as exc:  # noqa: BLE001 - user code can fail at import time
        raise TargetConnectError(
            f"callable target could not import {mod_name!r} from path {path!r}: "
            f"{exc.__class__.__name__}: {exc}",
            hint="check the module is importable from this interpreter "
                 "(PYTHONPATH / venv) and imports cleanly on its own",
            context={"path": path, "module": mod_name}) from exc
    try:
        return getattr(mod, attr)
    except AttributeError as exc:
        raise TargetConnectError(
            f"module {mod_name!r} has no attribute {attr!r} (from path {path!r})",
            hint=f"available: {sorted(n for n in vars(mod) if not n.startswith('_'))[:12]}",
            context={"path": path}) from exc


@register("callable")
class CallableTarget(Target):
    """Wrap a user-supplied agent shim as a Marionette target.

    ``capabilities`` is computed per *instance* from what the shim actually
    implements, so two callable targets in one fleet can legitimately have
    different surfaces.  The class-level value is the union, purely so
    ``marionette targets --list-kinds`` and the validator can see what this kind
    could ever offer.
    """

    capabilities = frozenset({"list_tools", "call_tool", "prompt", "snapshot"})

    def __init__(
        self,
        name: str = "callable",
        target: Any = None,
        command: str | list[str] | None = None,
        path: str | None = None,
        collector: Any = None,
        timeout: float = 20.0,
        **_ignored: Any,
    ) -> None:
        super().__init__(name=name, collector=collector)
        if path is None and command is not None:
            path = command if isinstance(command, str) else " ".join(command)
        if target is None and not path:
            raise ValueError(
                "CallableTarget requires `target` (an object) or a dotted "
                'import path, e.g. --command "myapp.agents:build_target"')
        self.path = path
        self.timeout = timeout
        self.impl: Any = target
        if self.impl is not None:
            self.capabilities = self._infer_caps(self.impl)

    # -- lifecycle ----------------------------------------------------------
    def connect(self) -> None:
        if self.impl is None:
            obj = load_object(self.path or "")
            # A class or factory is called with no args; an already-built
            # object is used as-is. That covers the three shapes people
            # naturally write without making them declare which one it is.
            if isinstance(obj, type) or (callable(obj) and not self._is_shim(obj)):
                try:
                    obj = obj()
                except Exception as exc:  # noqa: BLE001
                    raise TargetConnectError(
                        f"callable target factory {self.path!r} raised "
                        f"{exc.__class__.__name__}: {exc}",
                        hint="the factory must build your adapter with no "
                             "required arguments",
                        context={"path": self.path}) from exc
            self.impl = obj
        if not self._is_shim(self.impl):
            raise TargetConnectError(
                f"callable target {self.path!r} produced {type(self.impl).__name__}, "
                "which implements neither list_tools() nor call_tool()",
                hint="see marionette/targets/callable.py for the expected protocol",
                context={"path": self.path})
        self.capabilities = self._infer_caps(self.impl)
        self._maybe("connect")

    def close(self) -> None:
        self._maybe("close")

    def reset(self) -> None:
        self._maybe("reset")

    def health(self) -> tuple[bool, str | None]:
        if self.impl is None:
            return False, "not connected"
        fn = getattr(self.impl, "health", None)
        if fn is None:
            return True, None
        try:
            ok, reason = fn()
            return bool(ok), reason
        except Exception as exc:  # noqa: BLE001 - health never raises
            return False, str(exc)

    @staticmethod
    def _is_shim(obj: Any) -> bool:
        return any(callable(getattr(obj, m, None)) for m in ("list_tools", "call_tool"))

    @staticmethod
    def _infer_caps(impl: Any) -> frozenset[str]:
        caps = {cap for meth, cap in _METHOD_CAPS.items()
                if callable(getattr(impl, meth, None))}
        declared = getattr(impl, "capabilities", None)
        if declared:
            # A shim may declare capabilities the method probe cannot see
            # (memory, grant, rag_index...), but never one whose method is
            # missing — that would turn a SKIP into an AttributeError.
            caps |= {c for c in declared if _method_for(c) is None
                     or callable(getattr(impl, _method_for(c), None))}
        if "list_tools" in caps:
            caps.add("snapshot")
        return frozenset(caps)

    def _maybe(self, method: str) -> None:
        fn = getattr(self.impl, method, None)
        if callable(fn):
            fn()

    def _need(self, method: str, capability: str) -> Any:
        fn = getattr(self.impl, method, None) if self.impl is not None else None
        if not callable(fn):
            raise UnsupportedCapability(
                f"target {self.name!r} ({self.kind}) has no {method}(); "
                f"capability {capability!r} is unavailable",
                context={"path": self.path,
                         "has": sorted(self.capabilities)})
        return fn

    # -- capability surface -------------------------------------------------
    def list_tools(self) -> list[ToolSpec]:
        raw = self._need("list_tools", "list_tools")() or []
        tools = [self._to_spec(t) for t in raw]
        self.emit_tool_list(tools)
        return tools

    @staticmethod
    def _to_spec(t: Any) -> ToolSpec:
        # Accept the documented dict, a bare name, or anything with attributes:
        # the shim author should not have to marshal twice.
        if isinstance(t, ToolSpec):
            return t
        if isinstance(t, str):
            return ToolSpec(name=t)
        if isinstance(t, dict):
            return ToolSpec(
                name=str(t.get("name", "")),
                description=str(t.get("description", "") or ""),
                input_schema=t.get("input_schema") or t.get("inputSchema") or {},
            )
        return ToolSpec(
            name=str(getattr(t, "name", "")),
            description=str(getattr(t, "description", "") or ""),
            input_schema=getattr(t, "input_schema", {}) or {},
        )

    def call_tool(self, tool: str, args: dict[str, Any]) -> ToolResult:
        fn = self._need("call_tool", "call_tool")
        self.emit_tool_call(tool, args, principal="operator", provenance="marionette")
        try:
            raw = fn(tool, args)
        except Exception as exc:  # noqa: BLE001
            # The shim wraps foreign code; one tool blowing up is a finding for
            # the technique, not a run-ending failure.
            res = ToolResult(ok=False, error=f"{exc.__class__.__name__}: {exc}")
            self.emit_tool_result(tool, res)
            return res
        res = self._to_result(raw)
        self.emit_tool_result(tool, res)
        return res

    @staticmethod
    def _to_result(raw: Any) -> ToolResult:
        if isinstance(raw, ToolResult):
            return raw
        if isinstance(raw, dict) and ("ok" in raw or "error" in raw or "content" in raw):
            return ToolResult(ok=bool(raw.get("ok", raw.get("error") is None)),
                              content=raw.get("content"),
                              error=raw.get("error"))
        return ToolResult(ok=True, content=raw)

    def send_prompt(self, text: str, provenance: str = "user") -> str:
        fn = self._need("send_prompt", "prompt")
        self.emit_prompt(text, provenance)
        out = fn(text, provenance)
        return "" if out is None else str(out)


def _method_for(capability: str) -> str | None:
    for meth, cap in _METHOD_CAPS.items():
        if cap == capability:
            return meth
    return None
