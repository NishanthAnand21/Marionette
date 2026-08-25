"""Typed error hierarchy with stable, greppable codes.

Every failure a user can hit gets a code (``PRX-Exxx``), a plain-language
message, and an actionable ``hint``.  The contract: a user should never see a
bare traceback, and every error should say what to do next.

    [PRX-E102] mcp target 'prod-mail' timed out after 20.0s awaiting tools/list
      hint: raise timeout in your targets file, or check the server is not
            blocking on stdin
"""

from __future__ import annotations

from typing import Any


class PraxisError(Exception):
    """Base for every Praxis failure. Never raise this directly."""

    code = "PRX-E000"
    default_hint: str | None = None

    def __init__(self, message: str, *, hint: str | None = None,
                 context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint or self.default_hint
        self.context = context or {}

    def render(self, color: bool = False) -> str:
        code = f"[{self.code}]"
        if color:
            code = f"\033[31m{code}\033[0m"
        out = f"{code} {self.message}"
        if self.hint:
            out += f"\n  hint: {self.hint}"
        if self.context:
            kv = "  ".join(f"{k}={v!r}" for k, v in self.context.items())
            out += f"\n  context: {kv}"
        return out

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message,
                "hint": self.hint, "context": self.context}


# --- target errors (E1xx) ----------------------------------------------------

class TargetError(PraxisError):
    code = "PRX-E100"


class TargetConnectError(TargetError):
    code = "PRX-E101"
    default_hint = ("check the launch command runs standalone and that its "
                    "interpreter is on PATH")


class TargetTimeoutError(TargetError):
    code = "PRX-E102"
    default_hint = ("raise `timeout` for this target, or check the server is "
                    "not blocking without writing to stdout")


class TargetProtocolError(TargetError):
    code = "PRX-E103"
    default_hint = ("the server sent something that is not valid MCP JSON-RPC; "
                    "run it by hand and inspect stdout")


class TargetCrashedError(TargetError):
    code = "PRX-E104"
    default_hint = "inspect the captured stderr below for the server's own error"


class UnsupportedCapability(TargetError):
    code = "PRX-E105"
    default_hint = ("this technique needs a capability the target does not "
                    "expose; it is reported as SKIP, not a failure")


# --- technique errors (E2xx) -------------------------------------------------

class TechniqueError(PraxisError):
    code = "PRX-E200"


class TechniqueParseError(TechniqueError):
    code = "PRX-E201"
    default_hint = "check the YAML is well-formed and the file is not empty"


class TechniqueValidationError(TechniqueError):
    code = "PRX-E202"
    default_hint = "run `praxis validate` to see every problem at once"


class StepExecutionError(TechniqueError):
    code = "PRX-E203"
    default_hint = "the step's arguments did not match what the target expected"


# --- config errors (E3xx) ----------------------------------------------------

class ConfigError(PraxisError):
    code = "PRX-E300"


class ConfigParseError(ConfigError):
    code = "PRX-E301"
    default_hint = "targets file must be YAML mapping with a `targets:` list"


class UnknownTargetKind(ConfigError):
    code = "PRX-E302"
    default_hint = "valid kinds are listed by `praxis targets --list-kinds`"
