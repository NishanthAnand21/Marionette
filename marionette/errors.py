"""Typed error hierarchy with stable, greppable codes.

Every failure a user can hit gets a code (``MAR-Exxx``), a plain-language
message, and an actionable ``hint``.  The contract: a user should never see a
bare traceback, and every error should say what to do next.

    [MAR-E102] mcp target 'prod-mail' timed out after 20.0s awaiting tools/list
      hint: raise timeout in your targets file, or check the server is not
            blocking on stdin
"""

from __future__ import annotations

from typing import Any


class MarionetteError(Exception):
    """Base for every Marionette failure. Never raise this directly."""

    code = "MAR-E000"
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

class TargetError(MarionetteError):
    code = "MAR-E100"


class TargetConnectError(TargetError):
    code = "MAR-E101"
    default_hint = ("check the launch command runs standalone and that its "
                    "interpreter is on PATH")


class TargetTimeoutError(TargetError):
    code = "MAR-E102"
    default_hint = ("raise `timeout` for this target, or check the server is "
                    "not blocking without writing to stdout")


class TargetProtocolError(TargetError):
    code = "MAR-E103"
    default_hint = ("the server sent something that is not valid MCP JSON-RPC; "
                    "run it by hand and inspect stdout")


class TargetCrashedError(TargetError):
    code = "MAR-E104"
    default_hint = "inspect the captured stderr below for the server's own error"


class UnsupportedCapability(TargetError):
    code = "MAR-E105"
    default_hint = ("this technique needs a capability the target does not "
                    "expose; it is reported as SKIP, not a failure")


# --- technique errors (E2xx) -------------------------------------------------

class TechniqueError(MarionetteError):
    code = "MAR-E200"


class TechniqueParseError(TechniqueError):
    code = "MAR-E201"
    default_hint = "check the YAML is well-formed and the file is not empty"


class TechniqueValidationError(TechniqueError):
    code = "MAR-E202"
    default_hint = "run `marionette validate` to see every problem at once"


class StepExecutionError(TechniqueError):
    code = "MAR-E203"
    default_hint = "the step's arguments did not match what the target expected"


# --- config errors (E3xx) ----------------------------------------------------

class ConfigError(MarionetteError):
    code = "MAR-E300"


class ConfigParseError(ConfigError):
    code = "MAR-E301"
    default_hint = "targets file must be YAML mapping with a `targets:` list"


class UnknownTargetKind(ConfigError):
    code = "MAR-E302"
    default_hint = "valid kinds are listed by `marionette targets --list-kinds`"
