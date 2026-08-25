from .base import (Target, ToolSpec, ToolResult, build, register, available,
                   registry, known_capabilities)
# Importing each adapter module is what registers its kind.
from . import mcp, mock, hardened, http, callable  # noqa: F401

__all__ = ["Target", "ToolSpec", "ToolResult", "build", "register", "available",
           "registry", "known_capabilities"]
