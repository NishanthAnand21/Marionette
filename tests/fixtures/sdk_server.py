"""A *real* MCP server, built with the official MCP Python SDK.

Every other server in this suite is a stub we wrote ourselves, which makes
testing the adapter against them circular: our client talks to our own idea of
the protocol.  This one is driven by the SDK's own stdio server, so the frames
on the wire are whatever the reference implementation actually emits.

Run as ``python tests/fixtures/sdk_server.py`` (stdio transport).  Requires the
dev-only ``mcp`` package; it is deliberately NOT a Marionette dependency.
"""

from __future__ import annotations

import sys

try:                      # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _Server
except ModuleNotFoundError:   # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

mcp = _Server("marionette-sdk-fixture")


@mcp.tool()
def echo(text: str) -> str:
    """Echo the supplied text straight back to the caller."""
    return f"echo: {text}"


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers and return the sum."""
    return a + b


@mcp.tool()
def boom(reason: str = "requested") -> str:
    """Always raise, so the error path of tools/call can be exercised."""
    raise ValueError(f"boom: {reason}")


def main() -> None:
    # Lets the test suite verify the fixture imports under the installed SDK
    # without having to speak the protocol just to find out.
    if "--marionette-import-check" in sys.argv[1:]:
        return None
    mcp.run(transport="stdio")


if __name__ == "__main__":
    sys.exit(main())
