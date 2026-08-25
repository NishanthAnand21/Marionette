"""A stdio MCP server that misbehaves on demand.

Run as ``python hostile_mcp.py <mode>``.  Modes:

  ok            well-behaved: 2 tools, JSON-RPC errors for unknown tools
  huge          tools/list returns a very large tool registry
  noisy         emits unsolicited notifications (and junk) between the request
                and its reply, and a reply to an id nobody asked for
  close_stdout  answers the handshake, then closes stdout while staying alive
  crash         exits non-zero on the first request after the handshake
  hang          answers the handshake, then never answers anything again

It is a *server*, so it only ever writes to its own stdout; nothing here
touches the network or the filesystem.
"""

from __future__ import annotations

import json
import os
import sys
import time

MODE = sys.argv[1] if len(sys.argv) > 1 else "ok"
HUGE_N = int(sys.argv[2]) if len(sys.argv) > 2 else 1500

TOOLS = [
    {"name": "read_public", "description": "Read a public record.",
     "inputSchema": {"type": "object"}},
    {"name": "send_email", "description": "Send an email.",
     "inputSchema": {"type": "object"}},
]


def send(obj) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def tools_for(method_calls: int):
    if MODE == "huge":
        return [{"name": f"tool_{i:05d}",
                 "description": "x" * 200,
                 "inputSchema": {"type": "object"}}
                for i in range(HUGE_N)]
    return TOOLS


def main() -> None:
    seen = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        method = msg.get("method", "")
        req_id = msg.get("id")
        if req_id is None:
            continue  # a notification; nothing to answer
        seen += 1

        if method == "initialize":
            send({"jsonrpc": "2.0", "id": req_id,
                  "result": {"protocolVersion": "2024-11-05",
                             "capabilities": {},
                             "serverInfo": {"name": f"hostile-{MODE}",
                                            "version": "1.0"}}})
            if MODE == "close_stdout":
                sys.stdout.close()
                os.close(1)
                while True:  # still running, just deaf
                    time.sleep(0.05)
            continue

        if MODE == "crash":
            sys.stderr.write("hostile server: deliberate crash\n")
            sys.stderr.flush()
            os._exit(3)
        if MODE == "hang":
            while True:
                time.sleep(0.05)

        if MODE == "noisy":
            # Unsolicited chatter the client must skip past to find its reply.
            send({"jsonrpc": "2.0", "method": "notifications/message",
                  "params": {"level": "info", "data": "unsolicited"}})
            send({"jsonrpc": "2.0", "method": "notifications/progress",
                  "params": {"progress": 1}})
            sys.stdout.write("this line is not JSON at all\n")
            sys.stdout.flush()
            send({"jsonrpc": "2.0", "id": 999999, "result": {"tools": []}})

        if method == "tools/list":
            send({"jsonrpc": "2.0", "id": req_id,
                  "result": {"tools": tools_for(seen)}})
        elif method == "tools/call":
            name = (msg.get("params") or {}).get("name")
            if name not in {t["name"] for t in TOOLS}:
                send({"jsonrpc": "2.0", "id": req_id,
                      "error": {"code": -32602,
                                "message": f"unknown tool {name!r}"}})
            else:
                send({"jsonrpc": "2.0", "id": req_id,
                      "result": {"content": [{"type": "text",
                                              "text": f"{name} ok"}]}})
        else:
            send({"jsonrpc": "2.0", "id": req_id, "result": {}})


if __name__ == "__main__":
    try:
        main()
    except (BrokenPipeError, KeyboardInterrupt):
        pass
