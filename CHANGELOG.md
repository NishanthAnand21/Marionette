# Changelog

## 0.2.0 — unreleased

### Added
- 18 new techniques (MAR-0009..MAR-0026), covering 24 distinct ATLAS
  techniques across 9 tactics — 18 of the 39 agentic techniques.
- `reference/atlas-catalog.yaml`: the pinned, machine-readable MITRE ATLAS
  **2026.07** release (16 tactics, 178 techniques). `marionette validate` now
  cross-checks every `atlas:` and `owasp_asi:` id against it.
- Parallel multi-target execution (`marionette run --targets-file`, `--workers`,
  `--fail-fast`) with per-target fault isolation.
- Typed error taxonomy (`MAR-E1xx` target, `E2xx` technique, `E3xx` config)
  with actionable hints and stable exit codes.
- JUnit XML and JSON reporters for CI.
- Extended range verb surface: 19 verbs including `rag_index`/`rag_query`,
  `delegate`, `load_artifact`, `add_tool`/`remove_tool`, `env_set`/`env_read`,
  `set_system_prompt`, `set_identity`, `revoke`.
- `http` and `callable` target adapters.

### Added (continued)
- `hardened` target: the same agent as the range with real design-level
  defences, used as a negative control. 26 techniques pass on `mock`, 1 on
  `hardened` — a technique that passes on both is testing the harness, not the
  target, and `tests/test_negative_controls.py` fails the build when one
  appears. That test caught two genuine tautologies in the original pack.
- `marionette rules validate --against EVENTS.jsonl`: fails any rule that matches
  zero events, catching rules that can never fire.

### Portability
- Windows command strings are no longer mangled: `shlex.split` in POSIX mode
  treats `\` as an escape, silently turning `C:\Users\me\python.exe` into
  `C:Usersmepython.exe`.
- The minimal-env allowlist is matched case-insensitively. `os.environ`
  upper-cases keys on Windows, so the mixed-case `SystemRoot` entry could never
  match and subprocesses started without it — breaking socket/SSL init.
  `SYSTEMDRIVE`, `WINDIR`, `APPDATA` and friends added.
- Status glyphs fall back to ASCII when stdout cannot encode them. A redirected
  stdout on Windows uses cp1252, where the tick raised `UnicodeEncodeError` —
  precisely the CI case.
- Subprocess shutdown now escalates instead of going straight to a kill: close
  stdin (a well-behaved server exits on EOF), then `SIGTERM` — or
  `CTRL_BREAK_EVENT` on Windows, where children are placed in their own process
  group so it can be delivered — then `SIGKILL`. On Windows `terminate()` is
  `TerminateProcess`, an immediate hard kill, so without an EOF window the
  "terminate then kill" escalation was meaningless there. Budget is bounded
  (0.5s + 2s, tunable via `MARIONETTE_EOF_GRACE` / `MARIONETTE_SIGNAL_GRACE`).
- Report artifacts (JSON, JUnit XML, JSONL) and snapshots are written with
  `newline=""`, so they are LF-only and byte-identical on every platform.
  Previously Windows CRLF translation put a stray carriage return inside every
  JSONL record and made an unchanged snapshot hash differently.
- CI gained a `portability` job covering macOS and Windows, both hard gates.

### Interoperability
- Verified against a server built with the **official MCP Python SDK**, not
  only our own stubs. Tool names, descriptions, JSON Schema, `isError`
  handling, and the snapshot/run/drift flows all round-trip correctly.
- The negotiated `protocolVersion` is now recorded and a mismatch is surfaced,
  rather than silently continuing in a protocol that was never agreed.

### Security
- Target subprocesses no longer inherit the operator's environment. Marionette
  spawns servers it is testing for hostility; a malicious one could read
  `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` and every other ambient secret.
  Opt back in per target with `inherit_env: true`.
- JSON-RPC request ids are now unguessable. With sequential ids a server could
  answer a request that had not been made yet — emitting a reply for id N+1
  during the handshake let it forge an entire tool inventory. Replies for ids
  we never issued are refused.
- Target-controlled text is sanitised before it reaches the terminal. A tool
  description containing `ESC [ 2K CR` could repaint the line it printed on,
  letting a hostile server make `marionette drift` display "no drift detected"
  while poisoning a tool. Bidi overrides are neutralised the same way.
- JUnit XML strips codepoints illegal in XML 1.0. A single NUL in a
  server-controlled error string made the whole artifact unparseable, so CI
  reported "no test results" and went green by absence — suppressing exactly
  the findings Marionette had produced.
- Rule regexes run against a length-capped haystack, and target names may not
  contain path separators.

### Fixed
- **Corrected 5 of 8 ATLAS mappings.** Every original id existed but several
  named the wrong technique — `T0010` (supply chain) for a tool-description
  rug pull, `T0070` (RAG poisoning) for agent-memory poisoning, `T0007`
  (MLOps artifact discovery) for tool enumeration, `T0024` (inference-API
  exfiltration) for tool-invocation exfiltration. Root cause: `dist/ATLAS.yaml`
  is deprecated and frozen at legacy 5.6.0, and contains no agentic techniques
  at all. Marionette now pins `dist/v6/`.
- **`fail_fast` race.** The stop flag was only set by the main thread while
  draining completed futures, so a worker could start the next target before it
  flipped. Workers now set a `threading.Event` themselves.
- **Order-dependent techniques.** The engine reuses one connection per target,
  so techniques shared mutable state — before the fix only 6 of 25 shuffled
  technique orders were green. Targets are now `reset()` between techniques and
  a regression test enforces order-independence.
- `marionette drift` refused to compare snapshots from two different targets, which
  previously reported every tool as added/removed — a silent wrong answer in
  the tool's headline feature. `Snapshot.load` now fails with typed errors.
- Unbounded MCP frame reads: a 50MB reply was buffered and written to disk, and
  a ~1GB one pushed RSS to 1.4GB despite the timeout firing. Frames are now
  capped (own RSS 35MB under the same attack).
- Subprocesses, threads and pipes leaked when a handshake failed after launch.
- JUnit `<failure>` messages showed the literal string `None`, because the
  fallback in `getattr(res, "error", "assertions failed")` was unreachable.
- MCP adapter no longer hangs forever on an unresponsive server: reader threads
  plus a deadline bound every exchange, and crashes surface the child's stderr.
