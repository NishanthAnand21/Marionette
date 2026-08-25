# Contributing to Praxis

The most useful contribution is a **new technique**. The framework is only as
good as its pack, and the pack is deliberately easy to extend.

## Adding a technique

1. Pick a real MITRE ATLAS id from `reference/atlas-catalog.yaml`. That file is
   the pinned, machine-readable ATLAS **2026.07** release. `praxis validate`
   rejects any id not in it.

   Do not pick an id by name-similarity. Read its description in the catalog
   and confirm it matches what your technique actually does. The most common
   authoring error is an id that *exists* but means something else — it passes
   every automated check and is still wrong.

2. Copy the closest existing technique in `techniques/` and adapt it. Match the
   house style: a `description` that explains the real-world attack (not the
   harness mechanics), a real `references:` URL, and an ATLAS tactic name for
   `tactic:`, lowercase-hyphenated.

3. Declare every mock-only verb you use in `requires:`. The validator enforces
   this, because an undeclared verb turns an honest SKIP into a crash on any
   target that lacks it.

4. **Write assertions that discriminate.** This is the whole job. An assertion
   that would also hold for a neighbouring technique — or against a *secure*
   agent — is worse than no technique, because it reports green forever and
   nobody looks again. Assert on `provenance`, `tool_name`, and
   `field_contains` where those distinguish your case. Use `negate:` for
   negative controls.

5. Run the gate:

   ```bash
   praxis validate
   praxis run --technique PRX-00XX -v
   praxis run                                       # whole pack still green
   praxis run --targets-file targets.example.yaml   # SKIPs cleanly on mcp
   python3 -m pytest tests/ -q
   ```

If a technique cannot be made to pass without weakening its assertion to
something trivially true, **do not weaken it**. Open an issue describing the
mechanism the range is missing instead.

## Adding a target adapter

Subclass `Target` in `praxis/targets/`, `@register("your-kind")` it, and
implement `list_tools` / `call_tool`. Advertise only the `capabilities` you
genuinely support — techniques requiring anything else will then SKIP with an
honest reason instead of failing spuriously.

Implement `reset()` if your target holds mutable state. The engine reuses one
connection per target for speed and calls `reset()` between techniques; without
it, one technique's mutations change the next one's verdict.

The adapter conformance suite in `tests/test_adapters.py` runs against every
registered adapter automatically, so a new adapter inherits those tests.

## Ground rules for the codebase

- Python 3.10+, stdlib + PyYAML. New dependencies need a strong argument.
- Deterministic: no network, no randomness, no host filesystem writes in tests.
- Errors are typed `PraxisError`s with a code, a message, and an actionable
  hint. Never a bare traceback in normal operation.
- Comments explain *why*, not *what*.

## Scope

Praxis is a **defensive** tool: you run it against your own agents and MCP
servers to check that your detections fire. Contributions that only make sense
for attacking third-party systems are out of scope.
