## What this changes

<!-- One or two sentences. If it adds a technique, name the ATLAS id. -->

## Checks

- [ ] `make check` passes (`lint`, `test`, `run`)
- [ ] `marionette validate` is clean — no errors, no new warnings
- [ ] `marionette rules validate --against <events>` is clean, if rules changed

### If this adds or changes a technique

- [ ] The `atlas:` id exists verbatim in `reference/atlas-catalog.yaml`, and I
      read its description to confirm it means what this technique tests
- [ ] `requires:` declares every mock-only verb used
- [ ] It **passes on `mock` and fails on `hardened`**

  A technique that passes on both is testing the harness rather than the
  target. `tests/test_negative_controls.py` enforces this. If yours legitimately
  cannot discriminate, say why here rather than adding it to the allowlist.

### If this adds or changes a rule

- [ ] It fires on real technique telemetry (`marionette rules validate --against`)
- [ ] It has a `falsepositives:` note — a rule without one is how alert fatigue starts

## Anything reviewers should push back on

<!-- Assumptions you are unsure about, or a shortcut you took deliberately. -->
