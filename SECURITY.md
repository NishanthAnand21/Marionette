# Security policy

## Reporting a vulnerability in Marionette

Report privately through
[GitHub Security Advisories](https://github.com/NishanthAnand21/Marionette/security/advisories/new).
Please do not open a public issue first.

Include the version, the platform, a reproduction, and what an attacker gains.
A working proof of concept is welcome; you do not need one to report.

Expect an acknowledgement within a few days. There is no bounty.

## What counts as a vulnerability here

Marionette is pointed at MCP servers and agents that may be **actively
malicious**, so the target is untrusted input. Anything a target can do to the
operator is in scope:

- Escaping the client — code execution, file access, or unexpected network
  activity triggered by target-controlled data
- Corrupting or suppressing results — making a run report success when a
  technique fired, or producing artifacts a CI system cannot parse
- Leaking operator data to the target — credentials, environment, or file
  contents that a target should never see
- Denial of service that survives the configured timeout

Examples of things already fixed, to calibrate: forged JSON-RPC replies via
predictable request ids; terminal repainting via escape sequences in a tool
description; JUnit XML made unparseable by a single NUL (so CI reports "no test
results" and goes green by absence); the operator's whole environment inherited
by the target subprocess; and unbounded frame reads exhausting memory despite
the timeout firing.

## What is not a vulnerability

- **The range being exploitable.** `marionette/range/` and the `mock` target
  are *deliberately* vulnerable. That is the product, not a bug.
- **Techniques succeeding against a vulnerable agent.** Also the product.
- **Findings against a third party's MCP server.** Report those to that
  project's maintainers, not here.

## Scope of the tool itself

Marionette is a **defensive** tool: run it against agents and servers you own or
are authorised to test, to check that your detections fire. Pointing it at
someone else's infrastructure without permission is your problem, not ours.
