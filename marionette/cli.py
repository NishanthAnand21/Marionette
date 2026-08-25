"""marionette — command-line entry point.

    marionette list                          list techniques + ATLAS/OWASP mapping
    marionette run                           run everything against the mock range
    marionette run --targets-file f.yaml     run the matrix across a fleet
    marionette validate                      lint technique YAML and the fleet file
    marionette targets --list-kinds          show registered adapter kinds
    marionette snapshot --out snap.json      fingerprint a target's tools
    marionette drift OLD.json NEW.json       diff two snapshots (rug-pull detector)
    marionette run --events e.jsonl          also save the raw event stream
    marionette rules list                    list the shipped detection rules
    marionette rules validate                lint the rule pack
    marionette rules run --events e.jsonl    evaluate rules over a saved stream

Exit codes are the CI contract: 0 clean, 1 findings/failures, 2 config error,
3 target error, 4 technique error, 130 interrupted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading

from . import __version__
from . import report
from .config import Fleet
from .drift import Snapshot, diff
from .schema import write_jsonl
from .errors import (ConfigError, MarionetteError, TargetError, TechniqueError,
                     TechniqueParseError, UnknownTargetKind)
from .targets import available, build
from .technique import load_dir
from . import rules as rules_mod

DEFAULT_TECH_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "techniques")

# Error class -> exit code. Kept here (not on the exceptions) because it is a
# CLI-level policy, not a property of the failure itself.
_EXIT_CODES = ((ConfigError, 2), (TargetError, 3), (TechniqueError, 4))


def _exit_code_for(err: MarionetteError) -> int:
    for cls, code in _EXIT_CODES:
        if isinstance(err, cls):
            return code
    return 1


def _use_color(args) -> bool:
    return report.color_enabled(not getattr(args, "no_color", False))


# --- shared plumbing ---------------------------------------------------------

def _load_techniques(directory: str, ids=None, tactic=None):
    """Load + filter, converting any YAML blow-up into a typed error."""
    try:
        techs = load_dir(directory)
    except MarionetteError:
        raise
    except Exception as exc:
        raise TechniqueParseError(
            f"could not load techniques from {directory}: {exc}") from exc
    if not techs:
        raise TechniqueParseError(f"no technique YAML found in {directory}",
                                  hint="pass --techniques with a valid directory")
    if ids:
        want = set(ids)
        techs = [t for t in techs if t.id in want]
        missing = want - {t.id for t in techs}
        if missing:
            raise TechniqueError(
                f"unknown technique id(s): {', '.join(sorted(missing))}",
                hint="run `marionette list` to see available ids")
    if tactic:
        techs = [t for t in techs if t.tactic == tactic]
        if not techs:
            raise TechniqueError(f"no techniques with tactic {tactic!r}",
                                 hint="run `marionette list` to see tactics")
    return techs


def _fleet_from_args(args) -> Fleet:
    """A fleet either comes from a file or is synthesised from the shorthand."""
    path = getattr(args, "targets_file", None)
    if path:
        return Fleet.load(path)
    kind = getattr(args, "target", None) or "mock"
    if kind not in available():
        raise UnknownTargetKind(f"unknown target kind {kind!r}",
                                context={"available": sorted(available())})
    if kind == "mcp" and not getattr(args, "command", None):
        raise ConfigError("--target mcp requires --command",
                          hint='e.g. --command "python my_server.py"')
    return Fleet.single(kind=kind, name=kind,
                        command=getattr(args, "command", None),
                        cwd=getattr(args, "cwd", None),
                        timeout=getattr(args, "timeout", None) or 20.0)


def _select_specs(args) -> list:
    fleet = _fleet_from_args(args)
    specs = fleet.select(names=getattr(args, "name", None) or None,
                         tags=getattr(args, "tag", None) or None)
    if not specs:
        raise ConfigError("no targets selected",
                          hint="check --name/--tag filters, and that targets "
                               "are not disabled with `enabled: false`")
    return specs


# --- commands ----------------------------------------------------------------

def cmd_list(args) -> int:
    color = _use_color(args)
    techs = _load_techniques(args.techniques)
    if args.json:
        print(json.dumps([{"id": t.id, "name": t.name, "tactic": t.tactic,
                           "atlas": t.atlas, "owasp_asi": t.owasp_asi,
                           "requires": t.requires, "steps": len(t.steps),
                           "assertions": len(t.assertions),
                           "source_path": t.source_path} for t in techs],
                         indent=2))
        return 0
    for t in techs:
        ids = ",".join(t.atlas + t.owasp_asi)
        print(f"{report.paint(t.id, 'bold', color)}  {t.name}")
        print(f"    {report.paint(f'{t.tactic}  [{ids}]', 'dim', color)}")
    print(f"\n{len(techs)} techniques")
    return 0


def cmd_run(args) -> int:
    # Imported here so `list`/`targets`/`drift` keep working even while the
    # engine module is being reworked.
    from .engine import run_matrix

    color = _use_color(args)
    techs = _load_techniques(args.techniques, args.technique, args.tactic)
    specs = _select_specs(args)

    # Progress callbacks arrive from worker threads; one lock around every
    # print keeps lines from interleaving mid-write.
    lock = threading.Lock()

    def _target_name(payload) -> str:
        # target_start hands us a dict, target_done a TargetRunResult.
        if isinstance(payload, dict):
            return payload.get("target") or payload.get("target_name") or "?"
        return getattr(payload, "target_name", "?")

    def on_progress(kind, payload):
        with lock:
            if kind == "target_start":
                print(report.paint(f"→ {_target_name(payload)}", "cyan", color),
                      flush=True)
            elif kind == "technique_done":
                res = payload.get("result") if isinstance(payload, dict) else payload
                status = getattr(res, "status", "pass")
                tid = getattr(res, "technique_id", "?")
                tname = getattr(res, "name", "") or ""
                glyph = report.STATUS_GLYPH.get(status, "?")
                line = report.paint(f"  {glyph} {status.upper():<5}",
                                    report.STATUS_COLOR.get(status, "dim"), color)
                # Only disambiguate by target when several run concurrently.
                suffix = f"  ({_target_name(payload)})" if len(specs) > 1 else ""
                print(f"{line} {tid}  {tname}{suffix}", flush=True)
            elif kind == "target_done" and args.verbose:
                print(report.paint(f"← {_target_name(payload)} done", "dim", color),
                      flush=True)

    matrix = run_matrix(techs, specs, workers=args.workers,
                        on_progress=None if args.quiet else on_progress,
                        fail_fast=args.fail_fast)

    if not args.quiet:
        print()
        print(report.render_text(matrix, color=color, verbose=args.verbose))
    else:
        print(report.render_summary_line(matrix, color=color))

    if args.json:
        _write(args.json, report.render_json(matrix), args, color)
    if args.junit:
        _write(args.junit, report.render_junit(matrix), args, color)
    if getattr(args, "events", None):
        _write_events(args.events, matrix, args, color)
    return matrix.exit_code


def _write_events(path: str, matrix, args, color: bool) -> None:
    """Persist every target's telemetry as one JSONL stream.

    This is the other half of `marionette rules run`: the range produces events,
    the rule pack consumes them, and nothing in between has to be in memory.
    """
    evs = [e for run in matrix.runs
           if run.collector is not None for e in run.collector.events]
    try:
        n = write_jsonl(evs, path)
    except OSError as exc:
        raise ConfigError(f"could not write {path}: {exc}",
                          hint="check the directory exists and is writable") from exc
    if not args.quiet:
        print(report.paint(f"wrote {n} events to {path}", "dim", color))


def _write(path: str, text: str, args, color: bool) -> None:
    try:
        # newline="": report artifacts must be byte-identical across
        # platforms. Default text mode rewrites \n to \r\n on Windows, which
        # breaks byte comparison and puts a stray CR inside every JSONL record.
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
    except OSError as exc:
        raise ConfigError(f"could not write {path}: {exc}",
                          hint="check the directory exists and is writable") from exc
    if not args.quiet:
        print(report.paint(f"wrote {path}", "dim", color))


def cmd_validate(args) -> int:
    color = _use_color(args)
    problems: list[str] = []

    try:
        from .validate import validate_dir
    except ImportError:
        validate_dir = None

    if validate_dir is not None:
        found = validate_dir(args.techniques)
        n_err = sum(1 for p in found if p.severity == "error")
        for p in found:
            tag = report.paint(p.severity.upper(),
                               "red" if p.severity == "error" else "yellow", color)
            problems.append(f"[{tag}] {p.render()}")
    else:
        # Fallback: load every file individually so one bad YAML does not hide
        # the rest, and report each parse failure.
        import glob
        from .technique import Technique
        n_err = 0
        paths = sorted(glob.glob(os.path.join(args.techniques, "*.y*ml")))
        if not paths:
            problems.append(f"no technique YAML found in {args.techniques}")
            n_err += 1
        for path in paths:
            try:
                Technique.load(path)
            except Exception as exc:
                n_err += 1
                problems.append(f"[{report.paint('ERROR', 'red', color)}] "
                                f"{path}: {exc}")

    if args.targets_file:
        try:
            fleet = Fleet.load(args.targets_file)
            for msg in fleet.validate():
                n_err += 1
                problems.append(f"[{report.paint('ERROR', 'red', color)}] "
                                f"{args.targets_file}: {msg}")
        except MarionetteError as exc:
            n_err += 1
            problems.append(exc.render(color=color))

    for line in problems:
        print(line)
    if not problems:
        print(report.paint("all techniques valid", "green", color))
        return 0
    print(f"\n{len(problems)} problem(s), {n_err} error(s)")
    return 1 if n_err else 0


def cmd_targets(args) -> int:
    color = _use_color(args)
    if args.list_kinds:
        for kind in sorted(available()):
            print(kind)
        return 0
    fleet = (Fleet.load(args.targets_file) if args.targets_file
             else Fleet.single(kind="mock", name="mock"))
    for t in fleet.targets:
        state = (report.paint("enabled", "green", color) if t.enabled
                 else report.paint("disabled", "dim", color))
        tags = ",".join(t.tags) or "-"
        print(f"{report.paint(t.name, 'bold', color):<28} {t.kind:<6} "
              f"tags={tags:<20} {state}")
    print(f"\n{len(fleet.targets)} target(s)"
          + (f" from {fleet.source_path}" if fleet.source_path else ""))
    return 0


def cmd_snapshot(args) -> int:
    color = _use_color(args)
    specs = _select_specs(args)
    multi = len(specs) > 1
    base, ext = os.path.splitext(args.out)
    for spec in specs:
        target = build(spec.kind, **spec.build_kwargs())
        with target:
            tools = target.list_tools()
        snap = Snapshot.capture(target.name, tools)
        # One file per target when a fleet is given, else exactly --out.
        out = f"{base}.{spec.name}{ext}" if multi else args.out
        snap.save(out)
        print(f"captured {len(snap.tools)} tools from "
              f"{report.paint(target.name, 'bold', color)} -> {out}")
    return 0


def cmd_drift(args) -> int:
    color = _use_color(args)
    old, new = Snapshot.load(args.old), Snapshot.load(args.new)
    findings = diff(old, new, allow_cross_target=args.allow_cross_target)
    if not findings:
        print(report.paint("no drift", "green", color))
        return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda x: order.get(x.severity, 9)):
        col = "red" if f.severity in ("high", "critical") else "yellow"
        print(f"[{report.paint(f.severity.upper(), col, color)}] {f.change}  "
              f"{report.paint(report.sanitize(f.tool, 120), 'bold', color)}")
        # Descriptions are written by the target, which may be hostile: an
        # unsanitised ESC[2K\r can repaint this very line as "no drift".
        if f.before is not None:
            print(f"    - {report.paint(report.sanitize(f.before, 120), 'dim', color)}")
        if f.after is not None:
            print(f"    + {report.sanitize(f.after, 120)}")
    high = [f for f in findings if f.severity in ("high", "critical")]
    print(f"\n{len(findings)} change(s), "
          f"{report.paint(f'{len(high)} high-severity', 'red', color)}")
    return 1 if high else 0


# --- rules -------------------------------------------------------------------

_LEVEL_COLOR = {"critical": "red", "high": "red", "medium": "yellow",
                "low": "cyan", "informational": "dim"}


def _load_rules(args):
    return rules_mod.load_dir(args.rules)


def cmd_rules_list(args) -> int:
    color = _use_color(args)
    rules = _load_rules(args)
    if args.json:
        print(json.dumps([r.to_dict() for r in rules], indent=2))
        return 0
    for r in rules:
        lvl = report.paint(f"{r.level.upper():<13}",
                           _LEVEL_COLOR.get(r.level, "dim"), color)
        print(f"{report.paint(r.id, 'bold', color)}  {lvl} {r.title}")
        refs = ",".join(r.atlas) or "-"
        print(f"    {report.paint(f'{r.status}  [{refs}]', 'dim', color)}")
    print(f"\n{len(rules)} rules")
    return 0


def cmd_rules_validate(args) -> int:
    """Lint every rule file individually so one bad file cannot hide the rest."""
    import glob as _glob

    color = _use_color(args)
    paths = sorted(_glob.glob(os.path.join(args.rules, "*.y*ml")))
    if not paths:
        raise ConfigError(f"no rule YAML found in {args.rules}",
                          hint="pass --rules with a valid rule pack directory")
    problems: list[str] = []
    ok: list = []
    seen: dict[str, str] = {}
    for path in paths:
        try:
            rule = rules_mod.Rule.load(path)
        except MarionetteError as exc:
            problems.append(exc.render(color=color))
            continue
        if rule.id in seen:
            problems.append(
                f"[{report.paint('ERROR', 'red', color)}] {path}: duplicate "
                f"rule id {rule.id!r} (first seen in {seen[rule.id]})")
            continue
        seen[rule.id] = path
        # Style checks: not fatal, but a rule without a false-positive story
        # is how alert fatigue starts, so it is called out every time.
        if not rule.falsepositives:
            problems.append(
                f"[{report.paint('WARN', 'yellow', color)}] {path}: rule "
                f"{rule.id} has no `falsepositives` note")
        if not rule.description:
            problems.append(
                f"[{report.paint('WARN', 'yellow', color)}] {path}: rule "
                f"{rule.id} has no `description`")
        ok.append(rule)

    # Empirical dead-rule check. A rule whose path is misspelled resolves to
    # nothing and can never fire, yet lints perfectly -- which is precisely the
    # "matched nothing since day one" failure this project exists to catch. The
    # only reliable test is to run it against real telemetry.
    if getattr(args, "against", None):
        corpus = rules_mod.load_events(args.against)
        for rule in ok:
            if not any(rule.matches(ev) for ev in corpus):
                problems.append(
                    f"[{report.paint('ERROR', 'red', color)}] {seen[rule.id]}: "
                    f"rule {rule.id} matched 0 of {len(corpus)} events in "
                    f"{args.against} — it may never fire (check its field "
                    f"paths; a misspelled path resolves silently)")

    n_err = sum(1 for p in problems if "ERROR" in p or "MAR-E" in p)
    for line in problems:
        print(line)
    if not problems:
        print(report.paint(f"all {len(ok)} rules valid", "green", color))
        return 0
    print(f"\n{len(problems)} problem(s), {n_err} error(s)")
    return 1 if n_err else 0


def cmd_rules_run(args) -> int:
    color = _use_color(args)
    rules = _load_rules(args)
    events = rules_mod.load_events(args.events)
    matches = rules_mod.evaluate(rules, events)
    cov = rules_mod.coverage(rules, events) if args.coverage else None

    if args.json:
        out = {"event_count": len(events), "rule_count": len(rules),
               "matches": [m.to_dict() for m in matches]}
        if cov is not None:
            out["coverage"] = cov.to_dict()
        print(json.dumps(out, indent=2))
        return 1 if matches else 0

    order = {lv: i for i, lv in enumerate(reversed(rules_mod.LEVELS))}
    for m in sorted(matches, key=lambda x: (order.get(x.level, 9), x.rule_id)):
        lvl = report.paint(m.level.upper(), _LEVEL_COLOR.get(m.level, "dim"), color)
        print(f"[{lvl}] {report.paint(m.rule_id, 'bold', color)}  {m.title}")
        print(f"    {report.paint(f'{m.count} matching event(s)', 'dim', color)}")
    if cov is not None:
        print()
        print(report.paint("coverage", "bold", color))
        for t in cov.techniques:
            glyph = "\u2713" if t.covered else "\u2717"
            col = "green" if t.covered else "yellow"
            hits = ",".join(sorted({m.rule_id for m in t.matches})) or "-"
            print(f"  {report.paint(glyph, col, color)} {t.technique_id}  "
                  f"{t.name}\n      {report.paint(hits, 'dim', color)}")
        silent = cov.silent_rules
        if silent:
            print(report.paint(f"  silent rules: {', '.join(silent)}",
                               "yellow", color))
    if not matches:
        print(report.paint(
            f"no rules fired over {len(events)} event(s)", "green", color))
        return 0
    print(f"\n{len(matches)} of {len(rules)} rule(s) fired over "
          f"{len(events)} event(s)")
    return 1


def cmd_rules(args) -> int:
    # `marionette rules` with no subcommand: show what is available rather than
    # an argparse stack trace.
    raise ConfigError("`marionette rules` needs a subcommand",
                      hint="one of: list, validate, run")


# --- parser ------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="marionette",
        description="ATLAS has the techniques. Marionette pulls the strings.")
    p.add_argument("--version", action="version", version=f"marionette {__version__}")
    p.add_argument("--debug", action="store_true",
                   help="show the raw traceback instead of a rendered error")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_target_flags(sp):
        sp.add_argument("--targets-file", help="fleet YAML (see targets.example.yaml)")
        sp.add_argument("--target", default="mock",
                        help="single-target shorthand kind (default: mock)")
        sp.add_argument("--command", help="launch command for --target mcp")
        sp.add_argument("--cwd", help="working dir for the mcp server")
        sp.add_argument("--timeout", type=float, help="per-target timeout, seconds")
        sp.add_argument("--name", action="append",
                        help="only targets with this name (repeatable)")
        sp.add_argument("--tag", action="append",
                        help="only targets with this tag (repeatable)")

    def add_common(sp):
        sp.add_argument("--no-color", action="store_true",
                        help="disable ANSI colour")
        sp.add_argument("--debug", action="store_true",
                        help="show the raw traceback on error")

    lp = sub.add_parser("list", help="list techniques")
    lp.add_argument("--techniques", default=DEFAULT_TECH_DIR)
    lp.add_argument("--json", action="store_true", help="emit JSON")
    add_common(lp)
    lp.set_defaults(fn=cmd_list)

    rp = sub.add_parser("run", help="execute techniques and assert detections")
    rp.add_argument("--techniques", default=DEFAULT_TECH_DIR)
    rp.add_argument("--technique", action="append",
                    help="run only this id (repeatable)")
    rp.add_argument("--tactic", help="run only techniques with this tactic")
    rp.add_argument("--workers", type=int, default=8,
                    help="parallel targets (default: 8)")
    rp.add_argument("--fail-fast", action="store_true",
                    help="stop the matrix on the first failure")
    rp.add_argument("--json", metavar="PATH", help="write JSON results here")
    rp.add_argument("--junit", metavar="PATH", help="write JUnit XML here")
    rp.add_argument("--events", metavar="PATH",
                    help="write the raw agent event stream (JSONL) here")
    rp.add_argument("--verbose", "-v", action="store_true")
    rp.add_argument("--quiet", "-q", action="store_true",
                    help="summary line only")
    add_target_flags(rp)
    add_common(rp)
    rp.set_defaults(fn=cmd_run)

    vp = sub.add_parser("validate", help="lint technique YAML and the fleet file")
    vp.add_argument("--techniques", default=DEFAULT_TECH_DIR)
    vp.add_argument("--targets-file")
    add_common(vp)
    vp.set_defaults(fn=cmd_validate)

    tp = sub.add_parser("targets", help="list configured targets or adapter kinds")
    tp.add_argument("--targets-file")
    tp.add_argument("--list-kinds", action="store_true",
                    help="list registered adapter kinds instead")
    add_common(tp)
    tp.set_defaults(fn=cmd_targets)

    snp = sub.add_parser("snapshot", help="fingerprint a target's tools")
    snp.add_argument("--out", required=True)
    add_target_flags(snp)
    add_common(snp)
    snp.set_defaults(fn=cmd_snapshot)

    dp = sub.add_parser("drift", help="diff two snapshots (rug-pull detector)")
    dp.add_argument("old")
    dp.add_argument("new")
    dp.add_argument("--allow-cross-target", action="store_true",
                    help="permit diffing snapshots from two different targets")
    add_common(dp)
    dp.set_defaults(fn=cmd_drift)

    rules_p = sub.add_parser("rules",
                             help="detection rules over the agent event schema")
    add_common(rules_p)
    rules_p.set_defaults(fn=cmd_rules)
    rsub = rules_p.add_subparsers(dest="rules_cmd")

    def add_rules_dir(sp):
        sp.add_argument("--rules", default=rules_mod.DEFAULT_RULES_DIR,
                        help="rule pack directory (default: shipped pack)")
        add_common(sp)

    rl = rsub.add_parser("list", help="list the shipped rules")
    rl.add_argument("--json", action="store_true", help="emit JSON")
    add_rules_dir(rl)
    rl.set_defaults(fn=cmd_rules_list)

    rv = rsub.add_parser("validate", help="lint the rule pack")
    add_rules_dir(rv)
    rv.add_argument("--against", metavar="EVENTS.jsonl",
                    help="fail any rule that matches 0 events in this corpus; "
                         "catches rules that can never fire")
    rv.set_defaults(fn=cmd_rules_validate)

    rr = rsub.add_parser("run", help="evaluate rules against an event stream")
    rr.add_argument("--events", required=True, metavar="PATH",
                    help="JSONL event stream from `marionette run --events`")
    rr.add_argument("--coverage", action="store_true",
                    help="attribute hits back to the technique that caused them")
    rr.add_argument("--json", action="store_true", help="emit JSON")
    add_rules_dir(rr)
    rr.set_defaults(fn=cmd_rules_run)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    # Guard rendering itself: a bad --no-color/tty combination must not mask
    # the error we are trying to show.
    color = report.color_enabled(not getattr(args, "no_color", False),
                                 stream=sys.stderr)
    try:
        return args.fn(args) or 0
    except MarionetteError as exc:
        if getattr(args, "debug", False):
            raise
        print(exc.render(color=color), file=sys.stderr)
        return _exit_code_for(exc)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - last-resort net
        if getattr(args, "debug", False):
            raise
        print(f"[MAR-E000] unexpected error: {exc}\n"
              f"  hint: re-run with --debug for the traceback", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
