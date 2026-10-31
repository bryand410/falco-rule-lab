#!/usr/bin/env python3
"""falco-rule-lab — evaluate and lint a Falco rule without a running Falco.

Falco's own validator (build/checker/rules-check) loads the ruleset into a real
Falco container, which is the right gate but needs Docker. This tool answers the
two questions that gate cannot answer quickly:

  1. does this rule actually discriminate, or does it only look plausible?
  2. does it comply with the upstream style guide?

Conditions are parsed and evaluated by engine.py, which implements the Falco
condition language as a grammar. See the module docstring there for why the
previous text-substitution approach was replaced.

    python falco_rule_lab.py style --rules PATH --rule "Rule Name"
    python falco_rule_lab.py check --rules PATH --cases cases/file-capabilities.json
    python falco_rule_lab.py casegen --rules PATH --rule "Rule Name" --out cases/gen.json
    python falco_rule_lab.py self-test --rules PATH --rule "Rule Name"
    python falco_rule_lab.py parse --rules PATH
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

from engine import (
    ConditionError,
    Ruleset,
    evt_types,
    leading_fields,
)
from casegen import generate as generate_cases, to_case_file

MATURITY = {"maturity_stable", "maturity_incubating", "maturity_sandbox", "maturity_deprecated"}

CORE_OUTPUT_FIELDS = [
    "evt_type=%evt.type",
    "user=%user.name",
    "user_uid=%user.uid",
    "user_loginuid=%user.loginuid",
    "process=%proc.name",
    "proc_exepath=%proc.exepath",
    "parent=%proc.pname",
    "command=%proc.cmdline",
    "terminal=%proc.tty",
]


# --------------------------------------------------------------------------
# Style guide: https://falco.org/docs/rules/style-guide/
# --------------------------------------------------------------------------

def style_findings(rs: Ruleset, r: dict) -> tuple[list[str], list[str]]:
    """(hard, soft) findings.

    hard = the guide states it imperatively; a reviewer will block on it.
    soft = the guide recommends it but the existing ruleset varies; reported
           for information, never used to fail.
    """
    hard: list[str] = []
    soft: list[str] = []
    name = r["rule"]
    desc = str(r.get("desc", "")).strip()
    cond = " ".join(r.get("condition", "").split())
    output = str(r.get("output", ""))
    priority = str(r.get("priority", "")).strip().upper()
    tags = r.get("tags") or []

    if not name[:1].isupper():
        hard.append("rule name must start with an upper-case letter")
    if not desc.endswith("."):
        hard.append("desc must end with a period")

    try:
        node = rs.compile(cond)
    except ConditionError as exc:
        hard.append(f"condition does not parse: {exc}")
        node = None

    if node is not None:
        types = evt_types(node)
        if not types:
            hard.append("condition has no evt.type restriction (performance penalty)")
        else:
            leading = leading_fields(node)
            if not leading or not all(
                f.startswith("evt.type") or f.startswith("container") for f in leading
            ):
                shown = ", ".join(sorted(leading)) or "nothing"
                hard.append(f"evt.type/container restriction must come first, found {shown}")
            spawned_only = types <= {"execve", "execveat"}
            # The guide says "rules involving only spawned_process". Two merged
            # upstream rules (Launch Sensitive/Disallowed Container) reach
            # execve-only through container_started, and neither carries
            # exe_flags. So the hard check applies only when the author wrote
            # the exec restriction themselves; expansion-only cases are a note.
            named = "spawned_process" in cond or "execve" in cond
            has_flags = "exe_flags=%evt.arg.flags" in output
            if spawned_only and named and not has_flags:
                hard.append("spawned_process-only rule must output exe_flags=%evt.arg.flags")
            elif spawned_only and not named and not has_flags:
                soft.append("fires only on execve via macro expansion; "
                            "the guide asks for exe_flags here too")
            if not spawned_only and has_flags:
                soft.append("exe_flags is only meaningful for spawned_process-only rules")

    if not output:
        hard.append("output is empty")
    else:
        if "|" not in output:
            hard.append("output must be '<message> | <fields>'")
        missing = [f for f in CORE_OUTPUT_FIELDS if f not in output]
        if missing:
            soft.append(f"output is missing core fields: {', '.join(missing)}")

    if priority == "DEBUG":
        hard.append("priority DEBUG is forbidden for upstream rules")
    if not priority:
        hard.append("priority is missing")

    if not tags:
        hard.append("tags is empty")
    else:
        if tags[0] not in MATURITY:
            hard.append(f"first tag must be a maturity tag, got {tags[0]!r}")
        if "host" not in tags and "container" not in tags:
            hard.append("tags must state at least one workload (host or container)")
        if not any(str(t).startswith("mitre_") for t in tags):
            soft.append("tags have no mitre_* tag")
        if not any(re.fullmatch(r"T\d{4}(\.\d{3})?", str(t)) for t in tags):
            soft.append("tags have no ATT&CK technique id (T####[.###])")

    order = ["desc", "condition", "output", "priority", "tags"]
    present = [k for k in r if k in order]
    if present != [k for k in order if k in present]:
        soft.append(f"key order should be {order}, got {present}")

    return hard, soft


def self_test(rs: Ruleset, rule: dict) -> list[str]:
    """Mutate a compliant rule and prove the checker notices.

    A gate that never fails is decoration.
    """
    mutations = [
        ("drop exe_flags from a spawned_process-only output",
         lambda r: r.update(output=r["output"].replace(" exe_flags=%evt.arg.flags", ""))),
        ("lower-case the rule name",
         lambda r: r.update({"rule": r["rule"][0].lower() + r["rule"][1:]})),
        ("drop the maturity tag",
         lambda r: r.update(tags=[t for t in r["tags"] if not t.startswith("maturity_")])),
        ("drop the evt.type restriction",
         lambda r: r.update(condition="proc.name = setcap")),
        ("drop the trailing period from desc",
         lambda r: r.update(desc=r["desc"].rstrip().rstrip("."))),
    ]
    undetected = []
    for label, mutate in mutations:
        clone = copy.deepcopy(rule)
        mutate(clone)
        if not style_findings(rs, clone)[0]:
            undetected.append(label)
    return undetected


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_style(rs: Ruleset, name: str) -> int:
    rule = rs.rule(name)
    hard, soft = style_findings(rs, rule)
    print(f"rule: {name}")
    for f in hard:
        print(f"  [FAIL] {f}")
    for f in soft:
        print(f"  [note] {f}")
    if not hard:
        print("  [PASS] meets every mandatory style requirement")

    peers = sum(1 for n, r in rs.rules.items() if n != name and style_findings(rs, r)[0])
    print(f"\ncalibration: {peers}/{len(rs.rules) - 1} other rules in this file fail a hard check")
    return 1 if hard else 0


def cmd_check(rs: Ruleset, cases_path: Path) -> int:
    spec = json.loads(cases_path.read_text(encoding="utf-8"))
    name = spec["rule"]
    rule = rs.rule(name)
    node = rs.compile(rule["condition"])

    print(f"rule: {name}")
    print(f"condition: {' '.join(rule['condition'].split())}")
    print()
    failures = 0
    for case in spec["cases"]:
        got = node.evaluate(case["event"])
        want = case["expect"] == "fires"
        ok = got == want
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {'fires ' if got else 'silent'} | {case['label']}")
        print(f"        expected={'fires' if want else 'silent'} — {case['why']}")
    print(f"\n{len(spec['cases']) - failures}/{len(spec['cases'])} cases match expectation")
    return 1 if failures else 0


def cmd_self_test(rs: Ruleset, name: str) -> int:
    undetected = self_test(rs, rs.rule(name))
    for label in undetected:
        print(f"[FAIL] checker did not notice: {label}")
    if not undetected:
        print("[PASS] checker detected all 5 injected defects")
    return 1 if undetected else 0


def cmd_parse(rs: Ruleset) -> int:
    failures = rs.check_all()
    for name, err in failures:
        print(f"[FAIL] {name}: {err}")
    print(f"{len(rs.macros)} macros, {len(rs.rules)} rules, {len(failures)} parse failures")
    return 1 if failures else 0


def cmd_casegen(rs: Ruleset, name: str, out: Path | None) -> int:
    cases, notes = generate_cases(rs, name)
    for note in notes:
        print(f"[note] {note}")
    if not cases:
        print(f"0 cases generated for {name!r}")
        return 1
    spec = to_case_file(name, cases, notes)
    payload = json.dumps(spec, indent=2, ensure_ascii=False)
    if out:
        out.write_text(payload + "\n", encoding="utf-8")
        print(f"written: {out}")
    else:
        print(payload)
    fires = sum(1 for c in cases if c["expect"] == "fires")
    print(f"\n{len(cases)} cases ({fires} fires, {len(cases) - fires} silent), "
          f"all verified against the rule")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate and lint a Falco rule offline.")
    ap.add_argument("command", choices=["style", "check", "self-test", "parse", "casegen"])
    ap.add_argument("--rules", required=True, type=Path,
                    help="path to a falcosecurity/rules YAML file, e.g. rules/falco-sandbox_rules.yaml")
    ap.add_argument("--rule", help="rule name (for style, self-test and casegen)")
    ap.add_argument("--cases", type=Path, help="JSON file of cases (for check)")
    ap.add_argument("--out", type=Path, help="write the generated cases here (for casegen)")
    a = ap.parse_args()

    if not a.rules.is_file():
        raise SystemExit(f"no such rules file: {a.rules}")
    rs = Ruleset(a.rules)

    if a.command == "parse":
        return cmd_parse(rs)
    if a.command == "check":
        if not a.cases:
            raise SystemExit("check needs --cases")
        return cmd_check(rs, a.cases)
    if not a.rule:
        raise SystemExit(f"{a.command} needs --rule")
    if a.command == "style":
        return cmd_style(rs, a.rule)
    if a.command == "casegen":
        return cmd_casegen(rs, a.rule, a.out)
    return cmd_self_test(rs, a.rule)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ConditionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
