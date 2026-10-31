"""Tests for casegen.py.

Each test pins a defect that the generator actually had while it was being
written against the upstream ruleset. The list is the history, not a wish.

Run with: python tests/test_casegen.py
"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine import Ruleset  # noqa: E402
from casegen import generate  # noqa: E402

RULES_DIR = Path(os.environ.get("FALCO_RULES_DIR")
                 or Path(__file__).resolve().parent.parent / "upstream" / "rules")

RESULTS: list[tuple[str, bool, str]] = []


def check(label: str, got, want) -> None:
    RESULTS.append((label, got == want, f"got={got!r} want={want!r}"))


def write(tmp: Path, body: str) -> Path:
    path = tmp / "rules.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


HEADER = """
- list: package_mgmt_binaries
  items: [dnf, rpm, yum]

- macro: spawned_process
  condition: (evt.type in (execve, execveat))

- macro: never_true
  condition: (evt.num=0)
"""


def main() -> int:
    tmp = Path(__file__).resolve().parent / "_tmp"
    tmp.mkdir(exist_ok=True)

    # 1. A plain rule: one positive case, one near miss, one wrong event type.
    path = write(tmp, HEADER + """
- rule: Setcap
  desc: d.
  condition: spawned_process and proc.name = setcap
  output: o | evt_type=%evt.type
  priority: WARNING
  tags: [maturity_sandbox, host]
""")
    rs = Ruleset(path)
    cases, notes = generate(rs, "Setcap")
    labels = [c["label"] for c in cases]
    check("plain: positive generated", any(c["expect"] == "fires" for c in cases), True)
    check("plain: near miss generated",
          any("near miss" in label for label in labels), True)
    check("plain: wrong event type generated",
          any("evt.type=open" in label for label in labels), True)
    check("plain: no notes", notes, [])

    # 2. Every case must agree with the rule. This is the invariant that lets
    #    the tool claim the file is evidence rather than opinion.
    node = rs.compile_rule("Setcap")
    mismatched = [c["label"] for c in cases
                  if node.evaluate(c["event"]) != (c["expect"] == "fires")]
    check("plain: every case verified", mismatched, [])

    # 3. Two clauses on one field: the `!=` must not overwrite the `in`.
    path = write(tmp, HEADER + """
- rule: Two Clauses One Field
  desc: d.
  condition: >
    spawned_process
    and proc.name in (nginx, httpd)
    and proc.name != sshd
  output: o | evt_type=%evt.type
  priority: WARNING
  tags: [maturity_sandbox, host]
""")
    rs = Ruleset(path)
    cases, _ = generate(rs, "Two Clauses One Field")
    positive = [c for c in cases if c["expect"] == "fires"]
    check("!= keeps the value chosen by in",
          {c["event"]["proc"]["name"] for c in positive}, {"nginx", "httpd"})
    check("!= is never overwritten by a value invented for it",
          [c for c in positive if c["event"]["proc"]["name"] == "sshd-other"], [])

    # 4. Two `contains` on one field need a merged value, not the last write.
    path = write(tmp, HEADER + """
- rule: Merged Args
  desc: d.
  condition: >
    spawned_process
    and proc.name = sudo
    and (proc.args contains -s or proc.args contains -i)
    and (proc.args contains " " or proc.args endswith " ")
  output: o | evt_type=%evt.type
  priority: WARNING
  tags: [maturity_sandbox, host]
""")
    rs = Ruleset(path)
    cases, _ = generate(rs, "Merged Args")
    positive = [c for c in cases if c["expect"] == "fires"]
    check("merged: a satisfying event exists", bool(positive), True)
    check("merged: every firing event satisfies both clauses",
          [c["label"] for c in positive
           if "-s" not in c["event"]["proc"]["args"]
           or " " not in c["event"]["proc"]["args"]], [])

    # 5. A byte buffer must survive as bytes, not as a mangled decode.
    path = write(tmp, HEADER + """
- rule: Java Class
  desc: d.
  condition: spawned_process and evt.buffer bcontains cafebabe
  output: o | evt_type=%evt.type
  priority: WARNING
  tags: [maturity_sandbox, host]
""")
    rs = Ruleset(path)
    cases, notes = generate(rs, "Java Class")
    check("bcontains: generated", [c["expect"] for c in cases][:1], ["fires"])
    if cases:
        check("bcontains: stored as a byte marker",
              cases[0]["event"]["evt"]["buffer"], {"$bytes": "cafebabe"})

    # 6. An exclusion that can never matter must be reported, not dressed up
    #    as a passing case. `not package_mgmt_procs` is dead when the rule
    #    already requires proc.name = setcap.
    path = write(tmp, HEADER + """
- macro: package_mgmt_procs
  condition: (proc.name in (package_mgmt_binaries))

- rule: Dead Exclusion
  desc: d.
  condition: >
    spawned_process
    and proc.name = setcap
    and not package_mgmt_procs
  output: o | evt_type=%evt.type
  priority: WARNING
  tags: [maturity_sandbox, host]
""")
    rs = Ruleset(path)
    cases, notes = generate(rs, "Dead Exclusion")
    check("dead exclusion: no exclusion case claimed",
          [c["label"] for c in cases if c["label"].startswith("excluded")], [])
    check("dead exclusion: reported",
          any("vacuous" in note for note in notes), True)

    # 7. A rule whose exclusion contradicts its own requirement cannot fire.
    path = write(tmp, HEADER + """
- macro: container_started
  condition: (spawned_process and container.id != host)

- macro: allowed_containers
  condition: (container.id exists)

- rule: Unsatisfiable
  desc: d.
  condition: container_started and not allowed_containers
  output: o | evt_type=%evt.type
  priority: WARNING
  tags: [maturity_sandbox, container]
""")
    rs = Ruleset(path)
    cases, notes = generate(rs, "Unsatisfiable")
    check("unsatisfiable: nothing generated", cases, [])
    check("unsatisfiable: diagnosed, not blamed on the generator",
          any("cannot fire as written" in note for note in notes), True)

    # 8. An empty list disables the rule; say so instead of "not invertible".
    path = write(tmp, HEADER + """
- list: namespace_scope
  items: []

- rule: Empty Scope
  desc: d.
  condition: spawned_process and k8s.ns.name in (namespace_scope)
  output: o | evt_type=%evt.type
  priority: WARNING
  tags: [maturity_sandbox, host]
""")
    rs = Ruleset(path)
    cases, notes = generate(rs, "Empty Scope")
    check("empty list: nothing generated", cases, [])
    check("empty list: named as the reason",
          any("empty list" in note for note in notes), True)

    # 9. Across the whole upstream ruleset: no generator bug may remain, and
    #    every rule that does generate must verify. Skipped when the ruleset is
    #    not checked out; set FALCO_RULES_DIR to run it.
    if not (RULES_DIR / "falco_rules.yaml").is_file():
        print(f"skip: no upstream ruleset at {RULES_DIR}")
    else:
        tot = generated = 0
        bad: list[str] = []
        for name in ("falco_rules", "falco-incubating_rules", "falco-sandbox_rules"):
            upstream = Ruleset(RULES_DIR / f"{name}.yaml")
            for rule_name in upstream.rules:
                tot += 1
                made, notes = generate(upstream, rule_name)
                if made:
                    generated += 1
                    node = upstream.compile_rule(rule_name)
                    for case in made:
                        if node.evaluate(case["event"]) != (case["expect"] == "fires"):
                            bad.append(f"{rule_name}: {case['label']}")
                elif any("bug in the generator" in note for note in notes):
                    bad.append(f"{rule_name}: {notes[0][:80]}")
        check("upstream: no unverified case", bad, [])
        # A floor, not an exact count: CI runs against upstream HEAD, and the
        # number moves when rules are added. The invariant above is the one
        # that must not regress.
        check(f"upstream: covers at least {tot - 5} of {tot} rules",
              generated >= tot - 5, True)
        print(f"       upstream: {generated}/{tot} rules, {len(bad)} unverified")

    for name in tmp.iterdir():
        name.unlink()
    tmp.rmdir()

    failures = [r for r in RESULTS if not r[1]]
    for label, ok, detail in RESULTS:
        if not ok:
            print(f"[FAIL] {label}: {detail}")
    print(f"\n{len(RESULTS) - len(failures)}/{len(RESULTS)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
