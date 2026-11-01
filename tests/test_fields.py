"""Tests for fields.py, and for the check being wired into the linter.

A field that Falco does not know does not raise. It evaluates as absent, the
comparison is false, and the rule reads as "this event is not interesting" —
indistinguishable from a rule that works. So the two things worth testing are
that a misspelling is caught, and that a correctly spelled field is not.

Run with: python tests/test_fields.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import falco_rule_lab as lab  # noqa: E402
import fields  # noqa: E402
from engine import Ruleset  # noqa: E402

RULES_DIR = Path(os.environ.get("FALCO_RULES_DIR")
                 or Path(__file__).resolve().parent.parent / "upstream" / "rules")

RESULTS: list[tuple[str, bool, str]] = []


def check(label: str, got, want) -> None:
    RESULTS.append((label, got == want, f"got={got!r} want={want!r}"))


def ok(label: str, path: str) -> None:
    problem = fields.check(path)
    RESULTS.append((label, problem is None, f"rejected {path!r}: {problem}"))


def rejected(label: str, path: str, hint: str = "") -> None:
    problem = fields.check(path)
    got = problem or ""
    RESULTS.append((label, bool(problem) and hint in got,
                    f"accepted {path!r}" if not problem else f"no {hint!r} in {got!r}"))


def main() -> int:
    # -- accepted forms ----------------------------------------------------
    ok("plain documented field", "proc.name")
    ok("dotted documented field", "evt.time.s")
    ok("bracket argument on a list field", "proc.aname[2]")
    ok("path inside a bracket argument", "container.mount.dest[/var/run/docker.sock]")
    ok("extension of a dynamic field", "evt.arg.flags")
    ok("extension of a label field", "container.label.app")
    ok("label key containing dots and slashes",
       "k8s.pod.label.app.kubernetes.io/name")

    # -- rejected forms ----------------------------------------------------
    rejected("misspelled field", "proc.nmae", "proc.name")
    rejected("invented field", "proc.executable_name")
    rejected("plausible but undocumented", "container.image.hash")
    rejected("extension of a non-dynamic field", "evt.time.microseconds")

    # -- calibration: the checker must not cry wolf ------------------------
    # 97 merged rules, 89 distinct field references, no findings. A checker
    # that fails upstream code is a checker nobody runs.
    if (RULES_DIR / "falco_rules.yaml").is_file():
        total = bad = 0
        for name in ("falco_rules", "falco-incubating_rules", "falco-sandbox_rules"):
            rs = Ruleset(RULES_DIR / f"{name}.yaml")
            for rule_name, rule in rs.rules.items():
                total += 1
                hard, _ = lab.style_findings(rs, rule)
                if hard:
                    bad += 1
                    RESULTS.append((f"upstream {rule_name}", False, "; ".join(hard)[:120]))
        check(f"calibration: 0 of {total} upstream rules fail a hard check", bad, 0)

        # -- counter-proof: the check is wired, not merely correct ---------
        # Take a real rule and misspell one field it uses. The linter must
        # name the field and suggest the real one.
        #
        # The rule is picked from the file rather than named: this test runs
        # against upstream, where the rule proposed in falcosecurity/rules#397
        # does not exist yet, and a hard-coded name made the suite pass here
        # and fail in CI.
        rs = Ruleset(RULES_DIR / "falco-sandbox_rules.yaml")
        subject = next(r for r in rs.rules.values()
                       if "proc.name" in str(r.get("condition", "")))
        broken = dict(subject)
        broken["condition"] = broken["condition"].replace("proc.name", "proc.nmae", 1)
        hard, _ = lab.style_findings(rs, broken)
        hits = [h for h in hard if "proc.nmae" in h]
        check(f"counter-proof: a misspelled field is reported "
              f"({subject['rule']})", len(hits), 1)
        check("counter-proof: the report suggests the real field",
              "proc.name" in (hits[0] if hits else ""), True)
    else:
        print(f"no upstream ruleset at {RULES_DIR}; skipping calibration")

    width = max(len(label) for label, _, _ in RESULTS)
    failed = 0
    for label, ok_, detail in RESULTS:
        if not ok_:
            failed += 1
            print(f"[FAIL] {label:<{width}}  {detail}")
    print(f"\n{len(RESULTS) - failed}/{len(RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
