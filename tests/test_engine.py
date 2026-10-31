"""Tests for engine.py.

Every case in the `regressions` section failed against the previous
text-substitution evaluator. They are kept here as the reason this module
exists, not as a formality.

Run with: python tests/test_engine.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine import ConditionError, Ruleset, tokenize, Parser  # noqa: E402

RULES_DIR = Path(os.environ.get("FALCO_RULES_DIR")
                 or Path(__file__).resolve().parent.parent / "upstream" / "rules")

RESULTS: list[tuple[str, bool, str]] = []


def check(label: str, got, want) -> None:
    RESULTS.append((label, got == want, f"got={got!r} want={want!r}"))


def raises(label: str, fn, exc=ConditionError) -> None:
    try:
        fn()
    except exc:
        RESULTS.append((label, True, "raised as expected"))
    except Exception as e:                                    # noqa: BLE001
        RESULTS.append((label, False, f"wrong exception {type(e).__name__}: {e}"))
    else:
        RESULTS.append((label, False, "did not raise"))


def main() -> int:
    if not (RULES_DIR / "falco_rules.yaml").is_file():
        print(f"no upstream ruleset at {RULES_DIR}\n"
              "  git clone https://github.com/falcosecurity/rules "
              f"{RULES_DIR.parent}\n"
              "  (that repository keeps its files in rules/, hence upstream/rules)\n"
              "  or set FALCO_RULES_DIR to a directory holding falco_rules.yaml")
        return 2
    rs = Ruleset(RULES_DIR / "falco_rules.yaml")

    def ev(cond: str, event: dict) -> bool:
        return rs.compile(cond).evaluate(event)

    # -- the defects that motivated the rewrite ---------------------------
    # A macro named `container` must not be substituted inside a string.
    check('macro name inside a string is left alone',
          ev('proc.cmdline contains "container"', {"proc": {"cmdline": "run container now"}}),
          True)
    check('macro name inside a string, no false positive',
          ev('proc.cmdline contains "container"', {"proc": {"cmdline": "run podman now"}}),
          False)

    # `in` used to shadow `intersects` in the keyword alternation.
    check('intersects parses and matches',
          ev('evt.arg.flags intersects (O_TRUNC)', {"evt": {"arg": {"flags": ["O_WRONLY", "O_TRUNC"]}}}),
          True)
    check('intersects parses and rejects',
          ev('evt.arg.flags intersects (O_TRUNC)', {"evt": {"arg": {"flags": ["O_WRONLY"]}}}),
          False)

    # pmatch is a component-boundary prefix, not a full match and not a
    # plain startswith.
    check('pmatch matches a path below the prefix',
          ev('fd.name pmatch (/var/run)', {"fd": {"name": "/var/run/x"}}), True)
    check('pmatch matches the prefix itself',
          ev('fd.name pmatch (/var/run)', {"fd": {"name": "/var/run"}}), True)
    check('pmatch does not match a longer component',
          ev('fd.name pmatch (/var/run)', {"fd": {"name": "/var/runx"}}), False)
    check('pmatch accepts several prefixes',
          ev('fd.name pmatch (/var/run, /etc)', {"fd": {"name": "/etc/passwd"}}), True)

    # glob: `?` is one character, `*` does not cross a separator.
    check('glob honours ?',
          ev('fd.name glob "/tmp/a?c"', {"fd": {"name": "/tmp/abc"}}), True)
    check('glob * does not cross a separator',
          ev('fd.name glob "/var/*"', {"fd": {"name": "/var/run/x"}}), False)
    check('glob * matches within one component',
          ev('fd.name glob "/var/*"', {"fd": {"name": "/var/log"}}), True)

    # A list-valued field is a list, not a comma-joined string.
    check('in works on a list-valued field',
          ev('evt.arg.flags in (O_TRUNC, O_WRONLY)',
             {"evt": {"arg": {"flags": ["O_WRONLY", "O_TRUNC"]}}}), True)

    # Numbers compare as numbers.
    check('numeric > is not string comparison',
          ev('proc.pid > 9', {"proc": {"pid": 10}}), True)
    check('numeric < is not string comparison',
          ev('proc.pid < 100', {"proc": {"pid": 99}}), True)

    # -- operators and transformers ---------------------------------------
    check('icontains is case-insensitive',
          ev('proc.cmdline icontains "CURL"', {"proc": {"cmdline": "x curl y"}}), True)
    check('startswith', ev('proc.cmdline startswith "sh -c"', {"proc": {"cmdline": "sh -c id"}}), True)
    check('endswith', ev('proc.exepath endswith /dockerd', {"proc": {"exepath": "/usr/bin/dockerd"}}), True)
    check('exists on a present field', ev('proc.pname exists', {"proc": {"pname": "bash"}}), True)
    check('exists on a missing field', ev('proc.pname exists', {"proc": {}}), False)
    check('a comparison on a missing field is false',
          ev('proc.name = bash', {"proc": {}}), False)
    check('basename strips the directory',
          ev('basename(proc.exepath) = dockerd', {"proc": {"exepath": "/usr/bin/dockerd"}}), True)
    check('basename of a bare name is empty',
          ev('basename(proc.exepath) = ""', {"proc": {"exepath": "/usr/bin/"}}), True)
    check('len on a string', ev('len(proc.name) > 2', {"proc": {"name": "dockerd"}}), True)
    check('tolower', ev('tolower(proc.name) = bash', {"proc": {"name": "BASH"}}), True)
    check('bcontains matches raw bytes',
          ev('evt.buffer bcontains CAFEBABE', {"evt": {"buffer": b"\x00\xca\xfe\xba\xbe"}}), True)

    # -- macros and lists --------------------------------------------------
    check('a macro used as a boolean resolves',
          ev('container', {"container": {"id": "abc123"}}), True)
    check('a macro used as a boolean, negative case',
          ev('container', {"container": {"id": "host"}}), False)
    check('not binds tighter than and',
          ev('not container and proc.name = bash',
             {"container": {"id": "host"}, "proc": {"name": "bash"}}), True)
    check('and binds tighter than or',
          ev('proc.name = a or proc.name = b and proc.name = c',
             {"proc": {"name": "a"}}), True)
    check('nested lists flatten',
          ev('proc.name in (package_mgmt_binaries)', {"proc": {"name": "apt"}}), True)

    # -- the parser must be able to fail -----------------------------------
    raises('an unterminated string is rejected', lambda: rs.compile('proc.name = "bash'))
    raises('a trailing token is rejected', lambda: rs.compile('proc.name = bash extra'))
    raises('a bare word without an operator is rejected',
           lambda: rs.compile('spawned_process and nonsense_word'))
    raises('an unimplemented operator is named, not misread',
           lambda: rs.compile('proc.name regex "ba.*"'))

    cyclic = Ruleset(RULES_DIR / "falco_rules.yaml")
    cyclic.macros["loop_a"] = "loop_b"
    cyclic.macros["loop_b"] = "loop_a"
    raises('a macro cycle is detected', lambda: cyclic.compile("loop_a"))

    # -- the whole upstream ruleset must parse -----------------------------
    total_rules = total_macros = total_failures = 0
    for name in ("falco_rules.yaml", "falco-incubating_rules.yaml", "falco-sandbox_rules.yaml"):
        r = Ruleset(RULES_DIR / name)
        failures = r.check_all()
        total_rules += len(r.rules)
        total_macros += len(r.macros)
        total_failures += len(failures)
        for rule_name, err in failures[:3]:
            RESULTS.append((f"{name}: {rule_name}", False, err[:100]))
    check(f'every rule and macro in the upstream ruleset parses '
          f'({total_rules} rules, {total_macros} macros)', total_failures, 0)

    # -- report ------------------------------------------------------------
    width = max(len(label) for label, _, _ in RESULTS)
    failed = 0
    for label, ok, detail in RESULTS:
        if not ok:
            failed += 1
            print(f"[FAIL] {label:<{width}}  {detail}")
    print(f"\n{len(RESULTS) - failed}/{len(RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
