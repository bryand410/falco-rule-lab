#!/usr/bin/env python3
"""falco-rule-lab — evaluate and lint a Falco rule without a running Falco.

Falco's own validator (build/checker/rules-check) loads the ruleset into a real
Falco container, which is the right gate but needs Docker. This tool answers the
two questions that gate cannot answer quickly:

  1. does this rule actually discriminate, or does it only look plausible?
  2. does it comply with the upstream style guide?

It is a MODEL of Falco's condition language, not Falco. It resolves macros and
lists the way the loader does, then evaluates the expanded condition against
events you describe yourself.

    python falco_rule_lab.py style --rules PATH --rule "Rule Name"
    python falco_rule_lab.py check --rules PATH --cases cases/file-capabilities.json
    python falco_rule_lab.py self-test --rules PATH --rule "Rule Name"
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path

import yaml

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
# Ruleset: load, index, expand
# --------------------------------------------------------------------------

class Ruleset:
    def __init__(self, path: Path):
        self.path = path
        self.lists: dict[str, list[str]] = {}
        self.macros: dict[str, str] = {}
        self.rules: dict[str, dict] = {}
        for item in yaml.safe_load(path.read_text(encoding="utf-8")):
            if "list" in item:
                self.lists[item["list"]] = [str(i).strip("'\"") for i in item["items"]]
            elif "macro" in item:
                self.macros[item["macro"]] = " ".join(item["condition"].split())
            elif "rule" in item:
                self.rules[item["rule"]] = item

    def resolve_list(self, name: str, seen: frozenset[str] = frozenset()) -> list[str]:
        """Falco lists may reference other lists; flatten them.

        package_mgmt_binaries is [rpm_binaries, deb_binaries, ...], so treating
        its items as literal strings silently breaks every rule that relies on
        it. This is the first trap this tool was written to catch.
        """
        if name in seen:
            raise ValueError(f"list cycle at {name!r}")
        out: list[str] = []
        for entry in self.lists[name]:
            if entry in self.lists:
                out.extend(self.resolve_list(entry, seen | {name}))
            else:
                out.append(entry)
        return out

    def expand_macros(self, condition: str, seen: frozenset[str] = frozenset()) -> str:
        out = condition
        for name, body in self.macros.items():
            if name in seen:
                continue
            pattern = re.compile(rf"(?<![A-Za-z0-9_.]){re.escape(name)}(?![A-Za-z0-9_])")
            if pattern.search(out):
                out = pattern.sub(f"({self.expand_macros(body, seen | {name})})", out)
        return out

    def rule(self, name: str) -> dict:
        if name not in self.rules:
            close = [r for r in self.rules if name.lower() in r.lower()]
            hint = f" did you mean {close[0]!r}?" if close else ""
            raise SystemExit(f"rule {name!r} not found in {self.path.name}.{hint}")
        return self.rules[name]


# --------------------------------------------------------------------------
# Tokenizer, parser, evaluator
# --------------------------------------------------------------------------

TOKEN_RE = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<string>"[^"]*"|'[^']*')
  | (?P<number>\d+)
  | (?P<op>!=|<=|>=|=|<|>)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<comma>,)
  | (?P<keyword>and|or|not|in|contains|startswith|endswith|exists|intersects|pmatch|glob)
  | (?P<field>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\[\d+\])?)*)
    """,
    re.VERBOSE,
)


def tokenize(text: str) -> list[tuple[str, str]]:
    tokens, pos = [], 0
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m:
            raise SyntaxError(f"cannot tokenize at {pos}: {text[pos:pos + 30]!r}")
        pos = m.end()
        if m.lastgroup != "space":
            tokens.append((m.lastgroup, m.group()))
    return tokens


def expand_lists(rs: Ruleset, tokens: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Inside `in (...)`, replace list names by their flattened items."""
    out: list[tuple[str, str]] = []
    i = 0
    while i < len(tokens):
        kind, val = tokens[i]
        out.append((kind, val))
        if kind == "keyword" and val == "in" and i + 1 < len(tokens) and tokens[i + 1][1] == "(":
            out.append(tokens[i + 1])
            i += 2
            depth, first = 1, True
            while i < len(tokens) and depth:
                k2, v2 = tokens[i]
                if v2 == "(":
                    depth += 1
                elif v2 == ")":
                    depth -= 1
                if depth and k2 == "field" and v2 in rs.lists:
                    if not first:
                        out.append(("comma", ","))
                    for j, item in enumerate(rs.resolve_list(v2)):
                        if j:
                            out.append(("comma", ","))
                        out.append(("string", item))
                    first = False
                elif depth:
                    out.append((k2, v2))
                    first = False
                i += 1
            if depth == 0:
                out.append(("rparen", ")"))
            continue
        i += 1
    return out


class Parser:
    def __init__(self, tokens):
        self.t, self.i = tokens, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, expect=None):
        kind, val = self.peek()
        if expect is not None and val != expect:
            raise SyntaxError(f"expected {expect!r}, got {val!r}")
        self.i += 1
        return kind, val

    def parse(self):
        node = self.or_expr()
        if self.i != len(self.t):
            raise SyntaxError(f"trailing tokens from {self.t[self.i:]}")
        return node

    def or_expr(self):
        node = self.and_expr()
        while self.peek()[1] == "or":
            self.take()
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.unary()
        while self.peek()[1] == "and":
            self.take()
            node = ("and", node, self.unary())
        return node

    def unary(self):
        if self.peek()[1] == "not":
            self.take()
            return ("not", self.unary())
        return self.primary()

    def primary(self):
        if self.peek()[1] == "(":
            self.take()
            node = self.or_expr()
            self.take(")")
            return node
        field = self.take()[1]
        _, op = self.take()
        if op == "exists":
            return ("exists", field)
        if op == "in":
            self.take("(")
            values = []
            while self.peek()[1] != ")":
                k, v = self.take()
                if k in ("string", "number", "field"):
                    values.append(v.strip("'\""))
            self.take(")")
            return ("in", field, values)
        _, v = self.take()
        return (op, field, v.strip("'\""))


def compile_condition(rs: Ruleset, condition: str):
    return Parser(expand_lists(rs, tokenize(rs.expand_macros(condition)))).parse()


def lookup(event: dict, field: str):
    cur = event
    for part in field.split("."):
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)(?:\[(\d+)\])?", part)
        name, idx = m.group(1), m.group(2)
        if not isinstance(cur, dict) or name not in cur:
            return None
        cur = cur[name]
        if idx is not None:
            if not isinstance(cur, dict):
                return None
            # JSON case files key ancestors as strings, Python events as ints
            cur = cur.get(int(idx), cur.get(str(idx)))
        if cur is None:
            return None
    return cur


def evaluate(node, event: dict) -> bool:
    op = node[0]
    if op == "and":
        return evaluate(node[1], event) and evaluate(node[2], event)
    if op == "or":
        return evaluate(node[1], event) or evaluate(node[2], event)
    if op == "not":
        return not evaluate(node[1], event)
    if op == "exists":
        return lookup(event, node[1]) is not None

    actual = lookup(event, node[1])
    if op == "in":
        return actual is not None and str(actual) in node[2]
    if actual is None:
        return False

    a, e = str(actual), str(node[2])
    return {
        "=": lambda: a == e,
        "!=": lambda: a != e,
        "<": lambda: a < e,
        ">": lambda: a > e,
        "<=": lambda: a <= e,
        ">=": lambda: a >= e,
        "contains": lambda: e in a,
        "startswith": lambda: a.startswith(e),
        "endswith": lambda: a.endswith(e),
        "intersects": lambda: bool(set(a.split(",")) & set(e.split(","))),
        "pmatch": lambda: bool(re.fullmatch(e.replace("*", ".*"), a)),
        "glob": lambda: bool(re.fullmatch(e.replace("*", ".*"), a)),
    }[op]()


# --------------------------------------------------------------------------
# Style guide: https://falco.org/docs/rules/style-guide/
# --------------------------------------------------------------------------

def evt_types(expanded_condition: str) -> set[str]:
    """Every evt.type value the expanded condition can match.

    The style guide only demands exe_flags for rules that involve nothing but
    spawned_process. "Schedule Cron Jobs" mixes open_write with spawned_process,
    so it must NOT carry exe_flags — a substring test on the raw condition
    would get that backwards.
    """
    found: set[str] = set()
    for m in re.finditer(
        r"evt\.type\s*(?:in\s*\(([^)]*)\)|=\s*([A-Za-z_][A-Za-z0-9_]*))",
        expanded_condition,
    ):
        if m.group(1):
            found |= {t.strip().strip("'\"") for t in m.group(1).split(",") if t.strip()}
        elif m.group(2):
            found.add(m.group(2))
    return found


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

    expanded = rs.expand_macros(cond)
    types = evt_types(expanded)
    if not types:
        hard.append("condition has no evt.type restriction (performance penalty)")
    else:
        head = rs.expand_macros(cond.split(" and ")[0].strip()).lstrip("( ").strip()
        if not (head.startswith("evt.type") or head.startswith("container")):
            hard.append("evt.type/container restriction must come first")

    if not output:
        hard.append("output is empty")
    else:
        if "|" not in output:
            hard.append("output must be '<message> | <fields>'")
        missing = [f for f in CORE_OUTPUT_FIELDS if f not in output]
        if missing:
            soft.append(f"output is missing core fields: {', '.join(missing)}")
        spawned_only = bool(types) and types <= {"execve", "execveat"}
        if spawned_only and "exe_flags=%evt.arg.flags" not in output:
            hard.append("spawned_process-only rule must output exe_flags=%evt.arg.flags")
        if not spawned_only and "exe_flags=%evt.arg.flags" in output:
            soft.append("exe_flags is only meaningful for spawned_process-only rules")

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
    ast = compile_condition(rs, rule["condition"])

    print(f"rule: {name}")
    print(f"condition: {' '.join(rule['condition'].split())}")
    print()
    failures = 0
    for case in spec["cases"]:
        got = evaluate(ast, case["event"])
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
        print(f"[PASS] checker detected all 5 injected defects")
    return 1 if undetected else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate and lint a Falco rule offline.")
    ap.add_argument("command", choices=["style", "check", "self-test"])
    ap.add_argument("--rules", required=True, type=Path,
                    help="path to a falcosecurity/rules YAML file, e.g. rules/falco-sandbox_rules.yaml")
    ap.add_argument("--rule", help="rule name (for style and self-test)")
    ap.add_argument("--cases", type=Path, help="JSON file of cases (for check)")
    a = ap.parse_args()

    if not a.rules.is_file():
        raise SystemExit(f"no such rules file: {a.rules}")
    rs = Ruleset(a.rules)

    if a.command == "check":
        if not a.cases:
            raise SystemExit("check needs --cases")
        return cmd_check(rs, a.cases)
    if not a.rule:
        raise SystemExit(f"{a.command} needs --rule")
    if a.command == "style":
        return cmd_style(rs, a.rule)
    return cmd_self_test(rs, a.rule)


if __name__ == "__main__":
    sys.exit(main())
