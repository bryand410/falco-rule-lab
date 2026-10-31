"""casegen — build a behavioural case file from a rule, then prove it holds.

Hand-written case files have a failure mode nobody talks about: they encode the
author's belief about the rule, not the rule. The author writes the cases that
pass. A reviewer cannot tell the difference between "the rule discriminates" and
"the cases were chosen to agree with the rule".

This module inverts that. It reads the condition, constructs an event that
satisfies it by assignment, then derives the negative cases from the rule's own
exclusions. Every case is evaluated against the rule before it is emitted: a
case that does not hold is dropped and reported, never written.

The generator can therefore fail in public. When it cannot invert a clause it
says which clause, instead of silently producing a case file that looks
complete.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Iterator

from engine import (
    And,
    Bool,
    Compare,
    ConditionError,
    Exists,
    Field,
    Literal,
    Node,
    Not,
    Or,
    Ruleset,
    SetOp,
    Transform,
)

MAX_PER_EXCLUSION = 6

STRING_OPS = {"contains", "icontains", "startswith", "endswith", "glob", "bcontains"}


def _glob_seed(pattern: str) -> str:
    """A concrete string that matches a glob pattern.

    Wildcards are filled with a single character, never with '/', because a
    Falco glob does not cross a path separator.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch in "*?":
            out.append("x")
            i += 1
        elif ch == "[":
            end = pattern.find("]", i)
            if end == -1:
                out.append(ch)
                i += 1
            else:
                body = pattern[i + 1:end].lstrip("!^")
                out.append(body[:1] or "x")
                i = end + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _seed(op: str, want: Any) -> Any:
    """A field value that satisfies `field <op> want`."""
    if op == "glob":
        return _glob_seed(str(want))
    if op == "bcontains":
        # bcontains takes a hex string and tests raw bytes. The marker survives
        # a JSON round-trip; engine._as_bytes decodes it back.
        return {"$bytes": str(want)}
    return str(want)


# --------------------------------------------------------------------------
# Event construction
# --------------------------------------------------------------------------

_PART = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:\[(\d+)\])?")


def _set(event: dict, path: str, value: Any) -> bool:
    """Assign a dotted Falco field, creating the intermediate dicts.

    A scalar may already sit where a subtree is needed (`proc.aname` set by one
    clause, `proc.aname[2]` by another). Overwrite it rather than raising: the
    generator's job is to build an event, and verification catches the case
    where the two assignments contradict each other.
    """
    parts = path.split(".")
    cur: Any = event
    for i, part in enumerate(parts):
        m = _PART.fullmatch(part)
        if not m or not isinstance(cur, dict):
            return False
        name, idx = m.group(1), m.group(2)
        if i == len(parts) - 1:
            if idx is None:
                cur[name] = value
            else:
                branch = cur.get(name)
                if not isinstance(branch, dict):
                    branch = {}
                    cur[name] = branch
                branch[int(idx)] = value
            return True
        branch = cur.get(name)
        if not isinstance(branch, dict):
            branch = {}
            cur[name] = branch
        if idx is not None:
            slot = branch.get(int(idx))
            if not isinstance(slot, dict):
                slot = {}
                branch[int(idx)] = slot
            branch = slot
        cur = branch
    return False


def _simple_path(op: Any) -> str | None:
    """The field an operand writes to, or None if it is not invertible.

    `basename(proc.exepath) = setcap` cannot be satisfied by assignment: the
    transformer runs forward only. Reporting that honestly beats guessing.
    """
    return op.path if isinstance(op, Field) else None


def _satisfy(node: Node, event: dict, log: list[str] | None = None) -> bool:
    """Make `node` true by assigning fields. False if a clause is not invertible."""
    log = log if log is not None else []

    if isinstance(node, Bool):
        return node._v
    if isinstance(node, And):
        return _satisfy(node.left, event, log) and _satisfy(node.right, event, log)
    if isinstance(node, Or):
        # Try the left branch; fall back to the right one on a clean copy.
        snapshot = copy.deepcopy(event)
        depth = len(log)
        if _satisfy(node.left, event, log):
            return True
        event.clear()
        event.update(snapshot)
        del log[depth:]
        return _satisfy(node.right, event, log)
    if isinstance(node, Not):
        # A negation is satisfied when the event already fails its operand —
        # usually because the fields it tests were never set. Nothing to assign.
        return not node.operand.evaluate(event)
    if isinstance(node, Compare):
        if node.evaluate(event):
            # Never overwrite a value that already satisfies this clause:
            # `proc.name in (nginx, ...)` followed by `proc.name != sshd` must
            # keep nginx, not replace it with a string invented for the `!=`.
            return True
        path = _simple_path(node.left)
        if path is None or not isinstance(node.right, Literal):
            return False
        want = node.right.raw
        if node.op in ("=", "=="):
            ok = _set(event, path, want)
        elif node.op == "!=":
            # Omission evaluates False, so `!=` needs a real, different value.
            ok = _set(event, path, f"{want}-other")
        elif node.op in STRING_OPS:
            ok = _set(event, path, _seed(node.op, want))
        elif isinstance(want, (int, float)):
            step = 1 if node.op in (">", ">=") else -1
            ok = _set(event, path, want + step)
        else:
            return False
        if ok:
            log.append(f"{path}={event_value(event, path)}")
        return ok
    if isinstance(node, SetOp):
        path = _simple_path(node.left)
        if path is None or not node.values:
            return False
        ok = _set(event, path, node.values[0])
        if ok:
            log.append(f"{path}={node.values[0]}")
        return ok
    if isinstance(node, Exists):
        path = _simple_path(node.left)
        if path is None:
            return False
        log.append(f"{path} present")
        return _set(event, path, "present")
    return False


def event_value(event: dict, path: str) -> Any:
    cur: Any = event
    for part in path.split("."):
        m = _PART.fullmatch(part)
        if not m:
            return "?"
        cur = cur.get(m.group(1)) if isinstance(cur, dict) else None
        if m.group(2) is not None:
            cur = cur.get(int(m.group(2))) if isinstance(cur, dict) else None
        if cur is None:
            return "?"
    return cur


# --------------------------------------------------------------------------
# Reading the condition
# --------------------------------------------------------------------------

def _conjuncts(node: Node) -> Iterator[tuple[bool, Node]]:
    """Top-level `and` terms, each flagged negated or not."""
    if isinstance(node, And):
        yield from _conjuncts(node.left)
        yield from _conjuncts(node.right)
    elif isinstance(node, Not):
        yield True, node.operand
    else:
        yield False, node


def _describe(node: Node, limit: int = 120) -> str:
    if isinstance(node, Bool):
        text = "true" if node._v else "false"
    elif isinstance(node, And):
        text = f"{_describe(node.left)} and {_describe(node.right)}"
    elif isinstance(node, Or):
        text = f"{_describe(node.left)} or {_describe(node.right)}"
    elif isinstance(node, Not):
        text = f"not ({_describe(node.operand)})"
    elif isinstance(node, Compare):
        text = f"{_operand_text(node.left)} {node.op} {_operand_text(node.right)}"
    elif isinstance(node, SetOp):
        text = f"{_operand_text(node.left)} {node.op} ({', '.join(str(v) for v in node.values)})"
    elif isinstance(node, Exists):
        text = f"{_operand_text(node.left)} exists"
    else:
        text = "?"
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _operand_text(op: Any) -> str:
    if isinstance(op, Field):
        return op.path
    if isinstance(op, Literal):
        return repr(op.raw)
    if isinstance(op, Transform):
        return f"{op.fn}({_operand_text(op.inner)})"
    return "?"


def _mangle(value: Any) -> Any:
    """A nearby value that should not match the same clause."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    return f"{value}-near-miss"


MERGEABLE = {"=", "==", "contains", "icontains", "startswith", "endswith", "bcontains"}


def _atoms(node: Node, out: list[Node]) -> None:
    """Atomic clauses reachable without crossing a negation.

    Branches of an `or` are all collected on purpose: a value that satisfies
    every branch satisfies at least one, so over-collecting is safe there.
    """
    if isinstance(node, (And, Or)):
        _atoms(node.left, out)
        _atoms(node.right, out)
    elif not isinstance(node, Not):
        out.append(node)


def _merge_fields(node: Node, base: dict) -> None:
    """Re-solve fields that several clauses constrain at once.

    Assigning each clause independently loses: `proc.args contains -s` and
    `proc.args contains " "` are both true of "-s ", and of nothing either
    clause would have chosen alone.
    """
    atoms: list[Node] = []
    _atoms(node, atoms)
    groups: dict[str, list[Compare]] = {}
    for atom in atoms:
        if (isinstance(atom, Compare) and isinstance(atom.left, Field)
                and isinstance(atom.right, Literal) and atom.op in MERGEABLE):
            groups.setdefault(atom.left.path, []).append(atom)

    for path, clauses in groups.items():
        if any(c.op == "bcontains" for c in clauses):
            # Raw bytes were seeded by _satisfy; merging them as text would
            # corrupt the buffer.
            continue
        equal = {str(c.right.raw) for c in clauses if c.op in ("=", "==")}
        if len(equal) > 1:
            continue  # `x = a or x = b`: no single value can satisfy both.
        prefix = suffix = ""
        middle: list[str] = []
        for clause in clauses:
            value = str(clause.right.raw)
            if clause.op == "startswith":
                prefix = value if len(value) > len(prefix) else prefix
            elif clause.op == "endswith":
                suffix = value if len(value) > len(suffix) else suffix
            elif clause.op == "bcontains":
                value = bytes.fromhex(value).decode("utf-8", "replace")
                if value not in middle:
                    middle.append(value)
            elif value not in middle:
                middle.append(value)
        merged = prefix + "".join(middle) + suffix
        if not merged:
            continue
        for atom in atoms:
            if (isinstance(atom, Compare) and atom.op == "!="
                    and isinstance(atom.left, Field) and atom.left.path == path
                    and isinstance(atom.right, Literal)
                    and merged == str(atom.right.raw)):
                merged += "x"
        _set(base, path, merged)


def _without(node: Node, clause: Node) -> Node | None:
    """The condition with one top-level conjunct removed.

    None when the top level is not a plain `and` chain: rebuilding an arbitrary
    boolean expression minus one term is not sound, and guessing would be worse
    than declining.
    """
    if not isinstance(node, And):
        return None
    keep: list[Node] = []
    dropped = False
    for negated, term in _conjuncts(node):
        if not dropped and term is clause:
            dropped = True
            continue
        keep.append(Not(term) if negated else term)
    if not dropped or not keep:
        return None
    out = keep[0]
    for term in keep[1:]:
        out = And(out, term)
    return out


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------

def generate(rs: Ruleset, name: str) -> tuple[list[dict], list[str]]:
    """(verified cases, notes). Notes explain anything that was not generated."""
    rule = rs.rule(name)
    node = rs.compile(rule["condition"])
    notes: list[str] = []

    base: dict = {}
    log: list[str] = []
    unsupported: list[str] = []
    for negated, clause in _conjuncts(node):
        if negated:
            continue
        if not _satisfy(clause, base, log):
            text = _describe(clause, 80)
            if isinstance(clause, SetOp) and not clause.values:
                text += " [empty list: the clause can never match, so the rule is disabled until it is populated]"
            unsupported.append(text)

    if unsupported:
        notes.append(
            "no satisfying event could be built; clause(s) not invertible by "
            "assignment: " + "; ".join(unsupported)
        )
        return [], notes
    if not node.evaluate(base):
        _merge_fields(node, base)
    if not node.evaluate(base):
        blockers = [_describe(c, 90) for negated, c in _conjuncts(node)
                    if negated and c.evaluate(base)]
        if blockers:
            notes.append(
                "every positive clause is satisfied, but the event is excluded "
                "by " + "; ".join(blockers) + ". If that exclusion is the "
                "negation of a positive requirement, the rule cannot fire as "
                "written."
            )
        else:
            notes.append(
                "generator built an event the rule does not fire on. This is a "
                "bug in the generator, not a finding about the rule."
            )
        return [], notes

    cases: list[dict] = [{
        "label": "positive: " + (", ".join(log) or "always true"),
        "expect": "fires",
        "why": "constructed by satisfying every positive clause",
        "event": base,
    }]

    # Negative cases, derived from the rule's own exclusions.
    #
    # A silent case only proves something if deleting the exclusion would make
    # the rule fire. Otherwise the event is silent for some other reason and the
    # case passes even when the exclusion does nothing at all.
    vacuous: dict[int, tuple[Node, list[str]]] = {}

    def admit(event: dict, clause: Node, label: str, why: str) -> bool:
        rest = _without(node, clause)
        if rest is not None and not rest.evaluate(event):
            vacuous.setdefault(id(clause), (clause, []))[1].append(label)
            return False
        cases.append({"label": label, "expect": "silent", "why": why, "event": event})
        return True

    for negated, clause in _conjuncts(node):
        if not negated:
            continue
        if isinstance(clause, SetOp) and clause.op in ("in", "pmatch"):
            path = _simple_path(clause.left)
            if path is None:
                notes.append(f"exclusion not invertible: {_describe(clause, 80)}")
                continue
            emitted = 0
            for value in clause.values:
                if emitted >= MAX_PER_EXCLUSION:
                    notes.append(
                        f"exclusion capped at {MAX_PER_EXCLUSION} of "
                        f"{len(clause.values)} values: {_describe(clause, 80)}"
                    )
                    break
                event = copy.deepcopy(base)
                _set(event, path, value)
                if admit(event, clause, f"excluded: {path}={value}",
                         f"{path} is on the rule's exclusion list"):
                    emitted += 1
            continue

        event = copy.deepcopy(base)
        if _satisfy(clause, event):
            admit(event, clause, "excluded: " + _describe(clause, 90),
                  "satisfies a negated clause, so the rule must stay quiet")
        else:
            notes.append(f"exclusion not invertible: {_describe(clause, 80)}")

    for clause, labels in vacuous.values():
        notes.append(
            f"exclusion {_describe(clause, 70)!r}: {len(labels)} silent case(s) "
            f"dropped as vacuous — the rule stays silent with this exclusion "
            f"removed, so either the clause is unreachable here or another "
            f"clause already covers these events"
        )

    # Near-miss cases: the positive clauses must match exactly.
    for negated, clause in _conjuncts(node):
        if negated:
            continue
        if (isinstance(clause, Compare) and clause.op in ("=", "==")
                and isinstance(clause.left, Field) and isinstance(clause.right, Literal)):
            event = copy.deepcopy(base)
            other = _mangle(clause.right.raw)
            _set(event, clause.left.path, other)
            cases.append({
                "label": f"near miss: {clause.left.path}={other}",
                "expect": "silent",
                "why": f"one character off the value {clause.left.path} must match",
                "event": event,
            })
        elif isinstance(clause, SetOp) and clause.op == "in" and len(clause.values) > 1:
            event = copy.deepcopy(base)
            path = _simple_path(clause.left)
            if path:
                _set(event, path, clause.values[1])
                cases.append({
                    "label": f"second listed value: {path}={clause.values[1]}",
                    "expect": "fires",
                    "why": "every value in an `in` list must be accepted, not just the first",
                    "event": event,
                })

    # The event-type gate: if the rule fires on execve, it must not fire on open.
    evt = event_value(base, "evt.type")
    if evt in ("execve", "execveat"):
        event = copy.deepcopy(base)
        _set(event, "evt.type", "open")
        cases.append({
            "label": "wrong event type: evt.type=open",
            "expect": "silent",
            "why": "the event-type gate must reject non-exec events",
            "event": event,
        })

    return _verify(node, cases, notes), notes


def _verify(node: Node, cases: list[dict], notes: list[str]) -> list[dict]:
    """Drop any case whose expectation the rule does not actually meet."""
    kept: list[dict] = []
    for case in cases:
        got = node.evaluate(case["event"])
        want = case["expect"] == "fires"
        if got == want:
            kept.append(case)
        else:
            notes.append(
                f"dropped {case['label']!r}: the rule answered "
                f"{'fires' if got else 'silent'}, the case expected "
                f"{case['expect']}"
            )
    return kept


def to_case_file(rule_name: str, cases: list[dict], notes: list[str]) -> dict:
    return {
        "rule": rule_name,
        "generated_by": "casegen",
        "note": "regenerate with: falco_rule_lab.py casegen --rules FILE --rule NAME",
        "uncovered": notes,
        "cases": cases,
    }
