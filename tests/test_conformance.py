"""Conformance against the Falco maintainers' own unit tests.

The other two suites check this implementation against itself: they pin bugs
that were found, but they cannot show that the semantics match Falco's. This
one can, because the expectations are transcribed from falcosecurity/libs,
userspace/libsinsp/test/ — the files the maintainers use to define what each
operator means.

tests/conformance.json carries the assertions and names the file each group
came from. Every one of them failed to be invented here: if a group disagrees,
either this engine is wrong or the transcription is, and both are worth
knowing.

Run with: python tests/test_conformance.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine import ConditionError, Parser, tokenize  # noqa: E402

DATA = Path(__file__).resolve().parent / "conformance.json"

RESULTS: list[tuple[str, bool, str]] = []


def check(label: str, got, want) -> None:
    RESULTS.append((label, got == want, f"got={got!r} want={want!r}"))


def evaluate(expr: str, event: dict) -> bool:
    return Parser(tokenize(expr), {}, {}).parse().evaluate(event)


def main() -> int:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    upstream = data["upstream"]
    total_assertions = 0

    for group in data["groups"]:
        where = f"{upstream['path']}/{group['source']}"
        for a in group["assertions"]:
            total_assertions += 1
            label = f"{group['case']}: {a['expr']}"
            try:
                got = evaluate(a["expr"], group["event"])
            except ConditionError as e:
                RESULTS.append((label, False, f"did not parse: {e}"))
                continue
            check(label, got, a["expect"])

        # A malformed byte literal must be rejected when the condition is
        # compiled, as Falco does, not silently accepted until an event
        # arrives. filter_op_bytebuf.ut.cpp asserts filter_compiles() is false.
        for expr in group.get("must_not_compile", []):
            total_assertions += 1
            try:
                evaluate(expr, group["event"])
            except ConditionError:
                RESULTS.append((f"{group['case']}: rejects {expr!r}", True,
                                "rejected as expected"))
            else:
                RESULTS.append((f"{group['case']}: rejects {expr!r}", False,
                                "compiled, but upstream rejects it"))

    width = max(len(label) for label, _, _ in RESULTS)
    failed = 0
    for label, ok, detail in RESULTS:
        if not ok:
            failed += 1
            print(f"[FAIL] {label:<{width}}  {detail}")

    sources = sorted({g["source"] for g in data["groups"]})
    print(f"\n{len(RESULTS) - failed}/{total_assertions} upstream assertions hold")
    print(f"transcribed from {upstream['repo']}/{upstream['path']}: "
          f"{', '.join(sources)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
