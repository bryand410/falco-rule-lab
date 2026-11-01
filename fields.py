"""Field-name validation for a Falco condition.

A field that Falco does not know does not raise. It evaluates as absent, every
comparison against it is false, and the rule reads as "this event is not
interesting" — which is exactly what a working rule reads as on the events it
is not meant to catch. A misspelled field is therefore invisible in review, in
production, and in the upstream CI, which checks that a rules file loads rather
than that the fields in it exist.

The names come from the reference table the Falco project publishes. See
data/fields.txt for the source and tools/update-fields.py to regenerate it.
"""

from __future__ import annotations

import difflib
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"


def _read(path: Path) -> tuple[str, ...]:
    lines = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    return tuple(line for line in lines if line and not line.startswith("#"))


@lru_cache(maxsize=1)
def _tables() -> tuple[frozenset[str], tuple[str, ...]]:
    fields = frozenset(_read(DATA / "fields.txt"))
    # Longest first, so `container.mount.dest` is tried before `container.mount`.
    dynamic = tuple(sorted(_read(DATA / "fields-dynamic.txt"), key=len, reverse=True))
    return fields, dynamic


def documented() -> frozenset[str]:
    return _tables()[0]


def check(path: str) -> str | None:
    """None when `path` names something Falco can read, else a finding.

    Three forms are accepted: a documented name; a documented name with a
    bracket argument, which every list field takes (`proc.aname[2]`,
    `container.mount.dest[/etc]`); and a documented name that the documentation
    itself says may be extended (`evt.arg.flags`, `container.label.app`).
    """
    fields, dynamic = _tables()
    if path in fields:
        return None
    base = path.split("[", 1)[0]
    if base != path and base in fields:
        return None
    for name in dynamic:
        if path.startswith(name + ".") or path.startswith(name + "["):
            return None
    return "unknown field " + repr(path) + _suggest(path)


def _suggest(path: str) -> str:
    fields, _ = _tables()
    close = difflib.get_close_matches(path, fields, n=1, cutoff=0.7)
    return f"; did you mean {close[0]!r}?" if close else ""
