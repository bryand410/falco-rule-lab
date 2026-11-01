#!/usr/bin/env python3
"""Regenerate data/fields.txt and data/fields-dynamic.txt.

The reference table Falco publishes is generated from the libs source, so it is
the closest thing to an authoritative list of field names without running Falco.
This script fetches it and rewrites the two data files.

    python tools/update-fields.py            # rewrite
    python tools/update-fields.py --check    # fail if the files are stale

--check is the mode worth running in CI once the list is pinned: it turns "the
field list is out of date" into a failing build rather than a silent drift,
which matters because a stale list produces false positives on new fields.
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
import urllib.request
from pathlib import Path

SOURCE = ("https://raw.githubusercontent.com/falcosecurity/falco-website/master/"
          "content/en/docs/reference/rules/supported-fields/supported-fields.md")
PAGE = "https://falco.org/docs/reference/rules/supported-fields/"
DATA = Path(__file__).resolve().parent.parent / "data"

FIELDS_HEADER = """\
# Field names accepted by Falco, one per line.
# Generated from the reference table the Falco project publishes:
#   {page}
#   source: falcosecurity/falco-website content/en/docs/reference/rules/
#           supported-fields/supported-fields.md
# retrieved {date}
#
# Regenerate with tools/update-fields.py. Do not edit by hand: a name
# invented here would make the checker accept a field Falco rejects.
"""

DYNAMIC_HEADER = """\
# Documented names that a condition may extend, one per line.
#
# evt.arg.flags is valid although evt.arg.flags is not itself a documented
# name; the documentation for evt.arg says the argument is named by the
# syscall. The list is derived from the reference table: a name qualifies
# when its own description shows an extension of itself, plus every
# '*.label' field, which takes the label key as a suffix.
"""


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        return response.read().decode("utf-8")


def parse(text: str) -> tuple[list[str], list[str]]:
    names = sorted(set(re.findall(r"^`([A-Za-z0-9_.]+)`\s*\|", text, re.M)))
    rows = re.findall(r"^`([A-Za-z0-9_.]+)`\s*\|\s*([A-Z]+)\s*\|(.*)$", text, re.M)
    dynamic = {n for n, _, desc in rows if re.search(re.escape(n) + r"(\[|\.\w)", desc)}
    dynamic |= {n for n in names if n.endswith(".label")}
    return names, sorted(dynamic)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the checked-in files differ from upstream")
    a = ap.parse_args()

    text = fetch(SOURCE)
    names, dynamic = parse(text)
    if not names:
        print("the reference table parsed to nothing; upstream format changed?")
        return 1

    fields_body = "\n".join(names) + "\n"
    dynamic_body = DYNAMIC_HEADER + "\n".join(dynamic) + "\n"

    if a.check:
        current = (DATA / "fields.txt").read_text(encoding="utf-8")
        # Compare the names only: the header carries a retrieval date that is
        # expected to change whenever the file is regenerated.
        current_names = [ln for ln in current.splitlines()
                         if ln and not ln.startswith("#")]
        current_dyn = [ln for ln in (DATA / "fields-dynamic.txt")
                       .read_text(encoding="utf-8").splitlines()
                       if ln and not ln.startswith("#")]
        stale = []
        if current_names != names:
            added = sorted(set(names) - set(current_names))
            gone = sorted(set(current_names) - set(names))
            stale.append(f"fields.txt: +{added} -{gone}")
        if current_dyn != dynamic:
            stale.append(f"fields-dynamic.txt: {dynamic}")
        for line in stale:
            print(f"[STALE] {line}")
        return 1 if stale else 0

    header = FIELDS_HEADER.format(page=PAGE, date=datetime.date.today().isoformat())
    (DATA / "fields.txt").write_text(header + fields_body, encoding="utf-8")
    (DATA / "fields-dynamic.txt").write_text(dynamic_body, encoding="utf-8")
    print(f"{len(names)} fields, {len(dynamic)} dynamic bases written to {DATA}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
