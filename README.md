# falco-rule-lab

[![test](https://github.com/bryand410/falco-rule-lab/actions/workflows/test.yml/badge.svg)](https://github.com/bryand410/falco-rule-lab/actions/workflows/test.yml)

Evaluate and lint a [Falco](https://falco.org) rule without running Falco.

Falco's own validator (`build/checker/rules-check`) loads the ruleset into a real
Falco container. That is the right gate, but it needs Docker, it is slow, and it
only tells you whether the file *loads* — not whether the rule *discriminates*.

This tool answers three questions that gate cannot:

1. **Does the condition parse at all**, across every macro and rule in a file?
2. **Does the rule fire where it should, and stay silent where it should not?**
3. **Does it comply with the [upstream style guide](https://falco.org/docs/rules/style-guide/)?**

It is a model of Falco's condition language, not Falco. Conditions are parsed
into an AST, macros are resolved on that AST the way the loader does, and the
result is evaluated against events you describe — or events the tool builds for
you.

## Install

```sh
git clone https://github.com/bryand410/falco-rule-lab
cd falco-rule-lab
git clone https://github.com/falcosecurity/rules rules
pip install -r requirements.txt
```

The upstream ruleset goes in `rules/`, next to the tool. To keep it elsewhere,
set `FALCO_RULES_DIR`.

## Usage

```sh
# 1. does every macro and rule in the file parse?
python falco_rule_lab.py parse --rules rules/falco-sandbox_rules.yaml

# 2. style guide compliance, plus a calibration line against the rest of the file
python falco_rule_lab.py style \
    --rules rules/falco-sandbox_rules.yaml \
    --rule "File Capabilities Set on Binary"

# 3. behavioural cases: hand-written, or generated (see below)
python falco_rule_lab.py check \
    --rules rules/falco-sandbox_rules.yaml \
    --cases cases/file-capabilities.json

# 4. generate cases from the rule itself, then verify them against it
python falco_rule_lab.py casegen \
    --rules rules/falco-sandbox_rules.yaml \
    --rule "File Capabilities Set on Binary" \
    --out cases/file-capabilities.generated.json

# 5. prove the style checker can fail: it mutates a compliant rule five ways
python falco_rule_lab.py self-test \
    --rules rules/falco-sandbox_rules.yaml \
    --rule "File Capabilities Set on Binary"
```

`--rules` accepts any of the rules files. `--rule` accepts any rule name in that
file, and suggests a correction when you mistype it.

## casegen: cases as evidence, not opinion

A hand-written case file has a failure mode nobody mentions: it encodes what the
author *believes* about the rule. The author writes the cases that pass, and a
reviewer cannot tell "the rule discriminates" from "the cases were chosen to
agree with the rule".

`casegen` inverts that. It reads the condition, builds an event that satisfies it
by assignment, then derives the negative cases from the rule's own exclusions.
**Every case is evaluated against the rule before it is written.** A case that
does not hold is dropped and reported, never emitted.

Two things follow, and they are the reason the command exists:

- **A silent case must be earned.** It is only kept if deleting the exclusion
  would make the rule fire. Otherwise the event is silent for some other reason,
  and the case would pass even if the exclusion did nothing. Cases of that kind
  are reported as *vacuous*.
- **The generator can fail in public.** When it cannot invert a clause it names
  the clause. When it builds an event the rule does not fire on, it says so.

Across the upstream ruleset it builds a verified positive case for **95 of 97
rules**, 777 cases in total. The two it declines are both honest:

| Rule | Why |
| --- | --- |
| `Launch Disallowed Container` | `allowed_containers` is `(container.id exists)`, the exact negation of what `container_started` requires. As shipped the rule cannot fire; the comment above the macro says to override it. |
| `Network Connection outside Local Subnet` | `namespace_scope_network_only_subnet` is empty, so `k8s.ns.name in ()` matches nothing. Disabled until populated, by design. |

### Writing cases by hand

A case file is plain JSON. `expect` is `fires` or `silent`; `event` is the
minimum of Falco's event shape that the condition touches.

```json
{
  "rule": "File Capabilities Set on Binary",
  "cases": [
    {
      "label": "root runs setcap on a binary on the host",
      "expect": "fires",
      "why": "the case the rule exists for",
      "event": {
        "evt": {"type": "execve", "dir": "<", "num": 424242},
        "proc": {"name": "setcap", "pname": "bash", "aname": {}}
      }
    }
  ]
}
```

`proc.aname` holds the ancestor chain, so `package_mgmt_ancestor_procs` can be
exercised: `{"2": "apt-get", "3": "bash"}`. Byte-buffer fields (`bcontains`, such
as `evt.buffer`) are written as `{"$bytes": "cafebabe"}`.

The curated file and the generated one are complementary. `casegen` proves the
mechanical part; the curated file adds what no generator can know — an attacker
using `chmod u+s` instead, `setpriv --inh-caps`, a renamed `setcap`, the known
noise from image builders.

## What it caught

The tool was written to validate one rule
([falcosecurity/rules#397](https://github.com/falcosecurity/rules/pull/397)).
Every entry below is a defect it found, and most were defects in itself.

| Finding | Where |
| --- | --- |
| `not package_mgmt_procs` is **unreachable** in that rule: the macro is `proc.name in (package_mgmt_binaries)`, the rule already requires `proc.name = setcap`, and `setcap` is not in the list. All 48 candidate silent cases were silent with the clause deleted. | rule |
| `package_mgmt_binaries` contains **references to other lists** (`rpm_binaries`, `deb_binaries`, …) that Falco flattens recursively. Read as literal strings, every package-manager exclusion silently stopped working. | tool |
| The tokenizer matched `in`, `and` and `not` as field names, because the field pattern was tried first. No `in (...)` was ever parsed. | tool |
| A rule whose only event types are `execve`/`execveat` must carry `exe_flags=%evt.arg.flags`. The new rule did not; the 13 sibling rules did. | rule |
| "Schedule Cron Jobs" mixes `open_write` with `spawned_process`, so it must **not** carry `exe_flags`. A substring test on the raw condition gets this exactly backwards. | tool |
| Replacing the condition text before parsing turned `proc.cmdline contains "container"` into `proc.cmdline contains "((container.id != host))"`. Macros must be resolved on the AST, after tokenizing. | tool |

The first entry is why `casegen` checks for vacuity. The last is why `engine.py`
is a grammar instead of a `str.replace`.

The self-test exists for the same reason: a gate that never fails is decoration.
It mutates a compliant rule five ways and fails if any mutation goes unnoticed.

## Calibration

Run `style` against the upstream ruleset and it flags nothing, which is what a
well-calibrated checker should do:

| File | Rules failing a hard check |
| --- | --- |
| `falco_rules.yaml` | 0 / 25 |
| `falco-sandbox_rules.yaml` | 0 / 40 |
| `falco-incubating_rules.yaml` | 0 / 32 |

An earlier version flagged four container-launch rules for omitting `exe_flags`.
They reach `execve`-only through the `container_started` macro, and all four are
merged. The guide says "rules involving **only** `spawned_process`", so the hard
check now applies only when the author wrote the exec restriction; expansion-only
cases are reported as a note. A checker that fails merged upstream code is a
checker nobody runs.

## Limits

- It models the **condition language**, not the engine. Field names and
  `evt.arg` semantics are not validated; a typo in a field name evaluates to
  absent and reads as "silent".
- `casegen` inverts by assignment. Clauses it cannot invert — `basename(x) = y`,
  field-to-field comparisons, a value inside an empty list — are reported, not
  guessed.
- Transformers are supported for evaluation (`basename`, `tolower`, `toupper`,
  `len`) but not for inversion.
- Passing here does not mean the rule loads. Always run
  `build/checker/rules-check validate` before opening a pull request.

## Tests

```sh
python tests/test_engine.py    # the condition language
python tests/test_casegen.py   # the generator, and its coverage of upstream
```

## License

MIT.
