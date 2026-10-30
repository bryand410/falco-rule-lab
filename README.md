# falco-rule-lab

Evaluate and lint a [Falco](https://falco.org) rule without running Falco.

Falco's own validator (`build/checker/rules-check`) loads the ruleset into a real
Falco container. That is the right gate, but it needs Docker, it is slow, and it
only tells you whether the file *loads* — not whether the rule *discriminates*.

This tool answers the two questions that gate cannot:

1. **Does the rule actually fire where it should, and stay silent where it should not?**
2. **Does it comply with the [upstream style guide](https://falco.org/docs/rules/style-guide/)?**

It is a model of Falco's condition language, not Falco. It resolves macros and
lists the way the loader does, then evaluates the expanded condition against
events you describe yourself.

## Install

```sh
git clone https://github.com/falcosecurity/rules
pip install -r requirements.txt
```

## Usage

```sh
# 1. style guide compliance, plus a calibration line against the rest of the file
python falco_rule_lab.py style \
    --rules rules/falco-sandbox_rules.yaml \
    --rule "File Capabilities Set on Binary"

# 2. behavioural cases you write yourself
python falco_rule_lab.py check \
    --rules rules/falco-sandbox_rules.yaml \
    --cases cases/file-capabilities.json

# 3. prove the style checker can fail: it mutates a compliant rule five ways
python falco_rule_lab.py self-test \
    --rules rules/falco-sandbox_rules.yaml \
    --rule "File Capabilities Set on Binary"
```

`--rules` accepts any of the four rules files. `--rule` accepts any rule name in
that file, and suggests a correction when you mistype it.

### Writing cases

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
exercised: `{"2": "apt-get", "3": "bash"}`.

## What it caught

The tool was written to validate one rule
([falcosecurity/rules#397](https://github.com/falcosecurity/rules/pull/397)).
It found four things, and two of them were bugs in itself — which is the point.

| Finding | Where |
| --- | --- |
| `package_mgmt_binaries` contains **references to other lists** (`rpm_binaries`, `deb_binaries`, …) that Falco flattens recursively. Read as literal strings, every package-manager exclusion silently stopped working. | tool |
| The tokenizer matched `in`, `and` and `not` as field names, because the field pattern was tried first. No `in (...)` was ever parsed. | tool |
| A rule whose only event types are `execve`/`execveat` must carry `exe_flags=%evt.arg.flags`. The new rule did not; the 13 sibling rules did. | rule |
| "Schedule Cron Jobs" mixes `open_write` with `spawned_process`, so it must **not** carry `exe_flags`. A substring test on the raw condition gets this exactly backwards. | tool |

The self-test exists because a gate that never fails is decoration. It mutates a
compliant rule five ways and fails if any mutation goes unnoticed.

## Calibration

Run `style` against the upstream ruleset and it flags almost nothing, which is
what a well-calibrated checker should do:

| File | Rules failing a hard check |
| --- | --- |
| `falco_rules.yaml` | 0 / 24 |
| `falco-sandbox_rules.yaml` | 2 / 39 |
| `falco-incubating_rules.yaml` | 2 / 31 |

The four flagged rules are the same pattern: `Launch Disallowed Container`,
`Launch Privileged Container`, `Launch Sensitive Mount Container` and
`Launch Excessively Capable Container` expand to `spawned_process and
proc.vpid=1 and container` — spawned-process-only, but without `exe_flags`.
They predate the requirement. The check is left strict rather than special-cased
for them.

## Limits

- It models the **condition language**, not the engine. Field names, event
  schemas and `evt.arg` semantics are not validated; a typo in a field name
  evaluates to `None` and reads as "silent".
- Macro and list expansion is textual. It works on the upstream ruleset; it is
  not guaranteed for macros whose names appear inside quoted strings.
- Operators are implemented as a subset: `=`, `!=`, `<`, `>`, `<=`, `>=`, `in`,
  `contains`, `startswith`, `endswith`, `exists`, `intersects`, `pmatch`, `glob`.
  `exists` is approximated as "the field is present".
- Passing here does not mean the rule loads. Always run
  `build/checker/rules-check validate` before opening a pull request.

## License

MIT.
