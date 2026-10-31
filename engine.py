"""A parser and evaluator for the Falco condition language.

The previous evaluator in this repository worked on text: it substituted macros
with a regular expression over the raw condition, then tokenised what was left.
That approach has two defects that no amount of patching fixes.

  * A macro name appearing inside a quoted string was substituted. The condition
    `proc.cmdline contains "container"` became
    `proc.cmdline contains "((container.id != host))"`.
  * The keyword alternation listed `in` before `intersects`, so `intersects`
    tokenised as `in` + `tersects`.

This module treats the condition as a grammar instead. Macros and lists are
resolved after parsing, on AST nodes, so a name inside a string is a STRING
token and can never be mistaken for a reference. Keywords are classified after
tokenising, so a longer name can never be shadowed by a shorter prefix.

Scope is set by what the upstream ruleset actually uses: `=`, `!=`, `<`, `<=`,
`>`, `>=`, `contains`, `icontains`, `startswith`, `endswith`, `glob`,
`bcontains`, `in`, `intersects`, `pmatch`, `exists`, and the `basename`,
`tolower`, `toupper` and `len` transformers. `regex`, the `anyof`/`allof`/`oneof`
modifiers and `val()` are not implemented; the parser rejects them explicitly
rather than silently misreading them.

    >>> rs = Ruleset(path)
    >>> ast = rs.compile(rule["condition"])
    >>> ast.evaluate(event)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

MISSING = object()

COMPARATORS = {"=", "==", "!=", "<", "<=", ">", ">="}
STRING_OPS = {"contains", "icontains", "startswith", "endswith", "glob", "bcontains"}
SET_OPS = {"in", "intersects", "pmatch"}
TRANSFORMERS = {"basename", "tolower", "toupper", "len"}
KEYWORDS = {"and", "or", "not", "exists"} | STRING_OPS | SET_OPS
UNSUPPORTED = {"regex", "anyof", "allof", "oneof", "val"}


# --------------------------------------------------------------------------
# Lexer
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Token:
    kind: str          # word | string | number | op | lparen | rparen | comma
    value: str
    pos: int

    def __repr__(self) -> str:
        return f"{self.kind}({self.value!r})"


# A bareword runs until whitespace, punctuation, or the start of an operator.
# It must be allowed to contain '/', '.', '-', '[' and ']': paths such as
# /var/run and field references such as proc.aname[2] are barewords in Falco.
_STOP = set(" \t\r\n(),=!<>")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'"}


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "(":
            tokens.append(Token("lparen", "(", i)); i += 1; continue
        if c == ")":
            tokens.append(Token("rparen", ")", i)); i += 1; continue
        if c == ",":
            tokens.append(Token("comma", ",", i)); i += 1; continue
        if c in "=!<>":
            two = text[i:i + 2]
            if two in ("==", "!=", "<=", ">="):
                tokens.append(Token("op", two, i)); i += 2; continue
            if c in "=<>":
                tokens.append(Token("op", c, i)); i += 1; continue
            raise ConditionError(f"stray {c!r} at {i}: {text[max(0, i - 20):i + 20]!r}")
        if c in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(_ESCAPES.get(text[j + 1], text[j + 1]))
                    j += 2
                else:
                    buf.append(text[j])
                    j += 1
            if j >= n:
                raise ConditionError(f"unterminated string at {i}")
            tokens.append(Token("string", "".join(buf), i))
            i = j + 1
            continue
        j = i
        while j < n and text[j] not in _STOP:
            j += 1
        word = text[i:j]
        kind = "number" if re.fullmatch(r"\d+", word) else "word"
        tokens.append(Token(kind, word, i))
        i = j
    return tokens


class ConditionError(Exception):
    """A condition that does not parse. Carries the source offset."""


# --------------------------------------------------------------------------
# AST
# --------------------------------------------------------------------------

class Node:
    def evaluate(self, event: dict) -> bool:
        raise NotImplementedError


@dataclass(frozen=True)
class Bool(Node):
    def __init__(self, value: bool) -> None:
        object.__setattr__(self, "_v", value)

    def evaluate(self, event: dict) -> bool:
        return self._v


@dataclass(frozen=True)
class And(Node):
    left: Node
    right: Node

    def evaluate(self, event: dict) -> bool:
        return self.left.evaluate(event) and self.right.evaluate(event)


@dataclass(frozen=True)
class Or(Node):
    left: Node
    right: Node

    def evaluate(self, event: dict) -> bool:
        return self.left.evaluate(event) or self.right.evaluate(event)


@dataclass(frozen=True)
class Not(Node):
    operand: Node

    def evaluate(self, event: dict) -> bool:
        return not self.operand.evaluate(event)


@dataclass(frozen=True)
class Compare(Node):
    op: str
    left: "Operand"
    right: "Operand"

    def evaluate(self, event: dict) -> bool:
        a = self.left.value(event)
        b = self.right.value(event)
        if a is MISSING or b is MISSING:
            return False
        return _compare(self.op, a, b)


@dataclass(frozen=True)
class SetOp(Node):
    op: str                      # in | intersects | pmatch
    left: "Operand"
    values: tuple[Any, ...]

    def evaluate(self, event: dict) -> bool:
        a = self.left.value(event)
        if a is MISSING:
            return False
        items = a if isinstance(a, (list, tuple)) else [a]
        if self.op == "in":
            return any(_as_text(x) in {_as_text(v) for v in self.values} for x in items)
        if self.op == "intersects":
            return bool({_as_text(x) for x in items} & {_as_text(v) for v in self.values})
        return any(_pmatch(_as_text(x), _as_text(v)) for x in items for v in self.values)


@dataclass(frozen=True)
class Exists(Node):
    left: "Operand"

    def evaluate(self, event: dict) -> bool:
        return self.left.value(event) is not MISSING


# --------------------------------------------------------------------------
# Operands
# --------------------------------------------------------------------------

class Operand:
    def value(self, event: dict) -> Any:
        raise NotImplementedError


@dataclass(frozen=True)
class Literal(Operand):
    raw: Any

    def value(self, event: dict) -> Any:
        return self.raw


@dataclass(frozen=True)
class Field(Operand):
    path: str

    def value(self, event: dict) -> Any:
        return lookup(event, self.path)


@dataclass(frozen=True)
class Transform(Operand):
    fn: str
    inner: Operand

    def value(self, event: dict) -> Any:
        v = self.inner.value(event)
        if v is MISSING:
            return MISSING
        if self.fn == "len":
            return len(v) if hasattr(v, "__len__") else len(str(v))
        text = _as_text(v)
        if self.fn == "tolower":
            return text.lower()
        if self.fn == "toupper":
            return text.upper()
        if self.fn == "basename":
            return text.rsplit("/", 1)[-1] if "/" in text else ""
        raise ConditionError(f"unknown transformer {self.fn!r}")


def lookup(event: dict, path: str) -> Any:
    """Resolve a dotted field path, tolerating `[n]` ancestor indexes.

    Event dicts written by hand use string keys for indexed ancestors; events
    produced by code use ints. Accept both rather than forcing a convention on
    the caller.
    """
    cur: Any = event
    for part in path.split("."):
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)(?:\[(\d+)\])?", part)
        if not m:
            return MISSING
        name, idx = m.group(1), m.group(2)
        if isinstance(cur, dict):
            if name not in cur:
                return MISSING
            cur = cur[name]
        else:
            return MISSING
        if idx is not None:
            if not isinstance(cur, dict):
                return MISSING
            cur = cur.get(int(idx), cur.get(str(idx)))
            if cur is None:
                return MISSING
    return cur


def _as_text(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, tuple)):
        return ",".join(_as_text(x) for x in v)
    return str(v)


def _compare(op: str, a: Any, b: Any) -> bool:
    if op in ("<", "<=", ">", ">="):
        # Numeric when both sides are numeric; Falco compares numbers as
        # numbers, and '10' < '9' as text is how a rule silently stops working.
        if isinstance(a, (int, float)) and not isinstance(a, bool) and \
           isinstance(b, (int, float)) and not isinstance(b, bool):
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
        try:
            fa, fb = float(_as_text(a)), float(_as_text(b))
        except ValueError:
            return False
        return {"<": fa < fb, "<=": fa <= fb, ">": fa > fb, ">=": fa >= fb}[op]

    if op == "bcontains":
        needle = bytes.fromhex(_as_text(b))
        return needle in _as_bytes(a)

    items = a if isinstance(a, (list, tuple)) else [a]
    if op == "in":
        return any(_as_text(x) == _as_text(b) for x in items)
    if op == "intersects":
        return bool({_as_text(x) for x in items} & {_as_text(b)})

    text_b = _as_text(b)
    for x in items:
        text_a = _as_text(x)
        if op == "contains" and text_b in text_a:
            return True
        if op == "icontains" and text_b.lower() in text_a.lower():
            return True
        if op == "startswith" and text_a.startswith(text_b):
            return True
        if op == "endswith" and text_a.endswith(text_b):
            return True
        if op == "glob" and _glob(text_a, text_b):
            return True
    if op in ("=", "=="):
        return any(_as_text(x) == text_b for x in items)
    if op == "!=":
        return all(_as_text(x) != text_b for x in items)
    return False


def _as_bytes(v: Any) -> bytes:
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    # JSON cannot carry bytes, and a byte buffer such as evt.buffer is usually
    # not valid UTF-8, so it is written as {"$bytes": "<hex>"} in case files.
    if isinstance(v, dict) and set(v) == {"$bytes"}:
        return bytes.fromhex(str(v["$bytes"]))
    return _as_text(v).encode("utf-8", "surrogateescape")


def _glob(text: str, pattern: str) -> bool:
    """fnmatch, except that a wildcard does not cross a path separator."""
    out, i = ["^"], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    out.append("$")
    return re.match("".join(out), text) is not None


def _pmatch(path: str, prefix: str) -> bool:
    """True when path is prefix or lives below it, on component boundaries.

    `/var/run` matches `/var/run` and `/var/run/x`, never `/var/runx`.
    """
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

class Parser:
    def __init__(self, tokens: list[Token], lists: dict[str, list[str]],
                 macros: dict[str, str]) -> None:
        self.t = tokens
        self.i = 0
        self.lists = lists
        self.macros = macros
        self._macro_cache: dict[str, Node] = {}
        self._resolving: list[str] = []

    # -- token helpers ----------------------------------------------------
    def peek(self, offset: int = 0) -> Token | None:
        j = self.i + offset
        return self.t[j] if j < len(self.t) else None

    def peek_word(self) -> str | None:
        tok = self.peek()
        return tok.value if tok and tok.kind == "word" else None

    def take(self) -> Token:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.i += 1
        return tok

    def expect(self, kind: str, value: str | None = None) -> Token:
        tok = self.take()
        if tok.kind != kind or (value is not None and tok.value != value):
            want = value if value is not None else kind
            raise ConditionError(f"expected {want!r} at offset {tok.pos}, got {tok.value!r}")
        return tok

    # -- grammar ----------------------------------------------------------
    def parse(self) -> Node:
        if not self.t:
            raise ConditionError("empty condition")
        node = self.or_expr()
        if self.i != len(self.t):
            extra = self.t[self.i:]
            raise ConditionError(f"trailing tokens at offset {extra[0].pos}: {extra[:4]!r}")
        return node

    def or_expr(self) -> Node:
        node = self.and_expr()
        while self.peek_word() == "or":
            self.take()
            node = Or(node, self.and_expr())
        return node

    def and_expr(self) -> Node:
        node = self.unary()
        while self.peek_word() == "and":
            self.take()
            node = And(node, self.unary())
        return node

    def unary(self) -> Node:
        if self.peek_word() == "not":
            self.take()
            return Not(self.unary())
        return self.primary()

    def primary(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        if tok.kind == "lparen":
            self.take()
            node = self.or_expr()
            self.expect("rparen")
            return node

        left = self.operand(rhs=False)
        nxt = self.peek()

        if nxt is not None and nxt.kind == "op":
            op = self.take().value
            return Compare(op, left, self.operand(rhs=True))

        if nxt is not None and nxt.kind == "word":
            word = nxt.value
            if word in UNSUPPORTED:
                raise ConditionError(f"operator {word!r} is not implemented")
            if word == "exists":
                self.take()
                return Exists(left)
            if word in STRING_OPS:
                self.take()
                return Compare(word, left, self.operand(rhs=True))
            if word in SET_OPS:
                self.take()
                return SetOp(word, left, self.value_list())

        # A bare word in boolean position is a macro reference.
        if isinstance(left, Field) and left.path in self.macros:
            return self.macro(left.path)
        raise ConditionError(
            f"expected an operator after {getattr(left, 'path', left)!r}, got {nxt!r}")

    def operand(self, rhs: bool = False) -> Operand:
        """A side of a comparison.

        On the left a bare word is a field reference; on the right it is a
        literal. `proc.name = bash` compares the field against the string
        "bash", not against a field called bash. Falco only puts a field on the
        right through `val()`, which this module does not implement.
        """
        tok = self.take()
        if tok.kind == "string":
            return Literal(tok.value)
        if tok.kind == "number":
            return Literal(int(tok.value))
        if tok.kind != "word":
            raise ConditionError(f"expected a value at offset {tok.pos}, got {tok.value!r}")
        if tok.value in UNSUPPORTED:
            raise ConditionError(f"{tok.value!r} is not implemented")
        nxt = self.peek()
        if tok.value in TRANSFORMERS and nxt is not None and nxt.kind == "lparen":
            if rhs:
                raise ConditionError(f"transformer {tok.value!r} is not supported on the right-hand side")
            self.take()
            inner = self.operand()
            self.expect("rparen")
            return Transform(tok.value, inner)
        return Literal(tok.value) if rhs else Field(tok.value)

    def value_list(self) -> tuple[Any, ...]:
        self.expect("lparen")
        out: list[Any] = []
        while True:
            tok = self.take()
            if tok.kind == "rparen":
                break
            if tok.kind == "comma":
                continue
            if tok.kind == "string":
                out.append(tok.value)
            elif tok.kind == "number":
                out.append(int(tok.value))
            elif tok.kind == "word":
                if tok.value in self.lists:
                    out.extend(self.resolve_list(tok.value))
                else:
                    out.append(tok.value)
            else:
                raise ConditionError(f"unexpected {tok.value!r} in a value list")
        return tuple(out)

    # -- macro and list resolution ---------------------------------------
    def resolve_list(self, name: str, seen: frozenset[str] = frozenset()) -> list[str]:
        if name in seen:
            raise ConditionError(f"list cycle through {name!r}")
        out: list[str] = []
        for entry in self.lists[name]:
            if entry in self.lists:
                out.extend(self.resolve_list(entry, seen | {name}))
            else:
                out.append(entry)
        return out

    def macro(self, name: str) -> Node:
        if name in self._macro_cache:
            return self._macro_cache[name]
        if name in self._resolving:
            chain = " -> ".join(self._resolving + [name])
            raise ConditionError(f"macro cycle: {chain}")
        self._resolving.append(name)
        try:
            body = Parser(tokenize(self.macros[name]), self.lists, self.macros)
            body._macro_cache = self._macro_cache
            body._resolving = self._resolving
            node = body.parse()
        finally:
            self._resolving.pop()
        self._macro_cache[name] = node
        return node


# --------------------------------------------------------------------------
# Ruleset
# --------------------------------------------------------------------------

class Ruleset:
    """A rules file, parsed once and queryable by rule name."""

    def __init__(self, path: Path) -> None:
        import yaml

        self.path = Path(path)
        self.lists: dict[str, list[str]] = {}
        self.macros: dict[str, str] = {}
        self.rules: dict[str, dict] = {}
        for item in yaml.safe_load(self.path.read_text(encoding="utf-8")):
            if "list" in item:
                self.lists[item["list"]] = [str(x).strip("'\"") for x in item["items"]]
            elif "macro" in item:
                self.macros[item["macro"]] = " ".join(item["condition"].split())
            elif "rule" in item:
                self.rules[item["rule"]] = item

    def rule(self, name: str) -> dict:
        """Look a rule up by name, with a usable error when the name is wrong.

        A bare KeyError on a 97-rule file tells you nothing; the near-miss list
        usually does.
        """
        if name in self.rules:
            return self.rules[name]
        folded = name.casefold()
        near = [n for n in self.rules if folded in n.casefold()][:4]
        hint = " — did you mean: " + "; ".join(repr(n) for n in near) if near else ""
        raise ConditionError(f"no rule named {name!r} in {self.path.name}{hint}")

    def compile(self, condition: str) -> Node:
        return Parser(tokenize(condition), self.lists, self.macros).parse()

    def compile_rule(self, name: str) -> Node:
        return self.compile(self.rule(name)["condition"])

    def check_all(self) -> list[tuple[str, str]]:
        """Parse every macro and every rule. Returns [(name, error)]."""
        failures: list[tuple[str, str]] = []
        for name in self.macros:
            try:
                Parser(tokenize(self.macros[name]), self.lists, self.macros).macro(name)
            except ConditionError as exc:
                failures.append((f"macro:{name}", str(exc)))
        for name, rule in self.rules.items():
            try:
                self.compile(rule["condition"])
            except ConditionError as exc:
                failures.append((f"rule:{name}", str(exc)))
        return failures


# --------------------------------------------------------------------------
# AST queries used by the style checker
# --------------------------------------------------------------------------

def evt_types(node: Node) -> set[str]:
    """Every evt.type value the condition can match, after macro expansion.

    Walking the AST beats matching the expanded text: a rule that mixes
    open_write with spawned_process must not be judged on a substring that
    happens to appear somewhere in the condition.
    """
    found: set[str] = set()

    def walk(n: Node) -> None:
        if isinstance(n, Compare) and n.op in ("=", "==") \
                and isinstance(n.left, Field) and n.left.path == "evt.type" \
                and isinstance(n.right, Literal):
            found.add(str(n.right.raw))
        elif isinstance(n, SetOp) and n.op == "in" \
                and isinstance(n.left, Field) and n.left.path == "evt.type":
            found.update(str(v) for v in n.values)
        for child in _children(n):
            walk(child)

    walk(node)
    return found


def leading_fields(node: Node) -> set[str]:
    """Fields that gate the condition first.

    Descends the left spine of `and`, and both branches of a leading `or`, to
    find what actually prunes events before anything else is evaluated.
    """
    out: set[str] = set()

    def walk(n: Node) -> None:
        if isinstance(n, And):
            walk(n.left)
        elif isinstance(n, Or):
            walk(n.left)
            walk(n.right)
        elif isinstance(n, Not):
            walk(n.operand)
        elif isinstance(n, Compare) and isinstance(n.left, Field):
            out.add(n.left.path)
        elif isinstance(n, SetOp) and isinstance(n.left, Field):
            out.add(n.left.path)
        elif isinstance(n, Exists) and isinstance(n.left, Field):
            out.add(n.left.path)

    walk(node)
    return out


def _children(node: Node) -> tuple[Node, ...]:
    if isinstance(node, (And, Or)):
        return (node.left, node.right)
    if isinstance(node, Not):
        return (node.operand,)
    return ()
