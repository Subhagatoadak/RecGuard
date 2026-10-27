"""Declarative policy packs: policies, constants and checks in YAML or JSON.

A pack replaces hand-written Python check functions with ordered rules:

    recguard: 1
    name: shop-safety
    context: [CATALOG]              # host data supplied at load time
    constants: {max_price: 5000}
    policies:
      - {policy_id: base, version: 1, denied_categories: [rx-only]}
    checks:
      - name: catalog
        let: {trusted: "get(CATALOG, item.item_id)"}
        rules:
          - {reject: NOT_IN_CATALOG, if: "trusted is None"}
          - {reject: TOO_EXPENSIVE, if: "trusted.price > max_price"}

Expressions use a small, side-effect-free subset of Python syntax. They are parsed
with `ast` and interpreted node by node (never `eval`/`exec`): no imports, lambdas,
assignment, method calls or underscore attributes; only whitelisted functions and
callables the host passes in `context`. Unknown names fail at load time. Packs are
trusted configuration; the interpreter is defense in depth, not a sandbox for hostile
authors. A check whose expression raises at runtime fails closed (CHECK_ERROR).
"""
from __future__ import annotations
import ast, hashlib, json, math, operator, re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Callable, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator
from .contracts import ID, Candidate, Policy, Request
from .storage import canon

REASON = r"^[A-Za-z0-9][A-Za-z0-9_.:\-]*$"
MAX_EXPRESSION = 2_000
MAX_STEPS = 200_000
MAX_RANGE = 10_000


class PackError(ValueError):
    """Invalid pack: bad schema, disallowed syntax or unknown names. Message names the location."""


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    reject: str = Field(pattern=REASON, max_length=96)
    if_: str = Field(alias="if", max_length=MAX_EXPRESSION)
    unless: str | None = Field(default=None, max_length=MAX_EXPRESSION)


class CheckSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: ID
    description: str = ""
    applies_when: str | None = Field(default=None, max_length=MAX_EXPRESSION)
    parse_item_id: str | None = Field(default=None, max_length=500)
    on_unparseable: str = Field(default="ITEM_ID_UNPARSEABLE", pattern=REASON)
    let: dict[str, str] = Field(default_factory=dict)
    rules: list[Rule] = Field(min_length=1)

    @field_validator("parse_item_id")
    @classmethod
    def valid_regex(cls, v):
        if v is not None:
            try:
                re.compile(v)
            except re.error as exc:
                raise ValueError(f"invalid regex: {exc}") from None
        return v


class DecisionCheckSpec(BaseModel):
    """A rule over the whole approved list (`items`, best first), run after ranking.

    `on_violation: block` blocks the decision; `trim` removes the lowest-ranked item whose
    removal fixes the violation (or, if none does alone, the lowest-ranked item) and re-checks
    until the rule passes. The policy's min_results still applies afterwards.
    """
    model_config = ConfigDict(extra="forbid")
    name: ID
    description: str = ""
    applies_when: str | None = Field(default=None, max_length=MAX_EXPRESSION)
    on_violation: Literal["block", "trim"] = "block"
    let: dict[str, str] = Field(default_factory=dict)
    rules: list[Rule] = Field(min_length=1)


class PackTest(BaseModel):
    """An example the pack must classify correctly; run by `recguard policy validate`."""
    model_config = ConfigDict(extra="forbid")
    name: str
    context: dict[str, Any] = Field(default_factory=dict)   # plain data standing in for host context
    item: dict[str, Any] | None = None                       # Candidate fields; tenant_id defaults to "test"
    items: list[dict[str, Any]] | None = None                # for decision checks: the approved list, best first
    request: dict[str, Any] = Field(default_factory=dict)    # Request fields; purpose defaults to "test"
    expect: str | None                                       # "check:REASON", or null to admit


class PolicyPack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recguard: Literal[1]
    name: ID
    description: str = ""
    include: list[str] = Field(default_factory=list)
    context: list[str] = Field(default_factory=list)
    constants: dict[str, Any] = Field(default_factory=dict)
    policies: list[Policy] = Field(default_factory=list)
    checks: list[CheckSpec] = Field(default_factory=list)
    decision_checks: list[DecisionCheckSpec] = Field(default_factory=list)
    tests: list[PackTest] = Field(default_factory=list)

    @property
    def digest(self) -> str:
        return hashlib.sha256(canon(self.model_dump(mode="json", by_alias=True)).encode()).hexdigest()

    def check_digest(self, spec: CheckSpec | DecisionCheckSpec) -> str:
        """Content hash of one check plus the constants it can read."""
        body = {"check": spec.model_dump(mode="json", by_alias=True), "constants": self.constants}
        return hashlib.sha256(canon(body).encode()).hexdigest()

    def compile(self, context: Mapping[str, Any] | None = None) -> dict[str, Callable[[Candidate, Request], str | None]]:
        """Compile every check into a `fn(candidate, request) -> reason | None`."""
        context = dict(context or {})
        missing = [n for n in self.context if n not in context]
        if missing:
            raise PackError(f"pack {self.name!r}: context values not provided: {missing}")
        clash = set(self.constants) & set(context)
        if clash:
            raise PackError(f"pack {self.name!r}: names defined both as constants and context: {sorted(clash)}")
        env = {**self.constants, **{n: context[n] for n in self.context}}
        return {spec.name: _compile_check(self, spec, env) for spec in self.checks}

    def compile_decisions(self, context: Mapping[str, Any] | None = None) -> dict[str, Callable[[list, Request], str | None]]:
        """Compile every decision check into a `fn(items, request) -> reason | None`."""
        self.compile(context)  # same context validation
        context = dict(context or {})
        env = {**self.constants, **{n: context[n] for n in self.context}}
        return {spec.name: _compile_check(self, spec, env, kind="decision") for spec in self.decision_checks}

    def run_tests(self) -> list[dict]:
        """Run the pack's own `tests:` against its checks (policies are not involved)."""
        results = []
        for test in self.tests:
            try:
                if (test.item is None) == (test.items is None):
                    raise ValueError("a test needs exactly one of `item` or `items`")
                rows = [test.item] if test.item is not None else test.items
                tenant = (rows[0] if rows else {}).get("tenant_id", "test")
                items = [Candidate.model_validate({"tenant_id": tenant, "score": 1.0, **row}) for row in rows]
                req = Request.model_validate({"tenant_id": tenant, "request_id": "pack-test", "purpose": "test",
                                              **test.request, "candidates": items or [Candidate(item_id="none", tenant_id=tenant, score=0)]})
                checks = self.compile(test.context) if test.item is not None else self.compile_decisions(test.context)
                subject = items[0] if test.item is not None else items
                got = None
                for name, fn in checks.items():
                    try:
                        reason = fn(subject, req)
                    except Exception as exc:
                        reason = f"CHECK_ERROR ({type(exc).__name__}: {exc})"
                    if reason is not None:
                        got = f"{name}:{reason}"
                        break
            except Exception as exc:
                got = f"TEST_SETUP_ERROR ({exc})"
            results.append({"name": test.name, "passed": got == test.expect, "expected": test.expect, "got": got})
        return results

    def validate_names(self) -> None:
        """Static validation without context values (used by `recguard policy validate`)."""
        env_names = set(self.constants) | set(self.context)
        for spec in self.checks:
            _compile_check(self, spec, dict.fromkeys(env_names), static_only=True)
        for spec in self.decision_checks:
            _compile_check(self, spec, dict.fromkeys(env_names), static_only=True, kind="decision")


# ---- loading -------------------------------------------------------------------

def _read(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    elif path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            raise PackError("YAML packs need PyYAML: pip install 'recguard-kernel[yaml]' (or use .json)") from None
        data = yaml.safe_load(text)
    else:
        raise PackError(f"{path}: policy packs must be .yaml, .yml or .json")
    if not isinstance(data, dict):
        raise PackError(f"{path}: top level must be a mapping")
    return data


def _merge(base: dict, extra: dict, where: str) -> dict:
    """Combine an included pack (`base`) with the including one (`extra`, whose name/description win)."""
    out = {**base, **{k: v for k, v in extra.items() if k not in ("context", "policies", "checks", "decision_checks", "tests", "constants")}}
    for key in ("context",):
        out[key] = list(dict.fromkeys(base.get(key, []) + extra.get(key, [])))
    for key in ("policies", "checks", "decision_checks", "tests"):
        out[key] = base.get(key, []) + extra.get(key, [])
    constants = dict(base.get("constants", {}))
    for k, v in extra.get("constants", {}).items():
        if k in constants and constants[k] != v:
            raise PackError(f"{where}: constant {k!r} defined twice with different values")
        constants[k] = v
    out["constants"] = constants
    return out


def _resolve(data: dict, base_dir: Path | None, seen: tuple[Path, ...]) -> dict:
    merged = {k: v for k, v in data.items() if k != "include"}
    for rel in data.get("include", []) or []:
        if base_dir is None:
            raise PackError("include needs a pack loaded from a file")
        path = (base_dir / rel).resolve()
        if path in seen:
            raise PackError(f"include cycle: {' -> '.join(map(str, seen + (path,)))}")
        child = _resolve(_read(path), path.parent, seen + (path,))
        merged = _merge(child, merged, str(path))
    return merged


def load_pack(source: str | Path | Mapping) -> PolicyPack:
    """Load a pack from a .yaml/.yml/.json path or an already-parsed mapping. Includes are merged."""
    if isinstance(source, Mapping):
        data, base_dir, seen = dict(source), None, ()
    else:
        path = Path(source).resolve()
        data, base_dir, seen = _read(path), path.parent, (path,)
    data = _resolve(data, base_dir, seen)
    try:
        pack = PolicyPack.model_validate(data)
    except Exception as exc:
        raise PackError(f"invalid policy pack: {exc}") from None
    names = [c.name for c in pack.checks] + [c.name for c in pack.decision_checks]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise PackError(f"pack {pack.name!r}: duplicate check names {dupes}")
    keys = [(p.tenant_id or "*", p.policy_id) for p in pack.policies]
    if len(keys) != len(set(keys)):
        raise PackError(f"pack {pack.name!r}: a policy_id appears twice for the same tenant")
    return pack


# ---- expression compiler ---------------------------------------------------------

def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)

def _range(*args):
    r = range(*args)
    if len(r) > MAX_RANGE:
        raise ValueError("range too large")
    return r

def _matches(value, pattern):
    if len(pattern) > 200:
        raise ValueError("pattern too long")
    return re.fullmatch(pattern, str(value)) is not None


def _search(value, pattern):
    if len(pattern) > 200:
        raise ValueError("pattern too long")
    return re.search(pattern, str(value)) is not None

FUNCTIONS: dict[str, Callable] = {
    "len": len, "abs": abs, "min": min, "max": max, "sum": sum, "round": round, "int": int, "float": float,
    "str": str, "bool": bool, "any": any, "all": all, "sorted": sorted, "set": set, "list": list, "tuple": tuple,
    "range": _range, "isfinite": math.isfinite, "is_int": _is_int,
    "get": lambda m, k, default=None: m.get(k, default) if isinstance(m, Mapping) else default,
    "keys": lambda m: list(m.keys()), "values": lambda m: list(m.values()), "items": lambda m: list(m.items()),
    "startswith": lambda s, p: str(s).startswith(p), "endswith": lambda s, p: str(s).endswith(p),
    "lower": lambda s: str(s).lower(), "upper": lambda s: str(s).upper(), "matches": _matches, "search": _search,
    "split": lambda s, sep, maxsplit=-1: str(s).split(sep, maxsplit), "join": lambda sep, xs: str(sep).join(map(str, xs)),
}
BUILTIN_NAMES = {"None", "True", "False"}

BINOPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
          ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod}
CMPOPS = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le, ast.Gt: operator.gt,
          ast.GtE: operator.ge, ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
          ast.Is: operator.is_, ast.IsNot: operator.is_not}
ALLOWED = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not, ast.USub, ast.UAdd, ast.BinOp,
           ast.Compare, ast.IfExp, ast.Constant, ast.Name, ast.Load, ast.Store, ast.Attribute, ast.Subscript, ast.Slice,
           ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Call, ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp,
           ast.comprehension, *BINOPS, *CMPOPS)


def _parse(expr: str, where: str) -> ast.Expression:
    try:
        tree = ast.parse(expr.strip(), mode="eval")
    except SyntaxError as exc:
        raise PackError(f"{where}: syntax error: {exc.msg}") from None
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED):
            raise PackError(f"{where}: {type(node).__name__} is not allowed in policy expressions")
        if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
            raise PackError(f"{where}: attribute {node.attr!r} is not allowed")
        if isinstance(node, ast.Name) and node.id.startswith("_"):
            raise PackError(f"{where}: name {node.id!r} is not allowed")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise PackError(f"{where}: only plain function calls are allowed (no methods)")
            if node.keywords or any(isinstance(a, ast.Starred) for a in node.args):
                raise PackError(f"{where}: function calls take positional arguments only")
        if isinstance(node, ast.comprehension) and node.is_async:
            raise PackError(f"{where}: async comprehensions are not allowed")
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op, right in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Is, ast.IsNot)) and not (isinstance(right, ast.Constant) and right.value is None):
                    raise PackError(f"{where}: 'is' / 'is not' may only compare with None")
    return tree


def _free_names(tree: ast.AST) -> set[str]:
    """Names read by an expression that aren't bound by its own comprehensions."""
    free: set[str] = set()

    def targets(t):
        if isinstance(t, ast.Name):
            return {t.id}
        if isinstance(t, (ast.Tuple, ast.List)):
            return set().union(*(targets(e) for e in t.elts))
        raise PackError("comprehension targets must be names or tuples of names")

    def visit(node, bound):
        if isinstance(node, ast.Name):
            if node.id not in bound:
                free.add(node.id)
            return
        if isinstance(node, (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)):
            scope = set(bound)
            for gen in node.generators:
                visit(gen.iter, scope)
                scope |= targets(gen.target)
                for cond in gen.ifs:
                    visit(cond, scope)
            for part in ((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)):
                visit(part, scope)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, bound)

    visit(tree, set())
    return free


class _Budget:
    __slots__ = ("left",)

    def __init__(self):
        self.left = MAX_STEPS

    def tick(self):
        self.left -= 1
        if self.left < 0:
            raise RuntimeError("policy expression exceeded its evaluation budget")


_KINDS: dict[type, str] = {}

def _kind(tp: type) -> str:
    kind = _KINDS.get(tp)
    if kind is None:
        if issubclass(tp, Mapping):
            kind = "map"
        elif issubclass(tp, type) or any("__call__" in vars(k) for k in tp.__mro__):
            kind = "fn"  # functions, methods, classes: no attribute access (blocks e.g. fn.__globals__, Cls.mro)
        else:
            kind = "obj"
        _KINDS[tp] = kind
    return kind


def _attr(obj, name):
    kind = _kind(type(obj))
    if kind == "map":
        if name in obj:
            return obj[name]
        raise KeyError(name)
    if kind == "fn":
        raise TypeError("attribute access on functions and classes is not allowed")
    return getattr(obj, name)


def _build(node):
    """Compile a validated AST node into a closure `fn(scope, budget) -> value` (done once, at load)."""
    t = type(node)
    if t is ast.Expression:
        return _build(node.body)
    if t is ast.Constant:
        value = node.value
        return lambda scope, budget: value
    if t is ast.Name:
        name = node.id
        return lambda scope, budget: scope[name]
    if t is ast.BoolOp:
        parts = [_build(v) for v in node.values]
        if isinstance(node.op, ast.And):
            def and_(scope, budget):
                value = True
                for part in parts:
                    value = part(scope, budget)
                    if not value:
                        return value
                return value
            return and_
        def or_(scope, budget):
            value = False
            for part in parts:
                value = part(scope, budget)
                if value:
                    return value
            return value
        return or_
    if t is ast.UnaryOp:
        operand = _build(node.operand)
        if isinstance(node.op, ast.Not):
            return lambda scope, budget: not operand(scope, budget)
        if isinstance(node.op, ast.USub):
            return lambda scope, budget: -operand(scope, budget)
        return lambda scope, budget: +operand(scope, budget)
    if t is ast.BinOp:
        left, right, op = _build(node.left), _build(node.right), BINOPS[type(node.op)]
        if isinstance(node.op, ast.Mult):
            def mult(scope, budget):
                a, b = left(scope, budget), right(scope, budget)
                if isinstance(a, (str, list, tuple)) or isinstance(b, (str, list, tuple)):
                    raise TypeError("sequence repetition is not allowed")
                return a * b
            return mult
        return lambda scope, budget: op(left(scope, budget), right(scope, budget))
    if t is ast.Compare:
        first = _build(node.left)
        rest = [(CMPOPS[type(op)], _build(c)) for op, c in zip(node.ops, node.comparators)]
        if len(rest) == 1:
            (op, right), = rest
            return lambda scope, budget: op(first(scope, budget), right(scope, budget))
        def compare(scope, budget):
            left = first(scope, budget)
            for op, comp in rest:
                right = comp(scope, budget)
                if not op(left, right):
                    return False
                left = right
            return True
        return compare
    if t is ast.IfExp:
        test, body, orelse = _build(node.test), _build(node.body), _build(node.orelse)
        return lambda scope, budget: body(scope, budget) if test(scope, budget) else orelse(scope, budget)
    if t is ast.Attribute:
        value, name = _build(node.value), node.attr
        return lambda scope, budget: _attr(value(scope, budget), name)
    if t is ast.Subscript:
        container = _build(node.value)
        if isinstance(node.slice, ast.Slice):
            bounds = [None if b is None else _build(b) for b in (node.slice.lower, node.slice.upper, node.slice.step)]
            return lambda scope, budget: container(scope, budget)[slice(*(None if b is None else b(scope, budget) for b in bounds))]
        index = _build(node.slice)
        return lambda scope, budget: container(scope, budget)[index(scope, budget)]
    if t in (ast.List, ast.Tuple, ast.Set):
        elts, kind = [_build(e) for e in node.elts], {ast.List: list, ast.Tuple: tuple, ast.Set: set}[t]
        return lambda scope, budget: kind(e(scope, budget) for e in elts)
    if t is ast.Dict:
        pairs = [(_build(k), _build(v)) for k, v in zip(node.keys, node.values)]
        return lambda scope, budget: {k(scope, budget): v(scope, budget) for k, v in pairs}
    if t is ast.Call:
        name, args = node.func.id, [_build(a) for a in node.args]
        def call(scope, budget):
            fn = scope[name]
            if not callable(fn):
                raise TypeError(f"{name} is not callable")
            budget.tick()
            return fn(*[a(scope, budget) for a in args])
        return call
    if t in (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp):
        gens = [(_build(g.iter), _binder(g.target), [_build(c) for c in g.ifs]) for g in node.generators]
        if t is ast.DictComp:
            key, val = _build(node.key), _build(node.value)
            emit = lambda scope, budget: (key(scope, budget), val(scope, budget))
        else:
            emit = _build(node.elt)
        collect = {ast.SetComp: set, ast.DictComp: dict}.get(t, list)  # generators are materialised
        def comprehension(scope, budget):
            inner = _Scope(scope)
            inner.update(scope)  # flat copy of resolved names: loop lookups skip the parent chain
            out = []
            def loop(level):
                source, bind, conds = gens[level]
                for value in source(inner, budget):
                    budget.tick()
                    bind(inner, value)
                    if all(c(inner, budget) for c in conds):
                        if level + 1 < len(gens):
                            loop(level + 1)
                        else:
                            out.append(emit(inner, budget))
            loop(0)
            return collect(out)
        return comprehension
    raise TypeError(f"unsupported expression node {t.__name__}")


def _binder(target):
    if isinstance(target, ast.Name):
        name = target.id
        def bind(scope, value):
            scope[name] = value
        return bind
    parts = [_binder(e) for e in target.elts]
    def unpack(scope, value):
        values = list(value)
        if len(values) != len(parts):
            raise ValueError("cannot unpack comprehension target")
        for part, v in zip(parts, values):
            part(scope, v)
    return unpack


class _Scope(dict):
    """Layered lookup: local bindings, then parent; `let` values are computed lazily once."""

    def __init__(self, parent=None, lazy=None, budget=None):
        super().__init__()
        self.parent, self.lazy, self.budget, self.pending = parent, lazy or {}, budget, set()

    def __missing__(self, key):
        if key in self.lazy:
            if key in self.pending:
                raise RecursionError(f"'let' binding {key!r} refers to itself")
            self.pending.add(key)
            value = self.lazy[key](self, self.budget)
            self.pending.discard(key)
            self[key] = value
            return value
        if self.parent is not None:
            return self.parent[key]
        raise NameError(key)


def _number(text: str):
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d*|-?\.\d+", text):
        return float(text)
    return text


def _compile_check(pack: PolicyPack, spec, env: dict, static_only: bool = False, kind: str = "item"):
    where = f"pack {pack.name!r}, {'decision check' if kind == 'decision' else 'check'} {spec.name!r}"
    raw_pattern = getattr(spec, "parse_item_id", None)
    pattern = re.compile(raw_pattern) if raw_pattern else None
    groups = set(pattern.groupindex) if pattern else set()
    subject = "items" if kind == "decision" else "item"
    known = set(env) | set(FUNCTIONS) | BUILTIN_NAMES | {subject, "request"} | groups | set(spec.let)
    for reserved in ("item", "items", "request", *FUNCTIONS):
        if reserved in spec.let or reserved in groups or reserved in env:
            raise PackError(f"{where}: {reserved!r} is reserved and cannot be redefined")

    def compile_expr(expr, label):
        tree = _parse(expr, f"{where}, {label}")
        unknown = sorted(_free_names(tree) - known)
        if unknown:
            raise PackError(f"{where}, {label}: unknown name(s) {unknown}")
        return _build(tree)

    lets = {name: compile_expr(expr, f"let.{name}") for name, expr in spec.let.items()}
    applies = compile_expr(spec.applies_when, "applies_when") if spec.applies_when else None
    rules = [(r.reject, compile_expr(r.if_, f"rules[{i}].if"), compile_expr(r.unless, f"rules[{i}].unless") if r.unless else None)
             for i, r in enumerate(spec.rules)]
    if static_only:
        return None
    base = {**FUNCTIONS, "None": None, "True": True, "False": False, **env}

    def check(candidate, request: Request) -> str | None:
        budget = _Budget()
        root = _Scope(lazy=lets, budget=budget)
        root.update(base)
        root[subject], root["request"] = (list(candidate) if kind == "decision" else candidate), request
        if applies is not None and not applies(root, budget):
            return None
        if pattern is not None:
            match = pattern.fullmatch(candidate.item_id)  # item checks only
            if match is None:
                return spec.on_unparseable
            root.update({k: _number(v) if v is not None else None for k, v in match.groupdict().items()})
        for reason, cond, unless in rules:
            if cond(root, budget) and not (unless is not None and unless(root, budget)):
                return reason
        return None

    check.__name__ = f"pack_check_{spec.name}"
    check.__doc__ = spec.description or f"{spec.name} from policy pack {pack.name}"
    return check
