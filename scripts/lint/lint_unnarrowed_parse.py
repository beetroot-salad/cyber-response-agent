#!/usr/bin/env python3
"""Un-narrowed parse seam: a function that declares a shape may not let raw deserializer
output reach its ``return`` un-narrowed.

``json.loads`` is typed ``Any``, and ``Any`` satisfies every annotation, so::

    def read_json(path: Path) -> dict:
        return json.loads(raw) if raw else {}

type-checks clean under blocking mypy while every reader inherits a ``dict`` the runtime never
promised. This closes the one hole mypy cannot see.

The rule is a construction boundary: the parse and the shape check are one construction, owned
by the seam that parses. A raw parse handed straight to a validator
(``doc = validate(safe_load(text))``) is clean; a raw parse bound to a local and returned
under a shape annotation is the smell.

Two checks
----------
``unnarrowed-parse`` — for each FunctionDef/AsyncFunctionDef:

  1. *Claim.* The return annotation's Name/Attribute/forward-ref leaves are compared against
     ``UNCLAIMED``. ``-> Any`` / ``-> str`` / ``-> bool | None`` claim no shape and are
     skipped; ``-> dict``, ``-> list[dict]``, ``-> CaseRecord``, ``-> Path`` all claim one.
  2. *Parse sites.* The function's own body (nested defs and lambdas get their own visit) is
     searched for calls whose resolved origin, not spelling, is in ``RAW_PARSERS``.
  3. *Taint + narrowing.* A fixpoint over local bindings marks values derived from a parse;
     the finding fires when one reaches a ``return`` and nothing in the function narrowed it.

``unowned-iso-parse`` — a call resolving to ``datetime.datetime.fromisoformat`` outside the
module defining ``parse_iso_utc``. A bare ``fromisoformat`` returns a naive datetime for an
offset-less stamp and an aware one otherwise, and comparing the two raises ``TypeError``
wherever the values meet. The exemption follows the definition, so moving the owner moves it.

What is not mechanized
----------------------
The gate fires at the seam, not at the readers: sites that subscript a laundered ``dict`` are
not reported. Fixing the seam fixes every reader; chasing readers institutionalizes the
per-reader hardening that causes the defect.

So a green run means no new un-narrowed seam and no new bare ``fromisoformat``. It does not
mean the tree has no un-narrowed deref: reads of parse-derived state (``state["k"]``,
``state.get(...)``, ``**state``) are not mechanized (hundreds of sites with no shape-guard
convention to key on). Likewise the construction of a naive datetime is linted, but not what a
caller does with it.

The taint pass also cannot see: values reaching ``return`` through a container mutation
(``rows.append(json.loads(line))``), a global, or ``self``; laundering inside a first-party
helper (any non-parser call is treated as owning its return shape, so the helper is its own
finding); and a single ``isinstance`` on any tainted local clears the whole function — generous
on purpose, since partial checking is a review question.

Pre-existing sites are ratcheted via ``lint_unnarrowed_parse_baseline.json`` (see
scripts/lint/_baseline.py) with ``require_reasons=True``: the fingerprint is
file:function:check, no line number, so an unrelated edit above the seam does not churn it.
Suppress a deliberate site with ``# lint-parse: ok — <reason>`` on the ``def`` line, on the
``return``/call itself, or in the comment block directly above either.

Run from repo root:  python scripts/lint/lint_unnarrowed_parse.py
Regenerate the baseline:  python scripts/lint/lint_unnarrowed_parse.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites or an un-triaged baseline entry, 2 = the gate
could not read its own scope.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

try:  # package import in tests
    from ._astlib import ModuleEnv, ScanBlind, callee, module_env, read_and_parse, root_name
    from ._baseline import Finding, gate
except ImportError:  # direct ``python scripts/lint/...`` execution
    from _astlib import ModuleEnv, ScanBlind, callee, module_env, read_and_parse, root_name
    from _baseline import Finding, gate


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_unnarrowed_parse_baseline.json")
EXCLUDED_DIRS = frozenset(
    {".venv", "__pycache__", "tests", ".worktrees"}
)
SUPPRESS = "lint-parse: ok"

# Raw deserializers, keyed by resolved origin (so aliases and from-imports count). A positive
# table: a call this gate cannot resolve is not a parse.
RAW_PARSERS = frozenset({
    "json.loads",
    "json.load",
    "yaml.safe_load",
    "yaml.load",
    "yaml.full_load",
    "tomllib.loads",
    "tomllib.load",
    # The hardened YAML front door bounds recursion and refuses unconstructable scalars but
    # establishes no shape, so it launders `Any` like the stdlib.
    "defender._yaml.safe_load",
    "._yaml.safe_load",
    ".._yaml.safe_load",
    # Its sibling, which returns the same un-shaped document twice (typed and spelled).
    "defender._yaml.safe_load_typed_and_spelled",
    "._yaml.safe_load_typed_and_spelled",
    ".._yaml.safe_load_typed_and_spelled",
})

# The timestamp vocabulary's raw constructor, and the owner's answer to it. The module that
# defines that function is exempt, so the exemption follows the owner.
ISO_PARSER = "datetime.datetime.fromisoformat"
ISO_OWNER_FUNCTION = "parse_iso_utc"

# Annotations that claim nothing a parse could violate. Scalars are included: `-> str` on a
# laundered parse is also invisible to mypy, but cannot produce "dereferenced as if validated".
UNCLAIMED = frozenset({"Any", "object", "None", "bool", "int", "float", "str", "bytes"})

# Sanctioned narrowers: a positive table of first-party constructions that return a checked
# shape (or None).
NARROWERS = frozenset({
    "defender._clock.parse_iso_utc",
    "._clock.parse_iso_utc",
    ".._clock.parse_iso_utc",
})
# Methods whose receiver is a value (so `callee()` is None) and whose contract is the shape
# check: pydantic's validators.
NARROWING_METHODS = frozenset({"model_validate", "model_validate_json", "validate_python"})


def _in_scope(path: Path, scope: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.relative_to(scope).parts)


def _relative(path: Path, scope: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.relative_to(scope).as_posix()


def _qualnames(tree: ast.Module) -> dict[ast.AST, str]:
    """Every node -> the dotted path of its enclosing scopes, so same-named siblings
    (``_Run.breaker`` vs ``_Res.breaker``) never share a fingerprint. Keyed by node object,
    not ``id()``, which could alias a recycled address."""
    out: dict[ast.AST, str] = {}

    def walk(node: ast.AST, scope: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = (*scope, child.name)
                out[child] = ".".join(inner)
                walk(child, inner)
            else:
                out[child] = ".".join(scope) or "<module>"
                walk(child, scope)

    walk(tree, ())
    return out


def _claimed_shape(annotation: ast.expr | None) -> str | None:
    """The shape this return annotation claims, or None when it claims nothing checkable.

    Leaves are Names, Attributes and string forward-refs, so ``-> "CaseRecord"`` and
    ``-> t.Any`` read like their un-quoted / un-qualified twins."""
    if annotation is None:
        return None
    leaves = {n.id for n in ast.walk(annotation) if isinstance(n, ast.Name)}
    leaves |= {n.attr for n in ast.walk(annotation) if isinstance(n, ast.Attribute)}
    leaves |= {
        n.value
        for n in ast.walk(annotation)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    }
    if not leaves or leaves <= UNCLAIMED:
        return None
    return ast.unparse(annotation)


def _own_body(func: ast.AST):
    """``func``'s own statements, stopping at nested functions/lambdas, which get their own
    visit."""
    stack = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _parse_calls(func: ast.AST, env: ModuleEnv) -> set[ast.AST]:
    return {
        node
        for node in _own_body(func)
        if isinstance(node, ast.Call) and callee(node, env) in RAW_PARSERS
    }


def _reaches_raw(node: ast.expr, parses: set[ast.AST], tainted: set[str]) -> bool:
    """Whether this expression evaluates to raw parse output.

    Descent stops at any call that is neither a raw parser nor a method on raw output: an
    independent callee owns the shape of what it returns, so ``validate(safe_load(text))`` is
    parse-and-check as one construction — the cure this gate pushes toward.

    A method call on a tainted receiver does not stop descent: ``catalog.get("scenarios")``
    on an ``Any`` value is ``Any`` too, and treating the dot as a boundary would let one
    deref launder the whole chain."""
    if isinstance(node, ast.Call):
        if node in parses:
            return True
        return isinstance(node.func, ast.Attribute) and _reaches_raw(
            node.func.value, parses, tainted
        )
    if isinstance(node, ast.Name):
        return node.id in tainted
    return any(
        _reaches_raw(child, parses, tainted)
        for child in ast.iter_child_nodes(node)
        if isinstance(child, ast.expr)
    )


def _bound_name(node: ast.AST) -> str | None:
    if (
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    ):
        return node.targets[0].id
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    return None


def _tainted_locals(func: ast.AST, parses: set[ast.AST]) -> set[str]:
    """The locals derived from a raw parse, by fixpoint.

    Iterated because chains are multi-step (``doc = json.loads(text)`` … ``state = doc or
    {}`` … ``record = state["s"]``) and a binding can precede its source inside a loop. A
    loop/comprehension over a tainted iterable taints its element name, so ``[r for r in rows
    if isinstance(r, dict)]`` counts as narrowed."""
    tainted: set[str] = set()
    bindings = [n for n in _own_body(func) if isinstance(n, (ast.Assign, ast.AnnAssign))]
    iterations = [
        n for n in _own_body(func) if isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension))
    ]
    while True:
        before = set(tainted)
        for node in bindings:
            name = _bound_name(node)
            value = getattr(node, "value", None)
            if name is not None and value is not None and _reaches_raw(value, parses, tainted):
                tainted.add(name)
        for node in iterations:
            if _reaches_raw(node.iter, parses, tainted):
                tainted.update(
                    n.id for n in ast.walk(node.target) if isinstance(n, ast.Name)
                )
        if tainted == before:
            return tainted


def _narrowed(func: ast.AST, tainted: set[str], env: ModuleEnv) -> bool:
    """Whether the function establishes a shape for any tainted local — an ``isinstance``
    test on it, or handing it to a sanctioned narrower."""
    for node in _own_body(func):
        if not isinstance(node, ast.Call):
            continue
        origin = callee(node, env)
        if origin == "builtins.isinstance" and node.args and root_name(node.args[0]) in tainted:
            return True
        is_narrower = origin in NARROWERS or (
            isinstance(node.func, ast.Attribute) and node.func.attr in NARROWING_METHODS
        )
        if is_narrower and any(root_name(arg) in tainted for arg in node.args):
            return True
    return False


def _raw_return(func: ast.AST, parses: set[ast.AST], tainted: set[str]) -> ast.Return | None:
    """The first ``return`` whose expression mentions a parse call or a tainted local.

    Looser than `_reaches_raw`: a tainted local handed to a helper on the way out
    (``return esql_payload(query, resp)``) still crossed this seam's declared boundary
    un-narrowed."""
    for node in _own_body(func):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        for sub in ast.walk(node.value):
            if sub in parses or (isinstance(sub, ast.Name) and sub.id in tainted):
                return node
    return None


def _marked(lines: list[str], start: int, end: int) -> bool:
    """The marker anywhere in ``[start, end]``, or in the contiguous comment block directly
    above ``start`` (the reason rarely fits beside the code)."""
    if any(SUPPRESS in lines[i - 1] for i in range(start, end + 1) if 0 < i <= len(lines)):
        return True
    i = start - 1
    while i > 0 and lines[i - 1].lstrip().startswith("#"):
        if SUPPRESS in lines[i - 1]:
            return True
        i -= 1
    return False


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    return _marked(lines, start, end)


def _function_suppressed(func: ast.FunctionDef | ast.AsyncFunctionDef, lines: list[str]) -> bool:
    """The marker on the signature or above it. Not the body: a marker deep inside a long
    function would exempt a seam invisibly to anyone reading the signature."""
    end = func.body[0].lineno - 1 if func.body else func.lineno
    return _marked(lines, func.lineno, max(func.lineno, end))


def _owns_iso_vocabulary(tree: ast.Module) -> bool:
    """Whether this module defines ``parse_iso_utc``, the one place a bare ``fromisoformat``
    belongs."""
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == ISO_OWNER_FUNCTION
        for node in tree.body
    )


def _unnarrowed_parses(
    rel: str, tree: ast.Module, env: ModuleEnv, quals: dict[ast.AST, str], lines: list[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        claim = _claimed_shape(func.returns)
        if claim is None:
            continue
        parses = _parse_calls(func, env)
        tainted = _tainted_locals(func, parses)
        if not parses and not tainted:
            continue
        ret = _raw_return(func, parses, tainted)
        if ret is None or _narrowed(func, tainted, env):
            continue
        if _function_suppressed(func, lines) or _suppressed(ret, lines):
            continue
        qual = quals.get(func, func.name)
        findings.append(
            Finding(
                fingerprint=f"{rel}:{qual}:unnarrowed-parse",
                display=(
                    f"{rel}:{ret.lineno}: {qual}() is annotated `-> {claim}` but returns raw "
                    f"deserializer output un-narrowed — `Any` satisfies that annotation, so "
                    f"mypy cannot see it; narrow at this seam and every reader inherits it"
                ),
            )
        )
    return findings


def _unowned_iso_parses(
    rel: str, tree: ast.Module, env: ModuleEnv, quals: dict[ast.AST, str], lines: list[str]
) -> list[Finding]:
    if _owns_iso_vocabulary(tree):
        return []
    findings: list[Finding] = []
    seen: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or callee(node, env) != ISO_PARSER:
            continue
        if _suppressed(node, lines):
            continue
        qual = quals.get(node, "<module>")
        fingerprint = f"{rel}:{qual}:unowned-iso-parse"
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        findings.append(
            Finding(
                fingerprint=fingerprint,
                display=(
                    f"{rel}:{node.lineno}: {qual}() calls datetime.fromisoformat directly — "
                    f"it returns a NAIVE datetime for an offset-less stamp and an aware one "
                    f"otherwise, and comparing the two raises TypeError; call "
                    f"defender._clock.parse_iso_utc, which owns that normalization"
                ),
            )
        )
    return findings


def _scan(scope: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(scope.rglob("*.py")):
        if not _in_scope(path, scope):
            continue
        rel = _relative(path, scope)
        text, tree = read_and_parse(path, rel)
        env = module_env(tree)
        quals = _qualnames(tree)
        lines = text.splitlines()
        findings.extend(_unnarrowed_parses(rel, tree, env, quals, lines))
        findings.extend(_unowned_iso_parses(rel, tree, env, quals, lines))
    return findings


HEADER = (
    "lint_unnarrowed_parse baseline — a function that DECLARES a shape but lets raw "
    "deserializer output (json.loads / yaml.safe_load / tomllib.load / defender._yaml."
    "safe_load) reach its return un-narrowed, plus any bare datetime.fromisoformat outside "
    "the module owning defender._clock.parse_iso_utc. `json.loads` is typed Any and Any "
    "satisfies every annotation, so these type-check clean under a blocking mypy config: "
    "this is the hole mypy cannot see, not a duplicate of it. The gate fires at the SEAM and "
    "deliberately NOT at the readers of a laundered value — fixing the seam fixes every "
    "reader, present and future. Fingerprint is file:function:check (no line number). CI "
    "fails on a triple absent here, and on any entry whose reason is empty. Regenerate: "
    "python scripts/lint/lint_unnarrowed_parse.py --update-baseline."
)


def main(
    argv: list[str],
    *,
    scope: Path = DEFENDER,
    baseline_path: Path = BASELINE_PATH,
) -> int:
    if not scope.is_dir():
        print(f"scan scope not found at {scope}", file=sys.stderr)
        return 2
    # An unreadable file never entered the corpus, so a seam could hide in it. Exit 2: the
    # gate could not run, which is not "clean".
    try:
        findings = _scan(scope)
    except ScanBlind as exc:
        print(f"lint_unnarrowed_parse: {exc}", file=sys.stderr)
        return 2
    print(
        "The parse and the shape check are ONE construction, owned by the seam that performs "
        "the parse. Narrow there — a declared shape that returns `Any` type-checks clean and "
        "hands every reader a promise the runtime never made."
    )
    print(
        "This gate does NOT lint the readers of a laundered value, or what a caller does with "
        "a naive datetime. A clean run means no new SEAM."
    )
    print("Suppress a deliberate site with `# lint-parse: ok — <reason>`.")
    return gate(
        findings,
        baseline_path,
        argv,
        label="lint_unnarrowed_parse",
        header=HEADER,
        require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
