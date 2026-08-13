#!/usr/bin/env python3
"""Un-narrowed parse seam — a function that DECLARES a shape may not let raw deserializer
output reach its ``return`` un-narrowed.

``json.loads`` is typed ``Any``, and ``Any`` satisfies every annotation. So::

    def read_json_locked(path: Path) -> dict:      # defender/hooks/_run_dir.py
        ...
        return json.loads(raw) if raw else {}

type-checks CLEAN under this repo's blocking mypy config: the tree sits at zero mypy errors
with that lie in it, and every reader downstream inherits a ``dict`` that the runtime never
promised. This gate is not duplicating mypy — it closes the one hole mypy cannot see, because
``Any`` is precisely the value mypy has agreed to stop asking about.

The rule is a CONSTRUCTION BOUNDARY, not a blocklist: the parse and the shape check are ONE
construction, owned by the seam that performs the parse. A raw parse handed straight to a
validator (``doc = validate(safe_load(text))``) is that one construction and is clean; a raw
parse bound to a local, dereferenced raw, and returned under a shape annotation is the smell.

TWO CHECKS
----------
``unnarrowed-parse`` — for each FunctionDef/AsyncFunctionDef:

  1. *Claim.* The return annotation's Name/Attribute/forward-ref leaves are compared against
     ``UNCLAIMED``. ``-> Any`` / ``-> str`` / ``-> bool | None`` claim no shape and are
     skipped; ``-> dict``, ``-> list[dict]``, ``-> CaseRecord``, ``-> Path`` all claim one.
  2. *Parse sites.* The function's OWN body (nested defs and lambdas are their own visit) is
     searched for calls whose RESOLVED origin — never its dotted spelling (#602) — lands in
     ``RAW_PARSERS``. ``import json as j``/``from json import loads`` are the same case.
  3. *Taint + narrowing.* A fixpoint over local bindings marks the values derived from a
     parse; the finding fires when one reaches a ``return`` and nothing in the function
     narrowed it.

``unowned-iso-parse`` — a call resolving to ``datetime.datetime.fromisoformat`` in a module
that is not the owner of that vocabulary. This repo already owns
``defender._clock.parse_iso_utc``, whose docstring names the exact hole: a bare
``fromisoformat`` returns a NAIVE datetime for an offset-less stamp and an AWARE one
otherwise, and comparing the two raises ``TypeError`` at whatever distance the values meet.
The check is self-arming in the sense lint_borrowed_vocabulary is: the exempt module is
whichever one DEFINES ``parse_iso_utc``, so moving the owner moves the exemption with it.

WHAT IS MECHANIZED, AND WHAT IS NOT
-----------------------------------
This gate fires at the SEAM and DELIBERATELY NOT at the readers. ``read_json_locked`` in
``defender/hooks/_run_dir.py`` is reported; the sites that subscript its laundered ``dict``
(``runtime/driver.py``, ``runtime/circuit_breaker.py`` — the two audit findings of #878) are
NOT reported and never will be. That is the design: fixing the seam fixes every reader,
present and future, whereas chasing readers institutionalizes the per-reader hardening that
caused the defect in the first place.

So a green run means: **no NEW un-narrowed seam, and no new bare ``fromisoformat``.** It does
NOT mean the tree has no un-narrowed deref. The un-narrowed READ of parse-derived state —
``state["k"]``, ``state.get(...)``, ``**state`` on a value some other function laundered — is
the other half of this pattern and is NOT mechanized here. It was measured during design: 450
sites tree-wide, 124 of them production, no shape-guard convention to key on, and the
resulting per-site verdicts are noise. Do not read this gate's clean exit as coverage of that
half. The same asymmetry holds for the clock check: the CONSTRUCTION of a naive datetime is
linted, what a caller then DOES with it (comparison, subtraction, sorting a mixed batch — the
`TypeError` itself) is not.

Three more things the taint pass cannot see, named so a clean function is not mistaken for a
proved one: taint is intra-function and binding-based, so a value that reaches ``return``
through a container mutation (``rows.append(json.loads(line))``), through a global, or through
an attribute of ``self`` is invisible; a call to anything other than a raw parser is treated
as owning the shape of what it returns, so a first-party helper that itself launders ``Any``
hides the seam one frame further out (fix that helper — it is its own finding); and a single
``isinstance`` on any tainted local clears the whole function, which is generous on purpose —
a function that checks one branch and not another is a code-review question, not a lint one.

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
    {".venv", "__pycache__", "tests", "run-visualizations", "run-transcripts", ".worktrees"}
)
SUPPRESS = "lint-parse: ok"

# Raw deserializers, keyed by RESOLVED ORIGIN — `import json as j`, `from json import loads`
# and `json.loads` are ONE case, which is the whole reason the gates resolve rather than read
# spellings (#602). A POSITIVE table: a call this gate cannot resolve is not a parse.
RAW_PARSERS = frozenset({
    "json.loads",
    "json.load",
    "yaml.safe_load",
    "yaml.load",
    "yaml.full_load",
    "tomllib.loads",
    "tomllib.load",
    # This repo's hardened YAML front door. It bounds recursion and refuses unconstructable
    # scalars — it does NOT establish a shape, so it launders `Any` exactly like the stdlib.
    "defender._yaml.safe_load",
    "._yaml.safe_load",
    ".._yaml.safe_load",
})

# The timestamp vocabulary's raw constructor, and the name of the owner's answer to it. The
# module that DEFINES that function is the exempt one, so the exemption follows the owner
# instead of naming a path this file would have to be edited to keep true.
ISO_PARSER = "datetime.datetime.fromisoformat"
ISO_OWNER_FUNCTION = "parse_iso_utc"

# Annotations that claim nothing a parse could violate. A scalar is included: `-> str` on a
# laundered parse is a lie mypy also cannot see, but it cannot produce the
# "dereferenced as if validated" failure this gate exists for.
UNCLAIMED = frozenset({"Any", "object", "None", "bool", "int", "float", "str", "bytes"})

# Sanctioned narrowers — a POSITIVE table of first-party constructions that RETURN a checked
# shape (or None). Same idiom as _astlib.NO_ENCODING_OPENERS: it names what establishes a
# shape, never what fails to.
NARROWERS = frozenset({
    "defender._clock.parse_iso_utc",
    "._clock.parse_iso_utc",
    ".._clock.parse_iso_utc",
})
# Methods whose receiver is a value (so `callee()` is None by construction) and whose contract
# IS the shape check: pydantic's validators.
NARROWING_METHODS = frozenset({"model_validate", "model_validate_json", "validate_python"})


def _in_scope(path: Path, scope: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.relative_to(scope).parts)


def _relative(path: Path, scope: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.relative_to(scope).as_posix()


def _qualnames(tree: ast.Module) -> dict[ast.AST, str]:
    """Every node -> the dotted path of the scopes enclosing it, so two same-named siblings
    (``_Run.breaker`` vs ``_Res.breaker``) never share a fingerprint. Keyed by the node OBJECT
    rather than ``id()`` — an id-keyed map is a use-after-free waiting to alias a recycled
    address onto the wrong scope (``_astlib.ModuleEnv.scope_of`` says the same)."""
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

    Leaves are read as Names, Attributes and string forward-refs, so ``-> "CaseRecord"`` and
    ``-> t.Any`` are read the same way their un-quoted / un-qualified twins are."""
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
    """``func``'s own statements, stopping at every nested function/lambda: a parse inside a
    nested def belongs to THAT def's claim, and it gets its own visit."""
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

    Descent STOPS at any call that is not itself a raw parser AND is not a method on raw
    output: an independent callee owns the shape of what it returns, so
    ``validate(safe_load(text))`` is the parse and the check as ONE construction — the raw
    value is never bound, never dereferenced, never available to be returned. That is the cure
    this gate pushes toward, so it must not be flagged as the disease. (Its cost is named in
    the module docstring: a first-party helper that itself launders `Any` hides the seam one
    frame out, and is its own finding there.)

    A method call on a tainted receiver is the opposite case and must NOT stop the descent:
    ``catalog.get("scenarios")`` resolves against a value that is already ``Any``, so its
    result is ``Any`` too — nothing about a ``.get`` off raw output establishes a shape, and
    treating the dot as a boundary would let one deref launder the whole chain."""
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

    Iterated rather than single-pass because the chains are real: ``doc = json.loads(text)``
    … ``state = doc or {}`` … ``record = state["s"]`` is three steps, and a binding can
    precede the binding it derives from inside a loop. A loop/comprehension over a tainted
    iterable binds a tainted element name — without that, ``[r for r in rows if
    isinstance(r, dict)]`` reads as un-narrowed."""
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
    """The first ``return`` whose expression MENTIONS a parse call or a tainted local.

    Deliberately looser than `_reaches_raw`: a tainted local handed to a helper on the way out
    (``return esql_payload(query, resp)``) still crossed this seam's declared boundary
    un-narrowed, and the seam is where the shape was promised."""
    for node in _own_body(func):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        for sub in ast.walk(node.value):
            if sub in parses or (isinstance(sub, ast.Name) and sub.id in tainted):
                return node
    return None


def _marked(lines: list[str], start: int, end: int) -> bool:
    """The marker anywhere in ``[start, end]``, or in the contiguous comment block directly
    above ``start``. The block form matters: a suppression here has to say why one seam is
    exempt from a rule the rest of the tree follows, and that rarely fits beside the code."""
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
    """The marker on the SIGNATURE — ``def f(...) -> dict:`` — or above it. The body is
    excluded on purpose: a marker deep inside a long function would silently exempt a seam
    nobody reading the signature can see."""
    end = func.body[0].lineno - 1 if func.body else func.lineno
    return _marked(lines, func.lineno, max(func.lineno, end))


def _owns_iso_vocabulary(tree: ast.Module) -> bool:
    """Whether this module defines the owner's answer, ``parse_iso_utc``. That module is the
    one place a bare ``fromisoformat`` belongs, and locating the exemption by DEFINITION means
    moving the owner moves the exemption — no edit here, no stale path constant."""
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
    # A file inside the scan scope that could not be read or parsed never entered the corpus,
    # so an un-narrowed seam could sit in it and this gate would still print 0 findings. Exit
    # 2 — the gate could not run, which is categorically not "clean" (#618/#621/#652).
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
