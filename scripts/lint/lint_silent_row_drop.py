#!/usr/bin/env python3
"""Silent row drop: a row may not leave a loop in the invlang row-carrying surface unless,
unconditionally on that same path, a ``ParseWarning`` was raised or the row landed in a
destination.

Inside the two roles that carry invlang rows — the tokenizer that turns lines into
``Block``s, and the projector class that owns the ``list[ParseWarning]`` — an escape
(``continue`` / ``break`` / bare ``return``) out of a ``for`` over rows must be preceded, on
every path from the loop head, by a warning or a landing. Otherwise the row left the parser
and nothing downstream knows it existed: ``disposition: benign`` gets computed over a
silently shortened document. ``ParseWarning`` is the sanctioned drop channel; this gate
checks it is used.

Roles are derived structurally, so the gate arms itself as the parser grows:

  * Projector — any ``ClassDef`` that both declares an ``AnnAssign`` field whose annotation
    mentions ``ParseWarning`` and has a method that constructs one. Both halves are needed:
    ``corpus.Companion`` and ``corpus.LoadReport`` carry warnings others raised, so they own
    no drop channel. Every method of a matching class is in scope.
  * Tokenizer — any function whose return annotation mentions ``Block``, resolved through
    ``_astlib.origin`` so aliases and qualified forms count.

  The warn-emitter set is a fixpoint: a function emits if it constructs a ``ParseWarning``
  or calls something in the same module that does, so a new ``self._warn_*`` helper needs
  no edit here.

What is not mechanized — read this before treating a green run as a clean tree. Only the
explicit escape is seen. The implicit drop is not detectable by this construction:

  * a dispatch arm that returns "handled" without ever projecting the row;
  * an ``if`` / ``elif`` chain with no ``else`` — the row falls off the end of the body;
  * a suppressed conversion (``rec.get(...) or {}``, a swallowed ``RowError``) that turns a
    malformed row into an empty one that projects "successfully".

A clean run proves only that every explicit throw-away warns or lands; the implicit half
needs review and tests.

Without the role anchor and the unconditional-path rule, the escape rule is mostly noise from
read-side filters that drop no row. The rule is conservative: a landing or warning inside a
sibling ``if`` this path did not take does not clear the escape. The resulting false alarm is
answered by the marker; the reverse error is a silent drop that ships.

Suppress a deliberate site with ``# lint-row-drop: ok — <reason>`` on the escape's own
lines. Pre-existing sites are ratcheted through ``lint_silent_row_drop_baseline.json``
(scripts/lint/_baseline.py) and every entry must carry a reason (``require_reasons`` is on).

Run from repo root:       python scripts/lint/lint_silent_row_drop.py
Regenerate the baseline:  python scripts/lint/lint_silent_row_drop.py --update-baseline
Exit 0 = clean, 1 = a new site or an un-triaged entry, 2 = the gate could not run.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

try:  # package import in tests
    from ._astlib import ModuleEnv, ScanBlind, module_env, origin, read_and_parse, source_files
    from ._baseline import Finding, gate
except ImportError:  # direct ``python scripts/lint/...`` execution
    from _astlib import ModuleEnv, ScanBlind, module_env, origin, read_and_parse, source_files
    from _baseline import Finding, gate


REPO_ROOT = Path(__file__).resolve().parents[2]
INVLANG = REPO_ROOT / "defender" / "skills" / "invlang"
BASELINE_PATH = Path(__file__).with_name("lint_silent_row_drop_baseline.json")
EXCLUDED_DIRS = frozenset({".venv", "__pycache__", "tests"})
SUPPRESS = "lint-row-drop: ok"

#: The sanctioned drop channel's type.
WARNING_TYPE = "ParseWarning"
#: The row container the tokenizer emits; a function returning it is a tokenizer.
BLOCK_TYPE = "Block"

#: Duck-typed landing verbs: the row reached a destination on this path. A positive table of
#: sanctioned mutations; the receiver is a value, so ``callee()`` cannot resolve it.
LANDING_ATTRS = frozenset({"append", "extend", "update", "add", "setdefault", "insert"})


# resolution


def _local_defs(tree: ast.Module) -> frozenset[str]:
    """Top-level names this module defines — the classes a bare ``Block`` / ``ParseWarning``
    annotation could name without any import."""
    return frozenset(
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )


def _names_type(
    node: ast.expr | None, env: ModuleEnv, defs: frozenset[str], want: str
) -> bool:
    """Whether an annotation mentions ``want`` anywhere inside it (``Block``,
    ``list[Block]``, ``tuple[X, list[ParseWarning]]`` all count).

    Resolved through ``_astlib.origin``, so aliased and qualified imports count. A locally
    defined class is checked first: it has no import to resolve, and the module defining
    the container is the one the tokenizer rule most needs to see.
    """
    if node is None:
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id == want and sub.id in defs:
            return True
        if isinstance(sub, (ast.Name, ast.Attribute)):
            resolved = origin(sub, env)
            if resolved is not None and resolved.rsplit(".", 1)[-1] == want:
                return True
    return False


def _self_method(call: ast.Call) -> str | None:
    """``self.foo(...)`` -> ``"foo"``. Methods on ``self`` are module-local functions the
    emitter fixpoint ranges over, which the resolver cannot chase as values."""
    func = call.func
    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == "self"
    ):
        return func.attr
    return None


def _bare_name(call: ast.Call) -> str | None:
    return call.func.id if isinstance(call.func, ast.Name) else None


# roles + emitters


def _functions(node: ast.AST):
    """Every function in the tree, methods included, innermost included."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield child
            yield from _functions(child)
        elif isinstance(child, ast.ClassDef):
            yield from _functions(child)


def _constructs_warning(node: ast.AST, env: ModuleEnv, defs: frozenset[str]) -> bool:
    """Whether anything under ``node`` calls the warning type itself, resolved by origin so
    an aliased import counts."""
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        if _bare_name(sub) == WARNING_TYPE and WARNING_TYPE in defs:
            return True
        resolved = origin(sub.func, env)
        if resolved is not None and resolved.rsplit(".", 1)[-1] == WARNING_TYPE:
            return True
    return False


def _warn_emitters(tree: ast.Module, env: ModuleEnv, defs: frozenset[str]) -> set[str]:
    """The fixpoint of warn-emitting function names in this module: a function that
    constructs a ``ParseWarning``, or calls something here which does.

    A fixpoint rather than a hardcoded name set, so warnings raised through a helper chain
    (``_project_rows`` -> ``_warn`` -> ``ParseWarning(...)``) and future helpers are covered.
    Keyed on the bare name: calls arrive as ``self._warn(...)`` or a module-level
    ``_two_site_reason(...)``, both answered by this module.
    """
    bodies = {fn.name: fn for fn in _functions(tree)}
    emitters = {
        name for name, fn in bodies.items() if _constructs_warning(fn, env, defs)
    }
    changed = True
    while changed:
        changed = False
        for name, fn in bodies.items():
            if name in emitters:
                continue
            if any(
                isinstance(sub, ast.Call)
                and (_self_method(sub) in emitters or _bare_name(sub) in emitters)
                for sub in ast.walk(fn)
            ):
                emitters.add(name)
                changed = True
    return emitters


def _projector_methods(
    tree: ast.Module, env: ModuleEnv, defs: frozenset[str]
) -> list[ast.AST]:
    """Every method of every class that both holds ``ParseWarning`` state and raises one
    (a class that only holds the field, like ``corpus.Companion``, is not a projector).
    """
    methods: list[ast.AST] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        holds = any(
            isinstance(stmt, ast.AnnAssign)
            and _names_type(stmt.annotation, env, defs, WARNING_TYPE)
            for stmt in node.body
        )
        if not holds:
            continue
        own_methods = [
            stmt
            for stmt in node.body
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        if any(_constructs_warning(m, env, defs) for m in own_methods):
            methods.extend(own_methods)
    return methods


def _tokenizers(
    tree: ast.Module, env: ModuleEnv, defs: frozenset[str]
) -> list[ast.AST]:
    return [
        fn
        for fn in _functions(tree)
        if _names_type(fn.returns, env, defs, BLOCK_TYPE)
    ]


# path walk


def _is_escape(node: ast.AST) -> bool:
    """``continue`` / ``break`` / a bare ``return``. A ``return <value>`` carries something
    out, which is the caller's business."""
    if isinstance(node, (ast.Continue, ast.Break)):
        return True
    if isinstance(node, ast.Return):
        return node.value is None or (
            isinstance(node.value, ast.Constant) and node.value.value is None
        )
    return False


def _paths_to_escapes(
    loop: ast.AST,
) -> list[tuple[ast.stmt, list[ast.stmt], list[ast.expr]]]:
    """Every escape in this loop's own body, with the statements that precede it on the
    path from the loop head and the guard tests it sits under.

    Descends through ``if`` / ``try`` / ``with`` but never into a nested loop or function:
    an escape there belongs to that loop, which ``_scan`` reaches separately.
    """
    results: list[tuple[ast.stmt, list[ast.stmt], list[ast.expr]]] = []

    def walk_body(
        body: list[ast.stmt], prefix: list[ast.stmt], guards: list[ast.expr]
    ) -> None:
        for index, stmt in enumerate(body):
            before = prefix + list(body[:index])
            if _is_escape(stmt):
                results.append((stmt, before, list(guards)))
                continue
            if isinstance(stmt, ast.If):
                walk_body(stmt.body, before, [*guards, stmt.test])
                walk_body(stmt.orelse, before, [*guards, stmt.test])
            elif isinstance(stmt, ast.Try):
                walk_body(stmt.body, before, guards)
                for handler in stmt.handlers:
                    walk_body(handler.body, before, guards)
                walk_body(stmt.orelse, before, guards)
                walk_body(stmt.finalbody, before, guards)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                walk_body(stmt.body, before, guards)

    walk_body(list(getattr(loop, "body", [])), [], [])
    return results


def _unconditional(stmt: ast.stmt, predicate) -> bool:
    """Whether ``predicate`` holds on every path through this one preceding statement.

    An ``if`` clears only with an ``else`` and both branches clearing. A nested loop clears
    nothing (it may run zero times), and a ``def`` / ``class`` is a binding, not an execution.
    """
    if isinstance(stmt, ast.If):
        return bool(stmt.orelse) and all(
            any(_unconditional(inner, predicate) for inner in branch)
            for branch in (stmt.body, stmt.orelse)
        )
    if isinstance(stmt, (ast.Try, ast.With, ast.AsyncWith)):
        return any(_unconditional(inner, predicate) for inner in stmt.body)
    if isinstance(
        stmt,
        (
            ast.For,
            ast.AsyncFor,
            ast.While,
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.ClassDef,
            ast.Match,
        ),
    ):
        return False
    return predicate(stmt)


def _lands(node: ast.AST) -> bool:
    """Whether the row reached a destination in this statement: a sanctioned mutation verb
    on some receiver (``rows.append(...)``, ``lead.setdefault(...)``), or a write through a
    subscript (``out["leads"] = ...``)."""
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr in LANDING_ATTRS
        ):
            return True
        if isinstance(sub, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
            if any(isinstance(target, ast.Subscript) for target in targets):
                return True
    return False


def _warns(
    node: ast.AST, emitters: set[str], env: ModuleEnv, defs: frozenset[str]
) -> bool:
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        if _self_method(sub) in emitters or _bare_name(sub) in emitters:
            return True
    return _constructs_warning(node, env, defs)


def _qualname(tree: ast.Module, target: ast.AST) -> str:
    """The dotted path of enclosing classes/defs for ``target``, so same-named methods on
    different classes never share a fingerprint."""
    stack: list[tuple[ast.AST, str]] = [(tree, "")]
    while stack:
        node, name = stack.pop()
        for child in ast.iter_child_nodes(node):
            child_name = name
            if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                child_name = f"{name}.{child.name}" if name else child.name
            if child is target:
                return child_name or "<module>"
            stack.append((child, child_name))
    return "<module>"


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    return any(
        SUPPRESS in lines[index - 1]
        for index in range(start, end + 1)
        if 0 < index <= len(lines)
    )


# detector


def _escape_findings(
    rel: str, tree: ast.Module, env: ModuleEnv, lines: list[str]
) -> list[Finding]:
    defs = _local_defs(tree)
    emitters = _warn_emitters(tree, env, defs)
    roles = [*_projector_methods(tree, env, defs), *_tokenizers(tree, env, defs)]

    findings: list[Finding] = []
    seen: set[str] = set()
    for role in roles:
        qual = _qualname(tree, role)
        for node in ast.walk(role):
            if not isinstance(node, (ast.For, ast.AsyncFor)):
                continue
            for escape, before, guards in _paths_to_escapes(node):
                warned = any(
                    _unconditional(stmt, lambda s: _warns(s, emitters, env, defs))
                    for stmt in before
                ) or any(_warns(guard, emitters, env, defs) for guard in guards)
                if warned or any(_unconditional(stmt, _lands) for stmt in before):
                    continue
                if _suppressed(escape, lines):
                    continue
                guard_text = (
                    ast.unparse(guards[-1])
                    if guards
                    else f"@{ast.unparse(node.iter)}"
                )
                kind = type(escape).__name__.lower()
                fingerprint = f"{rel}:{qual}:{kind}:{guard_text}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                findings.append(
                    Finding(
                        fingerprint=fingerprint,
                        display=(
                            f"{rel}:{escape.lineno}: {kind} in {qual}() under "
                            f"`{guard_text}` drops the row with no ParseWarning and no "
                            f"landing on this path"
                        ),
                    )
                )
    return findings


def _relative(path: Path, scope: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.relative_to(scope).as_posix()


def _scan(scope: Path) -> list[Finding]:
    findings: list[Finding] = []
    for name in source_files(scope, EXCLUDED_DIRS):
        path = scope / name
        rel = _relative(path, scope)
        # Raises ScanBlind on an unreadable file rather than scanning a shrunken corpus.
        text, tree = read_and_parse(path, rel)
        env = module_env(tree)
        findings.extend(_escape_findings(rel, tree, env, text.splitlines()))
    return findings


HEADER = (
    "lint_silent_row_drop baseline — an invlang row leaving a loop by continue/break/bare "
    "return with neither a ParseWarning nor a landing unconditionally on that path (#876). "
    "Roles are derived structurally, never from a name list: the PROJECTOR is a class that "
    "both holds list[ParseWarning] state and raises one, the TOKENIZER is a function whose "
    "return annotation mentions Block (resolved by origin, not spelling). Only the EXPLICIT "
    "escape is mechanized — the implicit drop (a dispatch arm returning 'handled' without "
    "projecting, an if/elif chain with no else, a suppressed conversion) is out of scope, "
    "so a clean run is NOT proof the parser drops nothing. Fingerprint is "
    "file:function:escape-kind:guard (no line number). CI fails on a site absent here or on "
    "an un-triaged entry. Regenerate: python scripts/lint/lint_silent_row_drop.py "
    '--update-baseline. Every entry needs a reason; "" is refused.'
)


def main(
    argv: list[str],
    *,
    scope: Path = INVLANG,
    baseline_path: Path = BASELINE_PATH,
) -> int:
    if not scope.is_dir():
        print(f"scan scope not found at {scope}", file=sys.stderr)
        return 2
    try:
        findings = _scan(scope)
    except ScanBlind as exc:
        print(f"lint_silent_row_drop: {exc}", file=sys.stderr)
        return 2
    print(
        "A row may not leave a loop in the invlang row-carrying surface unless a "
        "ParseWarning was raised or the row landed somewhere, unconditionally on that same "
        "path. Only the EXPLICIT escape is checked — the implicit drop is not mechanized, "
        "so a clean run is not a clean tree."
    )
    print("Suppress a deliberate site with `# lint-row-drop: ok — <reason>`.")
    return gate(
        findings,
        baseline_path,
        argv,
        label="lint_silent_row_drop",
        header=HEADER,
        require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
