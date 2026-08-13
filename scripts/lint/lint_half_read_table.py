#!/usr/bin/env python3
"""Half-read policy table — flag a boundary that hardcodes ONE key of someone else's keyed
gate table, leaving the table's other keys with no reader at that boundary.

A module-level dict mapping string keys to per-key handlers is the one place a key's MEANING
is decided: every key has its own answer, and the owner reaches those answers through a
lookup (``T.get(d)`` / ``T[d]`` / ``d in T`` / iteration). A collaborating module that
branches on ONE key spelled as a string literal has, by construction, no reader for the
table's other keys — it re-decided one row of the table locally and silently declined to
decide the rest. That is #879: ``runtime/close_tool.py`` charges the ``"false-positive"``
entry price by literal, while ``"benign"`` — the other key of
``skills.invlang.validate._DISPOSITION_GATES`` — passes that boundary ungated.

WHAT IS MECHANIZED
------------------
The CONSUMER half, and only its SHAPE:

  - a TABLE is a module-level ``Assign``/``AnnAssign`` whose value is an ``ast.Dict`` with
    >= 2 keys, no ``**`` spread, every key resolving to a string through ``_astlib.str_value``
    (so a table that hoists its keys to module constants — ``{BENIGN: g, FALSE_POSITIVE: g}``
    — is the same table), and every VALUE a ``Name``/``Attribute``/``Lambda``: each key has
    its own ANSWER. A str->str map is a naming table, not a gate table, and is skipped.
  - a table is ARMED once it is looked up GENERICALLY anywhere in the corpus — ``T[expr]``
    with a non-Constant slice, ``T.get(...)``, ``.items()``/``.keys()``/``.values()``,
    ``x in T``, iteration, and the same through a resolved import (``m.T[...]``,
    ``getattr(m, "T")``). Self-arming, like ``lint_borrowed_vocabulary``: a new keyed gate
    table starts being guarded the moment it lands, with no edit to this lint.
  - a FINDING is a branch on a string equal to one of an armed table's keys, in a module that
    is not the table's owner but does import it, where the branching function does not itself
    reach the table's lookup — one finding per key of that table left unread at that
    boundary. "Branch" is ``==``/``!=`` against a string, ``in``/``not in`` a literal
    sequence of strings, and ``case "s":``.

Every call and every cross-module reference is resolved through ``_astlib``
(``origin``/``callee``/``module_env``), never by dotted spelling — the #602 rule.

WHAT IS **NOT** MECHANIZED — a clean run is NOT a clean tree
------------------------------------------------------------
Only one half of this pattern is lintable, and the green half is the narrow one. Do not read
an exit-0 here as "no table is half-read".

  1. **A boundary that enumerates EVERY key by literal is invisible.** The detector fires on
     the GAP (keys with no reader here), so a consumer that spells out all of the table's
     keys in its own if/elif chain — the fullest possible copy of someone else's dispatch,
     and the one that goes stale the day a key is added — produces zero findings. Completing
     the enumeration is a way to turn this gate green that makes the code worse.
  2. **Whether the branch actually re-derived the decision is not checked.** The gate proves
     a literal-keyed branch exists with unread siblings. It cannot tell a genuine local
     re-derivation from a boundary that legitimately treats one key as special (an entry
     price, a single exemption) after delegating everything else. That judgement is the
     reviewer's; the suppression marker is where it gets written down.
  3. **Cross-module key identity here is VALUE-based, not reference-based.** These tables are
     private (``_DISPOSITION_GATES`` is never imported), so there is no reference to follow:
     a consumer is tied to a table by its key STRINGS plus an import edge to the owning
     module. Two consequences, in both directions:
       - short, generic keys COLLIDE. ``learning/core/persist.py`` branches on
         ``direction == "benign"`` — the learning LANE, an unrelated vocabulary that merely
         shares a spelling with a disposition. That is a structural false positive, baselined
         as one, and no amount of resolver work removes it.
       - distinctive keys never collide, so a genuinely half-read table whose consumer does
         not import the owner is a false NEGATIVE. The import edge is a suffix match on the
         import's dotted path (anywhere in the file, function-local imports included), which
         is loose in the FP direction and blind in the FN one.
  4. **The OWNER half is out of scope entirely.** Nothing here checks that the table's
     handlers are complete, mutually exclusive, or correct, that a key added to the table
     gained a handler, or that the owner's own lookup fails closed on an unknown key.
  5. Values reached as DATA rather than as a branch — a lookup into a local dict, a key
     threaded through as a parameter — carry no literal and are never seen.

Mark a deliberate site with ``# lint-half-table: ok — <reason>``, on the site's own lines or
anywhere in the comment block directly above it.

Pre-existing sites are ratcheted via ``lint_half_read_table_baseline.json`` (see
scripts/lint/_baseline.py). ``require_reasons`` is on: an entry with no annotation fails the
gate exactly as a new finding does.

Run from repo root:  python scripts/lint/lint_half_read_table.py
Regenerate the baseline:  python scripts/lint/lint_half_read_table.py --update-baseline
Exit 0 = clean (no new sites), 1 = new/un-triaged sites, 2 = the gate could not look.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

try:  # package import in tests
    from ._astlib import (
        ModuleEnv,
        ScanBlind,
        callee,
        module_env,
        origin,
        read_and_parse,
        str_value,
    )
    from ._baseline import Finding, gate
except ImportError:  # direct ``python scripts/lint/...`` execution
    from _astlib import (
        ModuleEnv,
        ScanBlind,
        callee,
        module_env,
        origin,
        read_and_parse,
        str_value,
    )
    from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_half_read_table_baseline.json")
EXCLUDED_DIRS = frozenset(
    {".venv", "__pycache__", "tests", "run-visualizations", "run-transcripts", "runs"}
)
SUPPRESS = "lint-half-table: ok"

# One key is a constant, not a table. Two is the smallest dispatch with something to leave
# unread — and #879's table has exactly two.
MIN_KEYS = 2

# The reads that mean "this table answers for every key", as opposed to a literal subscript
# that answers for one.
_LOOKUP_METHODS = frozenset({"get", "items", "keys", "values"})


# --------------------------------------------------------------------------- corpus


def _in_scope(path: Path, scope: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.relative_to(scope).parts)


def _relative(path: Path, scope: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.relative_to(scope).as_posix()


def _dotted(rel: str) -> tuple[str, ...]:
    """The module path of a source file, as tuple parts: ``a/b/__init__.py`` -> ``(a, b)``."""
    parts = Path(rel).with_suffix("").parts
    return parts[:-1] if parts and parts[-1] == "__init__" else parts


# ----------------------------------------------------------------------- owner side


def _module_tables(tree: ast.Module, env: ModuleEnv) -> dict[str, tuple[str, ...]]:
    """``name -> keys`` for every module-level keyed gate table this module defines.

    Keys resolve through ``str_value``, so hoisting them to module constants — the tidy way
    to write the table — does not make it a different table. Every value must be a
    ``Name``/``Attribute``/``Lambda``: that is what makes each key's answer its OWN, and what
    separates a dispatch table from a str->str naming map.
    """
    tables: dict[str, tuple[str, ...]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        value = node.value
        if not isinstance(value, ast.Dict):
            continue
        if any(key is None for key in value.keys):  # `**spread`: the key set is not closed
            continue
        keys = [v for key in value.keys if (v := str_value(key, env)) is not None]
        if len(keys) != len(value.keys) or len(set(keys)) < MIN_KEYS:
            continue
        if not all(
            isinstance(answer, (ast.Name, ast.Attribute, ast.Lambda))
            for answer in value.values
        ):
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                tables[target.id] = tuple(keys)
    return tables


def _generic_lookups(tree: ast.AST, env: ModuleEnv) -> tuple[set[str], set[str]]:
    """What this tree looks up GENERICALLY, as ``(bare local names, resolved origins)``.

    Two channels because a table is reached two ways. Inside its owner it is a bare local
    name, which by construction resolves to nothing. Everywhere else it is reached through an
    import, and then the only sound identity is the dotted ORIGIN ``_astlib.origin`` resolves
    — ``m.T[...]``, ``from m import T`` then ``T.get(...)``, and ``getattr(m, "T")`` all land
    on the same string, while a same-named attribute of a local object lands on none.
    """
    local: set[str] = set()
    origins: set[str] = set()

    def record(expr: ast.expr) -> None:
        if isinstance(expr, ast.Name):
            local.add(expr.id)
        resolved = origin(expr, env)
        if resolved is not None:
            origins.add(resolved)

    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            # A literal subscript reads ONE key; anything else reads whichever key it is given.
            if not isinstance(node.slice, ast.Constant):
                record(node.value)
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _LOOKUP_METHODS:
                record(func.value)
            elif callee(node, env) == "builtins.getattr" and len(node.args) == 2:
                base = origin(node.args[0], env)
                attr = str_value(node.args[1], env)
                if base is not None and attr is not None:
                    origins.add(f"{base}.{attr}")
        elif isinstance(node, ast.Compare):
            for op, comparator in zip(node.ops, node.comparators):
                if isinstance(op, (ast.In, ast.NotIn)):
                    record(comparator)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            record(node.iter)
    return local, origins


# -------------------------------------------------------------------- consumer side


def _imported_modules(tree: ast.Module) -> set[tuple[str, ...]]:
    """Every module path this file imports, as dotted tuples.

    ``ast.walk``, not ``tree.body``: a function-local import is a collaboration edge exactly
    as a top-level one is, and ``learning/core/persist.py`` reaches the invlang validator
    that way and no other.
    """
    out: set[tuple[str, ...]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            base = tuple(node.module.split(".")) if node.module else ()
            if base:
                out.add(base)
            for alias in node.names:  # `from pkg import mod` / `from . import mod`
                if alias.name != "*":
                    out.add(base + (alias.name,))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                out.add(tuple(alias.name.split(".")))
    return out


def _imports_owner(imports: set[tuple[str, ...]], owner: tuple[str, ...]) -> bool:
    """Whether this file names the owner's module. A SUFFIX match, so a relative import
    (``from .validate import ...``, whose dots ``ast`` does not keep in ``module``) still
    counts — loose in the false-positive direction, and stated as such in the docstring."""
    return any(
        path and len(path) <= len(owner) and owner[-len(path):] == path for path in imports
    )


def _branch_literals(
    tree: ast.Module, env: ModuleEnv
) -> list[tuple[str, ast.AST, tuple[str, ...], ast.AST | None]]:
    """``(string, node, enclosing scope, enclosing function)`` for every literal a control-flow
    branch turns on: ``x == "s"``, ``x != "s"``, ``x in ("s", ...)``, ``case "s":``."""
    out: list[tuple[str, ast.AST, tuple[str, ...], ast.AST | None]] = []

    def visit(node: ast.AST, scope: tuple[str, ...], func: ast.AST | None) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope, func = (*scope, node.name), node
        elif isinstance(node, ast.ClassDef):
            scope = (*scope, node.name)
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for op, comparator in zip(node.ops, node.comparators):
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    for side in operands:
                        if (value := str_value(side, env)) is not None:
                            out.append((value, node, scope, func))
                elif isinstance(op, (ast.In, ast.NotIn)) and isinstance(
                    comparator, (ast.Tuple, ast.List, ast.Set)
                ):
                    for element in comparator.elts:
                        if (value := str_value(element, env)) is not None:
                            out.append((value, node, scope, func))
        elif isinstance(node, ast.MatchValue):
            if (value := str_value(node.value, env)) is not None:
                out.append((value, node, scope, func))
        for child in ast.iter_child_nodes(node):
            visit(child, scope, func)

    visit(tree, (), None)
    return out


def _reaches_lookup(func: ast.AST | None, env: ModuleEnv, table_origin: str) -> bool:
    """Whether the branching function ITSELF reaches the owner's lookup. A function that
    looks the table up generically is deciding through the owner's answer; the literal beside
    it is then a special case of a decision that was made, not a decision taken locally."""
    if func is None:
        return False
    return table_origin in _generic_lookups(func, env)[1]


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    """The marker on the site's own line span, OR anywhere in the contiguous comment block
    directly above it. Same two-place rule as ``lint_borrowed_vocabulary``: a suppression here
    has to say why one boundary may hardcode one row of someone else's table, and that reason
    rarely fits on the branch's own line."""
    start = getattr(node, "lineno", 0)
    end = getattr(node, "end_lineno", start) or start
    if any(SUPPRESS in lines[i - 1] for i in range(start, end + 1) if 0 < i <= len(lines)):
        return True
    i = start - 1
    while i > 0 and lines[i - 1].lstrip().startswith("#"):
        if SUPPRESS in lines[i - 1]:
            return True
        i -= 1
    return False


# --------------------------------------------------------------------------- the scan


def _scan_file(
    rel: str,
    tree: ast.Module,
    lines: list[str],
    env: ModuleEnv,
    tables: dict[tuple[str, str], tuple[str, ...]],
) -> list[Finding]:
    literals = _branch_literals(tree, env)
    if not literals:
        return []
    imports = _imported_modules(tree)
    # Which keys of which table this FILE branches on, and where each branch sits.
    covered: dict[tuple[str, str], set[str]] = {}
    sites: dict[tuple[str, str, str], tuple[ast.AST, tuple[str, ...]]] = {}
    for value, node, scope, func in literals:
        for (owner_rel, name), keys in tables.items():
            if owner_rel == rel or value not in keys:
                continue
            owner = _dotted(owner_rel)
            if not _imports_owner(imports, owner):
                continue
            if _reaches_lookup(func, env, f"{'.'.join(owner)}.{name}"):
                continue
            covered.setdefault((owner_rel, name), set()).add(value)
            sites.setdefault((owner_rel, name, value), (node, scope))

    findings: list[Finding] = []
    for (owner_rel, name), seen in sorted(covered.items()):
        missing = sorted(set(tables[(owner_rel, name)]) - seen)
        if not missing:
            # Every key has a reader here. The gate is blind to this shape on purpose —
            # see "WHAT IS NOT MECHANIZED" (1) in the module docstring.
            continue
        live = [
            (value, *sites[(owner_rel, name, value)])
            for value in sorted(seen)
            if not _suppressed(sites[(owner_rel, name, value)][0], lines)
        ]
        if not live:
            continue
        value, node, scope = live[0]
        qual = ".".join(scope) or "<module>"
        table = f"{'.'.join(_dotted(owner_rel))}.{name}"
        for gap in missing:
            findings.append(
                Finding(
                    fingerprint=f"{rel}:{qual}:{table}:unread:{gap}",
                    display=(
                        f"{rel}:{node.lineno}: {qual}() branches on {value!r}, one key of "
                        f"{table} — key {gap!r} has no reader here"
                    ),
                )
            )
    return findings


def _scan(scope: Path = DEFENDER) -> list[Finding]:
    """Two passes over ONE corpus: which tables are armed, then who half-reads them.

    ``scope`` is the testability seam the other gates carry, and load-bearing beyond
    convenience here: arming is a whole-corpus property, so a gate that could only scan the
    real tree could not be shown to arm and disarm.
    """
    corpus: list[tuple[str, ast.Module, list[str], ModuleEnv]] = []
    for path in sorted(scope.rglob("*.py")):
        if not _in_scope(path, scope):
            continue
        rel = _relative(path, scope)
        text, tree = read_and_parse(path, rel)
        corpus.append((rel, tree, text.splitlines(), module_env(tree)))

    # Pass 1: every keyed gate table, and whether anything in the corpus reads it generically.
    declared: dict[tuple[str, str], tuple[str, ...]] = {}
    owner_local: dict[str, set[str]] = {}
    corpus_origins: set[str] = set()
    for rel, tree, _lines, env in corpus:
        local, origins = _generic_lookups(tree, env)
        owner_local[rel] = local
        corpus_origins |= origins
        for name, keys in _module_tables(tree, env).items():
            declared[(rel, name)] = keys
    armed = {
        (rel, name): keys
        for (rel, name), keys in declared.items()
        if name in owner_local[rel]
        or f"{'.'.join(_dotted(rel))}.{name}" in corpus_origins
    }

    # Pass 2: everyone else branching on one of an armed table's keys.
    findings: list[Finding] = []
    for rel, tree, lines, env in corpus:
        findings.extend(_scan_file(rel, tree, lines, env, armed))
    return findings


HEADER = (
    "lint_half_read_table baseline — a boundary that branches on ONE key of another module's "
    "keyed gate table, spelled as a string literal, leaving that table's other keys with no "
    "reader there (#879: close_tool charges the `false-positive` entry price by literal while "
    "`benign` passes ungated). A table is watched only once something reads it generically, so "
    "the gate arms itself as tables land. Fingerprint is "
    "file:function:owner.TABLE:unread:KEY (no line number). CI fails on an entry absent here "
    "OR present with no reason. The gate covers only the one-key-branch shape: a boundary that "
    "enumerates EVERY key by literal is invisible to it, and key identity across modules is "
    "value-based, so short generic keys collide. Regenerate: python "
    "scripts/lint/lint_half_read_table.py --update-baseline."
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
    # so a violation could sit in it and this gate would still print 0 findings. Worse here
    # than for a single-pass lint: an unreadable OWNER silently disarms its table for the whole
    # repo. Exit 2 — the gate could not run, which is not "clean" (#618/#621/#652).
    try:
        findings = _scan(scope)
    except ScanBlind as exc:
        print(f"lint_half_read_table: {exc}", file=sys.stderr)
        return 2
    print(
        "A keyed gate table's owner decides what each key MEANS. Reach that decision through "
        "the owner's lookup instead of branching on one key's spelling and leaving the rest "
        "of the table unread at this boundary."
    )
    print("Suppress a deliberate site with `# lint-half-table: ok — <reason>`.")
    return gate(
        findings,
        baseline_path,
        argv,
        label="lint_half_read_table",
        header=HEADER,
        require_reasons=True,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
