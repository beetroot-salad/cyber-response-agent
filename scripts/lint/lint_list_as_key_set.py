#!/usr/bin/env python3
"""List-as-key-set smell: flag a fix-up pass that walks an ordered list to patch a table
already keyed by that same list, so a repeated element patches one bucket twice.

The shape::

    attribution = phase_attribution(events, phase_order, tags)   # keys came from phase_order
    ...
    for ph in phase_order:                                       # a list — may repeat a name
        attribution[ph]["cost"] += gather_by_phase.get(ph, 0.0)  # ← flagged

``phase_order`` is a render list (phase headers in written order); ``attribution`` is keyed on
the phase name. When a name repeats, one bucket is visited twice and billed twice — and a
wall-time twin that reads back the value the previous visit wrote compounds rather than
repeats.

A list recording what happened in what order and a key set naming the distinct things are
different values; one name for both hides the confusion. Where both are wanted, derive them
separately where the list is built (``dict.fromkeys(...)`` preserves order) and give the
deduped one its own name.

What is mechanized
------------------
Both halves must hold inside one function, which separates this from the counting idiom that
shares its syntax:

  - the table is bound in the function from a call that receives the sequence as an
    argument — ``D = f(..., SEQ, ...)``, including a tuple unpack. Its keys came from
    ``SEQ``, so the loop is a fix-up over an existing table, not a tally.
  - the loop is ``for x in SEQ:`` over a bare ``Name``, whose body writes ``D[x]`` —
    ``D[x] = ...``, ``D[x] op= ...``, or a nested ``D[x][k] = ...``.

``Counter()``/``{}`` accumulation never matches: those tables start empty and discover their
keys, so a repeat is the point. A plain "augmented assign into a dict keyed on the loop
variable" rule fires only on such tallies in this tree.

A sequence rebound from a provably unique source in the same function — ``set(...)``,
``sorted(set(...))``, ``dict.fromkeys(...)``, ``.keys()``, a set/dict comprehension — is
skipped.

What is not mechanized — a clean run is not a clean tree
--------------------------------------------------------
  1. Per-appearance rendering: emitting one segment per appearance, each sized as a share of
     a once-counted total, writes to no dict and is invisible here.
  2. Cross-function fix-ups: a table patched by a helper the loop calls does not match.
  3. Whether the list can actually repeat is not decided here; the gate fires on the shape.
     A sequence that genuinely cannot repeat is a suppression, not a redesign.

Mark a deliberate site with ``# lint-keyset: ok — <reason>`` on the loop's line span.
Pre-existing sites are ratcheted via ``lint_list_as_key_set_baseline.json`` (see
scripts/lint/_baseline.py); the gate fails only on a new file+function+names tuple.

Run from repo root:  python scripts/lint/lint_list_as_key_set.py
Regenerate the baseline:  python scripts/lint/lint_list_as_key_set.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites, 2 = the gate could not run.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ScanBlind, read_and_parse, source_files
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_list_as_key_set_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__")
SUPPRESS_MARKER = "lint-keyset: ok"

#: Callables whose result cannot repeat an element. `sorted` and friends are transparent:
#: `sorted(set(x))` cannot repeat, `sorted(list(x))` can, so the check looks through them.
_UNIQUE_CALLS = frozenset({"set", "frozenset", "fromkeys", "keys"})
_TRANSPARENT_CALLS = frozenset({"sorted", "list", "tuple", "reversed", "iter"})


def _callee_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return getattr(func, "id", "")


def _is_unique_source(node: ast.expr) -> bool:
    """True if `node` cannot produce the same element twice, looking through order/shape
    wrappers (`sorted`, `list`, ...) to what produced the elements."""
    if isinstance(node, (ast.Set, ast.SetComp, ast.DictComp)):
        return True
    if isinstance(node, ast.Call):
        name = _callee_name(node)
        if name in _UNIQUE_CALLS:
            return True
        if name in _TRANSPARENT_CALLS and node.args:
            return _is_unique_source(node.args[0])
    return False


def _arg_names(call: ast.Call) -> set[str]:
    """Every bare `Name` handed to `call`, positional or keyword."""
    names = {a.id for a in call.args if isinstance(a, ast.Name)}
    names |= {
        kw.value.id for kw in call.keywords if isinstance(kw.value, ast.Name)
    }
    return names


def _walk_scope(node: ast.AST, *, into_functions: bool):
    """`ast.walk`, optionally stopping at a nested `def`.

    A function scope descends into closures (one patching its enclosing scope's table is the
    same defect). Module scope must not, or every finding is reported twice.
    """
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        for child in ast.iter_child_nodes(cur):
            if not into_functions and isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                continue
            stack.append(child)


def _bindings(func: ast.AST, *, into_functions: bool) -> tuple[dict[str, list[ast.Call]], set[str]]:
    """`(name -> the calls it was bound from, names bound from a unique source)`."""
    from_call: dict[str, list[ast.Call]] = {}
    unique: set[str] = set()
    for node in _walk_scope(func, into_functions=into_functions):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if node.value is None:
            continue
        bound: list[str] = []
        for target in targets:
            if isinstance(target, ast.Name):
                bound.append(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                bound.extend(el.id for el in target.elts if isinstance(el, ast.Name))
        if _is_unique_source(node.value):
            unique.update(bound)
        if isinstance(node.value, ast.Call):
            for name in bound:
                from_call.setdefault(name, []).append(node.value)
    return from_call, unique


def _tables_written(loop: ast.AST, var: str) -> set[str]:
    """Names subscripted at `[var]` in a write position inside `loop`, walking out through
    nested subscripts so `d[var][k] = v` reports `d`."""
    written: set[str] = set()
    for node in ast.walk(loop):
        if isinstance(node, ast.AugAssign):
            targets: list[ast.expr] = [node.target]
        elif isinstance(node, ast.Assign):
            targets = list(node.targets)
        else:
            continue
        for target in targets:
            cur = target
            while isinstance(cur, ast.Subscript):
                keyed_on_var = isinstance(cur.slice, ast.Name) and cur.slice.id == var
                if keyed_on_var and isinstance(cur.value, ast.Name):
                    written.add(cur.value.id)
                cur = cur.value
    return written


def _suppressed(node: ast.AST, lines: list[str]) -> bool:
    start = node.lineno
    end = getattr(node, "end_lineno", start) or start
    return any(
        SUPPRESS_MARKER in lines[i - 1]
        for i in range(start, end + 1)
        if 0 < i <= len(lines)
    )


def _scan_function(
    rel: str, func: ast.AST, name: str, lines: list[str], *, into_functions: bool = True
) -> list[Finding]:
    from_call, unique = _bindings(func, into_functions=into_functions)
    findings: list[Finding] = []
    seen: set[str] = set()
    for loop in _walk_scope(func, into_functions=into_functions):
        if not isinstance(loop, (ast.For, ast.AsyncFor)):
            continue
        if not isinstance(loop.target, ast.Name) or not isinstance(loop.iter, ast.Name):
            continue
        seq, var = loop.iter.id, loop.target.id
        if seq in unique or _suppressed(loop, lines):
            continue
        for table in sorted(_tables_written(loop, var)):
            builders = [c for c in from_call.get(table, []) if seq in _arg_names(c)]
            if not builders:
                continue
            built_by = _callee_name(builders[0])
            fingerprint = f"{rel}:{name}:{seq}->{table}"
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            findings.append(Finding(
                fingerprint=fingerprint,
                display=(
                    f"{rel}:{loop.lineno}: `for {var} in {seq}` patches `{table}[{var}]` "
                    f"in {name}(), and `{table}` was keyed by `{seq}` "
                    f"({built_by}) — a repeat in `{seq}` patches one bucket twice"
                ),
            ))
    return findings


def _scan_file(rel: str, tree: ast.AST, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(_scan_function(rel, node, node.name, lines))
    # Module scope stops at every `def`, or each finding would be reported twice.
    findings.extend(_scan_function(rel, tree, "<module>", lines, into_functions=False))
    return findings


def _scan(root: Path) -> list[Finding]:
    """Findings under `root`, fingerprints relative to it (drivable on a tmp tree)."""
    findings: list[Finding] = []
    for rel in source_files(root, EXCLUDED_DIRS):
        path = root / rel
        text, tree = read_and_parse(path, rel)
        findings.extend(_scan_file(rel, tree, text.splitlines()))
    return findings


HEADER = (
    "lint_list_as_key_set baseline — a fix-up pass that walks an ordered LIST to patch a "
    "table already keyed by that same list, so a repeated element patches one bucket twice "
    "(#956: two GATHER headers in one loop normalize to one phase name, and the run page "
    "billed its cost twice and compounded its wall time). Fingerprint is "
    "file:function:seq->table (no line number). CI fails on a fingerprint absent here. "
    "This baseline ships EMPTY — an entry in it is a regression someone chose. Regenerate: "
    "python scripts/lint/lint_list_as_key_set.py --update-baseline."
)


def main(
    argv: list[str] | None = None,
    *,
    scope: Path | None = None,
    baseline_path: Path | None = None,
) -> int:
    # DI/test seams: the tests drive injected tmp trees and baselines.
    args = sys.argv[1:] if argv is None else argv
    root = SCOPE if scope is None else scope
    baseline = BASELINE_PATH if baseline_path is None else baseline_path
    if not root.is_dir():
        print(f"scan scope not found at {root}", file=sys.stderr)
        return 2
    # An unreadable file never entered the corpus. Exit 2: the gate could not run, which is
    # not "clean".
    try:
        findings = _scan(root)
    except ScanBlind as exc:
        print(f"lint_list_as_key_set: {exc}", file=sys.stderr)
        return 2
    print(
        "A render list is not a key set. Where a sequence records what happened in what "
        "order AND names the buckets of a table, derive the two separately at the one "
        "place the list is built — `dict.fromkeys(...)` keeps the order — and give the "
        "deduped one its own name."
    )
    print("Mark a deliberate site with `# lint-keyset: ok — <reason>`.")
    return gate(
        findings, baseline, args,
        label="lint_list_as_key_set", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main())
