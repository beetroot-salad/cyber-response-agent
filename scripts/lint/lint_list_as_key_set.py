#!/usr/bin/env python3
"""List-as-key-set smell — flag a fix-up pass that walks an ORDERED LIST to patch a
table already KEYED by that same list, so a repeated element patches one bucket twice.

The shape (#956, ``scripts/visualize/visualize_run.py``)::

    attribution = phase_attribution(events, phase_order, tags)   # keys came FROM phase_order
    ...
    for ph in phase_order:                                       # a LIST — may repeat a name
        attribution[ph]["cost"] += gather_by_phase.get(ph, 0.0)  # ← flagged

``phase_order`` is a render list — the investigation's ``## PHASE`` headers in the order
written. ``attribution`` is a dict keyed on the phase NAME. Two ``GATHER`` headers with no
``PLAN`` between them normalize to the same ``GATHER (loop N)``, so the name repeats, and
one bucket is visited twice: the cost is billed once per visit. The wall-time twin of the
same loop is worse — it reads ``duration_sec`` back out of the entry the previous visit
just wrote, so the adjustment COMPOUNDS rather than merely repeating.

The two meanings are the bug. A list that records *what happened in what order* and a key
set that names *the distinct things* are different values; spelling them with one name
makes the confusion invisible at every call site. Where both are wanted, derive them
separately at the one place the list is built (``dict.fromkeys(...)`` preserves order), and
give the deduped one its own name.

WHAT IS MECHANIZED
------------------
Both halves must hold inside ONE function, which is what separates this from the counting
idiom that shares its syntax:

  - the TABLE is bound in the function from a call that receives the sequence as an
    argument — ``D = f(..., SEQ, ...)``, including through a tuple unpack
    (``a, D = f(..., SEQ, ...)``). Its key set therefore came from ``SEQ``, so the loop is
    a fix-up pass over an existing table, not a tally being built.
  - the LOOP is ``for x in SEQ:`` over a bare ``Name``, whose body WRITES ``D[x]`` —
    ``D[x] = ...``, ``D[x] op= ...``, or a nested ``D[x][k] = ...``.

``Counter()``/``{}`` accumulation (``df[tok] += 1`` over a corpus, ``totals[k] += ...``
over messages) never matches: those tables are built empty and DISCOVER their keys, so a
repeat is the entire point. That distinction is the reason this gate is armed and a plain
"augmented assign into a dict keyed on the loop variable" rule is not — measured over the
tree, the plain rule fires six times and is wrong all six.

A sequence rebound from a provably-unique source in the same function — ``set(...)``,
``sorted(set(...))``, ``dict.fromkeys(...)``, ``.keys()``, a set/dict comprehension — is
skipped: repeats are impossible, so the loop is already the deduped walk this gate asks for.

WHAT IS **NOT** MECHANIZED — a clean run is NOT a clean tree
------------------------------------------------------------
  1. **Per-appearance RENDERING is invisible.** #956's third site emitted one bar segment
     per appearance while sizing each as a share of a once-counted total, so the segments
     overflowed 100%. It writes to no dict and this detector cannot see it. That half was
     also the half #956's own suggested fix missed — a gap worth knowing, because it is
     the half a reader notices first.
  2. **Cross-function fix-ups are invisible.** Both halves must sit in one function body;
     a table patched by a helper the loop calls does not match.
  3. **Whether the list can actually repeat is not decided here.** The gate fires on the
     shape and leaves the judgment to a reader — it cannot know that
     ``normalize_phase_names`` only advances its loop counter on a ``PLAN`` header. A
     sequence that genuinely cannot repeat is a suppression, not a redesign.

Mark a deliberate site with ``# lint-keyset: ok — <reason>`` on the loop's line span.
Pre-existing sites are ratcheted via ``lint_list_as_key_set_baseline.json`` (see
scripts/lint/_baseline.py); the gate fails only on a NEW file+function+names tuple.

Run from repo root:  python scripts/lint/lint_list_as_key_set.py
Regenerate the baseline:  python scripts/lint/lint_list_as_key_set.py --update-baseline
Exit 0 = clean (no new sites), 1 = new sites, 2 = the gate could not run.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

from _astlib import ScanBlind, read_and_parse
from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = REPO_ROOT / "defender"
BASELINE_PATH = Path(__file__).with_name("lint_list_as_key_set_baseline.json")

EXCLUDED_DIRS = (".venv", "__pycache__", "run-visualizations", "run-transcripts")
SUPPRESS_MARKER = "lint-keyset: ok"

#: Callables whose result cannot repeat an element. A sequence rebound from one of these
#: is already the deduped walk this gate asks for. `sorted` is here because its argument
#: is what decides — `sorted(set(x))` cannot repeat, `sorted(list(x))` can — and the
#: recursion below looks through it to the inner call rather than trusting the name.
_UNIQUE_CALLS = frozenset({"set", "frozenset", "fromkeys", "keys"})
_TRANSPARENT_CALLS = frozenset({"sorted", "list", "tuple", "reversed", "iter"})


def _callee_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return getattr(func, "id", "")


def _is_unique_source(node: ast.expr) -> bool:
    """True if `node` cannot produce the same element twice.

    Looks THROUGH the order/shape wrappers (`sorted`, `list`, ...) to whatever produced
    the elements, so `list(dict.fromkeys(order))` and `sorted(set(order))` both resolve to
    unique rather than to their outer call's name.
    """
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
    """`ast.walk`, but able to stop at a nested `def`.

    A function scope descends into its closures — one that patches its enclosing scope's
    table is the same defect, and only the outer walk can see where that table came from.
    MODULE scope must not, or every function is scanned twice and each finding is reported
    once under its own name and once under `<module>`.
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
    """`(name -> the calls it was bound from, names bound from a unique source)`.

    Both are collected in one walk over the scope's body.
    """
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
    """Names subscripted at `[var]` in a WRITE position anywhere inside `loop`.

    Walks out through nested subscripts so `d[var][k] = v` reports `d`, and so the
    fingerprint names the table rather than the innermost slice.
    """
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
    # Module scope stops at every `def`: without that, each function is scanned a second
    # time here and every finding is reported twice.
    findings.extend(_scan_function(rel, tree, "<module>", lines, into_functions=False))
    return findings


def _in_scope(path: Path) -> bool:
    return not any(part in EXCLUDED_DIRS for part in path.parts)


def _scan(root: Path) -> list[Finding]:
    """Findings under `root`, fingerprints relative to it — so the gate is drivable on an
    injected tmp tree, not just the repo checkout."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if not _in_scope(path):
            continue
        rel = path.relative_to(root).as_posix()
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
    # A file inside the scan scope that could not be read or parsed never entered the
    # corpus, so a double-counting fix-up could sit in it and this gate would still print
    # 0 findings. Exit 2 — the gate could not run, which is categorically not "clean"
    # (#618/#621/#652).
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
