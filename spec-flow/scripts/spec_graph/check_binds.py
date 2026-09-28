#!/usr/bin/env python3
"""spec-graph check #1 — prose-token ⊄ binds, plus the unexercised-seam check.

Two deterministic checks over a demand's `binds`, counted separately (both exit 1):

* **prose ⊄ binds**: a concept a demand's prose threads but its `binds` omits.
* **inspected but never exercised**: a demand binding `drives(A->B)` whose test names `B`
  only inside an `assert` (see `_unexercised`).

--- prose ⊄ binds ---

A spec graph's demands each carry a `binds` list naming the graph elements they cover. The
gate rules reason over `binds`, not prose, so a value named in the prose but not bound is
invisible to them and the test can silently drop the assertion (e.g. prose threading
`salt=deps.salt` while binding only the anchor tree lets a refactor drop the salt with every
test green).

Where the prose lives depends on form. A `form: test` demand is a pointer: its prose lives
in the docstring of the test named by `discharged_by`. A `form: clause` or `form: waiver`
demand keeps an `outcome: {nl}`. (A legacy `form: test` demand that inlines an `outcome` and
names no test is scanned via that `outcome`.)

For each demand's prose, find every `<concept>=<value>` kwarg whose value is a threaded
name/attribute (not `None` or a literal), map the concept through the code-name→graph-name
alias, and flag it if some other demand binds that concept but this one does not. Only
concepts the graph already models are flagged, so incidental locals never trip it. The
docstring is scanned rather than the test body, because the body threads every entry-point
argument while the docstring carries only the demand's contract. A `discharged_by` naming
no test, or a test with an empty docstring, is also flagged.

Usage:
    spec-graph binds [graph.yaml ...] [--config <path>]
(the `spec-graph` wrapper in the plugin's bin/ is on the Bash PATH and finds this script itself;
`$CLAUDE_PLUGIN_ROOT` does NOT expand in SKILL.md prose, so never spell a path with it).
Exit 1 if any orphan is found. Waive a deliberate incidental mention by binding the
concept (preferred — then the test is forced to assert it) or by listing the demand id +
concept under a top-level `binds_waivers:` map in the graph.
"""
from __future__ import annotations

import ast
import functools
import re
import sys
from pathlib import Path

import yaml

import _cli
import _config
import _suite

# A `<name>=<value>` kwarg whose RHS is a threaded name/attribute (deps.salt, wt,
# <worktree>/anchor). `None`, literals, and quoted strings are signature defaults, not threading.
_KWARG = re.compile(r"\b([a-z_][a-z0-9_]*)\s*=\s*([A-Za-z_<][\w.<>/]*)")
_NON_THREAD_RHS = {"None", "True", "False"}


def _concept_root(bind: str) -> str:
    """The head concept of a `binds` entry: `salt.domain.distinguished[carried]` → `salt`,
    `read_surface.access[bash-cat]` → `read_surface`, `anchor_tree` → `anchor_tree`."""
    return re.split(r"[.\[]", bind, maxsplit=1)[0].strip()


@functools.lru_cache(maxsize=None)  # several graphs share a suite dir
def _test_functions(test_dir: Path) -> dict[str, ast.AST]:
    """Map test-function name → its AST node, over the `*.py` files beside the graph.

    The prose⊄binds scan reads the docstrings, the unexercised scan the bodies.

    First definition of a name wins. An unparseable or unreadable file is skipped with a
    WARN (a broken suite is the null-stub gate's finding), so a `discharged_by` naming one of
    its tests reports as dangling."""
    fns: dict[str, ast.AST] = {}
    for py in _suite.suite_files(test_dir):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        except (SyntaxError, OSError, ValueError) as e:  # ValueError covers UnicodeDecodeError
            print(
                f"  WARN [check_binds] {py}: unscannable ({e.__class__.__name__}: {e}) — its test "
                f"docstrings are absent from this check; a `discharged_by` naming one will report "
                f"as dangling, and a name it shares with another file resolves to that file's prose",
                file=sys.stderr,
            )
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fns.setdefault(node.name, node)
    return fns


def _assert_scopes(fn: ast.AST) -> tuple[set[str], set[str]]:
    """Split a test's identifiers into (used outside any assert, used inside an assert).

    Skips whole assert subtrees: `ast.walk` yields a statement's children independently, so
    skipping only the `Assert` node would put every asserted name in both sets."""
    inside: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Assert):
            inside |= _suite.names_in(n)
    outside: set[str] = set()

    def rec(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Assert):
                continue
            if isinstance(child, ast.Name):
                outside.add(child.id)
            elif isinstance(child, ast.Attribute):
                outside.add(child.attr)
            rec(child)

    rec(fn)
    return outside, inside


def _test_docstrings(test_dir: Path) -> dict[str, str]:
    """Map test-function name → its docstring (the demand's prose for a `form: test` demand).

    A projection of `_test_functions`' parse.
    """
    return {
        name: (ast.get_docstring(node) or "")
        for name, node in _test_functions(test_dir).items()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


#: A `drives(A->B)` binds entry: the demand claims its test drives A, reaching B. A trailing
#: `.suffix` (`interacts(X->Y).response`) is tolerated by matching only the head.
_DRIVES = re.compile(r"drives\(\s*([\w.]+)\s*->\s*([\w.]+)\s*\)")


def _unexercised(
    path: Path, did: str, demand: dict, fn: ast.AST, waived: set[str]
) -> list[str]:
    """Flag a `drives(A->B)` demand whose test names B ONLY inside an assertion.

    Example: a demand binding `drives(_tool_bash->BoxExecutor)` discharged by

        deps = bind(defn, run_dir, ...)            # no box= threaded
        assert isinstance(deps.box, box.BoxExecutor)

    cannot fail, because `AgentDeps.box` defaults to a `BoxExecutor`: the test checks a type,
    not an attachment.

    Deliberately narrow: B absent entirely is not flagged, since a test driving the real loop
    reaches B through production wiring without naming it. Widen only against a larger corpus.
    """
    outside, inside = _assert_scopes(fn)
    findings: list[str] = []
    seen: set[str] = set()
    for b in demand.get("binds", []) or []:
        m = _DRIVES.search(str(b))
        if not m:
            continue
        driver, target = m.group(1), m.group(2)
        if target in seen or target in waived:
            continue
        seen.add(target)
        if target in inside and target not in outside:
            findings.append(
                f"UNEXERCISED {path.name}:{did}: binds `drives({driver}->{target})`, but its test "
                f"names `{target}` only inside an assertion — it INSPECTS the seam without ever "
                f"exercising it, so the demand is discharged by a shape check that holds whether "
                f"or not {driver} is wired to {target} (drive {driver} and assert the observable "
                f"outcome, or waive under exercise_waivers)."
            )
    return findings


class _Scan:
    """One graph's graph-wide context (modelled vocabulary, waivers, parsed tests), resolved
    once for the per-demand checks."""

    def __init__(self, path: Path, cfg: dict) -> None:
        self.path = path
        graph = _cli.load_graph(path)
        self.demands: list[dict] = graph.get("demands", []) or []
        self.waivers: dict = graph.get("binds_waivers", {}) or {}
        self.exercise_waivers: dict = graph.get("exercise_waivers", {}) or {}
        # Anchored on the graph: it may live in another checkout than the process cwd.
        self.suite_dir = _suite.suite_dir_for(path, graph, root=path.parent)
        self.test_fns = _test_functions(self.suite_dir)
        # Code kwarg name → graph concept name, when the two disagree (`anchor_dir=` vs
        # `anchor_tree`). Without it such prose maps to an unmodelled concept and is skipped.
        # Normally empty: prefer renaming the graph to the code's name (schema.md); use an
        # alias only for per-call-site spellings or third-party names.
        self.alias: dict[str, str] = cfg["conceptAliases"]
        # Every concept some demand binds is "modelled"; only those are flagged.
        self.modelled: set[str] = {
            _concept_root(b) for d in self.demands for b in d.get("binds", []) or []
        }
        self.docstrings = _test_docstrings(self.suite_dir)


def _pointer_prose(
    scan: _Scan, did: str, d: dict, test_name: str, findings: list[str]
) -> str | None:
    """A form:test demand's prose: the docstring of the test `discharged_by` names.

    Also runs the exercise check, before the empty-docstring return: a test with no
    docstring still has a body worth checking.
    """
    path = scan.path
    suite_dir = scan.suite_dir.name
    if test_name not in scan.docstrings:
        findings.append(
            f"ORPHAN {path.name}:{did}: `discharged_by: {test_name}` names no test function "
            f"in {suite_dir}/ — the pointer dangles, so its prose is unscannable "
            f"(write the test, or fix the name)."
        )
        return None
    if test_name in scan.test_fns:
        findings.extend(_unexercised(
            path, did, d, scan.test_fns[test_name],
            set(scan.exercise_waivers.get(did, []) or []),
        ))
    prose = scan.docstrings[test_name]
    if not prose.strip():
        findings.append(
            f"ORPHAN {path.name}:{did}: `discharged_by: {test_name}` points at a test with "
            f"no docstring — the demand's prose is missing, so there is nothing to check "
            f"against `binds` (step 8 puts the outcome sentence in that docstring)."
        )
        return None
    return prose


def _demand_prose(scan: _Scan, did: str, d: dict, findings: list[str]) -> str | None:
    """Where this demand's prose lives, or None when there is none to scan (the findings
    record why). `outcome` is read up front so a scalar `outcome` raises regardless."""
    outcome_nl = (d.get("outcome", {}) or {}).get("nl", "") or ""
    test_name = d.get("discharged_by")
    if test_name:
        return _pointer_prose(scan, did, d, test_name, findings)
    if outcome_nl:
        return outcome_nl  # clause/waiver, or a legacy form:test demand inlining its outcome
    if d.get("form", "test") == "test":
        findings.append(
            f"ORPHAN {scan.path.name}:{did}: form:test demand carries neither `discharged_by` "
            f"nor `outcome` — no prose to check for prose⊄binds (add the `discharged_by` "
            f"pointer)."
        )
    return None  # a clause/waiver with no prose has nothing to scan


def _prose_orphans(scan: _Scan, did: str, d: dict, prose: str) -> list[str]:
    """The check proper: a concept this demand's prose THREADS, the graph models, and its
    own `binds` omits."""
    bind_roots = {_concept_root(b) for b in (d.get("binds", []) or [])}
    waived = set(scan.waivers.get(did, []) or [])
    findings: list[str] = []
    seen: set[str] = set()
    for kw, rhs in _KWARG.findall(prose):
        if rhs in _NON_THREAD_RHS:
            continue  # signature default, not a threaded value
        concept = scan.alias.get(kw, kw)
        if concept in seen:
            continue
        seen.add(concept)
        if concept in scan.modelled and concept not in bind_roots and concept not in waived:
            findings.append(
                f"ORPHAN {scan.path.name}:{did}: threads `{kw}={rhs}` in prose but does not "
                f"bind `{concept}` — the gate rules cover {sorted(bind_roots)}, so the "
                f"`{concept}` assertion is untracked (bind it, or waive under binds_waivers)."
            )
    return findings


def check(path: Path, cfg: dict) -> list[str]:
    scan = _Scan(path, cfg)
    findings: list[str] = []
    for d in scan.demands:
        did = d.get("id", "<no-id>")
        prose = _demand_prose(scan, did, d, findings)
        if prose is None:
            continue
        findings.extend(_prose_orphans(scan, did, d, prose))
    return findings


def main(argv: list[str]) -> int:
    _cli.utf8_stdio()
    opts, args = _cli.parse_argv(argv, valued={"--config"})
    cfg = _config.load(opts["config"])
    paths = [Path(a) for a in args] or _config.artifacts(cfg)
    if not paths:
        # Nothing to read is could-not-look (2), not a clean run.
        print("check_binds: no spec_graph_*.yaml found", file=sys.stderr)
        return 2
    all_findings: list[str] = []
    unreadable: list[Path] = []
    for p in paths:
        # An unreadable graph is exit 2 (could not look), not a traceback behind exit 1.
        try:
            all_findings.extend(check(p, cfg))
        # `ValueError` covers UnicodeDecodeError, which is not an OSError.
        except (OSError, ValueError, yaml.YAMLError, TypeError, AttributeError) as e:
            print(f"check_binds: cannot read {p}: {e.__class__.__name__}: {e}", file=sys.stderr)
            unreadable.append(p)
            continue
    for f in all_findings:
        print(f"  {f}")
    n = len(all_findings)
    # Counted by kind: under-binding and never-exercising are different slips.
    orphans = sum(1 for f in all_findings if f.startswith("ORPHAN "))
    print(
        f"\n[check_binds] {orphans} prose-orphan(s), {n - orphans} unexercised seam(s) "
        f"over {len(paths)} graph(s)."
    )
    if unreadable:
        return 2
    return 1 if n else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
