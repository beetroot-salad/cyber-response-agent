#!/usr/bin/env python3
"""spec-graph check #1 — prose-token ⊄ binds (the F7 class), plus the unexercised-seam check.

Two checks, both deterministic, both over a demand's `binds`:

* **prose ⊄ binds** — a concept a demand's PROSE threads but its `binds` omits. Documented in
  full below; it is the check this module was forged on.
* **inspected but never exercised** — a demand binding `drives(A->B)` whose test names `B` only
  inside an `assert`. The demand claims a wiring; the test checks a shape. See `_unexercised`
  for the #540 defect that produced it — a `parity` demand discharged by
  `assert isinstance(deps.box, BoxExecutor)`, where the field's own default IS a `BoxExecutor`,
  so the assertion could not fail and two roles shipped with no box attached.

Both fail the run (exit 1) and are counted separately, because they name different slips.

--- prose ⊄ binds ---

A write-tests spec graph (`spec_graph_*.yaml`, committed beside the tests) is a list of
*demands*, each with a `binds` list naming the graph elements it covers. The gate rules
R0–R6 reason over `binds` (the edges), NOT the prose — so a value named in a demand's prose
but not wired into its `binds` is INVISIBLE to the rules, and the realized test silently
drops the assertion.

Where the prose lives depends on form. A `form: test` demand is a POINTER: it carries no
`outcome`, and its observable-outcome prose lives in the docstring of the test it names via
`discharged_by` (the test IS the demand's executable form). A `form: clause` or
`form: waiver` demand has no test, so it keeps an `outcome: {nl}`. This check scans whichever
holds the prose — the pointed-to test's docstring, or the `outcome`. (A legacy `form: test`
demand that still inlines an `outcome` and names no test is scanned via that `outcome`.)

The canonical escape (the class this check was forged on): a demand whose prose read
"…threads `salt=deps.salt`…" bound only the anchor tree — so nothing forced the test to
assert the salt, and a refactor that dropped it would have failed a prompt-injection defence
OPEN with every test still green.

THE CHECK (deterministic, no LLM): for each demand, take its prose (the pointed-to test's
docstring, or `outcome.nl`) and find every `<concept>=<value>` kwarg where the value is a
threaded name/attribute (not `None`/a literal). Map the concept through the
code-name→graph-name alias, and if that graph concept is *modelled elsewhere in the graph*
(it is the root of some `binds` entry) but is NOT in THIS demand's `binds`, flag it: the
demand threads a first-class concept it doesn't cover. A `form: test` demand whose
`discharged_by` names no test in the suite dir is a dangling pointer — also flagged, since a
pointer to nothing scans nothing; a pointer to a test with an EMPTY docstring is flagged for
the same reason (the demand's prose is required to live there — SKILL.md step 8).

Grounding: the graph's own vocabulary is the oracle — a concept is "modelled" iff some
demand binds it. We only flag threading of a concept the graph already treats as real, so
an incidental mention of an unmodelled local never trips it. The docstring is scanned, not
the test body: the body threads every entry-point argument, but the docstring carries only
the concepts the demand's contract is about — the same prose the pre-pointer `outcome` held.

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

import _config

# A `<name>=<value>` kwarg whose RHS is a threaded name/attribute (deps.salt, wt,
# <worktree>/anchor) — NOT `None`, a bare literal, or a quoted string. Those are
# signature-default declarations, not value threading, so they carry no coverage duty.
_KWARG = re.compile(r"\b([a-z_][a-z0-9_]*)\s*=\s*([A-Za-z_<][\w.<>/]*)")
_NON_THREAD_RHS = {"None", "True", "False"}


def _concept_root(bind: str) -> str:
    """The head concept of a `binds` entry: `salt.domain.distinguished[carried]` → `salt`,
    `read_surface.access[bash-cat]` → `read_surface`, `anchor_tree` → `anchor_tree`."""
    return re.split(r"[.\[]", bind, maxsplit=1)[0].strip()


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@functools.lru_cache(maxsize=None)  # several graphs share a suite dir; parse it once
def _test_functions(test_dir: Path) -> dict[str, ast.AST]:
    """Map test-function name → its AST node, over the `*.py` files beside the graph.

    Two checks read this. The prose⊄binds scan wants only the docstring; the
    inspected-but-never-exercised scan wants the BODY. Both come off one parse."""
    fns: dict[str, ast.AST] = {}
    for py in sorted(test_dir.glob("*.py")):
        if re.search(r"\.copy\d+\.py$", py.name):
            continue
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        except (SyntaxError, OSError, ValueError) as e:  # ValueError covers UnicodeDecodeError
            # Not silent — see _test_docstrings' note; the same fail-closed consequences apply.
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


def _names_in(node: ast.AST) -> set[str]:
    """Every identifier reachable from `node` — bare names and attribute tails alike, so
    `box.BoxExecutor` and a bare `BoxExecutor` both answer to `BoxExecutor`."""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
    return out


def _assert_scopes(fn: ast.AST) -> tuple[set[str], set[str]]:
    """Split a test's identifiers into (used outside any assert, used inside an assert).

    The exclusion must skip assert SUBTREES, not just the `Assert` node — `ast.walk` yields a
    statement's children independently of the statement, so a naive walk-and-skip puts every
    asserted name in both sets and the check inverts."""
    inside: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Assert):
            inside |= _names_in(n)
    outside: set[str] = set()

    def rec(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Assert):
                continue          # the whole assert subtree is inspection, not exercise
            if isinstance(child, ast.Name):
                outside.add(child.id)
            elif isinstance(child, ast.Attribute):
                outside.add(child.attr)
            rec(child)

    rec(fn)
    return outside, inside


def _test_docstrings(test_dir: Path) -> dict[str, str]:
    """Map test-function name → its docstring, over the `*.py` files beside the graph.

    The artifact rule commits the suite in the same directory as `spec_graph_*.yaml`, so a
    `form: test` demand's `discharged_by` names a function defined here. That docstring is the
    relocated home of the demand's prose — what this check scans in place of `outcome`. First
    definition of a name wins (test names are unique across a suite); an unparseable or
    unreadable file is skipped, not fatal — a broken suite is step-9's null-stub gate to catch,
    not this one's. `shuffle-premises` copies (`*.copyN.py`) are excluded: they carry the same
    test names with premise-only docstrings, sort before the real file, and would silently
    shadow the prose this check exists to scan.

    The parse — and its unscannable-file WARN, whose fail-closed consequences are unchanged —
    lives in `_test_functions`. This is the docstring projection of that one parse.
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

    The class (found in #540's own graph): `d_every_bash_enabled_role_has_a_box` bound
    `drives(_tool_bash->BoxExecutor)` and discharged it with

        deps = bind(defn, run_dir, ...)            # no box= threaded
        assert isinstance(deps.box, box.BoxExecutor)

    `AgentDeps.box` defaults to `field(default_factory=BoxExecutor)`, so the inert default and
    an attached container are the SAME TYPE and the assertion cannot fail. The demand's content
    is attachment; the test asserts only the field's type. It stayed green through a change that
    left two bash-enabled roles with no box at all.

    The discriminator is deliberately NARROW: B present, but present only inside `assert`
    statements. "B absent entirely" is NOT flagged — a test that drives the real loop reaches B
    through production wiring and never names it (`test_the_existing_e2e_bash_corpus_...` reaches
    `_tool_bash` only via the driver's tool registration), so requiring a mention there is a false
    positive. What is left is the shape that cannot be anything but inspection: the test knows B
    well enough to name it, and never once puts it to work.

    Measured over every `spec_graph_*.yaml` in this repo at authoring time — 14 `drives()`
    bindings across 17 graphs — this fires exactly once, on the defect above. That corpus is
    small; widen the rule only against a bigger one.
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


def check(path: Path, cfg: dict) -> list[str]:
    graph = _load(path)
    demands = graph.get("demands", []) or []
    waivers = graph.get("binds_waivers", {}) or {}
    exercise_waivers = graph.get("exercise_waivers", {}) or {}
    test_fns = _test_functions(path.parent)
    # Code kwarg name → graph concept name, when the two disagree: the graph may model the
    # anchor tree as `anchor_tree` while the code threads it as the `anchor_dir=` kwarg.
    #
    # The alias makes the check SEE such a demand, it does not silence one. A concept is only
    # flaggable when it is `modelled` — i.e. some demand binds it — and the graph never binds
    # the code's spelling (`anchor_dir`). So without the alias, prose threading `anchor_dir=`
    # maps to an unmodelled concept and is skipped: a false NEGATIVE, exactly the escape this
    # check exists to catch.
    #
    # Which is why this map should normally be EMPTY. The fix for a spelling mismatch is to
    # rename the graph to the code's name (schema.md, "Coin ids from the code's name"), not to
    # alias around it — an alias silently disables the check for any concept whose entry someone
    # forgets. Legitimate entries: a concept the code genuinely spells differently per call site,
    # or a third-party name you cannot rename.
    alias: dict[str, str] = cfg["conceptAliases"]

    # The graph's own vocabulary: every concept some demand binds is "modelled". A threaded
    # value we flag must be one the graph already treats as first-class somewhere.
    modelled: set[str] = set()
    for d in demands:
        for b in d.get("binds", []) or []:
            modelled.add(_concept_root(b))

    # A form:test demand carries its prose in the docstring of the test it names
    # (`discharged_by`); clause/waiver keep `outcome.nl`. Scan whichever holds the prose.
    docstrings = _test_docstrings(path.parent)

    findings: list[str] = []
    for d in demands:
        did = d.get("id", "<no-id>")
        outcome_nl = (d.get("outcome", {}) or {}).get("nl", "") or ""
        test_name = d.get("discharged_by")
        if test_name:
            suite_dir = path.resolve().parent.name
            if test_name not in docstrings:
                findings.append(
                    f"ORPHAN {path.name}:{did}: `discharged_by: {test_name}` names no test function "
                    f"in {suite_dir}/ — the pointer dangles, so its prose is unscannable "
                    f"(write the test, or fix the name)."
                )
                continue
            # The exercise check reads the BODY, so it runs before the docstring gate below —
            # a test with no docstring still has a body worth checking.
            if test_name in test_fns:
                findings.extend(_unexercised(
                    path, did, d, test_fns[test_name],
                    set(exercise_waivers.get(did, []) or []),
                ))
            prose = docstrings[test_name]
            if not prose.strip():
                findings.append(
                    f"ORPHAN {path.name}:{did}: `discharged_by: {test_name}` points at a test with "
                    f"no docstring — the demand's prose is missing, so there is nothing to check "
                    f"against `binds` (step 8 puts the outcome sentence in that docstring)."
                )
                continue
        elif outcome_nl:
            prose = outcome_nl  # clause/waiver, or a legacy form:test demand inlining its outcome
        elif d.get("form", "test") == "test":
            findings.append(
                f"ORPHAN {path.name}:{did}: form:test demand carries neither `discharged_by` nor "
                f"`outcome` — no prose to check for prose⊄binds (add the `discharged_by` pointer)."
            )
            continue
        else:
            continue  # a clause/waiver with no prose has nothing to scan
        bind_roots = {_concept_root(b) for b in (d.get("binds", []) or [])}
        waived = set(waivers.get(did, []) or [])
        seen: set[str] = set()
        for kw, rhs in _KWARG.findall(prose):
            if rhs in _NON_THREAD_RHS:
                continue  # signature default, not a threaded value
            concept = alias.get(kw, kw)
            if concept in seen:
                continue
            seen.add(concept)
            if concept in modelled and concept not in bind_roots and concept not in waived:
                findings.append(
                    f"ORPHAN {path.name}:{did}: threads `{kw}={rhs}` in prose but does not bind "
                    f"`{concept}` — the gate rules cover {sorted(bind_roots)}, so the "
                    f"`{concept}` assertion is untracked (bind it, or waive under binds_waivers)."
                )
    return findings


def main(argv: list[str]) -> int:
    config: str | None = None
    args = []
    it = iter(argv)
    for a in it:
        if a == "--config":
            config = next(it, None)
        else:
            args.append(a)
    cfg = _config.load(config)
    paths = [Path(a) for a in args] or _config.artifacts(cfg)
    if not paths:
        print("check_binds: no spec_graph_*.yaml found", file=sys.stderr)
        return 0
    all_findings: list[str] = []
    for p in paths:
        all_findings.extend(check(p, cfg))
    for f in all_findings:
        print(f"  {f}")
    n = len(all_findings)
    # Counted by kind: the two findings answer different questions (a demand that under-BINDS a
    # concept vs. one whose test never EXERCISES a seam it binds), and collapsing them into one
    # number hides which discipline slipped.
    orphans = sum(1 for f in all_findings if f.startswith("ORPHAN "))
    print(
        f"\n[check_binds] {orphans} prose-orphan(s), {n - orphans} unexercised seam(s) "
        f"over {len(paths)} graph(s)."
    )
    return 1 if n else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
