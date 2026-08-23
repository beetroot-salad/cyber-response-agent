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

import _cli
import _config
import _suite

# A `<name>=<value>` kwarg whose RHS is a threaded name/attribute (deps.salt, wt,
# <worktree>/anchor) — NOT `None`, a bare literal, or a quoted string. Those are
# signature-default declarations, not value threading, so they carry no coverage duty.
_KWARG = re.compile(r"\b([a-z_][a-z0-9_]*)\s*=\s*([A-Za-z_<][\w.<>/]*)")
_NON_THREAD_RHS = {"None", "True", "False"}


def _concept_root(bind: str) -> str:
    """The head concept of a `binds` entry: `salt.domain.distinguished[carried]` → `salt`,
    `read_surface.access[bash-cat]` → `read_surface`, `anchor_tree` → `anchor_tree`."""
    return re.split(r"[.\[]", bind, maxsplit=1)[0].strip()


@functools.lru_cache(maxsize=None)  # several graphs share a suite dir; parse it once
def _test_functions(test_dir: Path) -> dict[str, ast.AST]:
    """Map test-function name → its AST node, over the `*.py` files beside the graph.

    Two checks read this. The prose⊄binds scan wants only the docstring; the
    inspected-but-never-exercised scan wants the BODY. Both come off one parse."""
    fns: dict[str, ast.AST] = {}
    for py in _suite.suite_files(test_dir):
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


def _assert_scopes(fn: ast.AST) -> tuple[set[str], set[str]]:
    """Split a test's identifiers into (used outside any assert, used inside an assert).

    The exclusion must skip assert SUBTREES, not just the `Assert` node — `ast.walk` yields a
    statement's children independently of the statement, so a naive walk-and-skip puts every
    asserted name in both sets and the check inverts."""
    inside: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Assert):
            inside |= _suite.names_in(n)
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


class _Scan:
    """One graph's worth of context, resolved once and read by every rule below.

    The two checks are per-demand, but everything they compare a demand AGAINST is
    graph-wide — the modelled vocabulary, the waivers, the suite's parsed tests. Held
    here rather than threaded through each helper's signature.
    """

    def __init__(self, path: Path, cfg: dict) -> None:
        self.path = path
        graph = _cli.load_graph(path)
        self.demands: list[dict] = graph.get("demands", []) or []
        self.waivers: dict = graph.get("binds_waivers", {}) or {}
        self.exercise_waivers: dict = graph.get("exercise_waivers", {}) or {}
        self.suite_dir = _suite.suite_dir_for(path, graph)
        self.test_fns = _test_functions(self.suite_dir)
        # Code kwarg name → graph concept name, when the two disagree: the graph may model
        # the anchor tree as `anchor_tree` while the code threads it as the `anchor_dir=`
        # kwarg.
        #
        # The alias makes the check SEE such a demand, it does not silence one. A concept is
        # only flaggable when it is `modelled` — i.e. some demand binds it — and the graph
        # never binds the code's spelling (`anchor_dir`). So without the alias, prose
        # threading `anchor_dir=` maps to an unmodelled concept and is skipped: a false
        # NEGATIVE, exactly the escape this check exists to catch.
        #
        # Which is why this map should normally be EMPTY. The fix for a spelling mismatch is
        # to rename the graph to the code's name (schema.md, "Coin ids from the code's
        # name"), not to alias around it — an alias silently disables the check for any
        # concept whose entry someone forgets. Legitimate entries: a concept the code
        # genuinely spells differently per call site, or a third-party name you cannot rename.
        self.alias: dict[str, str] = cfg["conceptAliases"]
        # The graph's own vocabulary: every concept some demand binds is "modelled". A
        # threaded value we flag must be one the graph already treats as first-class somewhere.
        self.modelled: set[str] = {
            _concept_root(b) for d in self.demands for b in d.get("binds", []) or []
        }
        # A form:test demand carries its prose in the docstring of the test it names
        # (`discharged_by`); clause/waiver keep `outcome.nl`. Scan whichever holds the prose.
        self.docstrings = _test_docstrings(self.suite_dir)


def _pointer_prose(
    scan: _Scan, did: str, d: dict, test_name: str, findings: list[str]
) -> str | None:
    """A form:test demand's prose: the docstring of the test `discharged_by` names.

    Also runs the exercise check while the pointer is resolved — that check reads the
    test's BODY, so it must run before the empty-docstring gate below returns: a test
    with no docstring still has a body worth checking.
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
    record why). `outcome` is read up front, not inside the branch: a demand whose
    `outcome` is a scalar must still raise here, whatever else it carries."""
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
    opts, args = _cli.parse_argv(argv, valued={"--config"})
    cfg = _config.load(opts["config"])
    paths = [Path(a) for a in args] or _config.artifacts(cfg)
    if not paths:
        # 2, not 0 (#949): "there was nothing to read" is a could-not-look, not a clean run.
        # `check_claims`, `check_lint` and `check_gate` all return 2 on this identical branch,
        # and this file's own unreadable-graph arm returns 2 four lines down — this was the one
        # member of the family that reported an empty corpus as a pass.
        print("check_binds: no spec_graph_*.yaml found", file=sys.stderr)
        return 2
    all_findings: list[str] = []
    unreadable: list[Path] = []
    for p in paths:
        # The family's could-not-read contract (exit 2): a list-top-level graph used to
        # surface as an AttributeError traceback behind exit 1 ("found findings").
        try:
            all_findings.extend(check(p, cfg))
        except (OSError, yaml.YAMLError, TypeError, AttributeError) as e:
            print(f"check_binds: cannot read {p}: {e.__class__.__name__}: {e}", file=sys.stderr)
            unreadable.append(p)
            continue
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
    if unreadable:
        return 2
    return 1 if n else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
