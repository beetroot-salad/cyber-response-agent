#!/usr/bin/env python3
"""spec-graph check #1 — prose-token ⊄ binds (the F7 class).

A write-tests spec graph (`spec_graph_*.yaml`, committed beside the tests) is a list of
*demands*, each with a `binds` list naming the graph elements it covers. The gate rules
R0–R5 reason over `binds` (the edges), NOT the prose — so a value named in a demand's prose
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
pointer to nothing scans nothing.

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
    with path.open() as fh:
        return yaml.safe_load(fh)


def _test_docstrings(test_dir: Path) -> dict[str, str]:
    """Map test-function name → its docstring, over the `*.py` files beside the graph.

    The artifact rule commits the suite in the same directory as `spec_graph_*.yaml`, so a
    `form: test` demand's `discharged_by` names a function defined here. That docstring is the
    relocated home of the demand's prose — what this check scans in place of `outcome`. First
    definition of a name wins (test names are unique across a suite); an unparseable or
    unreadable file is skipped, not fatal — a broken suite is step-9's null-stub gate to catch,
    not this one's.
    """
    docs: dict[str, str] = {}
    for py in sorted(test_dir.glob("*.py")):
        try:
            tree = ast.parse(py.read_text(), filename=str(py))
        except (SyntaxError, OSError, ValueError):  # ValueError covers UnicodeDecodeError
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                docs.setdefault(node.name, ast.get_docstring(node) or "")
    return docs


def check(path: Path, cfg: dict) -> list[str]:
    graph = _load(path)
    demands = graph.get("demands", []) or []
    waivers = graph.get("binds_waivers", {}) or {}
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
            if test_name not in docstrings:
                findings.append(
                    f"{path.name}:{did}: `discharged_by: {test_name}` names no test function in "
                    f"{path.parent.name}/ — the pointer dangles, so its prose is unscannable "
                    f"(write the test, or fix the name)."
                )
                continue
            prose = docstrings[test_name]
        elif outcome_nl:
            prose = outcome_nl  # clause/waiver, or a legacy form:test demand inlining its outcome
        elif d.get("form", "test") == "test":
            findings.append(
                f"{path.name}:{did}: form:test demand carries neither `discharged_by` nor "
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
                    f"{path.name}:{did}: threads `{kw}={rhs}` in prose but does not bind "
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
        print(f"  ORPHAN {f}")
    n = len(all_findings)
    print(f"\n[check_binds] {n} prose-orphan(s) over {len(paths)} graph(s).")
    return 1 if n else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
