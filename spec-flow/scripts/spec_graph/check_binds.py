#!/usr/bin/env python3
"""spec-graph check #1 — prose-token ⊄ binds (the F7 class).

A write-tests spec graph (`spec_graph_*.yaml`, committed beside the tests) is a list of
*demands*, each with a natural-language `outcome` and a `binds` list naming the graph
elements it covers. The gate rules R0–R5 reason over `binds` (the edges), NOT the prose — so
a value named in a demand's prose but not wired into its `binds` is INVISIBLE to the rules,
and the realized test silently drops the assertion.

The canonical escape (the project this check was forged in): a demand whose outcome read
"…threads `salt=deps.salt`…" bound only the anchor tree — so nothing forced the test to
assert the salt, and a refactor that dropped it would have failed a prompt-injection defence
OPEN with every test still green.

THE CHECK (deterministic, no LLM): for each demand, find every `<concept>=<value>` kwarg
in the prose where the value is a threaded name/attribute (not `None`/a literal). Map the
concept through the code-name→graph-name alias, and if that graph concept is *modelled
elsewhere in the graph* (it is the root of some `binds` entry) but is NOT in THIS demand's
`binds`, flag it: the demand threads a first-class concept it doesn't cover.

Grounding: the graph's own vocabulary is the oracle — a concept is "modelled" iff some
demand binds it. We only flag threading of a concept the graph already treats as real, so
an incidental mention of an unmodelled local never trips it.

Usage:
    python "$CLAUDE_PLUGIN_ROOT"/scripts/spec_graph/check_binds.py [graph.yaml ...] [--config <path>]
Exit 1 if any orphan is found. Waive a deliberate incidental mention by binding the
concept (preferred — then the test is forced to assert it) or by listing the demand id +
concept under a top-level `binds_waivers:` map in the graph.
"""
from __future__ import annotations

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


def check(path: Path, cfg: dict) -> list[str]:
    graph = _load(path)
    demands = graph.get("demands", []) or []
    waivers = graph.get("binds_waivers", {}) or {}
    # Code kwarg name → graph concept name, when the two disagree (a graph may model the
    # anchor tree as `anchor_tree` while the code threads it as `anchor_dir=`). Without the
    # alias the check false-flags every such kwarg as unbound. Project-configured.
    alias: dict[str, str] = cfg["conceptAliases"]

    # The graph's own vocabulary: every concept some demand binds is "modelled". A threaded
    # value we flag must be one the graph already treats as first-class somewhere.
    modelled: set[str] = set()
    for d in demands:
        for b in d.get("binds", []) or []:
            modelled.add(_concept_root(b))

    findings: list[str] = []
    for d in demands:
        did = d.get("id", "<no-id>")
        prose = (d.get("outcome", {}) or {}).get("nl", "") or ""
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
