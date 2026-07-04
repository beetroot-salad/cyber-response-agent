#!/usr/bin/env python3
"""Pitfalls curation mode (Stage 2) — fold agent-fixable general failures into each
system's ``execution.md`` ``## Common pitfalls``.

A second, cross-run, threshold-gated spawn that rides the SAME lead-author drain
(worktree / committer / PR) as the per-run author in ``lead_author.py``. It drains the
central pitfalls queue that the per-run tick fills (``collect_general_failures``) into
each system's ``execution.md`` — the file gather reads at dispatch, so the mistake is
PREVENTED next time, not merely catalogued. Its edit scope is disjoint from the per-run
agent's (``execution.md`` only), enforced by ``_verify_pitfalls_state``.

#455 Part 2 (#513): lifted out of ``lead_author.py`` so that module is the per-run
author only. Both modes share the spawn / verify / commit spine in ``_lead_spine``.
"""
from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports resolve whether
# this file is imported or run directly (mirrors lead_author.py; see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import shared as _author_shared
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist
from defender.learning.leads._lead_spine import (
    _log,
    _loop_commit_body,
    _spawn_author_agent,
    _verify_corpus_scope,
)
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import (
    LEARNING_DIR,
    SKILLS_REL,
    _is_system_execution_md,
)

LEAD_PITFALLS_PROMPT = LEARNING_DIR / "leads" / "lead_pitfalls.md"


def _build_pitfalls_handoffs(rows: list[dict]) -> list[dict]:
    """Group queued pitfalls by system → one handoff per system.

    Carries the repo-relative ``execution.md`` path the curator edits plus the
    failures to fold (query_id / goal / executed_query / stderr_digest). The
    curator Reads the execution.md itself — the handoff is records + path only,
    mirroring the system-draft handoff. Rows with no ``system`` are dropped.
    """
    by_system: dict[str, list[dict]] = {}
    for r in rows:
        system = str(r.get("system") or "").strip()
        if system:
            by_system.setdefault(system, []).append(r)
    out: list[dict] = []
    for system in sorted(by_system):
        out.append(
            {
                "system": system,
                "execution_md_path": f"{SKILLS_REL}{system}/execution.md",
                "failures": [
                    {
                        "query_id": f.get("query_id", ""),
                        "goal": f.get("goal", ""),
                        "executed_query": f.get("executed_query", ""),
                        "stderr_digest": f.get("stderr_digest", ""),
                    }
                    for f in by_system[system]
                ],
            }
        )
    return out


def _invoke_pitfalls_agent(handoffs: list[dict], *, repo_root: Path) -> int:
    """Spawn the pitfalls curator via ``_spawn_author_agent``. The coarse ``_ALLOWLIST``
    (Edit/Write ``defender/skills/**``) already covers execution.md; the ``rm`` grant goes
    unused (the curator only edits)."""
    user_prompt = (
        f"skills_dir: {SKILLS_REL}\n"
        f"pitfalls_handoffs ({len(handoffs)}):\n"
        f"{json.dumps(handoffs, indent=2)}\n"
    )
    return _spawn_author_agent(
        system_prompt_file=LEAD_PITFALLS_PROMPT,
        batch_id="pitfalls",
        user_prompt=user_prompt,
        repo_root=repo_root,
        log_label="pitfalls curator",
    )


def _pitfalls_path_rule(xy: str, path: str) -> None:
    """Per-path scope rule for the pitfalls curator: the ONLY permitted in-corpus change is an
    edit to a system ``execution.md``. Raises ``LeadAuthorError`` on any other skills path or
    on a deletion (execution.md is pruned in place, never removed)."""
    if not _is_system_execution_md(path):
        raise LeadAuthorError(
            f"pitfalls curator edited a non-execution.md skills path ({path}); "
            "refusing to commit (its scope is execution.md only)"
        )
    if "D" in xy:
        raise LeadAuthorError(
            f"pitfalls curator deleted {path}; refusing to commit "
            "(execution.md is pruned in place, never removed)"
        )


def _verify_pitfalls_state(repo_root: Path, baseline_stray: list[str]) -> list[str]:
    """Verify the curator's working-tree edits before the loop commits. Routes the shared
    preamble through ``_verify_corpus_scope`` and the per-path contract through
    ``_pitfalls_path_rule``; returns the changed paths."""
    return _verify_corpus_scope(
        repo_root, baseline_stray, actor="pitfalls curator", rule=_pitfalls_path_rule,
    )


def _pitfalls_commit_message(changed: list[str]) -> str:
    """Deterministic loop-authored message for the execution.md fold (fixed title)."""
    return _loop_commit_body(
        "learning(lead-author): execution.md pitfalls",
        "Folded agent-fixable general failures into per-system execution.md "
        "## Common pitfalls; loop-committed (the agent runs no git).",
        changed,
    )


def run_pitfalls(
    *,
    paths: _loop_config.LoopPaths = _loop_config.DEFAULT_PATHS,
    invoke: Callable[..., int] | None = None,
) -> int:
    """Curation mode: fold queued general failures into per-system ``execution.md``.

    Cross-run + threshold-gated (unlike the per-run tick). Below threshold it is a
    no-op with the queue intact. Otherwise: build per-system handoffs, spawn the
    curator (edits execution.md, runs no git), verify the working tree, commit
    pathspec-scoped, and rotate the processed batch out of the central queue. Runs
    inside the lead-author drain's worktree (``paths.repo_root``); the queue
    resolves to the shared state root.

    The batch rotates out once the curator has *processed* it (returned rc=0),
    whether or not it produced a commit — a no-edit tick is a valid outcome (the
    prompt blesses making no edits when every failure is already documented or too
    thin to name a fix), and an all-system-less batch can't be folded at all.
    Leaving such a batch queued would keep it at/above threshold and re-spawn the
    curator on the same un-foldable rows every drain tick. Rotation is immediate by
    design (no ``hold_committed``); a failure that recurs is re-collected.

    ``invoke`` is injectable for tests. Returns 0 on success / no-op / no-edit, 2
    on a curator spawn failure (queue left intact for retry). A scope violation
    raises ``LeadAuthorError``, which the drain (``_drain_pitfalls``) logs and
    swallows — discarding the worktree edits and leaving the queue intact; there is
    no marker to quarantine on this cross-run path.
    """
    rows = _loop_persist.read_pitfalls(paths)
    threshold = _loop_config.pitfalls_threshold()
    if len(rows) < threshold:
        if rows:
            _log(
                f"pitfalls queue below threshold (n={len(rows)}, "
                f"threshold={threshold}) — skipping curation"
            )
        return 0
    batch_ids = [str(r["pitfall_id"]) for r in rows if r.get("pitfall_id")]
    handoffs = _build_pitfalls_handoffs(rows)
    if not handoffs:
        # No row carried a system, so none maps to a defender/skills/{system}/
        # execution.md to fold into. Drop the batch rather than leave it stuck at
        # threshold re-waking the drain forever; an unfoldable row is dead weight.
        _log(f"{len(rows)} queued pitfall(s) but none carried a system — dropping")
        _loop_persist.rotate_pitfalls(batch_ids, None, paths=paths)
        return 0
    repo_root = paths.repo_root
    baseline_stray = _author_shared.changes_outside(repo_root, SKILLS_REL)
    _log(f"pitfalls curation: {len(rows)} failure(s) across {len(handoffs)} system(s)")

    rc = (invoke or _invoke_pitfalls_agent)(handoffs, repo_root=repo_root)
    if rc != 0:
        _log(f"FATAL: pitfalls curator exited rc={rc}; leaving queue intact")
        return 2

    changed = _verify_pitfalls_state(repo_root, baseline_stray)
    sha = None
    if changed:
        sha = _author_shared.commit_corpus(
            repo_root, repo_root / "defender" / "skills",
            _pitfalls_commit_message(changed),
        )
    else:
        _log("pitfalls curator made no execution.md edits (valid no-edit tick)")
    # Rotate whether or not a commit was made: the curator processed the batch, so
    # leaving it queued would only re-spawn the curator on the same rows next tick.
    _loop_persist.rotate_pitfalls(batch_ids, sha, paths=paths)
    _log(
        f"pitfalls curation done; commit={(sha or 'none')[:12]}, edits={len(changed)}, "
        f"rotated {len(batch_ids)} row(s) out of the queue"
    )
    return 0
