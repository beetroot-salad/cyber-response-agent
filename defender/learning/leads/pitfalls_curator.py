#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import shared as _author_shared
from defender.learning.core import config as _loop_config
from defender.learning.core import persist as _loop_persist
from defender.learning.leads._lead_spine import (
    PENDING_DIR,
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
        learning_run_dir=PENDING_DIR,
        log_label="pitfalls curator",
    )


def _pitfalls_path_rule(xy: str, path: str) -> None:
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
    return _verify_corpus_scope(
        repo_root, baseline_stray, actor="pitfalls curator", rule=_pitfalls_path_rule,
    )


def _pitfalls_commit_message(changed: list[str]) -> str:
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
    _loop_persist.rotate_pitfalls(batch_ids, sha, paths=paths)
    _log(
        f"pitfalls curation done; commit={(sha or 'none')[:12]}, edits={len(changed)}, "
        f"rotated {len(batch_ids)} row(s) out of the queue"
    )
    return 0
