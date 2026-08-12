#!/usr/bin/env python3
from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from uuid import uuid4
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import shared as _author_shared
from defender._untrusted import wrap
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
from defender.learning.pipeline._prompt import stage_user_message, structured_json_body
from defender.learning.leads.path_validation import (
    LEARNING_DIR,
    SKILLS_REL,
    _is_system_execution_md,
)

LEAD_PITFALLS_PROMPT = LEARNING_DIR / "leads" / "lead_pitfalls.md"


def _build_pitfalls_handoffs(rows: list[dict]) -> list[dict]:
    """One entry per system, one failure per distinct MISTAKE (#840).

    Merges the rows itself rather than trusting its caller to have merged them — the merge
    is idempotent, and this is the last seam before the prompt, so no reader of the queue
    can hand the curator N copies of one bullet. `occurrences` rides along and orders the
    list, so the mistake a lead made eight times is the first failure the curator weighs,
    not the eighth copy it has to notice is a copy.
    """
    by_system: dict[str, list[dict]] = {}
    for r in _loop_persist.merge_pitfalls(rows):
        system = str(r.get("system") or "").strip()
        if system:
            by_system.setdefault(system, []).append(r)
    out: list[dict] = []
    for system in sorted(by_system):
        # `occurrences` is stamped on every record `merge_pitfalls` returns, so it is read
        # here as a key, not coalesced a second time.
        failures = sorted(by_system[system], key=lambda f: f["occurrences"], reverse=True)
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
                        "occurrences": f["occurrences"],
                    }
                    for f in failures
                ],
            }
        )
    return out


def _invoke_pitfalls_agent(
    handoffs: list[dict], *, repo_root: Path,
    spawn: Callable[..., int] = _spawn_author_agent,
    salt: str | None = None,
    box=None,
) -> int:
    stage_salt = salt if salt is not None else uuid4().hex
    user_prompt = stage_user_message(
        stage_salt,
        wrap(f"skills_dir: {SKILLS_REL}", "pitfalls_context", stage_salt),
        wrap(structured_json_body(handoffs), "pitfalls_handoffs", stage_salt),
    )
    return spawn(
        system_prompt_file=LEAD_PITFALLS_PROMPT,
        batch_id="pitfalls",
        user_prompt=user_prompt,
        repo_root=repo_root,
        learning_run_dir=PENDING_DIR,
        log_label="pitfalls curator",
        salt=stage_salt, box=box,
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
    box=None,
) -> int:
    rows = _loop_persist.read_pitfalls(paths)
    # The gate counts DISTINCT MISTAKES, not rows (#840). The queue keeps one row per
    # failure, so a looping lead used to clear a threshold of 3 on a single lesson — and the
    # threshold is #823 O3's evidence that the channel learned N things, which a count of
    # failures is not.
    records = _loop_persist.merge_pitfalls(rows)
    threshold = _loop_config.pitfalls_threshold()
    if len(records) < threshold:
        if records:
            _log(
                f"pitfalls queue below threshold (n={len(records)} distinct mistake(s) "
                f"in {len(rows)} row(s), threshold={threshold}) — skipping curation"
            )
        return 0
    # From the RAW rows: rotation is what empties the queue, so it has to name every row
    # that fed a record, not just the exemplar the merge kept.
    batch_ids = [str(r["pitfall_id"]) for r in rows if r.get("pitfall_id")]
    handoffs = _build_pitfalls_handoffs(records)
    if not handoffs:
        _log(
            f"{len(records)} queued pitfall(s) in {len(batch_ids)} row(s) but none carried "
            "a system — dropping"
        )
        _loop_persist.rotate_pitfalls(batch_ids, None, paths=paths)
        return 0
    repo_root = paths.repo_root
    baseline_stray = _author_shared.changes_outside(repo_root, SKILLS_REL)
    # `len(rows)`, not `sum(occurrences)`: a queue row IS one occurrence, so the two are the
    # same number and only one of them costs a pass over the records.
    _log(
        f"pitfalls curation: {len(records)} distinct mistake(s) "
        f"({len(rows)} failure(s)) across {len(handoffs)} system(s)"
    )

    rc = (invoke or _invoke_pitfalls_agent)(handoffs, repo_root=repo_root, box=box)
    if rc != 0:
        # RAISED, not returned (#719). The rc was the pitfalls channel's dominant failure
        # and nothing ever inspected it, so a repeatedly failing batch was discarded
        # silently and forever. `AuthorError` is a member of the drain's retire set, so
        # the fault now reaches the same bounded retirement every other queue has.
        raise _author_shared.AuthorError(
            f"pitfalls curator exited rc={rc}; leaving queue intact"
        )

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
