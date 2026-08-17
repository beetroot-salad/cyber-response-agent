#!/usr/bin/env python3
from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.core import config as _loop_config
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import SKILLS_REL, _porcelain_records


PENDING_DIR = _loop_config.DEFAULT_PATHS.lead_pending_dir

_log = _loop_config.make_logger("lead-author", flush=True)


def _spawn_author_agent(
    *,
    system_prompt_file: Path,
    batch_id: str,
    user_prompt: str,
    repo_root: Path,
    learning_run_dir: Path,
    log_label: str,
    salt: str,
    box=None,
) -> int:
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    from defender.learning.leads import lead_author_engine
    # Every knob below is read HERE, at spawn — each is env-backed and a module-level or
    # signature default would freeze it at import (#717).
    return lead_author_engine.run_author_stage(
        wiring=_loop_config.StageWiring.for_batch(
            system_prompt_file,
            _loop_config.lead_author_model(),
            _loop_config.lead_author_effort(),
            batch_id=batch_id, label=log_label,
        ),
        ctx=_loop_config.StageContext(
            learning_run_dir=learning_run_dir,
            user=user_prompt,
            request_limit=_loop_config.lead_author_request_limit(),
            wall_clock_timeout=_loop_config.lead_author_timeout(),
            repo_root=repo_root,
            box=box,
            salt=salt,
        ),
        log_label=log_label,
        log=_log,
    )


def _verify_corpus_scope(
    repo_root: Path,
    baseline_stray: list[str],
    *,
    actor: str,
    rule: Callable[[str, str], None],
    batch_rule: Callable[[list[tuple[str, str]]], None] | None = None,
) -> list[str]:
    """Per-path `rule` over every in-corpus change, then an optional whole-batch `batch_rule`.

    Two hooks because two kinds of invariant live here. Almost everything the gate asks is
    answerable from one path ("may the agent touch this", "is what it wrote well-formed"), and
    `rule` keeps those cheap and independent. What `batch_rule` is for is the questions that are
    only decidable across the batch — a deleted draft is legitimate or not depending on whether
    some OTHER file in the same commit took over the identity it carried, and no per-path pass
    can see that. It runs last, on the records the per-path rule already admitted, so a batch
    rule never reasons about a path the gate has refused."""
    records = _porcelain_records(repo_root)

    def _in_corpus(p: str) -> bool:
        return p.startswith(SKILLS_REL) and p.endswith(".md")

    new_stray = sorted({p for _, p in records if not _in_corpus(p)} - set(baseline_stray))
    if new_stray:
        raise LeadAuthorError(
            f"{actor} changed files outside {SKILLS_REL}*.md: {new_stray}; refusing to commit"
        )
    changed: list[str] = []
    in_corpus: list[tuple[str, str]] = []
    for xy, path in records:
        if not _in_corpus(path):
            continue
        rule(xy, path)
        in_corpus.append((xy, path))
        changed.append(path)
    if batch_rule is not None:
        batch_rule(in_corpus)
    return sorted(changed)


def _loop_commit_body(
    title: str, summary: str, changed: list[str], *, trailer: str = "",
) -> str:
    body_paths = "\n".join(f"- {p}" for p in changed)
    return f"{title}\n\n{summary}\n\nPaths:\n{body_paths}\n{trailer}"
