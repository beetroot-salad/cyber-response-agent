#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender._io import Held, is_plain_entry, stat_entry
from defender.learning.core import config as _loop_config
from defender.learning.core.lane_trees import DrainTrees, TreeFor
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender._claim_git import ClaimGit
from defender.learning.leads.path_validation import SKILLS_REL

_logger = logging.getLogger(__name__)


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
    from defender.learning.leads import lead_author_engine
    # Every knob is read at spawn: each is env-backed, and a default would freeze it at import.
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
        log=_logger,
    )


def _verify_corpus_scope(
    repo_root: Path,
    baseline_stray: list[str],
    *,
    actor: str,
    rule: Callable[[str, str], None],
    tree_for: TreeFor,
    git: ClaimGit,
    batch_rule: Callable[[list[tuple[str, str]]], None] | None = None,
) -> list[str]:
    """Per-path `rule` over every in-corpus change, then an optional whole-batch `batch_rule`.

    `batch_rule` is for invariants only decidable across the batch (e.g. whether a deleted
    draft's identity was taken over by another file in the same commit). It runs last, on
    records `rule` already admitted.

    Every record `rule` admits that is not a deletion must also be a plain, single-linked file,
    judged without following it through the lane's held mount (`tree_for`): a link, a hard link
    or a FIFO at a committed name is refused, never committed, and so is a name no held mount
    places (#1178). Checked after `rule`, so a refusal `rule` already gives keeps its own
    message.

    The changes come from the claim's `git` session, which no ignore or attributes file the agent
    left can hide a path from or block (#1175); its corpus test is the one the baseline used."""
    records = git.changes()
    new_stray = sorted({p for _, p in records if not git.in_corpus(p)} - set(baseline_stray))
    if new_stray:
        raise LeadAuthorError(
            f"{actor} changed files outside {SKILLS_REL}*.md: {new_stray}; refusing to commit"
        )
    in_corpus: list[tuple[str, str]] = []
    for xy, path in records:
        if not git.in_corpus(path):
            continue
        rule(xy, path)
        if "D" not in xy:
            _require_committable_entry(repo_root, tree_for, path, actor=actor)
        in_corpus.append((xy, path))
    if batch_rule is not None:
        batch_rule(in_corpus)
    return sorted(path for _, path in in_corpus)


def _require_committable_entry(repo_root: Path, tree_for: TreeFor, path: str, *, actor: str) -> None:
    """`LeadAuthorError` unless the entry at `path` is a plain, single-linked regular file, judged
    by a no-follow stat through the held mount that places it (nothing is opened at the leaf, so
    a FIFO cannot block it, and nothing is read or decoded). A name outside every held mount is
    refused too: the lane commits only what its mounts hold."""
    hit = tree_for(repo_root / path)
    if hit is None:
        raise LeadAuthorError(
            f"{actor} changed {path}, which no held mount of the lane places; refusing to commit"
        )
    held, name = hit
    got = stat_entry(held.view(), name)
    if got.st is None or not is_plain_entry(got.st):
        why = got.reason or ("gone" if got.absent else "a link, a hard link or a FIFO")
        raise LeadAuthorError(
            f"{actor} left {path} as something other than a plain file ({why}); "
            "refusing to commit"
        )


def lane_skills(trees: DrainTrees, paths: _loop_config.LoopPaths) -> Held:
    """The held `skills/` mount of the lane's trees, `trees.mount(paths.skills_dir)`: never a
    handle built here. The lane's trees must hold `paths.skills_dir` itself as a mount point; trees
    opened for a label that grants no such mount (another lane's, an unknown one, a mount list that
    moved it or holds a folder above it) are refused rather than left to fall back on plain paths
    (#1134)."""
    try:
        return trees.mount(paths.skills_dir)
    except ValueError:
        raise LeadAuthorError(
            f"refused: the lane's held trees {[str(m) for m in trees.mounts]} hold no mount at "
            f"{paths.skills_dir}"
        ) from None


def _loop_commit_body(
    title: str, summary: str, changed: list[str], *, trailer: str = "",
) -> str:
    body_paths = "\n".join(f"- {p}" for p in changed)
    return f"{title}\n\n{summary}\n\nPaths:\n{body_paths}\n{trailer}"
