#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import _git
from defender._io import Held, is_plain_entry, stat_entry
from defender.knowledge._knowledge import AGENT_REL
from defender.learning.core import config as _loop_config
from defender.learning.core.lane_trees import DrainTrees, TreeFor
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.author.version_control import ChangeSet
from defender.learning.leads.path_validation import SKILLS_PREFIX

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
    """Spawn one lead-lane curator over the lane's tree at `repo_root` (a batch draft's root):
    the stage writes the `agent/` root it holds (#1108 P4 O7)."""
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
            repo_root=repo_root / AGENT_REL,
            box=box,
            salt=salt,
        ),
        log_label=log_label,
        log=_logger,
    )


def committed_text(
    root: Path, path: str, *, base: Mapping[str, bytes] | None = None,
) -> str | None:
    """`path` (repo-relative) as the batch's `base` commits it (`Batch.base`'s blobs), or
    `None` when the base does not carry it. With no base given, a `root` that is itself a git
    checkout answers from its HEAD; any other root commits nothing."""
    if base is not None:
        blob = base.get(path)
        return None if blob is None else blob.decode("utf-8", "replace")
    if (root / ".git").exists():
        return _git.git_show_file(root, "HEAD", path)
    return None


def _in_corpus(path: str) -> bool:
    """A repo-relative path the lane's corpus holds: a `.md` file under `agent/skills/`."""
    return path.startswith(SKILLS_PREFIX) and path.endswith(".md")


def change_records(
    change_set: ChangeSet, *, base: Mapping[str, bytes] | None = None,
) -> list[tuple[str, str]]:
    """The claim as the gates' `(xy, path)` records, in path order: `D ` for a deletion, `A `
    for a file the base does not hold, else `M ` (every write `M ` when no base is given)."""
    return [
        ("D " if change.content is None
         else "A " if base is not None and change.path not in base else "M ", change.path)
        for change in sorted(change_set, key=lambda c: c.path)
    ]


def _verify_corpus_scope(  # noqa: PLR0913 — the claim, its base, and the lane's three rules
    root: Path,
    change_set: ChangeSet,
    *,
    actor: str,
    rule: Callable[[str, str], None],
    tree_for: TreeFor,
    base: Mapping[str, bytes] | None = None,
    batch_rule: Callable[[list[tuple[str, str]]], None] | None = None,
) -> list[str]:
    """Per-path `rule` over every change of the claim (`change_set`, the batch's draft against
    its base, #1108 P4 O7), then an optional whole-batch `batch_rule`. Paths are repo-relative
    under the draft's `root` (`agent/skills/...`, OD6). A change outside the lane's corpus — any
    file not an `agent/skills/**.md` — is a stray, refusing the claim (the batch's own
    derivation refuses one outside its lanes first)."""
    records = change_records(change_set, base=base)
    stray = sorted(p for _, p in records if not _in_corpus(p))
    if stray:
        raise LeadAuthorError(
            f"{actor} changed files outside {SKILLS_PREFIX}*.md: {stray}; refusing to commit"
        )
    for xy, path in records:
        rule(xy, path)
        if "D" not in xy:
            _require_committable_entry(root, tree_for, path, actor=actor)
    if batch_rule is not None:
        batch_rule(records)
    return [path for _, path in records]


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


def lane_skills(
    trees: DrainTrees, paths: _loop_config.LoopPaths, *, skills_dir: Path | None = None,
) -> Held:
    """The held `skills/` mount of the lane's trees, `trees.mount(skills_dir)` (a batch draft's
    `agent/skills`; `paths.skills_dir` when none is named): never a handle built here. The
    lane's trees must hold that folder itself as a mount point; trees opened for a label that
    grants no such mount (another lane's, an unknown one, a mount list that moved it or holds a
    folder above it) are refused rather than left to fall back on plain paths (#1134)."""
    where = skills_dir if skills_dir is not None else paths.skills_dir
    try:
        return trees.mount(where)
    except ValueError:
        raise LeadAuthorError(
            f"refused: the lane's held trees {[str(m) for m in trees.mounts]} hold no mount at "
            f"{where}"
        ) from None


def _loop_commit_body(
    title: str, summary: str, changed: list[str], *, trailer: str = "",
) -> str:
    body_paths = "\n".join(f"- {p}" for p in changed)
    return f"{title}\n\n{summary}\n\nPaths:\n{body_paths}\n{trailer}"
