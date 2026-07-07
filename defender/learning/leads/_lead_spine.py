#!/usr/bin/env python3
"""Shared spine for the two lead-author modes — the per-run author (``lead_author``)
and the cross-run pitfalls curator (``pitfalls_curator``).

#455 Part 1 (#511) deduped each mode's invoke/verify/commit triplet onto three shared
helpers; Part 2 (#513) lifts the pitfalls mode into its own module, so those helpers
move here — a named seam both modules import, rather than one reaching a ``_``-private
symbol on the other. Owns the one spawn envelope, the one working-tree scope-gate
preamble, and the one loop-authored commit-message skeleton, plus the constants they
need (the coarse skills allowlist, the shared model/timeout, the pending-queue dir and
run log, the ``lead-author`` run logger).
"""
from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports resolve whether
# this file is imported or run directly (mirrors lead_author.py; see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.core import config as _loop_config
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import SKILLS_REL, _porcelain_records


# Mutable lead-author queue state resolves from DEFAULT_PATHS so it honors
# DEFENDER_LEARNING_STATE_DIR (out-of-repo under concurrent runs). The in-process engine reads its
# model/effort/timeout straight from core.config; the per-spawn observability trace is the
# RequestLogger file under the spawn's learning_run_dir (no separate run-log file).
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
) -> int:
    """Shared spawn envelope for both lead-author modes (the per-run catalog/skill author and the
    cross-run pitfalls curator); they differ only in ``system_prompt_file`` / ``batch_id`` /
    ``learning_run_dir`` (the RequestLogger trace anchor — the case ``run_dir`` for the per-run
    author, ``PENDING_DIR`` for the cross-run pitfalls curator) / the caller-built ``user_prompt``.

    Routes through the in-process PydanticAI engine (GLM). The heavy engine module (it pulls the
    pydantic-ai graph via ``_pydantic_stage``) is imported LAZILY here, and ``run_author_stage`` is
    looked up on the module at CALL time so a test can patch that seam. The agent runs no git and
    writes no result marker — its output is the working tree under ``repo_root`` (the batch
    worktree), verified + committed by the loop; ``repo_root`` is where its file writers land. The
    fine scope (in-scope, no protected-surface mutation, draft-only deletion) is enforced by the
    write gate + ``_verify_corpus_scope`` + the per-mode rule. Returns the engine rc (0 success /
    124 per-run fault); a systemic ``FatalConfigError`` / ``StageAbort`` PROPAGATES (F1)."""
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    from defender.learning.leads import lead_author_engine
    return lead_author_engine.run_author_stage(
        system_prompt_file=system_prompt_file,
        batch_id=batch_id,
        user_prompt=user_prompt,
        repo_root=repo_root,
        learning_run_dir=learning_run_dir,
        log_label=log_label,
        log=_log,
    )


def _verify_corpus_scope(
    repo_root: Path,
    baseline_stray: list[str],
    *,
    actor: str,
    rule: Callable[[str, str], None],
) -> list[str]:
    """Shared verify preamble for both commit modes. One ``git status`` read drives every
    check. Rejects any NEW change outside ``defender/skills/``*.md (diffed against
    ``baseline_stray`` so pre-existing leftovers aren't blamed on the agent). This stray-gate
    runs BEFORE the per-path loop, so a run that both strays and breaks an in-corpus rule is
    rejected as a stray. Then applies the per-mode ``rule`` to each in-corpus change and
    returns the accepted paths ``sorted``. ``actor`` names the culprit in the stray error."""
    records = _porcelain_records(repo_root)

    def _in_corpus(p: str) -> bool:
        return p.startswith(SKILLS_REL) and p.endswith(".md")

    new_stray = sorted({p for _, p in records if not _in_corpus(p)} - set(baseline_stray))
    if new_stray:
        raise LeadAuthorError(
            f"{actor} changed files outside {SKILLS_REL}*.md: {new_stray}; refusing to commit"
        )
    changed: list[str] = []
    for xy, path in records:
        if not _in_corpus(path):
            continue  # non-corpus strays already rejected above
        rule(xy, path)
        changed.append(path)
    return sorted(changed)


def _loop_commit_body(
    title: str, summary: str, changed: list[str], *, trailer: str = "",
) -> str:
    """Shared loop-authored commit-message skeleton: a ``title`` line, a ``summary``
    paragraph, a bulleted ``Paths:`` block over ``changed``, and an optional ``trailer``.
    (Distinct from ``_author_shared._commit_message``, which *extracts* the agent-authored
    message — opposite direction.)"""
    body_paths = "\n".join(f"- {p}" for p in changed)
    return f"{title}\n\n{summary}\n\nPaths:\n{body_paths}\n{trailer}"
