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

from defender.learning.author import runner as _author_runner
from defender.learning.core import config as _loop_config
from defender.learning.leads.lead_extraction import LeadAuthorError
from defender.learning.leads.path_validation import SKILLS_REL, _porcelain_records


# Mutable lead-author queue state resolves from DEFAULT_PATHS so it honors
# DEFENDER_LEARNING_STATE_DIR (out-of-repo under concurrent runs).
PENDING_DIR = _loop_config.DEFAULT_PATHS.lead_pending_dir
RUN_LOG_FILE = PENDING_DIR / "lead_author_run.log"

# Sourced from core.config (single env-read site, no duplicated default).
LEAD_AUTHOR_MODEL = _loop_config.LEAD_AUTHOR_MODEL
LEAD_AUTHOR_TIMEOUT = _loop_config.LEAD_AUTHOR_TIMEOUT

_log = _loop_config.make_logger("lead-author", flush=True)


# The agent runs NO git — the loop is the sole committer. Edit/Write are scoped to the
# skills tree; promote = Write the established template + ``rm`` the draft, discard = ``rm``
# the draft, fold/split/lift = Edit/Write. The loop's scope gate (``_verify_corpus_scope``
# + the per-mode rule) enforces the fine scope (in-scope, no protected-surface mutation,
# draft-only deletion), so the allowlist itself can be the coarse ``defender/skills/`` tree.
#
# Two matcher grammars, deliberately: ``**`` is the documented recursive glob for the
# *file-path* tools (Edit/Write/Read), so it matches a nested draft path there. Claude
# Code's *Bash* matcher is a different grammar — a single ``*`` over the raw command
# string, which already crosses ``/`` — and ``**`` is undefined for it, so the ``rm`` grant
# uses the documented ``:*`` prefix form (``Bash(rm defender/skills/:*)``) rather than an
# undocumented ``**`` that only matches nested drafts by accident. The drain hands the agent
# repo-relative paths and runs it with cwd at the worktree, so one repo-relative matcher
# covers every removal — no worktree-absolute twin needed.
_ALLOWLIST = (
    "Read,Glob,Grep,"
    f"Edit({SKILLS_REL}**),"
    f"Write({SKILLS_REL}**),"
    f"Bash(rm {SKILLS_REL}:*)"
)


def _spawn_author_agent(
    *,
    system_prompt_file: Path,
    batch_id: str,
    user_prompt: str,
    repo_root: Path,
    log_label: str,
) -> int:
    """Shared spawn envelope for both lead-author modes; they differ only in
    ``system_prompt_file`` / ``batch_id`` / the caller-built ``user_prompt``. The agent runs
    no git and writes no result marker, so this uses the raw runner variant and maps a
    ``RunnerError`` (timeout / spawn failure) to rc 124 (caller then returns rc=2). ``cwd`` is
    ``repo_root`` (the batch worktree), so the agent's repo-relative ``rm`` paths resolve under
    it. ``log_label`` names the spawn in the run log."""
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    _log(f"spawn {log_label} (model={LEAD_AUTHOR_MODEL}, timeout={LEAD_AUTHOR_TIMEOUT}s)")
    options = _author_runner.RunnerOptions(
        system_prompt_file=system_prompt_file,
        allowed_tools=_ALLOWLIST,
        model=LEAD_AUTHOR_MODEL,
        effort=None,
        timeout_seconds=LEAD_AUTHOR_TIMEOUT,
        cwd=repo_root,
        log_path=RUN_LOG_FILE,
        result_marker=None,
        batch_id=batch_id,
    )
    try:
        rc, _text = _author_runner.invoke_claude_print_raw(options, user_prompt, _log)
    except _author_runner.RunnerError as e:
        _log(f"{log_label} failed: {e}")
        return 124
    _log(f"{log_label} exited rc={rc}")
    return rc


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
