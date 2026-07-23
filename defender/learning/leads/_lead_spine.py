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
) -> int:
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
        salt=salt,
    )

def _verify_corpus_scope(
    repo_root: Path,
    baseline_stray: list[str],
    *,
    actor: str,
    rule: Callable[[str, str], None],
) -> list[str]:
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
            continue
        rule(xy, path)
        changed.append(path)
    return sorted(changed)


def _loop_commit_body(
    title: str, summary: str, changed: list[str], *, trailer: str = "",
) -> str:
    body_paths = "\n".join(f"- {p}" for p in changed)
    return f"{title}\n\n{summary}\n\nPaths:\n{body_paths}\n{trailer}"
