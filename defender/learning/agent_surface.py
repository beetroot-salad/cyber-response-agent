#!/usr/bin/env python3
"""Per-agent read surfaces: scope a subagent's file access *by construction*.

Each learning-loop subagent (`judge`, `oracle`, `actor`, …) runs with its
`cwd` + `--add-dir` pointed at a surface dir built here, so it can only reach
what we stage — replacing deny-lists as the *primary* read boundary (the
deny-list stays as defense-in-depth; see the agent settings).

This is the one place that knows how to assemble such a dir. It is deliberately
*not* part of `lead_repository` — that module owns the read/join surface over
the two lead/query tables, whereas a surface may hold tables, a symlink mirror
of the repo, or nothing at all. For the table case it composes
`lead_repository.stage_tables(..., link=True)` so the definition of "what files
are the two tables" stays in one place and can't drift.

NOT an OS sandbox: `--add-dir` bounds the Read/Grep/Glob tools but not `Bash`,
so an absolute-path or deep-`..` read can still reach outside the surface. The
per-agent deny-list is the backstop for that residual.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import lead_repository


AGENTS_DIR = "_agents"


def stage_agent_surface(
    src_run_dir: Path,
    agent: str,
    *,
    include_tables: bool = False,
    extra_files: dict[str, Path] | None = None,
    symlinks: dict[str, Path] | None = None,
) -> Path:
    """Assemble `{src_run_dir}/_agents/{agent}/` and return it as the agent's cwd.

    Built inside the run dir so it shares `gather_raw`'s filesystem (hardlinks
    work) and so `<surface>/gather_raw/..` resolves to this clean staged parent,
    not the run dir's `ground_truth.yaml` sibling.

    - `include_tables` hardlinks the two tables in via `stage_tables(link=True)`
      (a REAL `gather_raw/` dir, so the one-level `..` traversal is contained) —
      the judge's evidence surface.
    - `extra_files` (`{rel_name: src_abs}`) copies individual small inputs in
      (e.g. the judge's `alert.json`); a missing source is skipped.
    - `symlinks` (`{rel_path: target_abs}`) creates symlinks — used for the
      actor's read-only repo mirror (scripts + lessons corpora), where the
      narrow allow-list, not the surface, backstops `..` escapes.

    Rebuilt fresh each call (idempotent): a stale surface is removed first so a
    re-run never trips on an existing hardlink.
    """
    surface = Path(src_run_dir) / AGENTS_DIR / agent
    if surface.exists():
        shutil.rmtree(surface)
    surface.mkdir(parents=True, exist_ok=True)
    if include_tables:
        lead_repository.stage_tables(src_run_dir, surface, link=True)
    for name, src in (extra_files or {}).items():
        src = Path(src)
        if src.is_file():
            dst = surface / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    for rel, target in (symlinks or {}).items():
        link_path = surface / rel
        link_path.parent.mkdir(parents=True, exist_ok=True)
        link_path.symlink_to(target)
    return surface
