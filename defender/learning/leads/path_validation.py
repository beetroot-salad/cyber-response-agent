#!/usr/bin/env python3
"""Scope-gate path classifiers — lead_author's edit scope (domain logic, not git
lifecycle), plus the shared module-level path constants they key off.

These constants live here, the lowest leaf of the lead-author module group, so the
sibling leaves (``draft_synthesis`` / ``lead_extraction``) and ``lead_author`` itself
import them from one place rather than each redefining the catalog/skills layout — and
so a leaf never has to import them back *from* ``lead_author`` (which would cycle).
"""
from __future__ import annotations

import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
CATALOG_DIR = REPO_ROOT / "defender" / "skills" / "gather" / "queries"
CATALOG_REL = "defender/skills/gather/queries/"
SKILLS_DIR = REPO_ROOT / "defender" / "skills"
SKILLS_REL = "defender/skills/"


def _under_draft(path: str) -> bool:
    """True if ``path`` lies under any catalog ``{system}/_draft/`` subdirectory."""
    if not path.startswith(CATALOG_REL):
        return False
    rest = path[len(CATALOG_REL):]
    parts = rest.split("/")
    return len(parts) >= 3 and parts[1] == "_draft"


def _draft_twin(catalog_template: str) -> str:
    """The ``_draft/{id}.md`` path a promote of an established catalog template must remove.

    ``defender/skills/gather/queries/{system}/{id}.md`` →
    ``defender/skills/gather/queries/{system}/_draft/{id}.md``. Used by the scope gate to
    catch a half-promote (established written, draft never ``rm``'d).
    """
    p = Path(catalog_template)
    return str(p.parent / "_draft" / p.name)


def _is_catalog_path(path: str) -> bool:
    return path.startswith(CATALOG_REL)


def _is_system_file(path: str, name: str) -> bool:
    """True if ``path`` is exactly ``defender/skills/{system}/{name}`` (one segment
    deep). Shared by the top-level per-system file checks so the SKILL.md and
    execution.md scope gates classify the same path shape identically."""
    if not path.startswith(SKILLS_REL):
        return False
    rest = path[len(SKILLS_REL):]
    parts = rest.split("/")
    return len(parts) == 2 and parts[1] == name


def _is_system_skill_md(path: str) -> bool:
    """True if ``path`` is exactly ``defender/skills/{system}/SKILL.md``.

    Excludes ``gather/queries/SCHEMA.md`` and nested files like
    ``skills/{system}/queries/foo.md`` — only the top-level system SKILL
    is in lift scope.
    """
    return _is_system_file(path, "SKILL.md")


def _is_system_execution_md(path: str) -> bool:
    """True if ``path`` is exactly ``defender/skills/{system}/execution.md``.

    The pitfalls curation mode's *sole* edit target. Kept out of ``_is_in_scope``
    on purpose: the per-run lead-author agent must never touch execution.md, and
    the pitfalls agent must never touch the catalog / SKILL.md / drafts. The two
    modes' scopes are disjoint, enforced by their separate verify gates.
    """
    return _is_system_file(path, "execution.md")


def _is_system_skill_draft(path: str) -> bool:
    """True if ``path`` is under a system-skill ``_draft/`` (one segment deep).

    Catalog drafts at ``skills/gather/queries/{system}/_draft/`` are NOT
    system-skill drafts — they're handled by the catalog-side draft flow.
    """
    if not path.startswith(SKILLS_REL):
        return False
    rest = path[len(SKILLS_REL):]
    parts = rest.split("/")
    return len(parts) >= 3 and parts[1] == "_draft"


def _is_draft_readme(path: str) -> bool:
    """True if ``path`` is a ``_draft/README.md`` surface-declaration file."""
    if not _is_system_skill_draft(path) and not _under_draft(path):
        return False
    return Path(path).name == "README.md"


def _is_schema_md(path: str) -> bool:
    """True if ``path`` is a catalog ``SCHEMA.md`` (the template-schema doc, not a
    template). Loop-protected: the lead author curates templates, never the schema."""
    return _is_catalog_path(path) and Path(path).name == "SCHEMA.md"


def _is_in_scope(path: str) -> bool:
    """True if ``path`` is within lead_author's edit scope.

    Two scopes: the gather query catalog and the system-skill surface
    (``SKILL.md`` + sibling ``_draft/``).
    """
    return (
        _is_catalog_path(path)
        or _is_system_skill_md(path)
        or _is_system_skill_draft(path)
    )


def _porcelain_records(repo_root: Path) -> list[tuple[str, str]]:
    """``[(XY, path)]`` from ``git status --porcelain --untracked-files=all -z`` at
    ``repo_root`` (a batch worktree). The agent runs no git, so its edits sit uncommitted
    in the working tree (``M`` / ``D`` / ``??``) — this is the single read the scope gate
    verifies. The agent stages nothing, so no rename/copy (``R`` / ``C``) records arise (a
    "move" shows as a delete + an untracked add): each ``-z`` field is therefore one
    ``XY␣path`` record. A stray staged rename, were one ever to appear, fails safe — its
    second (source) field reads as an out-of-corpus path and the gate quarantines rather
    than mis-committing.
    """
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "-z"],
        cwd=repo_root, capture_output=True, text=True, check=True,
    )
    out: list[tuple[str, str]] = []
    for rec in proc.stdout.split("\0"):
        if not rec or len(rec) < 3:
            continue
        out.append((rec[:2], rec[3:] if rec[2] == " " else rec[2:]))
    return out
