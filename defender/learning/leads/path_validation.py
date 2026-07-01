#!/usr/bin/env python3
"""Scope-gate path classifiers — lead_author's edit scope (domain logic, not git
lifecycle), plus the leads-facing aliases of the shared repo layout they key off.

The catalog/skills layout is owned by ``defender._paths.DefenderPaths`` (the single
source, #476); this module re-exports the absolute forms + the ``_rel`` string twins so
the sibling leaves (``draft_synthesis`` / ``lead_extraction``) and ``lead_author`` keep
importing them from here — one leads-facing home, but the offsets are defined once, in
``DefenderPaths``, not redeclared per module. A leaf never imports them back *from*
``lead_author`` (which would cycle); ``_paths`` is a lower leaf still.
"""
from __future__ import annotations

from pathlib import Path

from defender import _git
from defender._paths import PATHS, DefenderPaths

# Aliases of the single owner (``defender._paths``): the absolute forms off the
# resolved ``PATHS`` singleton, the ``_rel`` string twins off its class constants.
# The classifiers below key off the ``_rel`` prefixes (repo-root-independent).
REPO_ROOT = PATHS.repo_root
LEARNING_DIR = PATHS.learning_dir
CATALOG_DIR = PATHS.catalog_dir
CATALOG_REL = DefenderPaths.catalog_rel
SKILLS_DIR = PATHS.skills_dir
SKILLS_REL = DefenderPaths.skills_rel


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
    """``[(XY, path)]`` working-tree status records at ``repo_root`` (a batch worktree).

    Thin alias over the shared ``-z`` reader (``defender._git.git_status``). The agent runs
    no git, so its edits sit uncommitted (``M`` / ``D`` / ``??``) — this is the single read
    the scope gate verifies. The agent stages nothing, so no rename/copy (``R`` / ``C``)
    records arise; a stray staged rename, were one ever to appear, fails safe — its second
    (source) field reads as an out-of-corpus record the gate quarantines.
    """
    return _git.git_status(repo_root)
