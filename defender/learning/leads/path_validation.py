#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from defender import _git
from defender._paths import PATHS, DefenderPaths

REPO_ROOT = PATHS.repo_root
LEARNING_DIR = PATHS.learning_dir
CATALOG_DIR = PATHS.catalog_dir
CATALOG_REL = DefenderPaths.catalog_rel
SKILLS_DIR = PATHS.skills_dir
SKILLS_REL = DefenderPaths.skills_rel


def _under_draft(path: str) -> bool:
    if not path.startswith(CATALOG_REL):
        return False
    rest = path[len(CATALOG_REL):]
    parts = rest.split("/")
    return len(parts) >= 3 and parts[1] == "_draft"


def _draft_twin(catalog_template: str) -> str:
    p = Path(catalog_template)
    return str(p.parent / "_draft" / p.name)


def _is_catalog_path(path: str) -> bool:
    return path.startswith(CATALOG_REL)


def _is_system_file(path: str, name: str) -> bool:
    if not path.startswith(SKILLS_REL):
        return False
    rest = path[len(SKILLS_REL):]
    parts = rest.split("/")
    return len(parts) == 2 and parts[1] == name


def _is_system_skill_md(path: str) -> bool:
    return _is_system_file(path, "SKILL.md")


def _is_system_execution_md(path: str) -> bool:
    return _is_system_file(path, "execution.md")


def _is_system_skill_draft(path: str) -> bool:
    if not path.startswith(SKILLS_REL):
        return False
    rest = path[len(SKILLS_REL):]
    parts = rest.split("/")
    return len(parts) >= 3 and parts[1] == "_draft"


def _is_draft_readme(path: str) -> bool:
    if not _is_system_skill_draft(path) and not _under_draft(path):
        return False
    return Path(path).name == "README.md"


def _is_schema_md(path: str) -> bool:
    return _is_catalog_path(path) and Path(path).name == "SCHEMA.md"


def _is_in_scope(path: str) -> bool:
    return (
        _is_catalog_path(path)
        or _is_system_skill_md(path)
        or _is_system_skill_draft(path)
    )


def _porcelain_records(repo_root: Path) -> list[tuple[str, str]]:
    return _git.git_status(repo_root)
