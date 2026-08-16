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


def _is_catalog_template(path: str) -> bool:
    """`{catalog}/{system}/…/{name}.md` — a file the content rule may read AS a template.

    Narrower than `_is_catalog_path`, which is true of anything under the catalog including
    `SCHEMA.md`, a `{system}/README.md` and a note dropped at the catalog root. The scaffold
    content rule reads a file as a template (`id:`, `verb:`, a system derived from its parent
    dir), so pointing it at one of those refuses the file for a reason that is not its defect.

    `README.md` is excluded by NAME, not by depth: it sits at `{system}/README.md`, exactly
    where a template sits, so the depth test alone let the content rule refuse a system's
    catalog notes for "no `id:`" — the very failure this predicate was split out to stop, on
    the one example of it the docstring above already named.

    What is NOT excluded is EXTRA depth. A `{system}/sub/x.md` is nobody's catalog note: the
    shape the catalog documents is two segments, so a third one is a file the content rule
    should still read and refuse (its parent dir names no system, so the resolver raises and
    the commit is refused). Keying on `len(parts) == 2` instead would have handed that shape a
    silent pass — a guard dropped, not a false refusal removed.
    """
    if not path.startswith(CATALOG_REL) or not path.endswith(".md"):
        return False
    parts = path[len(CATALOG_REL):].split("/")
    return len(parts) >= 2 and "_draft" not in parts and parts[-1] != "README.md"


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
