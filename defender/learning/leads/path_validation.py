#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from defender._paths import PATHS
from defender.knowledge._knowledge import AGENT_REL, CATALOG, SKILLS

REPO_ROOT = PATHS.repo_root
LEARNING_DIR = PATHS.learning_dir
#: The lead lanes' spellings, relative to the tenant repo that versions the agent root (OD6):
#: every change, commit and handoff path the lanes judge or name is `agent/skills/...`, a path
#: of a batch's draft (#1108 P4).
SKILLS_PREFIX = f"{AGENT_REL}/{SKILLS}/"
CATALOG_PREFIX = f"{AGENT_REL}/{CATALOG}/"
#: The catalog's folder below the `skills/` mount (`gather/queries`): drain code reaches the catalog
#: through the held `skills/` mount, never through a handle rooted at the catalog (#1134).
CATALOG_FOLDER = CATALOG[len(SKILLS):].strip("/")
#: The same two spellings under their former names, for callers outside production code.
SKILLS_REL = SKILLS_PREFIX
CATALOG_REL = CATALOG_PREFIX


def _under_draft(path: str) -> bool:
    if not path.startswith(CATALOG_PREFIX):
        return False
    rest = path[len(CATALOG_PREFIX):]
    parts = rest.split("/")
    return len(parts) >= 3 and parts[1] == "_draft"


def _draft_twin(catalog_template: str) -> str:
    p = Path(catalog_template)
    return str(p.parent / "_draft" / p.name)


def _is_catalog_path(path: str) -> bool:
    return path.startswith(CATALOG_PREFIX)


def _is_catalog_template(path: str) -> bool:
    """`{catalog}/{system}/…/{name}.md` — a file the content rule may read AS a template.

    Narrower than `_is_catalog_path`: excludes a root-level note and `README.md` (by name,
    since `{system}/README.md` sits at template depth). Extra depth is not excluded, so a
    `{system}/sub/x.md` is still read and refused by the content rule rather than silently
    passed. Drafts are excluded only at `_under_draft`'s documented depth, for the same reason.
    """
    if not path.startswith(CATALOG_PREFIX) or not path.endswith(".md"):
        return False
    parts = path[len(CATALOG_PREFIX):].split("/")
    return len(parts) >= 2 and not _under_draft(path) and parts[-1] != "README.md"


def _is_system_file(path: str, name: str) -> bool:
    if not path.startswith(SKILLS_PREFIX):
        return False
    rest = path[len(SKILLS_PREFIX):]
    parts = rest.split("/")
    return len(parts) == 2 and parts[1] == name


def _is_system_skill_md(path: str) -> bool:
    return _is_system_file(path, "SKILL.md")


def _is_system_execution_md(path: str) -> bool:
    return _is_system_file(path, "execution.md")


def _is_system_skill_draft(path: str) -> bool:
    if not path.startswith(SKILLS_PREFIX):
        return False
    rest = path[len(SKILLS_PREFIX):]
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
