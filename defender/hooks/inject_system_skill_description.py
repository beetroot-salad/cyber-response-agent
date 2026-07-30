
from __future__ import annotations

from functools import cache
from pathlib import Path

from defender._frontmatter import parse_frontmatter_or_none
from defender._io import read_text_soft
from defender.runtime.verb_grant import DENY_ALL, VerbGrant
from defender.runtime.verbs import ModuleVerbRegistry

DEFENDER_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = DEFENDER_DIR / "skills"
ADAPTERS_DIR = DEFENDER_DIR / "scripts" / "adapters"


def read_description(system: str, skills_dir: Path = SKILLS_DIR) -> str | None:
    skill_path = (skills_dir / system / "SKILL.md").resolve()
    try:
        skill_path.relative_to(skills_dir.resolve())
    except ValueError:
        return None
    if not skill_path.is_file():
        return None

    text, _reason = read_text_soft(skill_path)
    if text is None:
        return None
    front = parse_frontmatter_or_none(text)
    if front is None:
        return None
    desc = front.get("description")
    if not isinstance(desc, str):
        return None
    desc = desc.strip()
    return desc or None


@cache
def descriptor_catalog(
    skills_dir: Path, adapters_dir: Path, grant: VerbGrant,
) -> str | None:
    # DENY_ALL, not `grant`: this registry exists only to enumerate real systems and probe
    # whether each one's adapter actually IMPORTS (the `except` below) — narrowing to the
    # caller's grant happens after, against `grant.systems` directly. Constructing with
    # `grant` would run ModuleVerbRegistry's load check against these REAL adapters, which a
    # caller-supplied grant naming a system/verb this tree doesn't declare (a test's fake
    # registry's own auto-derived grant, #632) would fail for a reason that has nothing to do
    # with which systems this catalog should describe.
    registry = ModuleVerbRegistry(adapters_dir, DENY_ALL)
    lines = []
    for system in registry.systems():
        if system not in grant.systems:
            continue
        try:
            verbs = registry.verbs(system)
        except Exception:  # noqa: BLE001 — a system that will not load is unreachable, not fatal
            continue
        if not verbs:
            continue
        desc = read_description(system, skills_dir)
        if desc:
            lines.append(f"- `{system}`: {desc}")
    return "\n".join(lines) or None


