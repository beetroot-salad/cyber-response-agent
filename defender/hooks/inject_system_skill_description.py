
from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path

from defender._frontmatter import parse_frontmatter_or_none
from defender._io import read_text_soft
from defender._knowledge import CHECKOUT_KNOWLEDGE
from defender._paths import adapters_under
from defender.runtime.system_status import NONE_DOWN
from defender.runtime.verb_grant import DENY_ALL, VerbGrant
from defender.runtime.verbs import ModuleVerbRegistry, RosterRead

DEFENDER_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = CHECKOUT_KNOWLEDGE.skills_dir
ADAPTERS_DIR = adapters_under(DEFENDER_DIR)


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


@dataclass(frozen=True)
class SystemIndex:
    """Gather's system index for one grant: each system the grant reaches, in the registry's
    order, with its descriptor line. Built at run start (`descriptor_index`), so a roster fault
    fails there rather than mid-tool; rendered when a dispatch prompt is built, with the systems
    down AT THAT MOMENT marked (`render`) — a system downed after the start is marked too
    (#1256)."""

    #: `(system, line)`: the system's descriptor line, or `None` when it has none to show (no
    #: skill description, no verbs, an adapter that would not load, or one down at start and so
    #: never loaded).
    entries: tuple[tuple[str, str | None], ...]

    @property
    def systems(self) -> tuple[str, ...]:
        return tuple(system for system, _line in self.entries)

    def render(self, down: Mapping[str, str] = NONE_DOWN) -> str | None:
        """The index as the dispatch prompt shows it: each system's line, or — for a system in
        `down` (down for this run, with its cause as `system_status.cause_text` names it) — that
        it is DOWN and why (#1256 O-3). `None` when there is no line to show."""
        lines = []
        for system, line in self.entries:
            if system in down:
                lines.append(
                    f"- `{system}`: DOWN for this run, {down[system]}. Do not query it: what it "
                    "would have shown is a visibility gap — name the missing evidence in your "
                    "summary.")
            elif line:
                lines.append(line)
        return "\n".join(lines) or None


def descriptor_index(
    skills_dir: Path, roster: RosterRead, grant: VerbGrant,
    *, unloaded: Collection[str] = (),
) -> SystemIndex:
    """Gather's system index over `grant`, built once (`SystemIndex`): one entry per system the
    grant reaches — its skill's description, read now. A system in `unloaded` (down for this run
    from its start) is listed without being loaded, so its adapter is never imported into the
    call-time cache: no call will reach it."""
    # DENY_ALL, not `grant`: the registry only enumerates systems and probes that each adapter
    # imports; narrowing to `grant.systems` happens below. Constructing with `grant` would run
    # the registry's load check, which a grant naming an undeclared system/verb would fail for a
    # reason unrelated to the catalog. The roster was read (and could fail) at run start, so
    # this cannot raise for the tree.
    registry = ModuleVerbRegistry(roster, DENY_ALL)
    entries: list[tuple[str, str | None]] = []
    for system in registry.systems():
        if system not in grant.systems:
            continue
        entries.append(
            (system, None if system in unloaded else _descriptor_line(registry, system, skills_dir)))
    return SystemIndex(tuple(entries))


def _descriptor_line(registry: ModuleVerbRegistry, system: str, skills_dir: Path) -> str | None:
    try:
        verbs = registry.verbs(system)
    except Exception:  # noqa: BLE001 — a system that will not load is unreachable, not fatal
        return None
    if not verbs:
        return None
    desc = read_description(system, skills_dir)
    return f"- `{system}`: {desc}" if desc else None


def descriptor_catalog(
    skills_dir: Path, roster: RosterRead, grant: VerbGrant,
    *, down: Mapping[str, str] = NONE_DOWN,
) -> str | None:
    """Gather's system index over `grant`, built and rendered at once (`descriptor_index`, then
    `SystemIndex.render`): one line per system the grant reaches — its skill's description, or,
    for a system in `down`, that it is DOWN and why (#1256 O-3)."""
    return descriptor_index(skills_dir, roster, grant, unloaded=down).render(down)
