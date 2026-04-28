"""Playbook metadata loader.

`playbook.md` per signature is the declarative spec for the investigation —
archetypes, hypothesis seeds, lead order, optional Screen table, optional
benign-action shortcircuit, and per-signature opt-in flags carried in
frontmatter. This module loads it once and surfaces it as a frozen
dataclass that handlers can pass around.

Lifted out of contextualize.py because predict and report also need it
(both used to lazy-import contextualize to break a cycle that no longer
exists once the loader has its own module).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import frontmatter
import yaml

from scripts.orchestrate import OrchestrationError

from scripts.handlers._markdown import parse_markdown, table_rows_after_heading

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class PlaybookMetadata:
    signature_id: str
    archetype_names: list[str]
    archetype_story_paths: list[str]
    has_screen: bool
    hypothesis_seeds: list[str]
    leads: list[str]
    # PREDICT loop-1 fast-path opt-in. Maps each decision-relevant vertex
    # `classification` to a list of regex patterns that an `identifier` must
    # match to count as "same key-attribute family." Absent / None disables
    # the fast-path for this signature (gate is opt-in per signature).
    discriminating_classifications: dict[str, list[str]] | None = None
    # CONCLUDE-time benign-action short-circuit list. Command bodies that,
    # executed in isolation, cannot damage or exfiltrate. Drawn from the
    # `## Benign action classes` section's bullets. Empty when the section
    # is absent — the short-circuit only fires when the playbook explicitly
    # opts in.
    benign_action_classes: list[str] = field(default_factory=list)


_ARCHETYPE_NAME_RE = re.compile(r"^[a-z0-9-]+$")
_SECTION_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)


def _parse_frontmatter(text: str, *, source: Path) -> dict:
    """Return the YAML frontmatter as a dict, or {} when absent.

    Uses `python-frontmatter` (already a project dep) so CRLF / Windows line
    endings parse identically to LF. Malformed YAML raises OrchestrationError
    rather than silently disabling downstream features (fail-fast).
    """
    try:
        post = frontmatter.loads(text)
    except yaml.YAMLError as exc:
        raise OrchestrationError(
            f"playbook {source} has malformed YAML frontmatter: {exc}"
        ) from exc
    return dict(post.metadata) if post.metadata else {}


def load_playbook_metadata(signature_id: str) -> PlaybookMetadata:
    playbook_path = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "playbook.md"
    )
    if not playbook_path.exists():
        raise OrchestrationError(
            f"playbook not found for {signature_id}: {playbook_path}"
        )
    text = playbook_path.read_text()
    tokens = parse_markdown(text)
    sections = {
        m.group(1).lower(): m.start() for m in _SECTION_RE.finditer(text)
    }
    fm = _parse_frontmatter(text, source=playbook_path)

    if "archetypes" not in sections:
        raise OrchestrationError(
            f"playbook {playbook_path} has no ## Archetypes section"
        )
    archetype_rows = table_rows_after_heading(tokens, "Archetypes")
    archetype_names: list[str] = []
    for row in archetype_rows[1:]:  # skip header row
        if not row:
            continue
        cell = row[0].strip().strip("`").strip()
        if _ARCHETYPE_NAME_RE.fullmatch(cell):
            archetype_names.append(cell)
    if not archetype_names:
        raise OrchestrationError(
            f"playbook {playbook_path} ## Archetypes section has no archetype rows"
        )
    archetype_story_paths = [
        str(
            SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id
            / "archetypes" / name / "story.md"
        )
        for name in archetype_names
    ]

    has_screen = "screen" in sections

    hypothesis_seeds = _extract_section_bullet_ids(text, sections, "hypothesis seeds")
    leads = _extract_section_bullet_ids(text, sections, "starter lead order")

    raw_disc = fm.get("discriminating_classifications")
    disc: dict[str, list[str]] | None = None
    if raw_disc is not None:
        if not isinstance(raw_disc, dict):
            raise OrchestrationError(
                f"playbook {playbook_path}: `discriminating_classifications` "
                f"must be a mapping of classification → [regex, ...]; got "
                f"{type(raw_disc).__name__}"
            )
        disc = {}
        for k, v in raw_disc.items():
            if not isinstance(k, str):
                raise OrchestrationError(
                    f"playbook {playbook_path}: `discriminating_classifications` "
                    f"keys must be strings; got {type(k).__name__} ({k!r})"
                )
            if not isinstance(v, list) or not all(isinstance(p, str) for p in v):
                raise OrchestrationError(
                    f"playbook {playbook_path}: `discriminating_classifications` "
                    f"value for {k!r} must be a list of regex strings"
                )
            disc[k] = list(v)

    benign_action_classes = _extract_benign_action_classes(text, sections)

    return PlaybookMetadata(
        signature_id=signature_id,
        archetype_names=archetype_names,
        archetype_story_paths=archetype_story_paths,
        has_screen=has_screen,
        hypothesis_seeds=hypothesis_seeds,
        leads=leads,
        discriminating_classifications=disc,
        benign_action_classes=benign_action_classes,
    )


# Hypotheses are `?`-prefixed; leads are plain kebab-case words. Filter the
# two section extractors to their expected shapes so we don't pull in vertex
# IDs, edge IDs, attribute names, or stray YAML tokens from the prose around
# the bullets.
_HYPOTHESIS_TOKEN_RE = re.compile(r"`(\?[a-z0-9-]+)`")
_LEAD_TOKEN_RE = re.compile(r"`([a-z][a-z0-9-]+)`")

# Lead tokens that appear in playbook prose but are not lead names. Leads that
# ship under knowledge/common-investigation/leads/ are the authoritative set;
# this allow-list is a coarse sanity filter for names declared inline.
_LEAD_NAME_BLOCKLIST = {
    "data", "rule", "agent", "file", "process", "user", "alert",
    "yes", "no", "true", "false",
}


def _extract_section_bullet_ids(
    text: str, sections: dict[str, int], section_name: str
) -> list[str]:
    """Pull the bullet tokens from a named section.

    For `hypothesis seeds` we match `?foo` patterns; for `starter lead order`
    we match plain kebab-case names (filtered by a block-list of false
    positives from inline prose). Unknown sections return [] — the markdown
    line falls back to `(none)`.
    """
    start = sections.get(section_name)
    if start is None:
        return []
    next_start = min(
        (s for s in sections.values() if s > start), default=len(text)
    )
    block = text[start:next_start]
    if section_name == "hypothesis seeds":
        pattern = _HYPOTHESIS_TOKEN_RE
    elif section_name == "starter lead order":
        pattern = _LEAD_TOKEN_RE
    else:
        return []
    seen: list[str] = []
    for m in pattern.finditer(block):
        token = m.group(1)
        if token in _LEAD_NAME_BLOCKLIST:
            continue
        if token not in seen:
            seen.append(token)
    return seen


# Bullet token at the head of a line in a playbook section: ``- `whoami` ``
# (any trailing prose after the backticks is treated as commentary). When
# the bullet body is bare prose (no backticks), match the first word.
_BENIGN_ACTION_BULLET_RE = re.compile(
    r"^-\s+`([a-z][a-z0-9 _\-/\.]*)`", re.MULTILINE,
)


def load_screen_rows(signature_id: str) -> list[dict[str, str]]:
    """Parse the `## Screen` table of a signature's playbook.

    Returns a list of row dicts keyed by the table's header names, lowercased
    and stripped. Empty list when the section is absent OR present-but-empty
    (no data rows after the header separator). Missing playbook file raises
    OrchestrationError — that's a signature-config bug, not a silent skip.
    """
    playbook_path = (
        SOC_AGENT_ROOT / "knowledge" / "signatures" / signature_id / "playbook.md"
    )
    if not playbook_path.exists():
        raise OrchestrationError(
            f"playbook not found for {signature_id}: {playbook_path}"
        )
    tokens = parse_markdown(playbook_path.read_text())
    rows = table_rows_after_heading(tokens, "Screen")
    if len(rows) < 1:
        return []
    header = [c.strip().lower() for c in rows[0]]
    data_rows: list[dict[str, str]] = []
    for row in rows[1:]:
        cells = [c.strip() for c in row]
        if len(cells) != len(header):
            continue
        data_rows.append({header[i]: cells[i] for i in range(len(cells))})
    return data_rows


def _extract_benign_action_classes(
    text: str, sections: dict[str, int]
) -> list[str]:
    """Pull the bullet entries from ``## Benign action classes``.

    Each bullet's first backticked token is the canonical command body that
    the CONCLUDE short-circuit will compare against (after stripping any
    `bash -c` / `sh -c` wrapper from the alert's cmdline). Returns [] when
    the section is absent — short-circuit is opt-in per signature.
    """
    start = sections.get("benign action classes")
    if start is None:
        return []
    next_start = min(
        (s for s in sections.values() if s > start), default=len(text)
    )
    block = text[start:next_start]
    seen: list[str] = []
    for m in _BENIGN_ACTION_BULLET_RE.finditer(block):
        token = m.group(1).strip().lower()
        if token and token not in seen:
            seen.append(token)
    return seen
