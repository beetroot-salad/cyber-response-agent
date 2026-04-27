"""CONTEXTUALIZE phase handler.

Replaces the CONTEXTUALIZE section of `skills/investigate/SKILL.md`. Dispatches
two subagents in parallel:

    - ticket-context        — runs the 4-hour correlation script + emits dedup verdict
    - contextualize-prologue — builds the prologue YAML (vertices + edges)

Composes the `## CONTEXTUALIZE` markdown summary mechanically, validates the
combined new section against the invlang schema (by importing
`hooks/scripts/invlang_validate.py`), and writes it to
`{run_dir}/investigation.md`.

Archetype matching has moved to the REPORT phase handler, where it runs against
the *confirmed* investigation outcome to pick a resolvement label — not here,
where it would bias the investigation toward enumerated candidates.

Routes:
    - SCREEN   — playbook has a `## Screen` section
    - PREDICT  — default

The dedup fast-path (CONTEXTUALIZE→REPORT on ticket_context.dedup_candidate) is
retired pending a proper design; see tasks/dedup-fast-path.md. The ticket-context
subagent still emits `dedup_candidate`; the handler carries it forward as
`dedup_matched_ticket_id` telemetry only and does not steer routing on it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import frontmatter
import yaml

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._markdown import parse_markdown, table_rows_after_heading
from scripts.handlers._subagent import (
    extract_terminal_yaml,
    invoke_subagent as _shared_invoke,
)

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Subagent invocation (mockable)
# ---------------------------------------------------------------------------


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_CONTEXTUALIZE_TIMEOUT_SECONDS", "300")
)


def _invoke_ticket(prompt: str) -> str:
    return _shared_invoke("ticket-context", prompt, timeout=SUBAGENT_TIMEOUT_SECONDS)


def _invoke_prologue(prompt: str) -> str:
    return _shared_invoke(
        "contextualize-prologue", prompt, timeout=SUBAGENT_TIMEOUT_SECONDS,
    )


# ---------------------------------------------------------------------------
# Playbook metadata
# ---------------------------------------------------------------------------


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

    return PlaybookMetadata(
        signature_id=signature_id,
        archetype_names=archetype_names,
        archetype_story_paths=archetype_story_paths,
        has_screen=has_screen,
        hypothesis_seeds=hypothesis_seeds,
        leads=leads,
        discriminating_classifications=disc,
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


# ---------------------------------------------------------------------------
# Parallel dispatch
# ---------------------------------------------------------------------------


def _dispatch_parallel(ctx: Context, playbook: PlaybookMetadata) -> tuple[str, str]:
    """Invoke the two preload subagents concurrently, return (ticket_raw,
    prologue_raw) stdouts."""
    ticket_prompt = _assemble_ticket_prompt(ctx)
    prologue_prompt = _assemble_prologue_prompt(ctx)

    with ThreadPoolExecutor(max_workers=2) as ex:
        f_ticket = ex.submit(_invoke_ticket, ticket_prompt)
        f_prologue = ex.submit(_invoke_prologue, prologue_prompt)
        return f_ticket.result(), f_prologue.result()


def _assemble_ticket_prompt(ctx: Context) -> str:
    return f"run_dir={ctx.run_dir}\nsignature_id={ctx.signature_id}"


def _assemble_prologue_prompt(ctx: Context) -> str:
    alert_path = ctx.run_dir / "alert.json"
    field_quirks_path = (
        SOC_AGENT_ROOT / "knowledge" / "signatures"
        / ctx.signature_id / "field-quirks.md"
    )
    ip_ranges_path = (
        SOC_AGENT_ROOT / "knowledge" / "environment" / "context" / "ip-ranges.md"
    )
    identity_patterns_path = (
        SOC_AGENT_ROOT / "knowledge" / "environment" / "context"
        / "identity-patterns.md"
    )
    return (
        f"alert_path={alert_path}\n"
        f"field_quirks_path={field_quirks_path}\n"
        f"ip_ranges_path={ip_ranges_path}\n"
        f"identity_patterns_path={identity_patterns_path}"
    )


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


PREFLIGHT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_PREFLIGHT_TIMEOUT_SECONDS", "30")
)


def _run_preflight() -> dict:
    """Invoke `scripts/preflight.py --systems --json` and return the parsed
    dict. On any failure (timeout, non-zero exit with malformed JSON, etc.)
    return a sentinel `{"error": reason, "systems": []}` so the handler can
    degrade gracefully — preflight is advisory, not load-bearing.
    """
    argv = [
        sys.executable,
        str(SOC_AGENT_ROOT / "scripts" / "preflight.py"),
        "--systems", "--json",
    ]
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=PREFLIGHT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {"error": "preflight timed out", "systems": []}
    # Exit code 1 is expected when systems are degraded — still parse stdout.
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return {"error": f"preflight JSON parse failed: {exc}", "systems": []}


def _summarize_preflight(preflight: dict) -> str:
    """One-line summary for the `Data environment:` markdown field."""
    if preflight.get("error"):
        return f"preflight skipped ({preflight['error']})"
    systems = preflight.get("systems") or []
    if not systems:
        return "no systems configured"
    reachable = [s["system"] for s in systems if s.get("connected")]
    degraded = [
        f"{s['system']} ({(s.get('error') or 'unreachable').splitlines()[0]})"
        for s in systems if not s.get("connected")
    ]
    if not degraded:
        return f"all systems reachable ({', '.join(reachable)})"
    return (
        f"reachable: {', '.join(reachable) or 'none'}; "
        f"degraded: {', '.join(degraded)}"
    )


# ---------------------------------------------------------------------------
# Markdown composition (mechanical)
# ---------------------------------------------------------------------------


def _compose_markdown(
    ctx: Context,
    ticket: dict,
    playbook: PlaybookMetadata,
    preflight_summary: str,
) -> str:
    tc = ticket.get("ticket_context", {})
    entities = tc.get("entities", {}) or {}

    hypotheses_line = (
        ", ".join(playbook.hypothesis_seeds) if playbook.hypothesis_seeds else "(none)"
    )
    leads_line = ", ".join(playbook.leads) if playbook.leads else "(none)"

    entities_lines = (
        "\n".join(f"- {k}: {v}" for k, v in entities.items())
        if entities
        else "- (none — ticket-context returned no entities)"
    )

    data_env = preflight_summary
    if tc.get("queries_failed"):
        data_env = f"{data_env} | correlation queries failed: {tc['queries_failed']}"
    elif tc.get("queries_partial"):
        data_env = f"{data_env} | partial correlation: {tc['queries_partial']}"

    return (
        f"## CONTEXTUALIZE\n\n"
        f"**Alert:** {ctx.ticket_id} — {ctx.signature_id}\n"
        f"**Key observables:**\n{entities_lines}\n"
        f"**Playbook hypotheses:** {hypotheses_line}\n"
        f"**Available leads:** {leads_line}\n"
        f"**Data environment:** {data_env}\n"
    )


# ---------------------------------------------------------------------------
# Validate + write
# ---------------------------------------------------------------------------


def _extract_yaml_block(raw: str, key: str) -> str:
    """Pull the last ```yaml block containing top-level `key:` out of `raw`
    and return it as a YAML string (no fences).

    Distinct from `extract_terminal_yaml` which returns a parsed dict — here
    we want the formatted text so we can append it to `investigation.md`
    verbatim.
    """
    parsed = extract_terminal_yaml(raw)
    if key not in parsed:
        raise OrchestrationError(
            f"subagent output missing top-level `{key}:` — got keys {list(parsed)}"
        )
    return yaml.safe_dump({key: parsed[key]}, sort_keys=False)


def _validate_and_write(ctx: Context, new_section: str) -> None:
    """Append `new_section` to investigation.md after running
    `validate_companion` as a library check."""
    # Lazy import: invlang_validate is in hooks/scripts which isn't on sys.path
    # until we put it there.
    hooks_scripts = str(SOC_AGENT_ROOT / "hooks")
    if hooks_scripts not in sys.path:
        sys.path.insert(0, hooks_scripts)
    from scripts.invlang_validate import validate_companion  # type: ignore

    inv_path = ctx.run_dir / "investigation.md"
    current = inv_path.read_text() if inv_path.exists() else ""
    proposed = current + ("\n" if current and not current.endswith("\n") else "") + new_section

    errors = validate_companion(proposed, current if current else None)
    if errors:
        raise OrchestrationError(
            "CONTEXTUALIZE invlang validation failed:\n" + "\n".join(errors)
        )

    inv_path.write_text(proposed)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


def _route(ticket: dict, playbook: PlaybookMetadata) -> tuple[Phase, Optional[str]]:
    tc = ticket.get("ticket_context", {}) or {}
    dedup_id = tc.get("dedup_candidate")
    # Dedup fast-path retired — see module docstring. `dedup_id` is still returned
    # as telemetry in the handler payload but does not change routing.
    if playbook.has_screen:
        return Phase.SCREEN, str(dedup_id) if dedup_id else None
    return Phase.PREDICT, str(dedup_id) if dedup_id else None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def handle(ctx: Context) -> PhaseResult:
    if not ctx.ticket_id:
        raise OrchestrationError(
            "CONTEXTUALIZE handler: ctx.ticket_id is empty — must be set at "
            "Context construction by the /investigate entrypoint"
        )

    playbook = load_playbook_metadata(ctx.signature_id)
    preflight = _run_preflight()
    preflight_summary = _summarize_preflight(preflight)

    ticket_raw, prologue_raw = _dispatch_parallel(ctx, playbook)
    ticket = extract_terminal_yaml(ticket_raw)
    prologue_yaml_str = _extract_yaml_block(prologue_raw, "prologue")

    markdown = _compose_markdown(ctx, ticket, playbook, preflight_summary)
    new_section = (
        markdown
        + "\n"
        + "```yaml\n"
        + prologue_yaml_str
        + "```\n"
    )
    _validate_and_write(ctx, new_section)

    next_phase, dedup_id = _route(ticket, playbook)

    return PhaseResult(
        next_phase=next_phase,
        payload={
            # Retained as telemetry only; handler does not steer routing on these.
            # See module docstring + tasks/dedup-fast-path.md.
            "dedup": False,
            "dedup_matched_ticket_id": dedup_id,
            "entities": ticket.get("ticket_context", {}).get("entities", {}),
            "ticket_context_result": ticket.get("ticket_context", {}),
        },
    )
