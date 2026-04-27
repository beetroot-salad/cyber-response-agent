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


def _invoke_contextualize_lead(prompt: str) -> str:
    return _shared_invoke(
        "contextualize-lead", prompt, timeout=SUBAGENT_TIMEOUT_SECONDS,
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
    contextualize_leads: list[str]


_ARCHETYPE_NAME_RE = re.compile(r"^[a-z0-9-]+$")
_SECTION_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)


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
    contextualize_leads = _extract_section_bullet_ids(
        text, sections, "contextualize leads",
    )

    return PlaybookMetadata(
        signature_id=signature_id,
        archetype_names=archetype_names,
        archetype_story_paths=archetype_story_paths,
        has_screen=has_screen,
        hypothesis_seeds=hypothesis_seeds,
        leads=leads,
        contextualize_leads=contextualize_leads,
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
    elif section_name in ("starter lead order", "contextualize leads"):
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
    contextualize_lead_envelopes: list[dict] | None = None,
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

    block = (
        f"## CONTEXTUALIZE\n\n"
        f"**Alert:** {ctx.ticket_id} — {ctx.signature_id}\n"
        f"**Key observables:**\n{entities_lines}\n"
        f"**Playbook hypotheses:** {hypotheses_line}\n"
        f"**Available leads:** {leads_line}\n"
        f"**Data environment:** {data_env}\n"
    )
    if contextualize_lead_envelopes is not None:
        block += (
            f"**Contextualize leads:**\n"
            f"{_summarize_envelopes(contextualize_lead_envelopes)}\n"
        )
    return block


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


# ---------------------------------------------------------------------------
# Contextualize-leads dispatch + merge
# ---------------------------------------------------------------------------


def _load_lead_frontmatter(lead_name: str) -> dict:
    """Read `knowledge/common-investigation/leads/{lead_name}/definition.md`
    and return its YAML frontmatter as a dict.

    Raises OrchestrationError when the file is missing or has no
    frontmatter — that's a playbook-config bug (a signature declared a
    contextualize-lead that doesn't exist), not something to silently swallow.
    """
    path = (
        SOC_AGENT_ROOT / "knowledge" / "common-investigation" / "leads"
        / lead_name / "definition.md"
    )
    if not path.exists():
        raise OrchestrationError(
            f"contextualize-lead {lead_name!r} has no definition at {path}"
        )
    text = path.read_text()
    m = re.match(r"\A---\n(.*?)\n---\n", text, re.DOTALL)
    if not m:
        raise OrchestrationError(
            f"contextualize-lead {lead_name!r} definition.md has no frontmatter"
        )
    try:
        fm = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError as exc:
        raise OrchestrationError(
            f"contextualize-lead {lead_name!r} frontmatter did not parse: {exc}"
        ) from exc
    return fm


def _bind_lead_to_vertices(
    lead_name: str,
    fm: dict,
    vertices: list[dict],
) -> list[dict]:
    """Match a contextualize-lead's `target_vertex_kind` against the prologue
    vertex types. Returns the list of matching vertex dicts. Skipped (empty
    list) when no vertex matches — the lead was declared but the alert
    didn't carry that observable, which is a graceful no-op.
    """
    target_kind = fm.get("target_vertex_kind")
    if not target_kind:
        raise OrchestrationError(
            f"contextualize-lead {lead_name!r} frontmatter missing required "
            "`target_vertex_kind`"
        )
    return [v for v in vertices if v.get("type") == target_kind]


def _assemble_contextualize_lead_prompt(
    ctx: Context, lead_name: str, vertex: dict,
) -> str:
    return (
        f"lead_name={lead_name}\n"
        f"target_vertex_id={vertex.get('id', '')}\n"
        f"target_vertex_kind={vertex.get('type', '')}\n"
        f"target_identifier={vertex.get('identifier', '')}\n"
        f"soc_agent_root={SOC_AGENT_ROOT}\n"
        f"run_dir={ctx.run_dir}\n"
    )


def _dispatch_contextualize_leads(
    ctx: Context,
    prologue: dict,
    lead_names: list[str],
) -> tuple[list[dict], dict[str, dict]]:
    """Run all contextualize-leads × matching vertices in parallel.

    Returns `(envelopes, lead_fms)`. Each envelope is the parsed
    `contextualize_lead:` block emitted by the subagent. `lead_fms` maps
    lead_name → its parsed frontmatter dict, threaded through to
    `_apply_lead_updates` so the merge knows where each lead's record lands
    (`record_attr` is the source of truth).
    """
    if not lead_names:
        return [], {}
    vertices = (prologue or {}).get("vertices") or []

    # Pre-load every lead's frontmatter once; raise loudly if any is broken.
    lead_fms: dict[str, dict] = {n: _load_lead_frontmatter(n) for n in lead_names}

    # Enumerate (lead, vertex) pairs in declaration order; one subagent
    # invocation per pair. The handler dispatches them via ThreadPoolExecutor
    # so wall-clock is bounded by the slowest invocation, not the sum.
    invocations: list[tuple[str, dict, str]] = []  # (lead_name, vertex, prompt)
    for lead_name in lead_names:
        fm = lead_fms[lead_name]
        for vertex in _bind_lead_to_vertices(lead_name, fm, vertices):
            prompt = _assemble_contextualize_lead_prompt(ctx, lead_name, vertex)
            invocations.append((lead_name, vertex, prompt))
    if not invocations:
        return [], lead_fms

    envelopes: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(8, len(invocations))) as ex:
        futures = [
            (lead_name, vertex, ex.submit(_invoke_contextualize_lead, prompt))
            for lead_name, vertex, prompt in invocations
        ]
        for lead_name, vertex, fut in futures:
            raw = fut.result()
            parsed = extract_terminal_yaml(raw)
            env = parsed.get("contextualize_lead")
            if not isinstance(env, dict):
                raise OrchestrationError(
                    f"contextualize-lead {lead_name!r} for vertex "
                    f"{vertex.get('id')} returned no `contextualize_lead:` "
                    f"block"
                )
            envelopes.append(env)
    return envelopes, lead_fms


def _apply_lead_updates(
    prologue: dict, envelopes: list[dict], lead_fms: dict[str, dict],
) -> None:
    """Mutate `prologue['vertices']` in place — for each envelope, find the
    target vertex and merge `updates` onto it.

    `classification` lands at the vertex root. `record_path` points at the
    LookupContract JSON file the save_raw_tool_output hook wrote during the
    subagent's CLI invocation; the handler reads it, extracts `record`, and
    stores the verbatim record under `vertex.attributes[<record_attr>]`
    (where `record_attr` comes from the lead frontmatter — single source of
    truth for the attribute name).

    Updates apply at CONTEXTUALIZE authoring time (single-phase write); rule
    #8 (post-write append-only) is satisfied because nothing has been
    written to investigation.md yet.
    """
    by_id: dict[str, dict] = {
        v["id"]: v for v in prologue.get("vertices", []) if isinstance(v, dict)
    }
    for env in envelopes:
        if env.get("status") != "ok":
            # Errored leads are recorded in the audit trail (markdown) but
            # contribute no updates. Surfaces upstream via _summarize_envelopes.
            continue
        target = env.get("target")
        vertex = by_id.get(target)
        if vertex is None:
            raise OrchestrationError(
                f"contextualize-lead {env.get('lead_name')!r} returned target "
                f"{target!r} but no matching prologue vertex exists"
            )
        lead_name = env.get("lead_name", "")
        record_attr = (lead_fms.get(lead_name) or {}).get("record_attr")
        updates = env.get("updates") or {}
        for key, value in updates.items():
            if key == "record_path":
                continue  # handled below
            vertex[key] = value
        if "record_path" in updates:
            if not record_attr:
                raise OrchestrationError(
                    f"contextualize-lead {lead_name!r} returned `record_path` "
                    "but its frontmatter declares no `record_attr`"
                )
            record = _load_record_from_path(updates["record_path"], lead_name)
            attrs = vertex.setdefault("attributes", {})
            if not isinstance(attrs, dict):
                raise OrchestrationError(
                    f"vertex {target!r} has non-dict `attributes`; "
                    "cannot merge contextualize-lead record"
                )
            attrs[record_attr] = record


def _load_record_from_path(path_str: str, lead_name: str) -> dict | None:
    """Read the LookupContract JSON file the save_raw_tool_output hook wrote
    and return its `record` field (None when the lookup missed).
    """
    path = Path(path_str)
    if not path.is_absolute() or not path.exists():
        raise OrchestrationError(
            f"contextualize-lead {lead_name!r} record_path {path_str!r} is "
            "not an existing absolute path"
        )
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise OrchestrationError(
            f"contextualize-lead {lead_name!r} record_path {path_str!r} did "
            f"not parse as JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise OrchestrationError(
            f"contextualize-lead {lead_name!r} record_path {path_str!r} root "
            "must be a JSON object"
        )
    return payload.get("record")


def _summarize_envelopes(envelopes: list[dict]) -> str:
    """One bullet per envelope for the markdown audit trail."""
    if not envelopes:
        return "- (none)"
    lines = []
    for env in envelopes:
        name = env.get("lead_name", "?")
        target = env.get("target", "?")
        if env.get("status") == "ok":
            obs = env.get("observation") or "(no observation)"
            lines.append(f"- {name} → {target}: {obs}")
        else:
            reason = env.get("reason") or "(no reason)"
            lines.append(f"- {name} → {target}: error — {reason}")
    return "\n".join(lines)


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

    # Parse the prologue dict so we can mutate it before serialization. The
    # contextualize-leads (when declared by the playbook) run in parallel
    # against matching prologue vertices and feed their classification +
    # record updates back onto those vertices in-memory. Validation runs once
    # at the end on the merged result.
    prologue_parsed = extract_terminal_yaml(prologue_raw)
    if "prologue" not in prologue_parsed:
        raise OrchestrationError(
            "subagent output missing top-level `prologue:` — got keys "
            f"{list(prologue_parsed)}"
        )
    prologue_dict = prologue_parsed["prologue"]
    if not isinstance(prologue_dict, dict):
        raise OrchestrationError(
            f"prologue payload is not a mapping: {prologue_dict!r}"
        )

    contextualize_lead_envelopes, contextualize_lead_fms = (
        _dispatch_contextualize_leads(
            ctx, prologue_dict, playbook.contextualize_leads,
        )
    )
    _apply_lead_updates(
        prologue_dict, contextualize_lead_envelopes, contextualize_lead_fms,
    )

    prologue_yaml_str = yaml.safe_dump(
        {"prologue": prologue_dict}, sort_keys=False,
    )

    markdown = _compose_markdown(
        ctx, ticket, playbook, preflight_summary,
        contextualize_lead_envelopes=(
            contextualize_lead_envelopes
            if playbook.contextualize_leads
            else None
        ),
    )
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
