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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from schemas.state import Phase
from scripts.invlang.corpus import write_created_header
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._investigation_io import append_and_validate
from scripts.handlers._playbook import PlaybookMetadata, load_playbook_metadata
from scripts.handlers._prologue_dense import (
    PrologueOutputError,
    parse_prologue_dense,
)
from scripts.handlers._subagent import (
    extract_terminal_yaml,
    make_invoker,
)

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Subagent invocation (mockable)
# ---------------------------------------------------------------------------


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_CONTEXTUALIZE_TIMEOUT_SECONDS", "300")
)


_invoke_ticket = make_invoker(
    "ticket-context", default_timeout=SUBAGENT_TIMEOUT_SECONDS,
)
_invoke_prologue = make_invoker(
    "contextualize-prologue", default_timeout=SUBAGENT_TIMEOUT_SECONDS,
)


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


def _serialize_prologue(raw: str) -> str:
    """Parse the dense prologue envelope emitted by the subagent and re-serialize
    as YAML for embedding into `investigation.md`.

    The subagent emits dense-block grammar (`:V prologue.vertices` /
    `:E prologue.edges`); the on-disk companion stays YAML so the invlang
    validator and downstream tooling see the unchanged shape.
    """
    try:
        parsed = parse_prologue_dense(raw)
    except PrologueOutputError as exc:
        raise OrchestrationError(f"prologue subagent output: {exc}") from exc
    return yaml.safe_dump(parsed, sort_keys=False)


def _stamp_created_header() -> str:
    """First-write prefix: stamp the file's creation time so the corpus
    loader's recency filter has a stable per-file timestamp without needing
    to read sibling alert.json or trust file mtime."""
    return write_created_header(datetime.now(timezone.utc).isoformat())


def _validate_and_write(ctx: Context, new_section: str) -> None:
    append_and_validate(
        ctx.run_dir, new_section,
        phase="CONTEXTUALIZE",
        first_write_prefix=_stamp_created_header,
    )


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
    prologue_yaml_str = _serialize_prologue(prologue_raw)

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
