"""GATHER phase handler.

Replaces the GATHER section of `skills/investigate/SKILL.md` with a Python
orchestration that dispatches either the `gather` (Haiku, single template lead)
or `gather-composite` (Sonnet, composite / ad-hoc) subagent, transcribes the
subagent's characterization into an `## GATHER (loop N)` markdown section, and
routes to ANALYZE.

The handler is strictly mechanical:

    - Dispatch pick: single if a vendor template exists for the selected lead,
      else composite in `ad-hoc` mode. One lead + template present is the
      Haiku fast path; anything else is composite.
    - Scope fields (`incident_start/end`, `vendor`, `reporting_agent`,
      `entity_bindings`) are derived from the alert + signature + lead
      template frontmatter. The PREDICT payload only supplies
      `selected_lead` + `loop_n`; scope derivation is the handler's job.
    - `gather` returns `result: escalate` with trigger ∈ the composite-fallback
      set → re-dispatch via `gather-composite` in `redispatch` mode.
    - Silent-termination recovery: on truncated YAML output, read the
      checkpoint under `{run_dir}/subagent_checkpoints/`; if `status: complete`,
      transcribe verbatim, else re-dispatch with `resume_from_checkpoint=true`.
    - Routes to Phase.ANALYZE when at least one prior `hypothesize:` block
      carries declared hypotheses; otherwise (shape-E enrichment path with
      nothing to grade) routes straight to Phase.PREDICT for the next loop.
      ANALYZE owns rollup-driven routing on the normal path; the shape-E
      short-circuit reclaims a subagent spawn and sidesteps the envelope-
      violation failure mode where a subagent invents an `error:` top-level
      key the parser can't recognize.

Input (Context):
    ctx.run_dir, ctx.signature_id, ctx.alert, ctx.outputs[Phase.PREDICT]

Output:
    PhaseResult(next_phase=Phase.ANALYZE | Phase.PREDICT, payload={
        "lead_name": str,
        "mode": "single" | "composite",
        "status": "ok" | "partial" | "escalate" | ...,
        "characterization": dict | None,
        "cross_lead_notes": str,
        "raw_result": dict,
        "prescribed_leads": list[str],  # [selected_lead, *composite_secondary]
        "executed_leads": list[str],    # leads whose output carries resolved status
    })

Scope-check (composite path only): the subagent must emit an entry in `leads[]`
for every prescribed lead, even when intentionally skipped (status:
dropped_attempt). A prescribed lead that's entirely absent from output is a
silent-drop bug and raises.

Files written:
    {run_dir}/investigation.md — appends `## GATHER (loop N)` prose; no
    invlang YAML block (the full `gather[]` entry is composed at ANALYZE per
    the invlang schema's Phase-to-block map).
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import frontmatter
import yaml

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._output_parser import (
    GatherEnvelope,
    GatherOutputError,
    parse_gather_envelope,
)
from scripts.handlers._subagent import (
    extract_terminal_yaml,
    invoke_subagent as _shared_invoke,
)


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_GATHER_TIMEOUT_SECONDS", "300")
)


# Escalate triggers that the single `gather` subagent returns when the
# template-driven fast path is insufficient. On any of these, fall back to
# `gather-composite` in `redispatch` mode. Every entry here MUST match a
# trigger name the subagent actually emits in `escalate_trigger` — see the
# enum in agents/gather.md §Decision envelope.
_COMPOSITE_FALLBACK_TRIGGERS = {
    "missing_template",
    "binding_mismatch",
    "follow_up_needed",
    "siem_error",
    "empty_result",
    "health_probe_verdict",
}

# Default lookback window when the alert carries no explicit window hint.
_DEFAULT_WINDOW = timedelta(hours=1)


# ---------------------------------------------------------------------------
# Subagent invocation (mockable)
# ---------------------------------------------------------------------------


def _invoke_gather(prompt: str, *, timeout: int = SUBAGENT_TIMEOUT_SECONDS) -> str:
    """Module-level wrapper for the Haiku single-lead subagent."""
    return _shared_invoke("gather", prompt, timeout=timeout)


def _invoke_gather_composite(
    prompt: str, *, timeout: int = SUBAGENT_TIMEOUT_SECONDS,
) -> str:
    """Module-level wrapper for the Sonnet composite/ad-hoc subagent."""
    return _shared_invoke("gather-composite", prompt, timeout=timeout)


# ---------------------------------------------------------------------------
# Scope derivation
# ---------------------------------------------------------------------------


@dataclass
class Scope:
    lead_name: str
    vendor: str
    reporting_agent: str
    incident_start: str
    incident_end: str
    entity_bindings: dict[str, str]
    template_exists: bool


def _lead_template_path(lead_name: str, vendor: str) -> Path:
    return (
        SOC_AGENT_ROOT
        / "knowledge"
        / "common-investigation"
        / "leads"
        / lead_name
        / "templates"
        / f"{vendor}.md"
    )


def _derive_vendor(signature_id: str) -> str:
    """Vendor prefix by convention: `wazuh-rule-*` → `wazuh`, etc."""
    if "-" not in signature_id:
        raise OrchestrationError(
            f"GATHER: cannot derive vendor from signature_id {signature_id!r} "
            "(no '-' separator)"
        )
    return signature_id.split("-", 1)[0]


def _alert_dot_path(alert: dict, path: str) -> Optional[str]:
    """Walk `path` (dotted) through `alert`; return the string value or None."""
    cur: Any = alert
    for key in path.split("."):
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    if cur is None:
        return None
    return str(cur)


def _derive_reporting_agent(alert: dict) -> str:
    name = _alert_dot_path(alert, "agent.name")
    if name:
        return name
    # Predecoder hostname is the next-best Wazuh fallback.
    name = _alert_dot_path(alert, "predecoder.hostname")
    if name:
        return name
    raise OrchestrationError(
        "GATHER: alert has neither agent.name nor predecoder.hostname; "
        "cannot derive reporting_agent"
    )


def _derive_incident_window(
    alert: dict, scope_override: Optional[dict] = None,
) -> tuple[str, str]:
    """Return (incident_start, incident_end) ISO-8601 UTC strings.

    Default window: `[t - _DEFAULT_WINDOW, t]` anchored at the alert's
    `@timestamp` (or `now` if the timestamp is absent/unparseable — the
    subagent's data-source health probe flags that case either way).

    When `scope_override` is provided by PREDICT, it overrides:
      - `window_hours`: lookback duration (replaces _DEFAULT_WINDOW)
      - `anchor`: 'alert' (default) keeps T=@timestamp; 'now' moves T to
        current wall-clock time (useful for leads whose semantics are
        "since-last-baseline", not "at-incident-time")

    Per the predict output-parser contract (scope_override validated at
    parse time), the override is trusted here — no re-validation.
    """
    window = _DEFAULT_WINDOW
    anchor = "alert"
    if scope_override:
        hours = scope_override.get("window_hours")
        if isinstance(hours, int) and hours > 0:
            window = timedelta(hours=hours)
        anchor_override = scope_override.get("anchor")
        if anchor_override in ("alert", "now"):
            anchor = anchor_override

    end: Optional[datetime] = None
    if anchor == "alert":
        raw = _alert_dot_path(alert, "@timestamp") or _alert_dot_path(alert, "timestamp")
        if raw:
            try:
                # Wazuh `@timestamp` is ISO-8601 with a trailing `Z` or offset.
                end = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                if end.tzinfo is None:
                    end = end.replace(tzinfo=timezone.utc)
            except ValueError:
                end = None
    if end is None:
        end = datetime.now(timezone.utc)
    start = end - window
    return _iso(start), _iso(end)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _derive_entity_bindings(
    alert: dict, lead_name: str, vendor: str,
) -> tuple[dict[str, str], bool]:
    """Derive `entity_bindings` from the lead template frontmatter.

    Returns `(bindings, template_exists)`. When the template is missing,
    returns `({}, False)` — the handler will route to `gather-composite` in
    `ad-hoc` mode and the composite subagent will infer bindings from the
    alert + lead definition itself.
    """
    template_path = _lead_template_path(lead_name, vendor)
    if not template_path.exists():
        return {}, False

    parsed = frontmatter.loads(template_path.read_text())
    entity_fields = parsed.metadata.get("entity_fields") or {}
    if not isinstance(entity_fields, dict):
        raise OrchestrationError(
            f"GATHER: lead template {template_path} has malformed "
            f"entity_fields frontmatter: {entity_fields!r}"
        )

    bindings: dict[str, str] = {}
    for entity_name, alert_path in entity_fields.items():
        value = _alert_dot_path(alert, str(alert_path))
        if value is not None:
            bindings[str(entity_name)] = value
    return bindings, True


def _resolve_scope(
    ctx: Context, lead_name: str, *, scope_override: Optional[dict] = None,
) -> Scope:
    vendor = _derive_vendor(ctx.signature_id)
    reporting_agent = _derive_reporting_agent(ctx.alert)
    incident_start, incident_end = _derive_incident_window(
        ctx.alert, scope_override=scope_override,
    )
    entity_bindings, template_exists = _derive_entity_bindings(
        ctx.alert, lead_name, vendor,
    )
    return Scope(
        lead_name=lead_name,
        vendor=vendor,
        reporting_agent=reporting_agent,
        incident_start=incident_start,
        incident_end=incident_end,
        entity_bindings=entity_bindings,
        template_exists=template_exists,
    )


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


def _format_entity_bindings(bindings: dict[str, str]) -> str:
    """Render as a compact YAML flow-mapping for the subagent prompt."""
    if not bindings:
        return "{}"
    pairs = ", ".join(f"{k}: {v}" for k, v in bindings.items())
    return "{" + pairs + "}"


def _lead_id_for(loop_n: int, index: int) -> str:
    """Deterministic invlang lead id for an envelope entry.

    Single-lead dispatches use index=0 → `l-{loop_n:03d}`. Composite
    secondaries use 1, 2, ... → `l-{loop_n:03d}b`, `l-{loop_n:03d}c`, ...
    Predictable for tests and stable across retries within the same loop.
    """
    suffix = ""
    if index > 0:
        # 'b' for index 1, 'c' for index 2, ... (matches how humans read
        # "sibling lead in the same loop").
        suffix = chr(ord("b") + index - 1)
    return f"l-{loop_n:03d}{suffix}"


def _assemble_prompt_single(
    ctx: Context, scope: Scope, loop_n: int, *, resume: bool = False,
) -> str:
    lines = [
        f"run_dir={ctx.run_dir}",
        f"signature_id={ctx.signature_id}",
        f"loop_n={loop_n}",
        f"lead_id={_lead_id_for(loop_n, 0)}",
        f"lead_name={scope.lead_name}",
        f"reporting_agent={scope.reporting_agent}",
        f"incident_start={scope.incident_start}",
        f"incident_end={scope.incident_end}",
        f"entity_bindings={_format_entity_bindings(scope.entity_bindings)}",
        f"vendor={scope.vendor}",
    ]
    if resume:
        lines.append("resume_from_checkpoint=true")
    return "\n".join(lines)


def _build_lead_spec(
    scope: Scope,
    *,
    override_data_source: Optional[str] = None,
    lead_hint: Optional[str] = None,
) -> dict:
    spec = {
        "lead_name": scope.lead_name,
        "entity_bindings": scope.entity_bindings,
        "reporting_agent": scope.reporting_agent,
    }
    # Per-lead PREDICT→GATHER hints ride with the lead spec so the subagent
    # sees them attached to the specific lead, not as ambient dispatch metadata.
    if override_data_source:
        spec["override_data_source"] = override_data_source
    if lead_hint:
        spec["lead_hint"] = lead_hint
    return spec


def _assemble_prompt_composite(
    ctx: Context,
    scope: Scope,
    loop_n: int,
    *,
    mode: str,
    resume: bool = False,
    override_data_source: Optional[str] = None,
    lead_hint: Optional[str] = None,
    secondary_scopes: Optional[list[Scope]] = None,
) -> str:
    primary_spec = _build_lead_spec(
        scope, override_data_source=override_data_source, lead_hint=lead_hint,
    )
    primary_spec["lead_id"] = _lead_id_for(loop_n, 0)
    lead_specs = [primary_spec]
    for idx, sec in enumerate(secondary_scopes or [], start=1):
        spec = _build_lead_spec(sec)
        spec["lead_id"] = _lead_id_for(loop_n, idx)
        lead_specs.append(spec)
    lines = [
        f"run_dir={ctx.run_dir}",
        f"signature_id={ctx.signature_id}",
        f"loop_n={loop_n}",
        f"vendor={scope.vendor}",
        f"incident_start={scope.incident_start}",
        f"incident_end={scope.incident_end}",
        f"mode={mode}",
        "leads=" + yaml.safe_dump(lead_specs, default_flow_style=True).strip(),
    ]
    if resume:
        lines.append("resume_from_checkpoint=true")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------


def _try_extract_terminal_yaml(raw: str) -> Optional[dict]:
    """Return the terminal YAML block parsed as a mapping, or None on miss.

    Retained for checkpoint recovery paths that still want a best-effort
    parse without envelope shape enforcement.
    """
    try:
        return extract_terminal_yaml(raw)
    except OrchestrationError:
        return None


def _parse_envelope_response(
    raw: str, *, loop_n: int, mode: str,
) -> Optional[GatherEnvelope]:
    """Parse a gather / gather-composite envelope from subagent stdout.

    Returns None on truncation / unparseable output so the caller can route
    to the checkpoint-recovery path. Envelope-shape violations (missing
    fields, bad enums) also return None — the recovery path has better
    context for reconstructing from the checkpoint than we have here.

    `loop_n` is the orchestrator's computed loop number; we don't enforce
    it against the subagent's emitted `loop` field because retries and
    resume paths legitimately drift. The envelope carries the subagent's
    asserted loop for audit trails.
    """
    try:
        return parse_gather_envelope(raw, mode=mode)
    except GatherOutputError:
        return None


# ---------------------------------------------------------------------------
# Silent-termination recovery
# ---------------------------------------------------------------------------


def _checkpoint_path_single(ctx: Context, loop_n: int, lead_name: str) -> Path:
    return (
        ctx.run_dir
        / "subagent_checkpoints"
        / f"gather-loop-{loop_n}-{lead_name}.yaml"
    )


def _checkpoint_path_composite(ctx: Context, loop_n: int) -> Path:
    return (
        ctx.run_dir
        / "subagent_checkpoints"
        / f"gather-composite-loop-{loop_n}.yaml"
    )


def _load_checkpoint(path: Path) -> Optional[dict]:
    try:
        return yaml.safe_load(path.read_text())
    except FileNotFoundError:
        return None
    except yaml.YAMLError:
        return None


def _reconstruct_single_from_checkpoint(
    checkpoint: dict, *, loop_n: int,
) -> GatherEnvelope:
    """Rebuild a `GatherEnvelope` from a complete-single-gather checkpoint.

    Checkpoint schema mirrors the envelope's single-lead entry (see
    `agents/gather.md` §Progress checkpoint). We wrap the `result` block in
    a one-lead envelope so recovery emits the same shape a fresh dispatch
    would.
    """
    result_block = checkpoint.get("result")
    if not isinstance(result_block, dict):
        raise OrchestrationError(
            "gather checkpoint: `result:` block missing or malformed; cannot "
            "reconstruct — re-dispatch required"
        )
    status = result_block.get("status")
    if status not in {
        "ok", "partial", "data_missing", "dropped_attempt",
        "probe_broken", "siem_error", "error",
    }:
        raise OrchestrationError(
            f"gather checkpoint: unrecognized `result.status` {status!r}"
        )

    lead_entry: dict[str, Any] = {
        "id": result_block.get("id") or _lead_id_for(loop_n, 0),
        "name": result_block.get("name") or checkpoint.get("lead_name"),
        "status": status,
    }
    for key, value in result_block.items():
        if key in {"id", "name", "status", "raw"}:
            continue
        lead_entry[key] = value

    raw_by_lead: dict[str, dict[str, Any]] = {}
    raw = result_block.get("raw")
    if isinstance(raw, dict):
        raw_by_lead[lead_entry["id"]] = raw

    return GatherEnvelope(
        leads=[lead_entry],
        raw_by_lead=raw_by_lead,
        telemetry={"loop": loop_n, "mode": "single"},
    )


def _reconstruct_composite_from_checkpoint(
    checkpoint: dict, *, loop_n: int,
) -> GatherEnvelope:
    """Rebuild a `GatherEnvelope` from a complete-composite checkpoint.

    Per-lead entries already mirror the envelope shape (see
    `agents/gather-composite.md` §Progress checkpoint); we just lift them
    into a GatherEnvelope with raw payloads split off.
    """
    raw_leads = checkpoint.get("leads")
    if not isinstance(raw_leads, list):
        raise OrchestrationError(
            "gather-composite checkpoint: `leads:` missing or malformed"
        )

    leads: list[dict[str, Any]] = []
    raw_by_lead: dict[str, dict[str, Any]] = {}
    for i, lead in enumerate(raw_leads):
        if not isinstance(lead, dict):
            continue
        lead_id = lead.get("id") or _lead_id_for(loop_n, i)
        clean = {k: v for k, v in lead.items() if k != "raw"}
        clean.setdefault("id", lead_id)
        leads.append(clean)
        raw = lead.get("raw")
        if isinstance(raw, dict):
            raw_by_lead[lead_id] = raw

    return GatherEnvelope(
        leads=leads,
        raw_by_lead=raw_by_lead,
        telemetry={"loop": loop_n, "mode": "composite"},
    )


# ---------------------------------------------------------------------------
# Dispatch (with recovery + escalate fallback)
# ---------------------------------------------------------------------------


def _dispatch_single(
    ctx: Context, scope: Scope, loop_n: int,
) -> GatherEnvelope:
    """Invoke the single-gather subagent; on truncation, recover via
    checkpoint; on recoverable escalate triggers, fall back to composite.
    Returns a `GatherEnvelope` (mode="single" or "composite" after fallback).
    """
    prompt = _assemble_prompt_single(ctx, scope, loop_n)
    envelope = _parse_envelope_response(
        _invoke_gather(prompt), loop_n=loop_n, mode="single",
    )

    if envelope is None:
        envelope = _recover_single(ctx, scope, loop_n)

    # Escalate-to-composite fallback. The single-gather envelope has exactly
    # one lead; if it carries an escalating status (error / probe_broken) with
    # a recoverable trigger, redispatch via the composite path so the Sonnet
    # worker can run data-source-debug or multi-query construction.
    first = envelope.leads[0] if envelope.leads else {}
    if first.get("status") in {"error", "probe_broken"}:
        trigger = first.get("escalate_trigger")
        if trigger in _COMPOSITE_FALLBACK_TRIGGERS:
            return _dispatch_composite(
                ctx, scope, loop_n, mode="redispatch",
            )
        # Unrecognized trigger → surface single-lead escalation envelope as-is.
    return envelope


def _recover_single(ctx: Context, scope: Scope, loop_n: int) -> GatherEnvelope:
    ckpt_path = _checkpoint_path_single(ctx, loop_n, scope.lead_name)
    ckpt = _load_checkpoint(ckpt_path)
    if ckpt is None:
        raise OrchestrationError(
            f"gather subagent emitted no Decision YAML and no checkpoint "
            f"exists at {ckpt_path}; cannot recover"
        )
    if ckpt.get("status") == "complete":
        return _reconstruct_single_from_checkpoint(ckpt, loop_n=loop_n)
    # In-progress or unclear: re-dispatch with resume flag.
    resume_prompt = _assemble_prompt_single(ctx, scope, loop_n, resume=True)
    envelope = _parse_envelope_response(
        _invoke_gather(resume_prompt), loop_n=loop_n, mode="single",
    )
    if envelope is None:
        raise OrchestrationError(
            "gather subagent emitted no Decision YAML after resume re-dispatch"
        )
    return envelope


def _dispatch_composite(
    ctx: Context, scope: Scope, loop_n: int, *, mode: str,
    override_data_source: Optional[str] = None,
    lead_hint: Optional[str] = None,
    secondary_scopes: Optional[list[Scope]] = None,
) -> GatherEnvelope:
    prompt = _assemble_prompt_composite(
        ctx, scope, loop_n, mode=mode,
        override_data_source=override_data_source,
        lead_hint=lead_hint,
        secondary_scopes=secondary_scopes,
    )
    envelope = _parse_envelope_response(
        _invoke_gather_composite(prompt), loop_n=loop_n, mode="composite",
    )
    if envelope is None:
        return _recover_composite(
            ctx, scope, loop_n, mode,
            override_data_source=override_data_source,
            lead_hint=lead_hint,
            secondary_scopes=secondary_scopes,
        )
    return envelope


def _recover_composite(
    ctx: Context, scope: Scope, loop_n: int, mode: str,
    *,
    override_data_source: Optional[str] = None,
    lead_hint: Optional[str] = None,
    secondary_scopes: Optional[list[Scope]] = None,
) -> GatherEnvelope:
    ckpt_path = _checkpoint_path_composite(ctx, loop_n)
    ckpt = _load_checkpoint(ckpt_path)
    if ckpt is None:
        raise OrchestrationError(
            f"gather-composite subagent emitted no YAML and no checkpoint "
            f"exists at {ckpt_path}; cannot recover"
        )
    if ckpt.get("status") == "complete":
        return _reconstruct_composite_from_checkpoint(ckpt, loop_n=loop_n)
    resume_prompt = _assemble_prompt_composite(
        ctx, scope, loop_n, mode=mode, resume=True,
        override_data_source=override_data_source,
        lead_hint=lead_hint,
        secondary_scopes=secondary_scopes,
    )
    envelope = _parse_envelope_response(
        _invoke_gather_composite(resume_prompt), loop_n=loop_n, mode="composite",
    )
    if envelope is None:
        raise OrchestrationError(
            "gather-composite subagent emitted no YAML after resume re-dispatch"
        )
    return envelope


# ---------------------------------------------------------------------------
# Scope-check: prescribed vs executed
# ---------------------------------------------------------------------------


# Per-lead statuses that count as "the subagent got to a resolved answer" —
# ok/partial produce characterization; dropped_attempt/data_missing/probe_broken/
# siem_error are explicit non-resolutions that still cover the lead (so a
# missing lead that ANALYZE needs to re-prescribe gets surfaced as unresolved).
_RESOLVED_LEAD_STATUSES = {"ok", "partial"}


def _check_composite_scope(
    envelope: GatherEnvelope, prescribed: list[str],
) -> None:
    """Reject when the subagent silently dropped a prescribed lead.

    Contract: every prescribed lead must appear in `envelope.leads[]`, with
    a per-lead `status` naming its fate (`dropped_attempt` for an intentional
    skip, `data_missing` for an empty-result confirmation, etc.). An entirely
    missing entry is a silent-drop bug and is rejected loudly.

    A single-lead envelope with `status: error` and an `escalate_trigger`
    represents a dispatch-unparseable signal — scope enforcement doesn't
    apply because the subagent never got to executing leads. The handler
    routes those directly to ANALYZE.
    """
    if len(envelope.leads) == 1:
        only = envelope.leads[0]
        if only.get("status") == "error" and only.get("escalate_trigger"):
            return
    executed_names = {
        lead.get("name") for lead in envelope.leads
        if isinstance(lead.get("name"), str)
    }
    missing = [lead for lead in prescribed if lead not in executed_names]
    if missing:
        raise OrchestrationError(
            f"gather-composite: prescribed leads {missing!r} are missing "
            f"from envelope `leads[]`. Every prescribed lead must have an "
            f"entry (use `status: dropped_attempt` if intentionally skipped, "
            f"`status: data_missing` for empty-result confirmations). "
            f"Prescribed={prescribed!r}; listed={sorted(n for n in executed_names if n)!r}."
        )


def _extract_executed_leads(envelope: GatherEnvelope) -> list[str]:
    """Return names of leads that produced a resolved observation.

    ok/partial = executed. dropped_attempt / data_missing / probe_broken /
    siem_error / error are NOT executed — ANALYZE will see them as unresolved
    and may route PREDICT to re-prescribe.
    """
    executed: list[str] = []
    for lead in envelope.leads:
        if lead.get("status") in _RESOLVED_LEAD_STATUSES:
            name = lead.get("name")
            if isinstance(name, str):
                executed.append(name)
    return executed


# ---------------------------------------------------------------------------
# Raw details — write to disk, stash paths
# ---------------------------------------------------------------------------


def _write_raw_details(
    ctx: Context, loop_n: int, raw_by_lead: dict[str, dict],
) -> list[str]:
    """Write per-lead raw payloads to `runs/<run>/raw_details/loop-<N>/<lead-id>.yaml`.

    Returns the list of absolute path strings written, in lead-id order.
    Never raises on empty input — composite leads without a `raw` block
    (pure dropped_attempt / data_missing) simply contribute nothing.
    """
    if not raw_by_lead:
        return []
    detail_dir = ctx.run_dir / "raw_details" / f"loop-{loop_n}"
    detail_dir.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []
    for lead_id in sorted(raw_by_lead.keys()):
        path = detail_dir / f"{lead_id}.yaml"
        path.write_text(yaml.safe_dump(raw_by_lead[lead_id], sort_keys=False))
        paths.append(str(path))
    return paths


# ---------------------------------------------------------------------------
# Payload synthesis (backwards-compat with the pre-v2.12 shape)
# ---------------------------------------------------------------------------


def _build_payload(
    envelope: GatherEnvelope,
    *,
    scope: Scope,
    prescribed: list[str],
    raw_paths: list[str],
    cross_lead_notes: str,
    mode: str,
) -> dict:
    """Flatten the envelope into the handler-contract payload consumed by
    ANALYZE and by the handler's own tests.

    Preserves these top-level fields for callers that still read them:
        mode, status, lead_name, characterization, cross_lead_notes, raw_result

    Adds:
        leads                — full envelope.leads list (structured data)
        raw_details_paths    — absolute paths to the per-lead raw payloads
        prescribed_leads     — what PREDICT asked for
        executed_leads       — which prescribed leads produced resolved data
    """
    first = envelope.leads[0] if envelope.leads else {}
    first_status = first.get("status", "ok")

    payload: dict[str, Any] = {
        "mode": mode,
        "status": first_status,
        "lead_name": first.get("name", scope.lead_name),
        "characterization": first.get("characterization"),
        "cross_lead_notes": cross_lead_notes,
        "raw_result": {
            "gather": {
                "loop": envelope.telemetry.get("loop"),
                "mode": mode,
                "leads": envelope.leads,
                "cross_lead_notes": cross_lead_notes,
            },
        },
        "leads": envelope.leads,
        "raw_details_paths": raw_paths,
        "prescribed_leads": prescribed,
    }
    payload["executed_leads"] = _extract_executed_leads(envelope)
    return payload


# ---------------------------------------------------------------------------
# Markdown composition + write
# ---------------------------------------------------------------------------


def _compose_markdown(payload: dict, loop_n: int) -> str:
    lines = [
        f"## GATHER (loop {loop_n})",
        "",
        f"**Lead:** {payload['lead_name']}",
        f"**Status:** {payload['status']}",
    ]

    first = (payload.get("leads") or [{}])[0]
    query_block = first.get("query")
    if isinstance(query_block, dict):
        query_str = query_block.get("query") or "(not recorded)"
    elif isinstance(query_block, str):
        query_str = query_block
    else:
        query_str = "(not recorded)"
    lines.append(f"**Query:** `{query_str}`")

    characterization = payload.get("characterization")
    if characterization:
        lines.append("")
        lines.append("**Raw observation:**")
        for key, value in characterization.items():
            lines.append(f"- {key}: {value}")
    else:
        context = first.get("escalate_context") or first.get("status_detail")
        lines.append("")
        lines.append(
            f"**No characterization** — {context or 'see raw_details/loop-' + str(loop_n) + '/'}"
        )

    cross = payload.get("cross_lead_notes") or ""
    if cross:
        lines.append("")
        lines.append(f"**Cross-lead notes:** {cross}")

    if payload.get("raw_details_paths"):
        lines.append("")
        lines.append(
            "**Raw details:** "
            + ", ".join(Path(p).name for p in payload["raw_details_paths"])
            + f" under `raw_details/loop-{loop_n}/`"
        )

    return "\n".join(lines) + "\n"


def _append_to_investigation(ctx: Context, section: str) -> None:
    """Append a new markdown section to investigation.md, validating invlang.

    Appending prose only leaves the accumulated invlang YAML unchanged, but we
    still invoke `validate_companion` as a belt-and-suspenders check against
    any accidental YAML-fence contamination in the section. Matches
    `analyze.py:_validate_and_write`.
    """
    hooks_path = str(SOC_AGENT_ROOT / "hooks")
    if hooks_path not in sys.path:
        sys.path.insert(0, hooks_path)
    from scripts.invlang_validate import validate_companion  # type: ignore

    inv_path = ctx.run_dir / "investigation.md"
    current = inv_path.read_text() if inv_path.exists() else ""
    proposed = (
        current
        + ("\n" if current and not current.endswith("\n") else "")
        + section
    )

    errors = validate_companion(proposed, current if current else None)
    if errors:
        raise OrchestrationError(
            "GATHER invlang validation failed:\n" + "\n".join(errors)
        )

    inv_path.write_text(proposed)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


@dataclass
class _PredictPayload:
    selected_lead: str
    loop_n: int
    override_data_source: Optional[str]
    lead_hint: Optional[str]
    composite_secondary: list[str]
    # Lead-level predictions (`lp*` readings) pre-committed by PREDICT on the
    # Shape E path. Non-empty only when PREDICT emitted a `branch_plan`.
    # GATHER stamps these onto the gather[] entry's `predictions[]` so ANALYZE
    # matches the observed outcome against a pre-registered branch.
    branch_plan_predictions: list[dict]
    # Structured scope override from predict.routing.scope_override. Keys
    # (validated by the predict output parser at parse time):
    #   window_hours: int > 0   — replaces gather's default 1h lookback
    #   anchor: 'alert' | 'now' — window anchor point (default 'alert')
    # None when PREDICT did not override (use the default 1h alert-anchored
    # window).
    scope_override: Optional[dict]


def _read_predict_payload(ctx: Context) -> _PredictPayload:
    predict_out = ctx.outputs.get(Phase.PREDICT)
    if not isinstance(predict_out, dict):
        raise OrchestrationError(
            "GATHER: Phase.PREDICT payload not found on ctx.outputs — "
            "PREDICT must run before GATHER"
        )
    selected_lead = predict_out.get("selected_lead")
    if not isinstance(selected_lead, str) or not selected_lead.strip():
        raise OrchestrationError(
            f"GATHER: PREDICT payload missing non-empty selected_lead "
            f"(got {selected_lead!r})"
        )
    loop_n = predict_out.get("loop_n")
    if not isinstance(loop_n, int):
        raise OrchestrationError(
            f"GATHER: PREDICT payload missing int loop_n (got {loop_n!r})"
        )
    # Optional PREDICT→GATHER hints — forwarded into the gather-composite
    # dispatch when present, omitted otherwise. PREDICT trailer parser
    # already validated string-ness; we pass through as-is.
    override_data_source = predict_out.get("override_data_source")
    lead_hint = predict_out.get("lead_hint")
    # Composite prescription: PREDICT may name additional leads alongside the
    # primary selected_lead. Absent field → empty list (single-lead prescription).
    raw_secondary = predict_out.get("composite_secondary")
    if raw_secondary is None:
        composite_secondary: list[str] = []
    elif isinstance(raw_secondary, list) and all(
        isinstance(x, str) and x.strip() for x in raw_secondary
    ):
        composite_secondary = list(raw_secondary)
    else:
        raise OrchestrationError(
            f"GATHER: PREDICT payload composite_secondary must be "
            f"list[str] of non-empty slugs (got {raw_secondary!r})"
        )
    raw_bp = predict_out.get("branch_plan_predictions")
    if raw_bp is None:
        branch_plan_predictions: list[dict] = []
    elif isinstance(raw_bp, list) and all(isinstance(x, dict) for x in raw_bp):
        branch_plan_predictions = list(raw_bp)
    else:
        raise OrchestrationError(
            f"GATHER: PREDICT payload branch_plan_predictions must be "
            f"list[dict] when provided, got {raw_bp!r}"
        )
    # scope_override is a pass-through dict — parser-validated at predict
    # time, gather-side treats it as trusted structural input to
    # _derive_incident_window. Absent key → no override (default 1h window).
    raw_so = predict_out.get("scope_override")
    if raw_so is not None and not isinstance(raw_so, dict):
        raise OrchestrationError(
            f"GATHER: PREDICT payload scope_override must be a mapping when "
            f"provided, got {type(raw_so).__name__}"
        )
    return _PredictPayload(
        selected_lead=selected_lead,
        loop_n=loop_n,
        override_data_source=override_data_source,
        lead_hint=lead_hint,
        composite_secondary=composite_secondary,
        branch_plan_predictions=branch_plan_predictions,
        scope_override=raw_so,
    )


def handle(ctx: Context) -> PhaseResult:
    pp = _read_predict_payload(ctx)
    scope = _resolve_scope(ctx, pp.selected_lead, scope_override=pp.scope_override)
    prescribed_leads = [pp.selected_lead, *pp.composite_secondary]

    # Overrides only apply to the composite subagent — single-lead gather
    # executes a fixed vendor template and has no room for a data-source
    # override. Any of these force the composite path: explicit override,
    # prescribed secondaries (multi-lead dispatch), or no template.
    force_composite = (
        pp.override_data_source is not None
        or bool(pp.composite_secondary)
    )

    if scope.template_exists and not force_composite:
        envelope = _dispatch_single(ctx, scope, pp.loop_n)
        # _dispatch_single may have fallen back to composite under the
        # escalate-trigger path. Telemetry carries the resolved mode.
        mode = envelope.telemetry.get("mode", "single")
    else:
        # Secondary leads share the primary's scope override — PREDICT
        # prescribed them as part of one composite investigation step, so
        # the window is scoped identically across the dispatch.
        secondary_scopes = [
            _resolve_scope(ctx, lead, scope_override=pp.scope_override)
            for lead in pp.composite_secondary
        ]
        envelope = _dispatch_composite(
            ctx, scope, pp.loop_n,
            mode="ad-hoc" if not scope.template_exists else "composite",
            override_data_source=pp.override_data_source,
            lead_hint=pp.lead_hint,
            secondary_scopes=secondary_scopes,
        )
        _check_composite_scope(envelope, prescribed_leads)
        mode = "composite"

    raw_paths = _write_raw_details(ctx, pp.loop_n, envelope.raw_by_lead)
    payload = _build_payload(
        envelope,
        scope=scope,
        prescribed=prescribed_leads,
        raw_paths=raw_paths,
        cross_lead_notes=envelope.cross_lead_notes,
        mode=mode,
    )

    section = _compose_markdown(payload, pp.loop_n)
    _append_to_investigation(ctx, section)

    # Skip ANALYZE when no hypotheses have been declared yet (shape-E
    # enrichment path). ANALYZE grades against `hypothesize.hypotheses[]` —
    # with no h-ids on the frontier, the only contract-conformant output is
    # `resolutions: []` + `routing.decision: continue`, which is a no-op.
    # Routing straight to PREDICT N+1 saves the subagent spawn and removes
    # the envelope-shape failure mode where the subagent picks an informal
    # `error:` key the parser can't recognize.
    if not _any_hypotheses_declared(ctx):
        return PhaseResult(next_phase=Phase.PREDICT, payload=payload)

    return PhaseResult(next_phase=Phase.ANALYZE, payload=payload)


_HYP_FENCE_RE = re.compile(r"```yaml\n(?P<body>.*?)\n```", re.DOTALL)


def _any_hypotheses_declared(ctx: Context) -> bool:
    """True when any `hypothesize:` YAML fence in investigation.md carries a
    non-empty `hypotheses[]` list. Scans every fence (not just the last) so a
    shape-E block after a prior shape-A/M doesn't falsely look empty."""
    inv = ctx.run_dir / "investigation.md"
    if not inv.exists():
        return False
    for m in _HYP_FENCE_RE.finditer(inv.read_text()):
        try:
            parsed = yaml.safe_load(m.group("body"))
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        hyp = parsed.get("hypothesize")
        if isinstance(hyp, dict) and hyp.get("hypotheses"):
            return True
    return False
