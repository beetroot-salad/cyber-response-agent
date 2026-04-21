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
      template frontmatter. The HYPOTHESIZE payload only supplies
      `selected_lead` + `loop_n`; scope derivation is the handler's job.
    - `gather` returns `result: escalate` with trigger ∈ the composite-fallback
      set → re-dispatch via `gather-composite` in `redispatch` mode.
    - Silent-termination recovery: on truncated YAML output, read the
      checkpoint under `{run_dir}/subagent_checkpoints/`; if `status: complete`,
      transcribe verbatim, else re-dispatch with `resume_from_checkpoint=true`.
    - Always routes to Phase.ANALYZE. GATHER → HYPOTHESIZE re-entry is
      deliberately not taken from here — ANALYZE owns rollup-driven routing
      (the orchestrator's transition table still permits both edges so the
      existing `test_gather_to_hypothesize_reentry` test keeps working).

Input (Context):
    ctx.run_dir, ctx.signature_id, ctx.alert, ctx.outputs[Phase.HYPOTHESIZE]

Output:
    PhaseResult(next_phase=Phase.ANALYZE, payload={
        "lead_name": str,
        "mode": "single" | "composite",
        "status": "ok" | "partial" | "escalate" | ...,
        "characterization": dict | None,
        "cross_lead_notes": str,
        "raw_result": dict,
    })

Files written:
    {run_dir}/investigation.md — appends `## GATHER (loop N)` prose; no
    invlang YAML block (the full `gather[]` entry is composed at ANALYZE per
    the invlang schema's Phase-to-block map).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import frontmatter
import yaml

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._subagent import invoke_subagent as _shared_invoke


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_GATHER_TIMEOUT_SECONDS", "300")
)


# Escalate triggers that the single `gather` subagent returns when the
# template-driven fast path is insufficient. On any of these, fall back to
# `gather-composite` in `redispatch` mode.
_COMPOSITE_FALLBACK_TRIGGERS = {
    "missing_template",
    "binding_mismatch",
    "follow_up_needed",
    "siem_error",
    "empty_result",
    "elevated",
    "low",
    "broken",
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


def _derive_incident_window(alert: dict) -> tuple[str, str]:
    """Return (incident_start, incident_end) ISO-8601 UTC strings.

    Uses the alert's top-level `@timestamp` when present. Window is
    `[t - _DEFAULT_WINDOW, t]`. When the timestamp is absent or unparseable,
    fall back to now-window..now so the lead still runs; the subagent's
    data-source health probe will flag anomalies either way.
    """
    raw = _alert_dot_path(alert, "@timestamp") or _alert_dot_path(alert, "timestamp")
    end: Optional[datetime] = None
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
    start = end - _DEFAULT_WINDOW
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


def _resolve_scope(ctx: Context, lead_name: str) -> Scope:
    vendor = _derive_vendor(ctx.signature_id)
    reporting_agent = _derive_reporting_agent(ctx.alert)
    incident_start, incident_end = _derive_incident_window(ctx.alert)
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


def _assemble_prompt_single(
    ctx: Context, scope: Scope, loop_n: int, *, resume: bool = False,
) -> str:
    lines = [
        f"run_dir={ctx.run_dir}",
        f"signature_id={ctx.signature_id}",
        f"loop_n={loop_n}",
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


def _assemble_prompt_composite(
    ctx: Context,
    scope: Scope,
    loop_n: int,
    *,
    mode: str,
    resume: bool = False,
) -> str:
    lead_spec = {
        "lead_name": scope.lead_name,
        "entity_bindings": scope.entity_bindings,
        "reporting_agent": scope.reporting_agent,
    }
    lines = [
        f"run_dir={ctx.run_dir}",
        f"signature_id={ctx.signature_id}",
        f"loop_n={loop_n}",
        f"vendor={scope.vendor}",
        f"incident_start={scope.incident_start}",
        f"incident_end={scope.incident_end}",
        f"mode={mode}",
        "leads=" + yaml.safe_dump([lead_spec], default_flow_style=True).strip(),
    ]
    if resume:
        lines.append("resume_from_checkpoint=true")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------


def _first_yaml_block(raw: str) -> Optional[dict]:
    """Return the first fenced ```yaml block parsed as a dict, or None."""
    fence = "```yaml"
    end = "```"
    i = 0
    while True:
        start = raw.find(fence, i)
        if start == -1:
            return None
        body_start = start + len(fence)
        stop = raw.find(end, body_start)
        if stop == -1:
            return None
        body = raw[body_start:stop]
        try:
            parsed = yaml.safe_load(body)
        except yaml.YAMLError:
            i = stop + len(end)
            continue
        if isinstance(parsed, dict):
            return parsed
        i = stop + len(end)


def _parse_gather_output(raw: str) -> dict:
    """Parse the single-gather subagent's terminal YAML.

    Returns the parsed dict. Raises OrchestrationError if no `result:` key is
    found — that's a truncation, caller handles it.
    """
    parsed = _first_yaml_block(raw)
    if parsed is None or "result" not in parsed:
        raise OrchestrationError(
            "gather subagent: no `result:` YAML block found in output"
        )
    return parsed


def _parse_composite_output(raw: str) -> dict:
    """Parse the composite subagent's terminal YAML.

    Returns the parsed dict. Accepts either the normal `gather_composite:`
    top-level or the degraded `error:` top-level shape.
    """
    parsed = _first_yaml_block(raw)
    if parsed is None:
        raise OrchestrationError(
            "gather-composite subagent: no YAML block found in output"
        )
    if "gather_composite" not in parsed and "error" not in parsed:
        raise OrchestrationError(
            "gather-composite subagent: output is missing both "
            "`gather_composite:` and `error:` top-level keys"
        )
    return parsed


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
    if not path.exists():
        return None
    try:
        return yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        return None


def _reconstruct_single_from_checkpoint(checkpoint: dict) -> dict:
    """Map a complete-single-gather checkpoint's `result` block back into the
    shape `_parse_gather_output` would have returned from the subagent stdout.
    """
    result_block = checkpoint.get("result")
    if not isinstance(result_block, dict):
        raise OrchestrationError(
            "gather checkpoint: `result:` block missing or malformed; cannot "
            "reconstruct — re-dispatch required"
        )
    # The subagent's Decision YAML top-level shape is literally
    # `{result: finding, ...}` or `{result: escalate, ...}`. The checkpoint
    # stores all the same keys under its own `result:` wrapper, so we unwrap
    # by copying kind into `result` and lifting the siblings.
    kind = result_block.get("kind")
    if kind not in {"finding", "escalate"}:
        raise OrchestrationError(
            f"gather checkpoint: unrecognized `result.kind` {kind!r}"
        )
    out = {"result": kind}
    for key, value in result_block.items():
        if key == "kind":
            continue
        out[key] = value
    return out


def _reconstruct_composite_from_checkpoint(checkpoint: dict) -> dict:
    """Map a complete-composite checkpoint back into the subagent-stdout shape."""
    leads = checkpoint.get("leads")
    if not isinstance(leads, list):
        raise OrchestrationError(
            "gather-composite checkpoint: `leads:` missing or malformed"
        )
    return {
        "gather_composite": {
            "mode": "redispatch",
            "leads": leads,
            "cross_lead_notes": "",
            "notes": "reconstructed from checkpoint after silent termination",
        },
    }


# ---------------------------------------------------------------------------
# Dispatch (with recovery + escalate fallback)
# ---------------------------------------------------------------------------


def _needs_single_recovery(raw: str, parsed: Optional[dict]) -> bool:
    """Heuristic: the subagent truncated before emitting its Decision YAML."""
    if parsed is not None and "result" in parsed:
        return False
    # No well-formed YAML with `result:` found. That's a truncation.
    return True


def _needs_composite_recovery(raw: str, parsed: Optional[dict]) -> bool:
    if parsed is None:
        return True
    if "error" in parsed:
        return False  # explicit dispatch-unparseable; don't re-run blindly
    gc = parsed.get("gather_composite")
    if not isinstance(gc, dict):
        return True
    # If the final `cross_lead_notes` key is missing entirely, assume
    # truncation mid-compile — the subagent contract requires it even when
    # empty string for single-lead modes.
    return "cross_lead_notes" not in gc


def _dispatch_single(
    ctx: Context, scope: Scope, loop_n: int,
) -> dict:
    """Invoke the single-gather subagent; on truncation, recover via
    checkpoint; on recoverable escalate triggers, fall back to composite.
    Returns a normalized payload dict.
    """
    prompt = _assemble_prompt_single(ctx, scope, loop_n)
    raw = _invoke_gather(prompt)

    try:
        parsed = _parse_gather_output(raw)
    except OrchestrationError:
        parsed = None

    if _needs_single_recovery(raw, parsed):
        parsed = _recover_single(ctx, scope, loop_n)

    assert parsed is not None  # _recover_single either returns dict or raises

    if parsed.get("result") == "escalate":
        trigger = parsed.get("trigger")
        if trigger in _COMPOSITE_FALLBACK_TRIGGERS:
            composite_parsed = _dispatch_composite(
                ctx, scope, loop_n, mode="redispatch",
            )
            return _normalize_composite(composite_parsed, scope)
        # Unrecognized trigger → surface escalate payload to ANALYZE as-is.
    return _normalize_single(parsed, scope)


def _recover_single(ctx: Context, scope: Scope, loop_n: int) -> dict:
    ckpt_path = _checkpoint_path_single(ctx, loop_n, scope.lead_name)
    ckpt = _load_checkpoint(ckpt_path)
    if ckpt is None:
        raise OrchestrationError(
            f"gather subagent emitted no Decision YAML and no checkpoint "
            f"exists at {ckpt_path}; cannot recover"
        )
    if ckpt.get("status") == "complete":
        return _reconstruct_single_from_checkpoint(ckpt)
    # In-progress or unclear: re-dispatch with resume flag.
    resume_prompt = _assemble_prompt_single(ctx, scope, loop_n, resume=True)
    raw = _invoke_gather(resume_prompt)
    return _parse_gather_output(raw)


def _dispatch_composite(
    ctx: Context, scope: Scope, loop_n: int, *, mode: str,
) -> dict:
    prompt = _assemble_prompt_composite(ctx, scope, loop_n, mode=mode)
    raw = _invoke_gather_composite(prompt)

    try:
        parsed = _parse_composite_output(raw)
    except OrchestrationError:
        parsed = None

    if _needs_composite_recovery(raw, parsed):
        parsed = _recover_composite(ctx, scope, loop_n, mode)

    assert parsed is not None
    return parsed


def _recover_composite(
    ctx: Context, scope: Scope, loop_n: int, mode: str,
) -> dict:
    ckpt_path = _checkpoint_path_composite(ctx, loop_n)
    ckpt = _load_checkpoint(ckpt_path)
    if ckpt is None:
        raise OrchestrationError(
            f"gather-composite subagent emitted no YAML and no checkpoint "
            f"exists at {ckpt_path}; cannot recover"
        )
    if ckpt.get("status") == "complete":
        return _reconstruct_composite_from_checkpoint(ckpt)
    resume_prompt = _assemble_prompt_composite(
        ctx, scope, loop_n, mode=mode, resume=True,
    )
    raw = _invoke_gather_composite(resume_prompt)
    return _parse_composite_output(raw)


# ---------------------------------------------------------------------------
# Payload normalization
# ---------------------------------------------------------------------------


def _normalize_single(parsed: dict, scope: Scope) -> dict:
    result_kind = parsed.get("result")
    if result_kind == "finding":
        return {
            "lead_name": scope.lead_name,
            "mode": "single",
            "status": "ok",
            "characterization": parsed.get("characterization") or {},
            "cross_lead_notes": "",
            "raw_result": parsed,
        }
    # escalate path
    return {
        "lead_name": scope.lead_name,
        "mode": "single",
        "status": "escalate",
        "characterization": None,
        "cross_lead_notes": "",
        "raw_result": parsed,
    }


def _normalize_composite(parsed: dict, scope: Scope) -> dict:
    if "error" in parsed:
        return {
            "lead_name": scope.lead_name,
            "mode": "composite",
            "status": "error",
            "characterization": None,
            "cross_lead_notes": "",
            "raw_result": parsed,
        }
    gc = parsed.get("gather_composite", {})
    leads = gc.get("leads") or []
    # For a single-lead composite dispatch (the common case from fallback),
    # the first lead's characterization is the focal payload.
    first = leads[0] if leads else {}
    status = first.get("status", "ok")
    return {
        "lead_name": first.get("lead", scope.lead_name),
        "mode": "composite",
        "status": status,
        "characterization": first.get("characterization"),
        "cross_lead_notes": gc.get("cross_lead_notes") or "",
        "raw_result": parsed,
    }


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

    raw = payload["raw_result"]
    if payload["mode"] == "single":
        query = raw.get("query") or "(not recorded)"
        lines.append(f"**Query:** `{query}`")
    else:
        leads = raw.get("gather_composite", {}).get("leads") or []
        first = leads[0] if leads else {}
        query = first.get("query") or "(not recorded)"
        lines.append(f"**Query:** `{query}`")

    characterization = payload.get("characterization")
    if characterization:
        lines.append("")
        lines.append("**Raw observation:**")
        for key, value in characterization.items():
            lines.append(f"- {key}: {value}")
    else:
        context = raw.get("context") if payload["mode"] == "single" else None
        lines.append("")
        lines.append(f"**No characterization** — {context or 'see raw_result'}")

    cross = payload.get("cross_lead_notes") or ""
    if cross:
        lines.append("")
        lines.append(f"**Cross-lead notes:** {cross}")

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


def _read_hypothesize_payload(ctx: Context) -> tuple[str, int]:
    hypothesize_out = ctx.outputs.get(Phase.HYPOTHESIZE)
    if not isinstance(hypothesize_out, dict):
        raise OrchestrationError(
            "GATHER: Phase.HYPOTHESIZE payload not found on ctx.outputs — "
            "HYPOTHESIZE must run before GATHER"
        )
    selected_lead = hypothesize_out.get("selected_lead")
    if not isinstance(selected_lead, str) or not selected_lead.strip():
        raise OrchestrationError(
            f"GATHER: HYPOTHESIZE payload missing non-empty selected_lead "
            f"(got {selected_lead!r})"
        )
    loop_n = hypothesize_out.get("loop_n")
    if not isinstance(loop_n, int):
        raise OrchestrationError(
            f"GATHER: HYPOTHESIZE payload missing int loop_n (got {loop_n!r})"
        )
    return selected_lead, loop_n


def handle(ctx: Context) -> PhaseResult:
    selected_lead, loop_n = _read_hypothesize_payload(ctx)
    scope = _resolve_scope(ctx, selected_lead)

    if scope.template_exists:
        payload = _dispatch_single(ctx, scope, loop_n)
    else:
        composite_parsed = _dispatch_composite(
            ctx, scope, loop_n, mode="ad-hoc",
        )
        payload = _normalize_composite(composite_parsed, scope)

    section = _compose_markdown(payload, loop_n)
    _append_to_investigation(ctx, section)

    return PhaseResult(next_phase=Phase.ANALYZE, payload=payload)
