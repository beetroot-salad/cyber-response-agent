"""PREDICT phase handler.

Dispatches the `predict` subagent. PREDICT scaffolds: declares (possibly
zero) new hypotheses, always selects a lead, and hands off to GATHER.
Continuation planning is PREDICT's job — ANALYZE decided we're continuing;
PREDICT picks what to investigate next.

The subagent (agents/predict/SKILL.md, model=sonnet) emits one of:
    - `hypothesize:` invlang YAML block — when introducing 1+ new hypotheses
      (initial fork, fork refinement, or single-story declaration).
    - **No invlang YAML block** — when continuing an unchanged fork: the
      hypothesize state from prior loops stands; this loop only picks the
      next lead.
    - `error:` block (malformed inputs — raises).
followed by a terminal routing YAML:

    ```yaml
    selected_lead: <lead-slug>         # required, non-empty
    composite_secondary: [<slug>, ...]  # optional list; second+ prescribed leads
    override_data_source: <str>         # optional; per-lead override for GATHER
    lead_hints:                         # optional; per-lead PREDICT→GATHER prose
      <lead-slug>: <str>                #   keys must name selected_lead or one
      ...                               #   of composite_secondary
    ```

No `mode`, no `block_type`, no `loop_n` in the trailer. Cardinality of new
hypotheses is structural (invlang block present ↔ ≥1 new hypotheses). Novelty
of a hypothesis ID is derived from the accumulated companion, not declared.
Loop number is computed handler-side from `ctx.history` — not roundtripped
through the subagent.

A `gather:` block from PREDICT is still a contract violation — `gather[].lead`
entries require execution fields GATHER fills — and is handled with a
structured retry directive.

When ANALYZE's payload carries `unresolved_prescribed_set` (leads prescribed
but unresolved by gather), the handler threads those names into the subagent
prompt as remediation context so PREDICT preferentially re-prescribes them.

Handler responsibilities:
    - computes `loop_n` from ctx.history (count of prior PREDICT entries + 1)
    - invokes the subagent via the shared `_subagent.invoke_subagent` wrapper
    - detects `error:` blocks and raises
    - validates the terminal trailer shape (selected_lead + optional fields)
    - runs the invlang validator (`validate_companion`) on the proposed
      append; retries with validator errors as remediation_notes on failure
    - always routes to Phase.GATHER (the only legal outgoing edge)

Input (Context):
    ctx.run_dir, ctx.signature_id, ctx.history, ctx.alert,
    ctx.outputs[Phase.ANALYZE] (optional — carries unresolved_prescribed_set
    when PREDICT is re-prescribing)

Output:
    PhaseResult
      - always Phase.GATHER
      - payload: {
          selected_lead: str,
          loop_n: int,
          composite_secondary: list[str],  # empty when not prescribed
          override_data_source?: str,
          lead_hints?: dict[str, str],  # {lead_name: prose}, keys ⊆ prescribed
        }

Files written:
    {run_dir}/investigation.md — appends the invlang sections (no trailer).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path

import yaml

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._investigation_io import (
    append_unvalidated,
    validate_proposed_companion,
)
from scripts.handlers._context_loader import (
    format_alert_summary_block,
    format_predict_available_context_block,
    load_alert,
    load_investigation_md,
    load_run_salt,
)
from scripts.handlers._playbook import load_playbook_metadata
from scripts.handlers.predict_priors import (
    parse_prologue_and_last_hypothesize,
    safe_priors_section,
)
from scripts.handlers.investigation_views import format_predict_state_block
from scripts.handlers._subagent import (
    make_invoker,
)
from scripts.handlers._output_parser import (
    PredictOutputError,
    PredictParseResult,
    parse_predict_output,
)
from scripts.handlers._hypothesize_dense import emit_hypothesize_dense

# Lazy imports for priors (invlang + contextualize) live inside the priors
# helpers themselves — keeps import-time cycles avoided and lets failures in
# those subsystems degrade to a banner rather than block handler import.


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent


SUBAGENT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_PREDICT_TIMEOUT_SECONDS", "450")
)
# Timeout fails fast — the handler does not respawn on timeout. The
# validator-error retry path (which the handler does walk) is separate.


# ---------------------------------------------------------------------------
# Subagent invocation (mockable)
# ---------------------------------------------------------------------------


_invoke_subagent = make_invoker("predict", default_timeout=SUBAGENT_TIMEOUT_SECONDS)


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


def _compute_loop_n(ctx: Context) -> int:
    """Current loop number = count of prior PREDICT entries + 1.

    PREDICT stamps the loop number on the block it is about to emit
    (ANALYZE counts the prior loops retrospectively).
    """
    prior = sum(1 for p in ctx.history if p == Phase.PREDICT.value)
    # History includes the current phase (appended in orchestrate.run() before
    # the handler is called). Subtract 1 for the current entry so the count
    # reflects truly prior loops.
    if ctx.current_phase == Phase.PREDICT and prior > 0:
        prior -= 1
    return prior + 1


def _assemble_prompt(ctx: Context, *, remediation_notes: list[str] | None = None) -> str:
    """Build the predict subagent prompt around minimal inline state.

    Inline context stays intentionally narrow:
      - run metadata
      - matched priors (when useful)
      - a summarized alert block
      - compact structured investigation state
      - explicit on-disk retrieval pointers in `<available_context>`

    Full alert JSON, signature docs, lead definitions, and environment
    knowledge remain available on disk and are loaded on demand through the
    subagent's Read tool.
    """
    loop_n = _compute_loop_n(ctx)
    priors_section = _filtered_priors_section(ctx)

    alert = load_alert(ctx.run_dir)
    salt = load_run_salt(ctx.run_dir)
    investigation_md = load_investigation_md(ctx.run_dir)
    vendor = (
        ctx.signature_id.split("-", 1)[0]
        if "-" in ctx.signature_id
        else ctx.signature_id
    )

    blocks: list[str] = [
        (
            f"run_dir={ctx.run_dir}\n"
            f"signature_id={ctx.signature_id}\n"
            f"loop_n={loop_n}"
        ),
    ]
    if priors_section:
        blocks.append(priors_section)
    blocks.extend([
        format_alert_summary_block(
            alert, vendor, salt, soc_agent_root=SOC_AGENT_ROOT
        ),
        format_predict_state_block(investigation_md),
        format_predict_available_context_block(
            ctx.run_dir,
            investigation_md,
            ctx.signature_id,
            vendor,
            soc_agent_root=SOC_AGENT_ROOT,
        ),
    ])

    if remediation_notes:
        blocks.append(
            "resume_from_checkpoint=true\n"
            "remediation_notes=" + " | ".join(remediation_notes)
        )

    return "\n\n".join(blocks)


def _filtered_priors_section(ctx: Context) -> str:
    """Return only matched/useful priors for inline prompting.

    Sparse, unavailable, or explicit no-match renderings are omitted
    entirely so the prompt does not pay for banners that carry no actionable
    scaffold.
    """
    priors_section = safe_priors_section(ctx).strip()
    if not priors_section:
        return ""

    suppress_markers = (
        "(priors unavailable:",
        "(no frontier extracted)",
        "Priors at this topology are sparse",
        "Leads: (no corpus matches at any tier)",
    )
    if any(marker in priors_section for marker in suppress_markers):
        return ""

    useful_markers = (
        "**Strongest prior at this topology:**",
        "Leads (per-occurrence effectiveness; n = support):",
    )
    if any(marker in priors_section for marker in useful_markers):
        return priors_section
    return ""


# ---------------------------------------------------------------------------
# Validate + append (library invocation of the invlang validator)
# ---------------------------------------------------------------------------


def _validate_companion_proposed(ctx: Context, new_section: str) -> list[str]:
    """Validator errors for `investigation.md + new_section`, returned without
    raising. Used by the retry loop for remediation-note assembly."""
    return validate_proposed_companion(ctx.run_dir, new_section)


def _append_to_investigation(ctx: Context, new_section: str) -> None:
    """Append post-retry; the retry loop has already gated on validation."""
    append_unvalidated(ctx.run_dir, new_section)


# ---------------------------------------------------------------------------
# Single-attempt pipeline
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Failure-mode registry (lazy-loaded into the retry prompt)
# ---------------------------------------------------------------------------
# Each entry: a handler-recognized failure mode maps to a remediation
# directive that gets injected into the retry prompt's `remediation_notes`.
# This keeps the baseline prompt lean — failure-specific guidance arrives
# only when the failure actually happens.
#
# The registry is the single source of truth for handler-authored retry
# directives. Invlang validator errors (rules 26-30 etc.) pass through as
# free-form remediation_notes so the subagent can correct claim-level
# semantics against its checkpoint.

_FAILURE_REMEDIATIONS: dict[str, str] = {
    "stdout_empty": (
        "CONTRACT VIOLATION: your prior attempt produced no stdout — "
        "likely because your final assistant turn was a tool_use (Write "
        "M_last) instead of text. `claude --print` captures only the last "
        "text turn, so a response ending in a tool call is lost. "
        "REMEDIATION: write the checkpoint file FIRST, then emit your final "
        "YAML response as text. The text response is the deliverable; "
        "stdout is not optional. If you already wrote a checkpoint at "
        "`{run_dir}/subagent_checkpoints/predict-loop-{loop_n}.yaml` with "
        "the completed work, transcribe it verbatim to stdout in the "
        "single `predict: {...}` envelope shape."
    ),
}


@dataclass
class _AttemptResult:
    """Outcome of one subagent invocation + envelope parse + validator run.

    `section` is the markdown block to append to investigation.md (empty when
    no hypotheses landed this loop).
    `result` is the PredictParseResult when the envelope parsed cleanly.
    `errors` is the remediation-retry payload — non-empty means retry.
    """
    section: str
    result: PredictParseResult | None
    errors: list[str]


def _compose_section(result: PredictParseResult, loop_n: int) -> str:
    """Render the invlang-state delta from a parsed predict output into the
    markdown section the handler appends to investigation.md.

    On shape E (branch_plan only, no hypotheses) no section is emitted —
    the branch_plan predictions are carried via PhaseResult.payload and
    stamped by the GATHER handler onto its gather entry.

    On shape A/I/M/D-with-fork the hypotheses are rendered as a single
    `hypothesize:` invlang block under a `## PREDICT (loop N)` header.
    Invlang's block merge semantics fold multiple `hypothesize:` blocks
    (one per loop) into one accumulated companion state.
    """
    hypotheses = result.invlang_delta.get("hypotheses")
    if not hypotheses:
        return ""
    body = emit_hypothesize_dense(hypotheses)
    return (
        f"## PREDICT (loop {loop_n})\n\n"
        f"```invlang\n{body}\n```\n"
    )


def _attempt(
    ctx: Context,
    *,
    expected_loop_n: int,
    remediation_notes: list[str] | None,
    allow_checkpoint_recovery: bool = True,
) -> _AttemptResult:
    """Run one subagent invocation end-to-end.

    Flow:
      1. Assemble the prompt (with optional remediation notes from a prior
         failing attempt) and dispatch the subagent.
      2. On empty stdout, try checkpoint recovery (skipped on retries).
      3. Parse the envelope via `parse_predict_output`. PredictOutputError
         becomes a remediation-retry payload — the error message is passed
         verbatim so the subagent can read its own complaint.
      4. Compose the markdown section from `invlang_delta.hypotheses` (if
         any) and run `validate_companion_proposed` against it.
      5. Return the section + parsed result + any validator errors.

    `allow_checkpoint_recovery` gates the empty-stdout path. `handle()`
    passes False on the retry attempt so a stale/broken checkpoint cannot
    loop the recovery synthesis indefinitely.
    """
    prompt = _assemble_prompt(ctx, remediation_notes=remediation_notes)
    raw = _invoke_subagent(prompt)

    # Empty-stdout path: `claude --print` captures only the final text turn,
    # so when the subagent ends on a tool_use (Write M_last after emitting
    # the YAML response), stdout is empty. Before retrying, look for the
    # checkpoint — if present and complete, synthesize the response from it.
    # This converts a 300s retry into a ~0s checkpoint read.
    if not raw.strip():
        if allow_checkpoint_recovery:
            recovered = _synthesize_from_checkpoint(ctx, expected_loop_n)
            if recovered is not None:
                return recovered
        return _AttemptResult(
            section="",
            result=None,
            errors=[_FAILURE_REMEDIATIONS["stdout_empty"]],
        )

    # Parse the envelope. PredictOutputError surfaces contract violations
    # (missing `predict:` key, bad shape matrix, bad routing, loop mismatch)
    # as retry-directives — the subagent reads its own error on retry.
    try:
        result = parse_predict_output(raw, expected_loop_n=expected_loop_n)
    except PredictOutputError as e:
        return _AttemptResult(section="", result=None, errors=[str(e)])

    # Compose section + validate against companion.
    section = _compose_section(result, expected_loop_n)
    errors = _validate_companion_proposed(ctx, section) if section else []
    return _AttemptResult(section=section, result=result, errors=errors)


def _synthesize_from_checkpoint(
    ctx: Context, expected_loop_n: int,
) -> _AttemptResult | None:
    """Recovery path for the stdout-empty case.

    When the subagent wrote the M_last checkpoint (`status: complete`) but
    stdout is empty (final turn was a tool_use, dropped by `claude --print`),
    transcribe the checkpoint into the expected return shape.

    Checkpoint contract: top-level `{status: complete, predict: {...}}` where
    the `predict:` payload mirrors the envelope the subagent should have
    emitted to stdout. Synthesis = parse the embedded envelope through the
    same parser as stdout, then compose + validate as a normal attempt.

    Returns None when the checkpoint is absent / incomplete / parse-invalid;
    caller falls through to the retry path.
    """
    ckpt = ctx.run_dir / "subagent_checkpoints" / f"predict-loop-{expected_loop_n}.yaml"
    if not ckpt.exists():
        return None
    try:
        data = yaml.safe_load(ckpt.read_text())
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict) or data.get("status") != "complete":
        return None
    if "predict" not in data:
        return None

    # The embedded predict block is a multi-line dense-form scalar string
    # (see agents/predict/SKILL.md §Progress checkpoint). Pass it directly to the
    # parser so synthesis enforces the same contract as the stdout path.
    # Note: pre-dense (YAML-envelope) checkpoints carried `predict` as a dict;
    # those fall through here and force a retry. Only relevant if a run is
    # resumed across the dense-cutover deploy boundary.
    embedded = data["predict"]
    if not isinstance(embedded, str):
        return None
    try:
        result = parse_predict_output(embedded, expected_loop_n=expected_loop_n)
    except PredictOutputError:
        return None

    section = _compose_section(result, expected_loop_n)
    errors = _validate_companion_proposed(ctx, section) if section else []
    if errors:
        # Validator disagrees with the checkpoint — route into the retry
        # path so the subagent can correct with the errors as remediation.
        return _AttemptResult(section="", result=result, errors=errors)
    return _AttemptResult(section=section, result=result, errors=[])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _unresolved_prescribed_notes(ctx: Context) -> list[str]:
    """Surface ANALYZE's unresolved_prescribed_set to PREDICT as a remediation
    note. When ANALYZE flagged that gather didn't resolve some prescribed
    leads, PREDICT should preferentially re-prescribe them (the subagent
    decides; this is guidance, not a gate).
    """
    analyze_out = ctx.outputs.get(Phase.ANALYZE)
    if not isinstance(analyze_out, dict):
        return []
    unresolved = analyze_out.get("unresolved_prescribed_set")
    if not isinstance(unresolved, list) or not unresolved:
        return []
    names = ", ".join(str(x) for x in unresolved)
    return [
        "UNRESOLVED PRESCRIBED LEADS from prior gather: "
        f"[{names}]. These were prescribed but gather did not produce a "
        "resolved status. Prefer re-prescribing them via selected_lead + "
        "composite_secondary on this loop, unless you have specific "
        "reasoning that a different lead is now more discriminating."
    ]


# ---------------------------------------------------------------------------
# Fast-path (loop-1 cache lookup, signature-opt-in)
# ---------------------------------------------------------------------------


def _log_predict_priors_jsonl(
    ctx: Context,
    *,
    loop_n: int,
    status: str,
    cache_key: dict | None = None,
    fastpath_eligible: bool = False,
    fastpath_taken: bool = False,
    selected_lead: str | None = None,
    selection_method: str | None = None,
    matched_case_ids: list[str] | None = None,
    telemetry: dict | None = None,
    exc_type: str | None = None,
) -> None:
    """Append one line to `runs/<run>/predict_priors.jsonl` per loop.

    Replaces the silent banner returned by `_safe_priors_section` on failure
    so per-run hit-rate + failure-cause is visible without sifting prompts.
    Best-effort — log failures don't break the loop.
    """
    record: dict = {
        "ts": datetime.now(UTC).isoformat(),
        "loop_n": loop_n,
        "status": status,
        "fastpath_eligible": fastpath_eligible,
        "fastpath_taken": fastpath_taken,
    }
    if cache_key is not None:
        record["cache_key"] = cache_key
    if selected_lead is not None:
        record["selected_lead"] = selected_lead
    if selection_method is not None:
        record["selection_method"] = selection_method
    if matched_case_ids is not None:
        record["matched_case_ids"] = matched_case_ids
    if telemetry is not None:
        record["telemetry"] = telemetry
    if exc_type is not None:
        record["exc_type"] = exc_type
    log_path = ctx.run_dir / "predict_priors.jsonl"
    try:
        with log_path.open("a") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except OSError:
        pass


def _append_fastpath_marker(
    ctx: Context, hit, loop_n: int, cache_key
) -> None:
    """Write the handler-authored fast-path block to investigation.md.

    Visually distinct from a subagent-authored `## PREDICT` block — ANALYZE
    sees this loop's lead came from priors, not from a subagent emission.
    Crucially this is *not* an invlang `hypothesize:` block — no new
    hypotheses are authored on the fast path.
    """
    distribution_lines = "\n".join(
        f"  - {lead}: {count}"
        for lead, count in hit.lead_distribution.items()
    ) or "  - (none)"
    matched = ", ".join(hit.matched_case_ids) or "(none)"
    section = (
        f"## PREDICT (loop {loop_n}) — fast-path\n\n"
        f"- **selected_lead:** {hit.selected_lead}\n"
        f"- **selection_method:** {hit.selection_method}\n"
        f"- **signature_id:** {cache_key.signature_id}\n"
        f"- **matched_precedents:** [{matched}]\n"
        f"- **lead_distribution:**\n"
        f"{distribution_lines}\n"
    )
    _append_to_investigation(ctx, section)


def _try_fast_path(
    ctx: Context, expected_loop_n: int
) -> PhaseResult | None:
    """Attempt the cache lookup. Returns a PhaseResult on hit, None on miss
    or any error. Always writes one JSONL log line — every loop-1 attempt is
    visible regardless of outcome.

    All exceptions degrade to a JSONL `status=degraded` line + cache miss.
    The fast path must never break the loop.
    """
    if expected_loop_n != 1:
        return None
    try:
        from invlang.corpus import load_corpus
        from scripts.handlers import predict_fastpath

        playbook = load_playbook_metadata(ctx.signature_id)
        disc = playbook.discriminating_classifications
        if disc is None:
            _log_predict_priors_jsonl(
                ctx, loop_n=expected_loop_n, status="ok",
                fastpath_eligible=False,
                telemetry={"signature_opted_in": False},
            )
            return None

        inv_path = ctx.run_dir / "investigation.md"
        text = inv_path.read_text() if inv_path.exists() else ""
        prologue, _ = parse_prologue_and_last_hypothesize(text)
        prologue = prologue or {}

        cache_key = predict_fastpath.build_cache_key(
            signature_id=ctx.signature_id,
            prologue=prologue,
            discriminating_classifications=disc,
            frontier=None,
        )
        if cache_key is None:  # defensive — disc was non-None above
            return None

        lead_catalog = set(playbook.leads)
        corpus = load_corpus()
        hit, telemetry = predict_fastpath.lookup(
            corpus,
            cache_key,
            prologue=prologue,
            discriminating_classifications=disc,
            lead_catalog=lead_catalog,
            loop=1,
        )

        if hit is None:
            _log_predict_priors_jsonl(
                ctx, loop_n=expected_loop_n, status="ok",
                cache_key=cache_key.to_log_dict(),
                fastpath_eligible=True, fastpath_taken=False,
                telemetry=telemetry,
            )
            return None

        _append_fastpath_marker(ctx, hit, expected_loop_n, cache_key)
        _log_predict_priors_jsonl(
            ctx, loop_n=expected_loop_n, status="ok",
            cache_key=cache_key.to_log_dict(),
            fastpath_eligible=True, fastpath_taken=True,
            selected_lead=hit.selected_lead,
            selection_method=hit.selection_method,
            matched_case_ids=hit.matched_case_ids,
            telemetry=hit.telemetry,
        )
        return PhaseResult(
            next_phase=Phase.GATHER,
            payload={
                "selected_lead": hit.selected_lead,
                "loop_n": expected_loop_n,
                "composite_secondary": [],
                "fast_path": {
                    "selected_lead": hit.selected_lead,
                    "selection_method": hit.selection_method,
                    "matched_case_ids": hit.matched_case_ids,
                    "lead_distribution": hit.lead_distribution,
                },
            },
        )
    except Exception as exc:  # noqa: BLE001 — intentional broad catch
        _log_predict_priors_jsonl(
            ctx, loop_n=expected_loop_n, status="degraded",
            fastpath_eligible=True, fastpath_taken=False,
            exc_type=type(exc).__name__,
            telemetry={"error": str(exc)},
        )
        return None


def handle(ctx: Context) -> PhaseResult:
    expected_loop_n = _compute_loop_n(ctx)

    fast = _try_fast_path(ctx, expected_loop_n)
    if fast is not None:
        return fast

    initial_notes = _unresolved_prescribed_notes(ctx)
    attempt = _attempt(
        ctx,
        expected_loop_n=expected_loop_n,
        remediation_notes=initial_notes or None,
    )

    # Retry budget is 2. The parser's PredictOutputError messages pass through
    # verbatim as remediation notes; the invlang validator's rule-level errors
    # do too. Disable checkpoint recovery on retries so a stale checkpoint
    # cannot loop the recovery synthesis indefinitely.
    #
    # Two retries (vs one) handles the layered-schema cascade: the validator
    # reports only errors visible given the current structural shape. Fixing
    # outer shape on attempt 2 may surface inner errors — attempt 3 closes them.
    MAX_RETRIES = 2
    attempts_used = 1
    while attempt.errors and attempts_used <= MAX_RETRIES:
        attempts_used += 1
        attempt = _attempt(
            ctx,
            expected_loop_n=expected_loop_n,
            remediation_notes=attempt.errors,
            allow_checkpoint_recovery=False,
        )
    if attempt.errors:
        raise OrchestrationError(
            f"PREDICT failed after {attempts_used} attempts:\n"
            + "\n".join(f"  - {e}" for e in attempt.errors)
        )

    assert attempt.result is not None  # errors empty + no exception → parsed

    # Only append when there's something to append. Shape E writes no invlang
    # hypotheses block; its state (branch_plan predictions) flows through the
    # PhaseResult payload to GATHER, which stamps them on the gather entry.
    if attempt.section:
        _append_to_investigation(ctx, attempt.section)

    routing = attempt.result.routing
    invlang_delta = attempt.result.invlang_delta

    payload: dict = {
        "selected_lead": routing["selected_lead"],
        "loop_n": expected_loop_n,
        "composite_secondary": list(routing.get("composite_secondary") or []),
    }
    if routing.get("override_data_source") is not None:
        payload["override_data_source"] = routing["override_data_source"]
    if routing.get("lead_hints") is not None:
        payload["lead_hints"] = routing["lead_hints"]
    # Scope override — PREDICT's structured way to override GATHER's default
    # 1h lookback (window_hours + anchor). GATHER plumbs this into the
    # subagent prompt's incident_start/incident_end so the query covers the
    # intended range rather than silently narrowing.
    if routing.get("scope_override") is not None:
        payload["scope_override"] = routing["scope_override"]
    # Shape E carries branch_plan predictions to GATHER. GATHER stamps these
    # on the gather[] entry's `predictions[]` field (lp* lead-level readings).
    if "branch_plan" in invlang_delta:
        payload["branch_plan_predictions"] = invlang_delta["branch_plan"]["predictions"]
    return PhaseResult(next_phase=Phase.GATHER, payload=payload)
