"""PREDICT phase handler.

Dispatches the `predict` subagent. PREDICT scaffolds: declares (possibly
zero) new hypotheses, always selects a lead, and hands off to GATHER.
Continuation planning is PREDICT's job — ANALYZE decided we're continuing;
PREDICT picks what to investigate next.

The subagent (agents/predict.md, model=sonnet) emits one of:
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
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from schemas.state import Phase
from scripts.orchestrate import Context, OrchestrationError, PhaseResult

from scripts.handlers._context_loader import (
    format_alert_block,
    format_investigation_block,
    format_lead_definitions_summary_block,
    format_signature_text_block,
    load_alert,
    load_investigation_md,
    load_lead_definitions,
    load_run_salt,
    load_signature_text,
)
from scripts.handlers._subagent import (
    invoke_subagent as _shared_invoke,
)
from scripts.handlers._output_parser import (
    PredictOutputError,
    PredictParseResult,
    parse_predict_output,
)

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


def _invoke_subagent(prompt: str, *, timeout: int = SUBAGENT_TIMEOUT_SECONDS) -> str:
    """Module-level wrapper over the shared subagent dispatcher.

    Kept as a module-level function so tests can monkeypatch it with
    `monkeypatch.setattr(predict_handler, "_invoke_subagent", stub)`.
    """
    return _shared_invoke("predict", prompt, timeout=timeout)


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
    """Build the predict subagent prompt with all deterministic context inline.

    The subagent receives alert.json, investigation.md, signature playbook +
    context, and the full lead catalog preloaded — no Read tool calls
    required. Bash stays available for invlang corpus queries (pre-baked
    priors are inlined, but CLI is retained for shape-calibration lookups the
    priors don't answer).

    Archetype context is intentionally absent: PREDICT works at the mechanism
    layer, archetypes are a disposition-routing concern that REPORT consumes.
    """
    loop_n = _compute_loop_n(ctx)
    priors_section = _safe_priors_section(ctx)

    alert = load_alert(ctx.run_dir)
    salt = load_run_salt(ctx.run_dir)
    investigation_md = load_investigation_md(ctx.run_dir)
    signature_texts = load_signature_text(ctx.signature_id, SOC_AGENT_ROOT)
    lead_defs = load_lead_definitions(SOC_AGENT_ROOT)

    env_memory_section = _safe_env_memory_section(ctx)

    blocks = [
        (
            f"run_dir={ctx.run_dir}\n"
            f"signature_id={ctx.signature_id}\n"
            f"loop_n={loop_n}"
        ),
        priors_section,
    ]
    if env_memory_section:
        blocks.append(env_memory_section)
    blocks.extend([
        format_alert_block(alert, salt),
        format_investigation_block(investigation_md, mode="predict"),
        format_signature_text_block(signature_texts, exclude_archetype_catalog=True),
        format_lead_definitions_summary_block(lead_defs),
    ])

    if remediation_notes:
        blocks.append(
            "resume_from_checkpoint=true\n"
            "remediation_notes=" + " | ".join(remediation_notes)
        )

    return "\n\n".join(blocks)


# ---------------------------------------------------------------------------
# Past-investigation priors (topology-conditioned corpus retrieval)
# ---------------------------------------------------------------------------


def _safe_env_memory_section(ctx: Context) -> str:
    """Produce the environment-memory prompt block.

    Walks `knowledge/environment/{fleet,systems}/**/*.md`, scores atoms
    against anchors extracted from the live investigation state, returns the
    formatted block. Empty match → empty string (caller skips the section).

    All exceptions degrade to a banner — env-memory must never block the
    loop. Same discipline as `_safe_priors_section`.
    """
    try:
        from scripts.handlers import env_memory  # type: ignore

        matched = env_memory.retrieve(SOC_AGENT_ROOT, ctx)
        return env_memory.format_env_memory_block(matched)
    except Exception as exc:  # noqa: BLE001 — intentional broad catch
        return (
            "## Environment memory\n"
            f"(env-memory unavailable: {type(exc).__name__}: {exc})"
        )


def _safe_priors_section(ctx: Context) -> str:
    """Produce the `## Past-investigation priors` markdown block.

    Loop-aware: at loop 1 (no prior hypothesize block) we key retrieval off the
    *prologue* shape rather than synthesizing per-seed fingerprints that
    structurally can't match topology tiers 0–3. At loop 2+ the hypothesis
    frontier carries real proposed upstream edges, so per-hypothesis topology
    retrieval works as designed.

    All exceptions degrade to a banner — priors must never block the loop.
    """
    try:
        frontier = _extract_current_frontier(ctx)
        is_loop_1 = not frontier or all(
            _fp_get_relation(e["fingerprint"]) is None for e in frontier
        )
        if is_loop_1:
            return _format_prologue_priors(_compute_prologue_priors(ctx))
        priors = _compute_priors(frontier)
        return _format_priors(priors)
    except Exception as exc:  # noqa: BLE001 — intentional broad catch
        return (
            "## Past-investigation priors\n"
            f"(priors unavailable: {type(exc).__name__}: {exc})"
        )


def _fp_get_relation(fp: dict) -> str | None:
    r = fp.get("relation") if isinstance(fp, dict) else None
    return r if isinstance(r, str) else None


def _compute_prologue_priors(ctx: Context) -> dict:
    """Loop-1 prologue-keyed retrieval.

    Reads the prologue from the run's `investigation.md`, runs
    same-signature-scoped prologue retrieval, and falls back to
    cross-signature when the same-signature pass returns no cases.
    """
    from invlang import (  # type: ignore
        lead_effectiveness_for_prologue,
        load_corpus,
        peer_hypothesis_distribution_for_prologue,
    )

    inv_path = ctx.run_dir / "investigation.md"
    text = inv_path.read_text() if inv_path.exists() else ""
    prologue, _ = _parse_prologue_and_last_hypothesize(text)
    prologue = prologue or {}

    corpus = load_corpus()

    leads_same = lead_effectiveness_for_prologue(
        corpus, prologue, signature_id=ctx.signature_id
    )
    peers_same = peer_hypothesis_distribution_for_prologue(
        corpus, prologue, signature_id=ctx.signature_id
    )
    scope = "same-signature"
    leads = leads_same
    peers = peers_same
    if not leads_same.get("cases_matched"):
        leads_any = lead_effectiveness_for_prologue(
            corpus, prologue, signature_id=None
        )
        peers_any = peer_hypothesis_distribution_for_prologue(
            corpus, prologue, signature_id=None
        )
        if leads_any.get("cases_matched"):
            scope = "cross-signature"
            leads = leads_any
            peers = peers_any

    return {
        "prologue_signature": _prologue_signature_summary(prologue),
        "scope": scope,
        "leads": leads,
        "peers": peers,
    }


def _prologue_signature_summary(prologue: dict) -> dict:
    """Compact self-describing signature — shown in the rendered block so the
    subagent sees exactly what was matched on."""
    vertices = prologue.get("vertices") or []
    edges = prologue.get("edges") or []
    return {
        "vertex_types": sorted({v.get("type") for v in vertices if isinstance(v, dict) and v.get("type")}),
        "vertex_classifications": sorted({v.get("classification") for v in vertices if isinstance(v, dict) and v.get("classification")}),
        "edge_relations": sorted({e.get("relation") for e in edges if isinstance(e, dict) and e.get("relation")}),
    }


def _format_prologue_priors(payload: dict) -> str:
    """Render the loop-1 prologue-keyed priors block.

    Baseline-recommendation format: when the corpus carries strong support
    for a top-lead at this prologue topology, emit a single recommendation
    line — "use this scaffold unless the alert contradicts it." When
    support is weak, emit a sparse-prior fallback that tells PREDICT to
    scaffold from first principles.

    Peer-classification rendering is intentionally absent. A list of
    historically-proposed classifications drives enumerate-every-mechanism
    behavior (the FM4/FM5 failure modes); the priors block should nudge
    scaffold choice, not seed a fork space.
    """
    sig = payload["prologue_signature"]
    scope = payload["scope"]
    leads = payload["leads"]

    lead_rows = leads.get("hits") or []
    top = lead_rows[0] if lead_rows else None

    is_strong = (
        top is not None
        and (top.get("branching_support") or 0) >= _STRONG_PRIOR_MIN_SUPPORT
        and (top.get("fidelity_rate") or 0.0) >= _STRONG_PRIOR_MIN_FIDELITY
    )

    lines = [
        "## Past-investigation priors",
        "",
        f"Prologue topology — {scope} scope, "
        f"tier {leads['tier_used']}: {leads['tier_label']}, "
        f"{leads.get('cases_matched', 0)} cases matched. "
        f"Vertex types: {', '.join(sig['vertex_types']) or '—'}. "
        f"Edge relations: {', '.join(sig['edge_relations']) or '—'}.",
        "",
    ]

    if is_strong:
        n = top.get("branching_support") or 0
        total = leads.get("cases_matched") or n
        fidelity = top.get("fidelity_rate") or 0.0
        lines.append(
            f"**Strongest prior at this topology:** `{top['lead_name']}` "
            f"({n}/{total} cases, {int(fidelity * 100)}% fidelity rate). "
            "Use this scaffold unless the alert specifically contradicts it."
        )
    else:
        lines.append(
            "Priors at this topology are sparse — scaffold from first principles "
            "per PREDICT's ASSESS gate."
        )

    return "\n".join(lines)


def _extract_current_frontier(ctx: Context) -> list[dict]:
    """Return a list of `{name, fingerprint}` entries describing the frontier.

    Loop N (N ≥ 2): use the *last* `hypothesize:` yaml block in
    `investigation.md`; resolve each hypothesis's topology against the
    investigation's own prologue (first yaml block carrying `prologue:`).

    Loop 1 (no prior `hypothesize:`): synthesize one entry per playbook
    hypothesis seed, with `relation=None` and parent classification = the
    seed name stripped of the leading `?`. Loop-1 fingerprints never match
    tiers 0–3 (relation is required); retrieval naturally falls back to the
    name-glob tier, which is what the subagent expects at loop 1.
    """
    inv_path = ctx.run_dir / "investigation.md"
    text = inv_path.read_text() if inv_path.exists() else ""

    prologue, last_hypothesize = _parse_prologue_and_last_hypothesize(text)

    from invlang import hypothesis_topology  # type: ignore

    if last_hypothesize is not None:
        hypotheses = last_hypothesize.get("hypotheses") or []
        shelved = set(last_hypothesize.get("shelved") or [])
        active = [h for h in hypotheses if h.get("id") not in shelved]
        return [
            {
                "name": _hyp_name(h),
                "fingerprint": hypothesis_topology(prologue or {}, h, active),
            }
            for h in active
            if _hyp_name(h)
        ]

    # Loop 1 fallback — seeds from the signature playbook.
    from scripts.handlers.contextualize import load_playbook_metadata

    meta = load_playbook_metadata(ctx.signature_id)
    seeds = meta.hypothesis_seeds or []
    peers = tuple(sorted(seeds))
    frontier: list[dict] = []
    for seed in seeds:
        classification = seed.lstrip("?")
        frontier.append({
            "name": seed if seed.startswith("?") else f"?{seed}",
            "fingerprint": {
                "attached_vertex": None,
                "relation": None,
                "parent_vertex": {"type": None, "classification": classification},
                "peers": peers,
            },
        })
    return frontier


def _parse_prologue_and_last_hypothesize(
    text: str,
) -> tuple[dict | None, dict | None]:
    """Walk all yaml fences once; return (prologue, last_hypothesize)."""
    prologue: dict | None = None
    last_hyp: dict | None = None
    for m in _FIRST_FENCE_RE.finditer(text):
        try:
            parsed = yaml.safe_load(m.group("body"))
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        if prologue is None and "prologue" in parsed and isinstance(parsed["prologue"], dict):
            prologue = parsed["prologue"]
        if "hypothesize" in parsed and isinstance(parsed["hypothesize"], dict):
            last_hyp = parsed["hypothesize"]
    return prologue, last_hyp


def _hyp_name(h: dict) -> str:
    return h.get("name") or ""


def _compute_priors(frontier: list[dict]) -> list[dict]:
    """Compute `{name, fingerprint, tier_used, tier_label, leads, peers}` per entry."""
    from invlang import (  # type: ignore
        lead_effectiveness_for_topology,
        load_corpus,
        peer_hypothesis_distribution_for_topology,
    )

    corpus = load_corpus()
    out: list[dict] = []
    for entry in frontier:
        fp = entry["fingerprint"]
        leads = lead_effectiveness_for_topology(corpus, fp)
        peers = peer_hypothesis_distribution_for_topology(corpus, fp)
        out.append({
            "name": entry["name"],
            "fingerprint": fp,
            "tier_used": leads.get("tier_used"),
            "tier_label": leads.get("tier_label"),
            "leads": leads.get("hits") or [],
            "peers": peers.get("hits") or [],
        })
    return out


_PRIORS_LEADS_TOP_N = 5
_PRIORS_PEERS_TOP_N = 5

# Baseline-recommendation thresholds for _format_prologue_priors. Calibrated
# against the current corpus depth (~40 companions); revisit as the corpus
# grows or if eval shows the recommendation missing real patterns.
#   - support (branching_support): the per-lead case count at this topology.
#     Below 5 we can't reliably distinguish signal from coincidence.
#   - fidelity (fidelity_rate): fraction of cases where the lead's
#     prediction materialized — i.e. the lead actually discriminated when
#     it was fired. Below 0.5 the prior is a coin flip.
_STRONG_PRIOR_MIN_SUPPORT = 5
_STRONG_PRIOR_MIN_FIDELITY = 0.5


def _format_priors(priors: list[dict]) -> str:
    """Render a concise markdown block. Empty frontier or empty retrieval
    both still emit the section — honesty beats silent omission."""
    lines = ["## Past-investigation priors"]
    if not priors:
        lines.append("(no frontier extracted)")
        return "\n".join(lines)
    for entry in priors:
        lines.append("")
        lines.append(
            f"### {entry['name']} (tier {entry['tier_used']} — {entry['tier_label']})"
        )
        leads = entry["leads"][:_PRIORS_LEADS_TOP_N]
        if not leads:
            lines.append("Leads: (no corpus matches at any tier)")
        else:
            lines.append("Leads (per-occurrence effectiveness; n = support):")
            for row in leads:
                score = row.get("mean_branching_delta")
                fidelity = row.get("fidelity_rate")
                n = row.get("branching_support") or 0
                lines.append(
                    f"  - {row['lead_name']}: "
                    f"score={_fmt_num(score)}, fidelity={_fmt_num(fidelity)}, n={n}"
                )
        peers = entry["peers"][:_PRIORS_PEERS_TOP_N]
        if peers:
            lines.append("Peer hypotheses co-proposed at this topology:")
            for p in peers:
                hist = p.get("final_weight_histogram") or {}
                hist_str = ", ".join(
                    f"{k}={v}" for k, v in hist.items() if v
                ) or "—"
                lines.append(
                    f"  - {p['classification']} "
                    f"({p['peer_count']} cases, weights: {hist_str})"
                )
    return "\n".join(lines)


def _fmt_num(v: float | None) -> str:
    if v is None:
        return "—"
    return f"{v:.3f}"


# ---------------------------------------------------------------------------
# Block-type detection + error-block handling
# ---------------------------------------------------------------------------


# Detect top-level key of the first fenced ```yaml block that carries one of
# the expected keys. Tolerates preamble YAML blocks (unlikely, but defensive).
_FIRST_FENCE_RE = re.compile(
    r"```yaml\s*\n(?P<body>.*?)\n```",
    re.DOTALL,
)


# (Removed: _detect_block_type, _extract_error_reason, _validate_trailer,
# and _strip_terminal_routing — all internal helpers of the pre-unified-
# envelope contract. Superseded by parse_predict_output in
# scripts/handlers/_output_parser.py, which handles envelope extraction,
# shape validation, routing-field validation, and contract-violation
# messaging in one pass against a single YAML-block envelope.)


# ---------------------------------------------------------------------------
# Validate + append (library invocation of the invlang validator)
# ---------------------------------------------------------------------------


def _validate_companion_proposed(ctx: Context, new_section: str) -> list[str]:
    """Run `validate_companion` against `investigation.md + new_section`.

    Returns the validator's error list. Used both for pre-write gating and for
    producing remediation notes on the retry path.
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
        + new_section
    )
    return validate_companion(proposed, current if current else None)


def _append_to_investigation(ctx: Context, new_section: str) -> None:
    inv_path = ctx.run_dir / "investigation.md"
    current = inv_path.read_text() if inv_path.exists() else ""
    separator = "\n" if current and not current.endswith("\n") else ""
    inv_path.write_text(current + separator + new_section)


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
    dumped = yaml.safe_dump(
        {"hypothesize": {"hypotheses": hypotheses}},
        sort_keys=False, default_flow_style=False,
    )
    return (
        f"## PREDICT (loop {loop_n})\n\n"
        f"```yaml\n{dumped.rstrip()}\n```\n"
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

    # Re-dump the embedded predict envelope and run it through the parser so
    # synthesis enforces the same contract as the stdout path.
    envelope_yaml = yaml.safe_dump({"predict": data["predict"]}, sort_keys=False)
    try:
        result = parse_predict_output(envelope_yaml, expected_loop_n=expected_loop_n)
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
        "ts": datetime.now(timezone.utc).isoformat(),
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
    distribution_yaml = "\n".join(
        f"    {lead}: {count}"
        for lead, count in hit.lead_distribution.items()
    ) or "    (none)"
    matched = ", ".join(hit.matched_case_ids) or "(none)"
    section = (
        f"## PREDICT (loop {loop_n}) — fast-path\n\n"
        "```yaml\n"
        "fast_path:\n"
        f"  selected_lead: {hit.selected_lead}\n"
        f"  selection_method: {hit.selection_method}\n"
        f"  signature_id: {cache_key.signature_id}\n"
        f"  matched_precedents: [{matched}]\n"
        "  lead_distribution:\n"
        f"{distribution_yaml}\n"
        "```\n"
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
        from scripts.handlers.contextualize import load_playbook_metadata

        playbook = load_playbook_metadata(ctx.signature_id)
        disc = playbook.discriminating_classifications
        if disc is None:
            _log_predict_priors_jsonl(
                ctx, loop_n=expected_loop_n, status="ok",
                fastpath_eligible=False,
                telemetry={"reason": "signature_not_opted_in"},
            )
            return None

        inv_path = ctx.run_dir / "investigation.md"
        text = inv_path.read_text() if inv_path.exists() else ""
        prologue, _ = _parse_prologue_and_last_hypothesize(text)
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
