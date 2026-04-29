"""Mechanical parser for per-phase unified subagent output.

Each phase subagent (predict, analyze, ...) emits a single YAML block with a
phase-keyed top-level mapping. The orchestrator parses this block into three
clean buckets:

1. **invlang_delta** — state additions to append to the companion YAML
   (hypotheses, branch_plan → pending gather entry's predictions, etc.).
2. **routing** — orchestrator metadata consumed by the next handler, then
   discarded (selected_lead, composite_secondary, lead_hints, ...).
3. **telemetry** — audit / budget metadata (loop number, shape decision).

Design principles (see tasks-scratch/predict-output-schema.md):

- Invlang = state. Routing = orchestrator metadata. No routing keys leak
  into the invlang delta.
- Shape commitment is the literal first top-level field (`shape:`). The
  parser validates it matches the schema for the emitted sections.
- The parser is pure — no file I/O, no side effects. Handlers call it and
  then act on its result.

Currently implemented: `parse_predict_output`, `parse_gather_envelope`,
`parse_analyze_envelope`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class PredictParseResult:
    """Structured result of parsing a predict subagent output envelope.

    `invlang_delta` carries the state additions as a mapping:
      - `hypotheses` (list) — appended to `companion.hypothesize.hypotheses[]`
      - `branch_plan` (dict with `primary_lead` + `predictions`) — attached to
        the pending gather entry as `predictions[]` (lead-level lp* entries)

    `routing` carries orchestrator metadata:
      - `selected_lead` (required str)
      - `composite_secondary` (list, default [])
      - `override_data_source` (str | None)
      - `lead_hints` (dict[str, str] | None) — keyed by lead name; keys must
        appear in `selected_lead ∪ composite_secondary`

    `telemetry`: `{loop: int, shape: str}`.

    Only present keys appear in each bucket — callers should use
    `.get(key, default)` patterns rather than assuming every field is set.
    """
    invlang_delta: dict[str, Any] = field(default_factory=dict)
    routing: dict[str, Any] = field(default_factory=dict)
    telemetry: dict[str, Any] = field(default_factory=dict)


class PredictOutputError(ValueError):
    """Raised when the predict output envelope violates the parseable shape.

    Handlers catch this to trigger the remediation-notes retry flow. The
    message is passed verbatim into the retry prompt, so keep it actionable.
    """


# ---------------------------------------------------------------------------
# Envelope extraction
# ---------------------------------------------------------------------------


_VALID_SHAPES = frozenset({"E", "A", "M"})
_LEGACY_SHAPE_MAP = {"D": "E", "I": "A"}  # D→E (data-gap is enrichment); I→A (identity-of-use is authorization fork)
_YAML_FENCE_RE = re.compile(r"```(?:yaml)?\s*\n(.*?)\n```", re.DOTALL)


def _extract_top_level_envelope(
    stdout: str,
    *,
    key: str,
    error_cls: type[ValueError],
) -> dict[str, Any]:
    """Find and parse the single top-level `<key>:` YAML block.

    Supports two envelope shapes:
      - Unwrapped YAML (whole stdout is the YAML document).
      - One fenced ```yaml block containing the YAML document.

    Raises `error_cls` on parse failure, non-mapping top-level, or
    missing/wrong-shaped envelope key.
    """
    text = stdout.strip()
    if not text:
        raise error_cls(f"{key} output is empty")

    fence_match = _YAML_FENCE_RE.search(text)
    body = fence_match.group(1) if fence_match else text

    try:
        doc = yaml.safe_load(body)
    except yaml.YAMLError as e:
        raise error_cls(f"{key} output is not valid YAML: {e}") from e

    if not isinstance(doc, dict):
        raise error_cls(
            f"{key} output top-level must be a mapping, got {type(doc).__name__}"
        )
    if key not in doc:
        keys = sorted(doc.keys()) if doc else []
        raise error_cls(
            f"{key} output must have top-level key `{key}:`, got {keys}"
        )
    envelope = doc[key]
    if not isinstance(envelope, dict):
        raise error_cls(
            f"{key}.* must be a mapping, got {type(envelope).__name__}"
        )
    return envelope


def _extract_envelope(stdout: str) -> dict[str, Any]:
    """Predict-flavored wrapper around `_extract_top_level_envelope`."""
    return _extract_top_level_envelope(
        stdout, key="predict", error_cls=PredictOutputError,
    )


# ---------------------------------------------------------------------------
# Section extractors
# ---------------------------------------------------------------------------


def _extract_header(env: dict[str, Any]) -> dict[str, Any]:
    """Validate and extract the loop + shape header."""
    loop = env.get("loop")
    shape = env.get("shape")
    if not isinstance(loop, int):
        raise PredictOutputError(
            f"predict.loop must be an integer, got {type(loop).__name__}"
        )
    if shape in _LEGACY_SHAPE_MAP:
        # Tolerance: map pre-collapse D/I to their new equivalents so a
        # stray subagent emission doesn't block the handler. The parser
        # rewrites the header in place.
        shape = _LEGACY_SHAPE_MAP[shape]
    if shape not in _VALID_SHAPES:
        raise PredictOutputError(
            f"predict.shape must be one of {sorted(_VALID_SHAPES)}, got {shape!r}"
        )
    return {"loop": loop, "shape": shape}


def _extract_hypotheses(env: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull `hypotheses[]` if present. Schema validation happens downstream
    via `validate_companion_proposed()`."""
    hs = env.get("hypotheses")
    if hs is None:
        return []
    if not isinstance(hs, list):
        raise PredictOutputError(
            f"predict.hypotheses must be a list, got {type(hs).__name__}"
        )
    return hs


def _extract_branch_plan(env: dict[str, Any]) -> dict[str, Any] | None:
    """Pull `branch_plan` if present. Does not validate the inner predictions
    shape here — that's enforced at append time against the pending gather
    entry (rule #18 on the invlang side)."""
    bp = env.get("branch_plan")
    if bp is None:
        return None
    if not isinstance(bp, dict):
        raise PredictOutputError(
            f"predict.branch_plan must be a mapping, got {type(bp).__name__}"
        )
    primary = bp.get("primary_lead")
    predictions = bp.get("predictions")
    if not isinstance(primary, str) or not primary.strip():
        raise PredictOutputError(
            "predict.branch_plan.primary_lead must be a non-empty string"
        )
    if not isinstance(predictions, list) or not predictions:
        raise PredictOutputError(
            "predict.branch_plan.predictions must be a non-empty list of "
            "readings (lp* entries with if/read_as/advance_to)"
        )
    return bp


_VALID_SCOPE_ANCHORS = frozenset({"alert", "now"})


def _extract_scope_override(r: dict[str, Any]) -> dict[str, Any] | None:
    """Validate the optional `routing.scope_override` block.

    Shape:
      scope_override:
        window_hours: <positive int>   # override the 1h default lookback
        anchor: alert | now            # which T the window is centered on
                                       # (optional; default 'alert')

    Returns a validated dict when the block is present, or None when absent.
    Malformed blocks raise PredictOutputError — caller maps to retry.
    """
    so = r.get("scope_override")
    if so is None:
        return None
    if not isinstance(so, dict):
        raise PredictOutputError(
            f"predict.routing.scope_override must be a mapping when provided, "
            f"got {type(so).__name__}"
        )
    window_hours = so.get("window_hours")
    if not isinstance(window_hours, int) or isinstance(window_hours, bool):
        raise PredictOutputError(
            "predict.routing.scope_override.window_hours must be a positive "
            f"integer, got {window_hours!r}"
        )
    if window_hours <= 0:
        raise PredictOutputError(
            f"predict.routing.scope_override.window_hours must be > 0, got {window_hours}"
        )
    anchor = so.get("anchor", "alert")
    if anchor not in _VALID_SCOPE_ANCHORS:
        raise PredictOutputError(
            f"predict.routing.scope_override.anchor must be one of "
            f"{sorted(_VALID_SCOPE_ANCHORS)}, got {anchor!r}"
        )
    return {"window_hours": window_hours, "anchor": anchor}


def _extract_routing(env: dict[str, Any]) -> dict[str, Any]:
    """Pull `routing` and validate the minimum shape.

    `selected_lead` is required. `composite_secondary` defaults to [] when
    absent. `override_data_source`, `lead_hints`, and `scope_override` are
    optional (absent when not provided). The handler consumes `routing` into
    `ctx.outputs[Phase.PREDICT]`; a missing `selected_lead` means gather has
    nothing to dispatch — fatal.

    `lead_hints` is a `{lead_name: prose}` mapping — every key must name a
    lead that appears in `selected_lead ∪ composite_secondary`. This keeps
    composite leads first-class: secondaries can carry intent prose just
    like the primary.

    `scope_override` is the structured way for PREDICT to override gather's
    default 1-hour lookback window (e.g. a 24h cadence check on
    authentication-history). Prose hints in `lead_hints` are free-form and
    not authoritative on scope.
    """
    r = env.get("routing")
    if not isinstance(r, dict):
        raise PredictOutputError(
            f"predict.routing must be a mapping, got {type(r).__name__}"
        )
    selected = r.get("selected_lead")
    if not isinstance(selected, str) or not selected.strip():
        raise PredictOutputError(
            "predict.routing.selected_lead must be a non-empty string"
        )

    composite = r.get("composite_secondary") or []
    if not isinstance(composite, list) or not all(
        isinstance(x, str) and x.strip() for x in composite
    ):
        raise PredictOutputError(
            "predict.routing.composite_secondary must be a list of non-empty "
            f"strings, got {composite!r}"
        )

    out: dict[str, Any] = {
        "selected_lead": selected,
        "composite_secondary": composite,
    }
    ods = r.get("override_data_source")
    if ods is not None:
        if not isinstance(ods, str) or not ods.strip():
            raise PredictOutputError(
                "predict.routing.override_data_source must be null or a "
                f"non-empty string, got {ods!r}"
            )
        out["override_data_source"] = ods
    hints = r.get("lead_hints")
    if hints is not None:
        if not isinstance(hints, dict):
            raise PredictOutputError(
                "predict.routing.lead_hints must be a mapping of "
                f"{{lead_name: prose}}, got {type(hints).__name__}"
            )
        valid_names = {selected, *composite}
        for name, prose in hints.items():
            if not isinstance(name, str) or not name.strip():
                raise PredictOutputError(
                    f"predict.routing.lead_hints key must be a non-empty "
                    f"string, got {name!r}"
                )
            if name not in valid_names:
                raise PredictOutputError(
                    f"predict.routing.lead_hints[{name!r}] does not name a "
                    f"prescribed lead (selected_lead or composite_secondary)"
                )
            if not isinstance(prose, str) or not prose.strip():
                raise PredictOutputError(
                    f"predict.routing.lead_hints[{name!r}] must be a "
                    f"non-empty string, got {prose!r}"
                )
        out["lead_hints"] = dict(hints)
    scope_override = _extract_scope_override(r)
    if scope_override is not None:
        out["scope_override"] = scope_override
    return out


# ---------------------------------------------------------------------------
# Cross-section consistency
# ---------------------------------------------------------------------------


def _check_shape_consistency(
    shape: str, hypotheses: list[dict[str, Any]], branch_plan: dict[str, Any] | None
) -> None:
    """Per the field-presence matrix in agents/predict.md.

    Shape E → branch_plan required, hypotheses empty. (Enrichment; also
              covers the former "data-gap" case — filling a field gap is
              enrichment of the gap.)
    Shape A → hypotheses required (≥1, at least one carrying
              authorization_contract); branch_plan absent. (Authorization
              fork; also covers identity-of-use — identity is resolved by
              an authority/integrity contract.)
    Shape M → hypotheses required (≥2, diverging on observable fields);
              branch_plan absent. (Mechanism fork, contract-free.)
    """
    if shape == "E":
        if branch_plan is None:
            raise PredictOutputError(
                "predict.shape=E requires a branch_plan (enrichment shape "
                "carries lead-level readings that drive next-loop routing)"
            )
        if hypotheses:
            raise PredictOutputError(
                "predict.shape=E must have empty hypotheses (shape E is the "
                "deferred-fork shape — use shape A or M if you are authoring "
                "hypotheses this loop)"
            )
        return

    if shape in ("A", "M"):
        if not hypotheses:
            raise PredictOutputError(
                f"predict.shape={shape} requires at least one hypothesis"
            )
        if branch_plan is not None:
            raise PredictOutputError(
                f"predict.shape={shape} must not emit a branch_plan "
                f"(branch_plan is exclusive to shape E)"
            )
        return


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_predict_output(stdout: str, *, expected_loop_n: int | None = None) -> PredictParseResult:
    """Parse a predict subagent's unified YAML output into the three buckets.

    `expected_loop_n` lets the handler cross-check that the subagent emitted
    the correct loop number; mismatch is a PredictOutputError (the subagent
    is asserting a loop the orchestrator didn't authorize).

    Routes only the structural shape — `validate_companion_proposed()` still
    runs on the companion after the delta is appended, so schema errors on
    hypotheses land in the existing validator-retry flow.
    """
    env = _extract_envelope(stdout)

    header = _extract_header(env)
    if expected_loop_n is not None and header["loop"] != expected_loop_n:
        raise PredictOutputError(
            f"predict.loop={header['loop']} does not match orchestrator-"
            f"computed loop_n={expected_loop_n}. The subagent must emit the "
            f"loop number passed in its prompt."
        )

    hypotheses = _extract_hypotheses(env)
    branch_plan = _extract_branch_plan(env)
    routing = _extract_routing(env)

    _check_shape_consistency(header["shape"], hypotheses, branch_plan)

    invlang_delta: dict[str, Any] = {}
    if hypotheses:
        invlang_delta["hypotheses"] = hypotheses
    if branch_plan is not None:
        invlang_delta["branch_plan"] = branch_plan

    return PredictParseResult(
        invlang_delta=invlang_delta,
        routing=routing,
        telemetry=header,
    )


# ---------------------------------------------------------------------------
# Gather envelope
# ---------------------------------------------------------------------------


_VALID_LEAD_STATUSES = frozenset({
    "ok",               # lead executed, full characterization
    "partial",          # lead executed, some bullets "not available"
    "data_missing",     # source answered, empty result (verified)
    "dropped_attempt",  # structural refusal / skipped
    "probe_broken",     # health probe returned count_fn_error / baseline_no_samples
    "siem_error",       # SIEM CLI returned an error that couldn't be resolved
    "error",            # single-gather generic error (escalate_trigger carries the specific reason)
})


@dataclass
class GatherEnvelope:
    """Structured result of parsing a gather / gather-composite envelope.

    The envelope wraps plain-YAML observation data — no invlang vocabulary
    required in the subagent prompt. The handler synthesizes the `findings:`
    invlang block from `leads[]` and writes `raw[]` payloads to disk.

    `leads` — per-lead observation records. Each entry mirrors the shape a
    `findings[]` entry will take *minus* any analyze-authored fields. Fields
    the handler carries through unchanged: `id`, `name`, `status`, `query`,
    `observations`, `attribute_updates`, `consultations`.

    `raw_by_lead` — lead_id → {siem_response, consultations[]}. Handler
    writes each entry to `runs/<run-id>/raw_details/loop-<N>/<lead-id>.yaml`
    and stashes the path list on `ctx.outputs[Phase.GATHER]` for analyze's
    preload. Never written into the invlang companion.

    `telemetry`: `{loop: int, mode: "single" | "composite" | "parallel"}` —
    mode is inferred from the dispatch path, not asserted by the subagent.
    `parallel` is set by the parallel-singletons orchestrator after concat.
    """

    leads: list[dict[str, Any]] = field(default_factory=list)
    raw_by_lead: dict[str, dict[str, Any]] = field(default_factory=dict)
    cross_lead_notes: str = ""
    telemetry: dict[str, Any] = field(default_factory=dict)


class GatherOutputError(ValueError):
    """Raised when the gather envelope violates the parseable shape."""


def _extract_gather_envelope_doc(stdout: str) -> dict[str, Any]:
    return _extract_top_level_envelope(
        stdout, key="gather", error_cls=GatherOutputError,
    )


def _extract_gather_leads(
    env: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """Split `leads[]` into invlang-bound fields (returned as the leads list)
    and raw payloads (returned keyed by lead id).

    Each lead is expected to have `id` + `status`. The handler enforces
    downstream invlang shape via `validate_companion()`; this parser only
    asserts the outer shape + the `raw` extraction.
    """
    raw_leads = env.get("leads")
    if not isinstance(raw_leads, list) or not raw_leads:
        raise GatherOutputError(
            "gather.leads must be a non-empty list of lead entries"
        )

    cleaned: list[dict[str, Any]] = []
    raw_by_lead: dict[str, dict[str, Any]] = {}

    seen_ids: set[str] = set()
    for i, lead in enumerate(raw_leads):
        if not isinstance(lead, dict):
            raise GatherOutputError(
                f"gather.leads[{i}] must be a mapping, got {type(lead).__name__}"
            )
        lead_id = lead.get("id")
        if not isinstance(lead_id, str) or not lead_id.strip():
            raise GatherOutputError(
                f"gather.leads[{i}].id must be a non-empty string, got {lead_id!r}"
            )
        if lead_id in seen_ids:
            raise GatherOutputError(
                f"gather.leads[{i}].id={lead_id!r} duplicates a prior lead"
            )
        seen_ids.add(lead_id)

        status = lead.get("status")
        if status not in _VALID_LEAD_STATUSES:
            raise GatherOutputError(
                f"gather.leads[{i}].status must be one of "
                f"{sorted(_VALID_LEAD_STATUSES)}, got {status!r}"
            )

        # Split raw off the lead dict. We copy so the envelope caller sees a
        # clean `leads[]` with no `raw` key leaking into the invlang path.
        clean_lead = {k: v for k, v in lead.items() if k != "raw"}
        cleaned.append(clean_lead)

        raw = lead.get("raw")
        if raw is None:
            continue
        if not isinstance(raw, dict):
            raise GatherOutputError(
                f"gather.leads[{i}].raw must be a mapping when present, got "
                f"{type(raw).__name__}"
            )
        raw_by_lead[lead_id] = raw

    return cleaned, raw_by_lead


def parse_gather_envelope(
    stdout: str,
    *,
    expected_loop_n: int | None = None,
    mode: str | None = None,
) -> GatherEnvelope:
    """Parse a gather / gather-composite subagent envelope into the two buckets.

    `expected_loop_n` enforces the orchestrator's loop counter against the
    subagent-asserted `loop`. `mode` is injected into telemetry (dispatch
    path is the source of truth; subagent does not assert mode).
    """
    env = _extract_gather_envelope_doc(stdout)

    loop = env.get("loop")
    if not isinstance(loop, int) or isinstance(loop, bool):
        raise GatherOutputError(
            f"gather.loop must be an integer, got {type(loop).__name__}"
        )
    if expected_loop_n is not None and loop != expected_loop_n:
        raise GatherOutputError(
            f"gather.loop={loop} does not match orchestrator-computed "
            f"loop_n={expected_loop_n}"
        )

    leads, raw_by_lead = _extract_gather_leads(env)

    cross_lead_notes = env.get("cross_lead_notes") or ""
    if not isinstance(cross_lead_notes, str):
        raise GatherOutputError(
            f"gather.cross_lead_notes must be a string when present, got "
            f"{type(cross_lead_notes).__name__}"
        )

    telemetry: dict[str, Any] = {"loop": loop}
    if mode is not None:
        telemetry["mode"] = mode

    return GatherEnvelope(
        leads=leads,
        raw_by_lead=raw_by_lead,
        cross_lead_notes=cross_lead_notes,
        telemetry=telemetry,
    )


# ---------------------------------------------------------------------------
# Analyze envelope
# ---------------------------------------------------------------------------


_VALID_ROUTE_DECISIONS = frozenset({"continue", "halt"})
_VALID_TERMINATION_CATEGORIES = frozenset({
    "trust-root", "adversarial-refuted", "severity-ceiling", "exhaustion-escalation",
})
_VALID_DISPOSITIONS = frozenset({"benign", "true_positive", "unclear"})
_VALID_CONFIDENCES = frozenset({"high", "medium", "low"})


@dataclass
class AnalyzeEnvelope:
    """Structured result of parsing an analyze subagent envelope.

    Interpretation fields keyed by `lead_ref` — the handler merges them onto
    existing `findings[]` entries populated by gather. Keys may be absent
    when analyze has nothing to emit (e.g., a lead with no resolutions).

    `routing` carries the orchestrator's halt/continue decision plus CONCLUDE
    fields when halting. `anomalies[]` and `data_wishes[]` replace the
    prose Self-report section; each is a list of short free-text strings.
    """

    resolutions_by_lead: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    trust_anchor_by_lead: dict[str, dict[str, Any]] = field(default_factory=dict)
    legitimacy_by_lead: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    impact_by_lead: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    anomalies: list[str] = field(default_factory=list)
    data_wishes: list[str] = field(default_factory=list)
    routing: dict[str, Any] = field(default_factory=dict)
    telemetry: dict[str, Any] = field(default_factory=dict)


class AnalyzeOutputError(ValueError):
    """Raised when the analyze envelope violates the parseable shape."""


def _extract_analyze_envelope_doc(stdout: str) -> dict[str, Any]:
    return _extract_top_level_envelope(
        stdout, key="analyze", error_cls=AnalyzeOutputError,
    )


def _bucket_by_lead(
    entries: list[Any], field_name: str, *, singleton: bool = False,
) -> dict[str, Any]:
    """Group envelope entries by `lead_ref`.

    `singleton=False` → dict[lead_id, list[entry]].
    `singleton=True`  → dict[lead_id, entry]; each lead_ref unique.

    In both cases the per-lead entry/entries are stripped of the `lead_ref`
    key (that information is captured in the map key).
    """
    if not isinstance(entries, list):
        raise AnalyzeOutputError(
            f"analyze.{field_name} must be a list, got {type(entries).__name__}"
        )
    out_list: dict[str, list[dict[str, Any]]] = {}
    out_single: dict[str, dict[str, Any]] = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise AnalyzeOutputError(
                f"analyze.{field_name}[{i}] must be a mapping, got "
                f"{type(entry).__name__}"
            )
        lead_ref = entry.get("lead_ref")
        if not isinstance(lead_ref, str) or not lead_ref.strip():
            raise AnalyzeOutputError(
                f"analyze.{field_name}[{i}].lead_ref must be a non-empty "
                f"string, got {lead_ref!r}"
            )
        payload = {k: v for k, v in entry.items() if k != "lead_ref"}
        if singleton:
            if lead_ref in out_single:
                raise AnalyzeOutputError(
                    f"analyze.{field_name}: lead_ref={lead_ref!r} appears more "
                    "than once (expected at most one entry per lead)"
                )
            out_single[lead_ref] = payload
        else:
            # `entries` is the wrapper shape `{lead_ref, entries: [...]}` —
            # unwrap to a flat list-of-records per lead.
            inner = payload.get("entries")
            if not isinstance(inner, list):
                raise AnalyzeOutputError(
                    f"analyze.{field_name}[{i}].entries must be a list, got "
                    f"{type(inner).__name__}"
                )
            out_list.setdefault(lead_ref, []).extend(inner)
    return out_single if singleton else out_list


def _extract_analyze_routing(env: dict[str, Any]) -> dict[str, Any]:
    """Validate the routing trailer."""
    r = env.get("routing")
    if not isinstance(r, dict):
        raise AnalyzeOutputError(
            f"analyze.routing must be a mapping, got {type(r).__name__}"
        )
    decision = r.get("decision")
    if decision not in _VALID_ROUTE_DECISIONS:
        raise AnalyzeOutputError(
            f"analyze.routing.decision must be one of "
            f"{sorted(_VALID_ROUTE_DECISIONS)}, got {decision!r}"
        )
    out: dict[str, Any] = {"decision": decision}

    if decision == "halt":
        tc = r.get("termination_category")
        if tc not in _VALID_TERMINATION_CATEGORIES:
            raise AnalyzeOutputError(
                f"analyze.routing.termination_category must be one of "
                f"{sorted(_VALID_TERMINATION_CATEGORIES)} when halting, "
                f"got {tc!r}"
            )
        disp = r.get("disposition")
        if disp not in _VALID_DISPOSITIONS:
            raise AnalyzeOutputError(
                f"analyze.routing.disposition must be one of "
                f"{sorted(_VALID_DISPOSITIONS)} when halting, got {disp!r}"
            )
        conf = r.get("confidence")
        if conf not in _VALID_CONFIDENCES:
            raise AnalyzeOutputError(
                f"analyze.routing.confidence must be one of "
                f"{sorted(_VALID_CONFIDENCES)} when halting, got {conf!r}"
            )
        out["termination_category"] = tc
        out["disposition"] = disp
        out["confidence"] = conf
        # matched_archetype may be None, null, or a non-empty string.
        ma = r.get("matched_archetype")
        if ma is not None and not (isinstance(ma, str) and ma.strip()):
            raise AnalyzeOutputError(
                "analyze.routing.matched_archetype must be null or a "
                f"non-empty string when halting, got {ma!r}"
            )
        out["matched_archetype"] = ma
        sh = r.get("surviving_hypotheses") or []
        if not isinstance(sh, list) or not all(
            isinstance(x, str) and x.strip() for x in sh
        ):
            raise AnalyzeOutputError(
                "analyze.routing.surviving_hypotheses must be a list of "
                f"non-empty strings, got {sh!r}"
            )
        out["surviving_hypotheses"] = sh

    else:  # continue
        ups = r.get("unresolved_prescribed_set") or []
        if not isinstance(ups, list) or not all(
            isinstance(x, str) and x.strip() for x in ups
        ):
            raise AnalyzeOutputError(
                "analyze.routing.unresolved_prescribed_set must be a list of "
                f"non-empty strings, got {ups!r}"
            )
        out["unresolved_prescribed_set"] = ups

    return out


def _extract_string_list(
    env: dict[str, Any], field_name: str,
) -> list[str]:
    """Pull an optional list-of-strings field (anomalies, data_wishes)."""
    raw = env.get(field_name)
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(
        isinstance(x, str) and x.strip() for x in raw
    ):
        raise AnalyzeOutputError(
            f"analyze.{field_name} must be a list of non-empty strings when "
            f"present, got {raw!r}"
        )
    return raw


def parse_analyze_envelope(
    stdout: str,
    *,
    expected_loop_n: int | None = None,
) -> AnalyzeEnvelope:
    """Parse an analyze subagent envelope.

    Each interpretation field is optional — an analyze pass with no
    resolutions still has to emit a valid routing trailer. The handler
    composes per-lead `findings[].outcome.*` fragments only for leads that
    appear in the envelope.
    """
    env = _extract_analyze_envelope_doc(stdout)

    loop = env.get("loop")
    if not isinstance(loop, int) or isinstance(loop, bool):
        raise AnalyzeOutputError(
            f"analyze.loop must be an integer, got {type(loop).__name__}"
        )
    if expected_loop_n is not None and loop != expected_loop_n:
        raise AnalyzeOutputError(
            f"analyze.loop={loop} does not match orchestrator-computed "
            f"loop_n={expected_loop_n}"
        )

    resolutions = _bucket_by_lead(env.get("resolutions", []), "resolutions")
    trust_anchor = _bucket_by_lead(
        env.get("trust_anchor_result", []), "trust_anchor_result", singleton=True,
    )
    legitimacy = _bucket_by_lead(
        env.get("legitimacy_resolutions", []), "legitimacy_resolutions",
    )
    impact = _bucket_by_lead(
        env.get("impact_resolutions", []), "impact_resolutions",
    )

    anomalies = _extract_string_list(env, "anomalies")
    data_wishes = _extract_string_list(env, "data_wishes")

    routing = _extract_analyze_routing(env)

    return AnalyzeEnvelope(
        resolutions_by_lead=resolutions,
        trust_anchor_by_lead=trust_anchor,
        legitimacy_by_lead=legitimacy,
        impact_by_lead=impact,
        anomalies=anomalies,
        data_wishes=data_wishes,
        routing=routing,
        telemetry={"loop": loop},
    )


# ---------------------------------------------------------------------------
# Analyze envelope — DENSE block format
# ---------------------------------------------------------------------------
#
# The analyze subagent emits a sequence of dense blocks instead of a YAML
# envelope. Each block is `:A <name>` / `:T <name>` / `:R <name>` followed by
# one or more rows. The parser tokenizes blocks, validates structural rules
# defined in agents/analyze.md, and produces the same `AnalyzeEnvelope`
# dataclass shape that `parse_analyze_envelope` returns — so the handler is
# unchanged at the dataclass boundary.
#
# Wire-format / parsed-dict translation table (column → dict key):
#   :T resolutions row  → {hypothesis_id, weight, matched_prediction_ids,
#                          matched_refutation_ids?, supporting_edges,
#                          severity, reasoning}
#   :R authz row        → {edge_id, contract_id, verdict, grounding_kind,
#                          authority_for_question, as_of, reasoning,
#                          anchor_kind, anchor_id}
#   :R consultations    → singleton-per-lead {asks: [anchor_id], verdict,
#                          grounding_kind, authority_for_question, as_of,
#                          reasoning, anchor_kind}
#   :R impact row       → {prediction_ref, dimension, verdict, grounding_kind,
#                          authority_for_question, as_of, reasoning,
#                          observed, matched_pred, anchor_id, anchor_kind}


_VALID_AFTER_WEIGHTS = frozenset({"++", "+", "-", "--"})
_VALID_BEFORE_WEIGHTS = frozenset({"∅", "++", "+", "-", "--"})
_VALID_SEVERITIES = frozenset({"severe", "moderate", "weak"})
_DENSE_BLOCK_HEADER_RE = re.compile(r"^(:[ATR])\s+(\S.*)$")
_RESOLUTION_ROW_RE = re.compile(
    r"^(?P<hid>h-\S+)\s+"
    r"(?P<before>\S+)\s*→\s*(?P<after>\S+)\s+"
    r"\[(?P<body>.*)\]\s*$"
)
# RHS literal extraction: p1, ap2, r3 — order-independent on the RHS.
_PRED_LITERAL_RE = re.compile(r"\b(?:a?p\d+|r\d+)\b")
# Adversarial-token detection (X2, X5).
_ADVERSARIAL_TOKENS = (
    "?adversary-",
    "?attack-",
    "?credential-",
    "?bruteforce",
    "?compromise-",
    "?malware-",
    "?exfiltration-",
    "?lateral-",
    "?post-exploit-",
    "?dga-",
    "?beaconing-",
)


def _strip_dense_envelope(stdout: str) -> str:
    """Remove leading/trailing whitespace and any code-fence wrappers.

    Subagents may wrap the envelope in ``` for terminal display; strip a
    single outer fence pair if present. Inner content is treated literally.
    """
    text = stdout.strip()
    if not text:
        raise AnalyzeOutputError("analyze output is empty")
    # Tolerate a single outer ```/```text/```dense fence pair.
    if text.startswith("```"):
        first_newline = text.find("\n")
        if first_newline == -1:
            raise AnalyzeOutputError("analyze output: bare ``` with no body")
        body_start = first_newline + 1
        if text.endswith("```"):
            body = text[body_start:-3].rstrip()
        else:
            body = text[body_start:].rstrip()
        return body.strip()
    return text


def _split_dense_blocks(text: str) -> list[tuple[str, list[str]]]:
    """Tokenize the dense envelope into (header, body_lines) blocks.

    Block header line shape: `:<X> <name>` where `<X>` ∈ `{A, T, R}`.
    Body is every subsequent line until the next block header.
    Comments (`# ...`) and blank lines are stripped.
    """
    blocks: list[tuple[str, list[str]]] = []
    current_header: str | None = None
    current_body: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        # Strip line comments (`# ...`); preserve content before `#`.
        if "#" in line:
            # Don't strip `#` inside row content (e.g. fragment after `::`);
            # only strip lines whose first non-space char is `#`.
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
        if not line.strip():
            continue
        m = _DENSE_BLOCK_HEADER_RE.match(line)
        if m:
            if current_header is not None:
                blocks.append((current_header, current_body))
            tag = m.group(1)
            rest = m.group(2).strip()
            # `:R *` headers may carry a `[col1|col2|...]` column-spec inline.
            # Split it off the canonical name and push it onto the body so
            # the :R parser can validate it against the expected columns.
            if "[" in rest:
                name_only, col_spec_tail = rest.split("[", 1)
                current_header = f"{tag} {name_only.strip()}"
                current_body = ["[" + col_spec_tail.strip()]
            else:
                current_header = f"{tag} {rest}"
                current_body = []
        else:
            if current_header is None:
                raise AnalyzeOutputError(
                    f"analyze output: line before any block header: {line!r}"
                )
            current_body.append(line)
    if current_header is not None:
        blocks.append((current_header, current_body))
    if not blocks:
        raise AnalyzeOutputError("analyze output: no blocks found")
    return blocks


def _parse_loop_block(body: list[str], header: str) -> int:
    """Parse `:A loop  <int>` (single line — int on the header)."""
    parts = header.split(maxsplit=2)
    if len(parts) >= 3 and parts[1] == "loop":
        try:
            return int(parts[2])
        except ValueError:
            pass
    raise AnalyzeOutputError(
        f"analyze :A loop must be a single line `:A loop <int>`, got "
        f"header={header!r} body={body!r}"
    )


def _annotation_split_iffs(annotation: str) -> list[tuple[str, str]]:
    """Split annotation on `;` and parse iff (`LHS ⟺ RHS`) segments.

    Segments containing `⟺` (or ASCII `<=>`) are parsed as iffs. Segments
    without an iff operator are treated as narrative continuation and
    silently dropped (their content remains in the original `reasoning`
    string preserved by the caller). At least one iff segment is required.

    ASCII fallbacks: `<=>` for `⟺`, `&` for `∧`, `|` for `∨`, `~` for `¬`.
    """
    segments = [s.strip() for s in annotation.split(";") if s.strip()]
    out: list[tuple[str, str]] = []
    for seg in segments:
        if "⟺" in seg:
            parts = seg.split("⟺", 1)
        elif "<=>" in seg:
            parts = seg.split("<=>", 1)
        else:
            # Narrative continuation segment — not an iff, skip.
            continue
        lhs, rhs = parts[0].strip(), parts[1].strip()
        if not lhs or not rhs:
            raise AnalyzeOutputError(
                f"analyze :T resolutions: iff has empty LHS or RHS: {seg!r}"
            )
        out.append((lhs, rhs))
    if not out:
        raise AnalyzeOutputError(
            f"analyze :T resolutions: annotation has no iff segments — "
            f"`LHS ⟺ RHS` is required (S3): {annotation!r}"
        )
    return out


def _rhs_literals(rhs: str) -> set[str]:
    """Extract `p*`/`ap*`/`r*` literals from an iff RHS expression."""
    return set(_PRED_LITERAL_RE.findall(rhs))


def _parse_resolution_row(line: str) -> dict[str, Any]:
    """Parse one `:T resolutions` row into the parsed-dict shape.

    Row shape: `<hid> <before> → <after> [<lead-id> <severity> ⟂ <supp-edges> :: <iff-annotation>]`

    `matched_prediction_ids` and `matched_refutation_ids` are derived from the
    iff RHS literal set (positive AND negative polarities both count as
    "tested"). The polarity carries reasoning narrative, not parsed shape.
    """
    m = _RESOLUTION_ROW_RE.match(line)
    if not m:
        raise AnalyzeOutputError(
            f"analyze :T resolutions: row does not match shape "
            f"`<hid> <before> → <after> [body]`: {line!r}"
        )
    hid = m.group("hid")
    before = m.group("before")
    after = m.group("after")
    body = m.group("body")

    if before not in _VALID_BEFORE_WEIGHTS:
        raise AnalyzeOutputError(
            f"analyze :T resolutions row {hid}: invalid <before>={before!r}, "
            f"must be one of {sorted(_VALID_BEFORE_WEIGHTS)}"
        )
    if after not in _VALID_AFTER_WEIGHTS:
        raise AnalyzeOutputError(
            f"analyze :T resolutions row {hid}: invalid <after>={after!r}, "
            f"must be one of {sorted(_VALID_AFTER_WEIGHTS)}"
        )

    # Body shape: <lead-id> <severity> ⟂ <supp-edges> :: <annotation>
    if "::" not in body:
        raise AnalyzeOutputError(
            f"analyze :T resolutions row {hid}: body missing `::` annotation "
            f"separator: {body!r}"
        )
    pre_anno, anno = body.split("::", 1)
    annotation = anno.strip()

    if "⟂" not in pre_anno:
        raise AnalyzeOutputError(
            f"analyze :T resolutions row {hid}: body missing `⟂` separator "
            f"between severity and supp-edges: {pre_anno!r}"
        )
    pre_perp, supp_edges_raw = pre_anno.split("⟂", 1)
    supp_edges_token = supp_edges_raw.strip()

    # pre_perp shape: "<lead-id> <severity>"
    pre_tokens = pre_perp.strip().split()
    if len(pre_tokens) != 2:
        raise AnalyzeOutputError(
            f"analyze :T resolutions row {hid}: pre-`⟂` segment must be "
            f"<lead-id> <severity>, got {pre_tokens!r}"
        )
    lead_ref, severity = pre_tokens

    if not lead_ref.startswith("l-"):
        raise AnalyzeOutputError(
            f"analyze :T resolutions row {hid}: lead-id must start with "
            f"`l-`, got {lead_ref!r}"
        )
    if severity not in _VALID_SEVERITIES:
        raise AnalyzeOutputError(
            f"analyze :T resolutions row {hid}: invalid severity={severity!r}, "
            f"must be one of {sorted(_VALID_SEVERITIES)}"
        )

    # Supp-edges parse.
    if supp_edges_token in {"no-authority", "partial-authority"}:
        supporting_edges: list[str] = []
        supp_marker = supp_edges_token
    else:
        supporting_edges = [
            e.strip() for e in supp_edges_token.split(",") if e.strip()
        ]
        for e in supporting_edges:
            if not e.startswith("e-"):
                raise AnalyzeOutputError(
                    f"analyze :T resolutions row {hid}: <supp-edges> token "
                    f"{e!r} is not an e-* id or a valid marker"
                )
        supp_marker = None

    # iff parse — literal set is derived from the iff RHS (S3 = non-empty).
    iffs = _annotation_split_iffs(annotation)
    iff_literals: set[str] = set()
    for _lhs, rhs in iffs:
        iff_literals |= _rhs_literals(rhs)
    if not iff_literals:
        raise AnalyzeOutputError(
            f"analyze :T resolutions row {hid}: iff RHS contains no "
            f"`p*`/`ap*`/`r*` literals (S3); at least one required"
        )
    matched_predictions = sorted(t for t in iff_literals if not t.startswith("r"))
    matched_refutations = sorted(t for t in iff_literals if t.startswith("r"))

    # S1: ++/-- requires severe.
    if after in {"++", "--"} and severity != "severe":
        raise AnalyzeOutputError(
            f"analyze :T resolutions row {hid}: weight={after} requires "
            f"severity=severe (S1), got severity={severity}"
        )
    # S2: -- requires at least one r* literal on iff RHS (any polarity).
    if after == "--" and not matched_refutations:
        raise AnalyzeOutputError(
            f"analyze :T resolutions row {hid}: weight=-- requires at least "
            f"one r* literal on the iff RHS (S2)"
        )

    out: dict[str, Any] = {
        "hypothesis_id": hid,
        "weight": after,
        "before_weight": before,
        "matched_prediction_ids": matched_predictions,
        "supporting_edges": supporting_edges,
        "severity": severity,
        "reasoning": annotation,
        "lead_ref": lead_ref,
    }
    if matched_refutations:
        out["matched_refutation_ids"] = matched_refutations
    if supp_marker:
        out["supporting_edges_marker"] = supp_marker
    return out


def _parse_pipe_row(
    line: str, columns: list[str], block_label: str,
) -> dict[str, str]:
    """Parse a `|`-delimited row against a column spec.

    The annotation-style column count is exact; trailing empty columns are
    permitted and result in empty-string values.
    """
    parts = [p.strip() for p in line.split("|")]
    if len(parts) > len(columns):
        # Last column may legitimately contain `|` (e.g. reasoning prose with
        # pipes). Collapse the overflow into the last column.
        parts = parts[: len(columns) - 1] + [
            "|".join(line.split("|")[len(columns) - 1 :]).strip()
        ]
    if len(parts) < len(columns):
        # Pad trailing optional columns.
        parts = parts + [""] * (len(columns) - len(parts))
    return dict(zip(columns, parts, strict=True))


_AUTHZ_COLUMNS = [
    "lead",
    "edge",
    "verdict",
    "anchor_kind",
    "anchor_id",
    "grounding",
    "authority",
    "as_of",
    "fulfills",
    "reasoning",
]
_CONSULTATIONS_COLUMNS = [
    "lead",
    "anchor_id",
    "anchor_kind",
    "grounding",
    "verdict",
    "as_of",
    "authority",
    "reasoning",
]
_IMPACT_COLUMNS = [
    "lead",
    "pred_ref",
    "dim",
    "observed",
    "verdict",
    "matched_pred",
    "grounding",
    "anchor_id",
    "anchor_kind",
    "authority",
    "as_of",
    "reasoning",
]


def _parse_R_block(
    body: list[str], expected_columns: list[str], block_label: str,
) -> list[dict[str, str]]:
    """Parse `:R *` block body: header column-spec then pipe-delimited rows.

    First non-blank body line MUST be the column spec `[col1|col2|...]`.
    Validates the columns match `expected_columns`.
    """
    if not body:
        return []
    header = body[0].strip()
    if not (header.startswith("[") and header.endswith("]")):
        raise AnalyzeOutputError(
            f"analyze {block_label}: first line must be column spec "
            f"`[col1|col2|...]`, got {header!r}"
        )
    declared = [c.strip() for c in header[1:-1].split("|")]
    if declared != expected_columns:
        raise AnalyzeOutputError(
            f"analyze {block_label}: column spec mismatch. "
            f"expected={expected_columns}, got={declared}"
        )
    rows: list[dict[str, str]] = []
    for line in body[1:]:
        if not line.strip():
            continue
        rows.append(_parse_pipe_row(line, expected_columns, block_label))
    return rows


def _bucket_authz_rows(
    rows: list[dict[str, str]],
) -> dict[str, list[dict[str, Any]]]:
    """Translate :R authz rows into legitimacy_by_lead dict shape."""
    out: dict[str, list[dict[str, Any]]] = {}
    valid_authz_verdicts = {"authorized", "unauthorized", "indeterminate"}
    valid_authz_groundings = {"org-authority", "past-case"}
    for r in rows:
        lead = r["lead"]
        if not (isinstance(lead, str) and lead.startswith("l-")):
            raise AnalyzeOutputError(
                f"analyze :R authz: lead must be l-*, got {lead!r}"
            )
        edge = r["edge"]
        if not (isinstance(edge, str) and edge.startswith("e-")):
            raise AnalyzeOutputError(
                f"analyze :R authz: edge must be e-*, got {edge!r}"
            )
        verdict = r["verdict"]
        if verdict not in valid_authz_verdicts:
            raise AnalyzeOutputError(
                f"analyze :R authz: verdict={verdict!r}, must be one of "
                f"{sorted(valid_authz_verdicts)}"
            )
        grounding = r["grounding"]
        if grounding not in valid_authz_groundings:
            raise AnalyzeOutputError(
                f"analyze :R authz: grounding={grounding!r}, must be one of "
                f"{sorted(valid_authz_groundings)} (telemetry-baseline is "
                f"rejected here per validator rule #11)"
            )
        contract = r["fulfills"]
        if not re.match(r"^h-[^.]+\.ac\d+$", contract):
            raise AnalyzeOutputError(
                f"analyze :R authz: fulfills={contract!r} must match "
                f"`^h-[^.]+\\.ac\\d+$`"
            )
        out.setdefault(lead, []).append({
            "edge_id": edge,
            "contract_id": contract,
            "verdict": verdict,
            "grounding_kind": grounding,
            "authority_for_question": r["authority"] or None,
            "as_of": r["as_of"] or None,
            "reasoning": r["reasoning"],
            "anchor_kind": r["anchor_kind"] or None,
            "anchor_id": r["anchor_id"] or None,
        })
    return out


def _bucket_consultation_rows(
    rows: list[dict[str, str]],
) -> dict[str, dict[str, Any]]:
    """Translate :R consultations rows into trust_anchor_by_lead (singleton)."""
    out: dict[str, dict[str, Any]] = {}
    valid_groundings = {"org-authority", "telemetry-baseline"}
    for r in rows:
        lead = r["lead"]
        if not (isinstance(lead, str) and lead.startswith("l-")):
            raise AnalyzeOutputError(
                f"analyze :R consultations: lead must be l-*, got {lead!r}"
            )
        if lead in out:
            raise AnalyzeOutputError(
                f"analyze :R consultations: lead {lead!r} appears more than "
                f"once (one row per lead expected)"
            )
        grounding = r["grounding"]
        if grounding not in valid_groundings:
            raise AnalyzeOutputError(
                f"analyze :R consultations: grounding={grounding!r}, must be "
                f"one of {sorted(valid_groundings)}"
            )
        out[lead] = {
            "asks": [r["anchor_id"]] if r["anchor_id"] else [],
            "verdict": r["verdict"],
            "grounding_kind": grounding,
            "authority_for_question": r["authority"] or None,
            "as_of": r["as_of"] or None,
            "reasoning": r["reasoning"],
            "anchor_kind": r["anchor_kind"] or None,
        }
    return out


def _bucket_impact_rows(
    rows: list[dict[str, str]],
) -> dict[str, list[dict[str, Any]]]:
    """Translate :R impact rows into impact_by_lead dict shape."""
    out: dict[str, list[dict[str, Any]]] = {}
    valid_verdicts = {"within", "exceeds", "indeterminate"}
    valid_groundings = {
        "telemetry-baseline", "business-owner-attestation", "dlp-policy",
    }
    for r in rows:
        lead = r["lead"]
        if not (isinstance(lead, str) and lead.startswith("l-")):
            raise AnalyzeOutputError(
                f"analyze :R impact: lead must be l-*, got {lead!r}"
            )
        verdict = r["verdict"]
        if verdict not in valid_verdicts:
            raise AnalyzeOutputError(
                f"analyze :R impact: verdict={verdict!r}, must be one of "
                f"{sorted(valid_verdicts)}"
            )
        grounding = r["grounding"]
        if grounding not in valid_groundings:
            raise AnalyzeOutputError(
                f"analyze :R impact: grounding={grounding!r}, must be one of "
                f"{sorted(valid_groundings)}"
            )
        out.setdefault(lead, []).append({
            "prediction_ref": r["pred_ref"],
            "dimension": r["dim"],
            "verdict": verdict,
            "grounding_kind": grounding,
            "authority_for_question": r["authority"] or None,
            "as_of": r["as_of"] or None,
            "reasoning": r["reasoning"],
            "observed": r["observed"] or None,
            "matched_pred": r["matched_pred"] or None,
            "anchor_id": r["anchor_id"] or None,
            "anchor_kind": r["anchor_kind"] or None,
        })
    return out


def _parse_routing_block(body: list[str]) -> dict[str, Any]:
    """Parse :A routing flat key/value body."""
    fields: dict[str, str] = {}
    for line in body:
        if not line.strip():
            continue
        # Each line is `<key><whitespace><value>` or `<key>` alone (empty
        # value). Aligned columns use ≥2 spaces between key and value.
        m = re.match(r"^(\S+)\s{2,}(.+)$", line.strip())
        if m:
            key, value = m.group(1), m.group(2).strip()
        else:
            parts = line.strip().split(None, 1)
            if len(parts) == 1:
                # Bare key, empty value (e.g. `surviving` with no list).
                key, value = parts[0], ""
            elif len(parts) == 2:
                key, value = parts[0], parts[1].strip()
            else:
                raise AnalyzeOutputError(
                    f"analyze :A routing: row missing key/value: {line!r}"
                )
        fields[key] = value

    decision = fields.get("decision")
    if decision != "halt":
        raise AnalyzeOutputError(
            f"analyze :A routing: decision must be `halt` when block is "
            f"present (continue is implied by absence), got {decision!r}"
        )
    tc = fields.get("termination_category")
    if tc not in _VALID_TERMINATION_CATEGORIES:
        raise AnalyzeOutputError(
            f"analyze :A routing: termination_category must be one of "
            f"{sorted(_VALID_TERMINATION_CATEGORIES)}, got {tc!r}"
        )
    disp = fields.get("disposition")
    if disp not in _VALID_DISPOSITIONS:
        raise AnalyzeOutputError(
            f"analyze :A routing: disposition must be one of "
            f"{sorted(_VALID_DISPOSITIONS)}, got {disp!r}"
        )
    conf = fields.get("confidence")
    if conf not in _VALID_CONFIDENCES:
        raise AnalyzeOutputError(
            f"analyze :A routing: confidence must be one of "
            f"{sorted(_VALID_CONFIDENCES)}, got {conf!r}"
        )
    surviving_raw = fields.get("surviving", "")
    surviving = [s.strip() for s in surviving_raw.split(",") if s.strip()]
    matched_archetype_raw = fields.get("matched_archetype", "null")
    matched_archetype = (
        None if matched_archetype_raw in {"null", "None", ""}
        else matched_archetype_raw
    )

    return {
        "decision": "halt",
        "termination_category": tc,
        "disposition": disp,
        "confidence": conf,
        "surviving_hypotheses": surviving,
        "matched_archetype": matched_archetype,
    }


def _parse_string_list_block(body: list[str]) -> list[str]:
    """Parse `:A anomalies` / `:A data_wishes` / `:A unresolved_prescribed` body.

    Each non-blank line is one entry. The single literal `none` indicates
    "intentionally empty" and produces `[]`.
    """
    rows = [line.strip() for line in body if line.strip()]
    if rows == ["none"]:
        return []
    return rows


def _validate_cross_block_invariants(
    resolutions_by_lead: dict[str, list[dict[str, Any]]],
    legitimacy_by_lead: dict[str, list[dict[str, Any]]],
    routing: dict[str, Any],
    declared_hypothesis_names: dict[str, str] | None = None,
) -> None:
    """Enforce X1–X6 from agents/analyze.md.

    `declared_hypothesis_names` maps `h-id` → hypothesis name for X2/X5
    adversarial-token detection. When None, those checks are skipped at
    the parser level (the handler can re-check after composing findings).
    """
    decision = routing.get("decision")
    if decision != "halt":
        # Continue case: only X1 is meaningful (surviving completeness),
        # but routing has no `surviving` field on continue. Skip.
        return

    # Build (h-id → after-weight) map from this loop's resolutions.
    # Multiple leads can grade the same hypothesis in one loop; pick the
    # most-decisive grade deterministically (`--` and `++` outrank `-`/`+`,
    # which outrank no entry). This avoids dict-iteration-order surprises
    # when X1's surviving check evaluates the hypothesis's effective weight.
    _decisiveness = {"--": 3, "++": 3, "-": 2, "+": 2}
    final_after: dict[str, str] = {}
    for entries in resolutions_by_lead.values():
        for e in entries:
            hid = e["hypothesis_id"]
            new_w = e["weight"]
            cur = final_after.get(hid)
            if cur is None or _decisiveness.get(new_w, 0) > _decisiveness.get(cur, 0):
                final_after[hid] = new_w

    surviving = set(routing.get("surviving_hypotheses") or [])

    # X1: surviving = {hid : after != --}
    expected_survivors = {hid for hid, w in final_after.items() if w != "--"}
    refuted = {hid for hid, w in final_after.items() if w == "--"}
    missing = expected_survivors - surviving
    extra = refuted & surviving
    if missing or extra:
        msg_parts = []
        if missing:
            msg_parts.append(
                f"missing from surviving: {sorted(missing)} "
                f"(hypotheses graded != -- must appear)"
            )
        if extra:
            msg_parts.append(
                f"refuted but listed in surviving: {sorted(extra)} "
                f"(hypotheses at -- must not appear)"
            )
        raise AnalyzeOutputError(
            f"analyze :A routing surviving completeness violated (X1): "
            f"{'; '.join(msg_parts)}"
        )

    # X6: every authz row's contract_id must point to a surviving hypothesis.
    for lead_authz in legitimacy_by_lead.values():
        for row in lead_authz:
            contract = row.get("contract_id", "")
            owner = contract.split(".", 1)[0] if "." in contract else contract
            if owner and owner not in surviving:
                raise AnalyzeOutputError(
                    f"analyze :R authz fulfills={contract!r}: contract owner "
                    f"{owner} is not in surviving={sorted(surviving)} (X6)"
                )

    # X4: disposition=benign requires every authz row on a survivor to have
    # verdict=authorized.
    if routing.get("disposition") == "benign":
        for lead_authz in legitimacy_by_lead.values():
            for row in lead_authz:
                contract = row.get("contract_id", "")
                owner = contract.split(".", 1)[0] if "." in contract else ""
                if owner in surviving and row.get("verdict") != "authorized":
                    raise AnalyzeOutputError(
                        f"analyze :A routing disposition=benign requires every "
                        f"authz on a survivor to be `authorized` (X4); "
                        f"contract {contract} resolved as "
                        f"{row.get('verdict')!r}"
                    )

    # X2 and X5 require the hypothesis-name map. Skip when not provided.
    if declared_hypothesis_names is None:
        return

    def _is_adversarial(hid: str) -> bool:
        name = declared_hypothesis_names.get(hid, "")
        return any(name.startswith(tok) for tok in _ADVERSARIAL_TOKENS)

    # X2: adversarial-refuted requires all adversarial hypotheses at --.
    if routing.get("termination_category") == "adversarial-refuted":
        for hid, w in final_after.items():
            if _is_adversarial(hid) and w != "--":
                raise AnalyzeOutputError(
                    f"analyze :A routing termination_category="
                    f"adversarial-refuted requires every adversarial "
                    f"hypothesis at -- (X2); {hid} (adversarial) is at {w}"
                )

    # X5: disposition=true_positive requires at least one adversarial ++ in
    # surviving.
    if routing.get("disposition") == "true_positive":
        if not any(
            _is_adversarial(hid) and final_after.get(hid) == "++"
            for hid in surviving
        ):
            raise AnalyzeOutputError(
                f"analyze :A routing disposition=true_positive requires at "
                f"least one surviving hypothesis whose name carries an "
                f"adversarial token AND whose final weight is ++ (X5, "
                f"validator rule #36); surviving={sorted(surviving)}"
            )


def parse_analyze_envelope_dense(
    stdout: str,
    *,
    expected_loop_n: int | None = None,
    declared_hypothesis_names: dict[str, str] | None = None,
) -> AnalyzeEnvelope:
    """Parse the dense-format analyze subagent envelope.

    Returns the same `AnalyzeEnvelope` dataclass shape as
    `parse_analyze_envelope` (the YAML form) so the handler is unchanged.

    `declared_hypothesis_names` maps declared `h-id` → hypothesis name
    (e.g. `?adversary-controlled-source`). When provided, enables the X2/X5
    adversarial-token cross-block invariant checks. When None, those checks
    are skipped at the parser level.

    Raises `AnalyzeOutputError` on any structural rule violation (S1–S4 row
    rules + X1–X6 cross-block invariants).
    """
    text = _strip_dense_envelope(stdout)
    blocks = _split_dense_blocks(text)

    # First block must be `:A loop`.
    loop_header, loop_body = blocks[0]
    if not loop_header.startswith(":A loop"):
        raise AnalyzeOutputError(
            f"analyze output: first block must be `:A loop`, got "
            f"{loop_header!r}"
        )
    loop = _parse_loop_block(loop_body, loop_header)
    if expected_loop_n is not None and loop != expected_loop_n:
        raise AnalyzeOutputError(
            f"analyze :A loop={loop} does not match orchestrator-computed "
            f"loop_n={expected_loop_n}"
        )

    resolutions_by_lead: dict[str, list[dict[str, Any]]] = {}
    legitimacy_by_lead: dict[str, list[dict[str, Any]]] = {}
    trust_anchor_by_lead: dict[str, dict[str, Any]] = {}
    impact_by_lead: dict[str, list[dict[str, Any]]] = {}
    anomalies: list[str] = []
    data_wishes: list[str] = []
    unresolved_prescribed: list[str] = []
    routing: dict[str, Any] = {}
    seen_blocks: set[str] = {":A loop"}

    for header, body in blocks[1:]:
        # Normalize header to a canonical key (e.g. ":T resolutions").
        canonical = " ".join(header.split())
        if canonical in seen_blocks:
            raise AnalyzeOutputError(
                f"analyze output: block {canonical!r} appears more than once"
            )
        seen_blocks.add(canonical)

        if canonical == ":T resolutions":
            for line in body:
                if not line.strip():
                    continue
                row = _parse_resolution_row(line)
                lead = row.pop("lead_ref")
                resolutions_by_lead.setdefault(lead, []).append(row)
        elif canonical == ":R authz":
            rows = _parse_R_block(body, _AUTHZ_COLUMNS, ":R authz")
            legitimacy_by_lead = _bucket_authz_rows(rows)
        elif canonical == ":R consultations":
            rows = _parse_R_block(
                body, _CONSULTATIONS_COLUMNS, ":R consultations",
            )
            trust_anchor_by_lead = _bucket_consultation_rows(rows)
        elif canonical == ":R impact":
            rows = _parse_R_block(body, _IMPACT_COLUMNS, ":R impact")
            impact_by_lead = _bucket_impact_rows(rows)
        elif canonical == ":A routing":
            routing = _parse_routing_block(body)
        elif canonical == ":A anomalies":
            anomalies = _parse_string_list_block(body)
        elif canonical == ":A data_wishes":
            data_wishes = _parse_string_list_block(body)
        elif canonical == ":A unresolved_prescribed":
            unresolved_prescribed = _parse_string_list_block(body)
        else:
            raise AnalyzeOutputError(
                f"analyze output: unknown block tag {canonical!r}"
            )

    if ":T resolutions" not in seen_blocks:
        raise AnalyzeOutputError(
            "analyze output: missing required `:T resolutions` block "
            "(empty allowed for enrichment-only loops, but the header must "
            "be present)"
        )

    # Routing default: continue if no :A routing block.
    if not routing:
        routing = {"decision": "continue"}
        if unresolved_prescribed:
            routing["unresolved_prescribed_set"] = unresolved_prescribed
    else:
        # Halt case: unresolved_prescribed (rarely emitted) is informational.
        if unresolved_prescribed:
            routing["unresolved_prescribed_set"] = unresolved_prescribed

    _validate_cross_block_invariants(
        resolutions_by_lead,
        legitimacy_by_lead,
        routing,
        declared_hypothesis_names,
    )

    # Strip the parser-internal `before_weight` and `severity` /
    # `supporting_edges_marker` keys from resolutions before returning?
    # No — keep them. The handler's findings synthesizer is robust to extra
    # keys (it only reads what it needs), and downstream consumers (REPORT,
    # corpus queries) benefit from the additional context. Tests assert on
    # presence of specific keys, not absence of others.

    return AnalyzeEnvelope(
        resolutions_by_lead=resolutions_by_lead,
        trust_anchor_by_lead=trust_anchor_by_lead,
        legitimacy_by_lead=legitimacy_by_lead,
        impact_by_lead=impact_by_lead,
        anomalies=anomalies,
        data_wishes=data_wishes,
        routing=routing,
        telemetry={"loop": loop},
    )
