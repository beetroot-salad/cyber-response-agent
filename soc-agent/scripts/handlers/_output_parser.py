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
