"""Code-based forbidden-pattern detectors for PREDICT envelopes.

One detector per `forbidden_patterns` token in the case YAML. Each takes the
parsed envelope dict and returns `True` when the pattern fires (i.e., the
output VIOLATES the case's discipline).

Detectors are deliberately conservative — false positives cost fewer
investigations than false negatives. When a check is ambiguous, return False
and let the human-readable post-mortem catch it.
"""

from __future__ import annotations

import re

# Vocabulary that demonstrates a refutation names a deviation, not a presence.
DEVIATION_VOCAB = re.compile(
    r"\b(deviates?|outside|novel|off the baseline|deviation from|"
    r"absent from|not in|differs? from|departs?|materially|"
    r"baseline|recurring|cadence)\b",
    re.IGNORECASE,
)

# Banned vague predicate vocabulary (D8a falsifiable_observable check).
VAGUE_VOCAB = re.compile(
    r"\b(looks suspicious|consistent with|behavior matches|indicates|"
    r"appears to|seems to|suggests|might be|likely|potentially)\b",
    re.IGNORECASE,
)

# Specific-value leak vocabulary (port numbers, IP literals, exact thresholds).
VALUE_LEAK_PATTERNS = [
    re.compile(r"\bport\s+\d+\b", re.IGNORECASE),
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),  # IPv4 literal
    re.compile(r"\b(?:exactly|precisely)\s+\d+\b", re.IGNORECASE),
    re.compile(r"\bequals?\s+['\"]?\w", re.IGNORECASE),
]

# Compound-claim markers (AND / OR / comma-list).
COMPOUND_MARKERS = re.compile(
    r"\s+(AND|OR)\s+|\s+,\s+(?=\w+\s+(is|has|equals|matches))",
)

EVAL_PACKED_NAME = re.compile(
    r"\?(legitimate|authorized|benign|malicious|adversary|compromised)-",
    re.IGNORECASE,
)


def _hypotheses(envelope: dict) -> list[dict]:
    return envelope.get("predict", {}).get("hypotheses") or []


def _branch_plan(envelope: dict) -> dict:
    return envelope.get("predict", {}).get("branch_plan") or {}


def _all_predictions(envelope: dict) -> list[dict]:
    """Every prediction-like entry: predictions, attribute_predictions,
    refutation_shape, and lead-level branch_plan.predictions."""
    out = []
    for h in _hypotheses(envelope):
        out.extend(h.get("predictions") or [])
        out.extend(h.get("attribute_predictions") or [])
        out.extend(h.get("refutation_shape") or [])
    out.extend(_branch_plan(envelope).get("predictions") or [])
    return out


def _all_refutations(envelope: dict) -> list[dict]:
    out = []
    for h in _hypotheses(envelope):
        out.extend(h.get("refutation_shape") or [])
    return out


def _claim_text(entry: dict) -> str:
    """Pull the comparable text out of a prediction-like entry."""
    return str(entry.get("claim") or entry.get("if") or "")


# -----------------------------------------------------------------------------
# Detectors. Each returns True when the pattern fires (violation).
# -----------------------------------------------------------------------------


def presence_test_refutation(envelope: dict) -> bool:
    for r in _all_refutations(envelope):
        text = _claim_text(r)
        if not text:
            continue
        if not DEVIATION_VOCAB.search(text):
            return True
    return False


def baseline_value_leak(envelope: dict) -> bool:
    for entry in _all_predictions(envelope):
        text = _claim_text(entry)
        for pat in VALUE_LEAK_PATTERNS:
            if pat.search(text):
                return True
    return False


def compound_claim(envelope: dict) -> bool:
    for entry in _all_predictions(envelope):
        text = _claim_text(entry)
        if COMPOUND_MARKERS.search(text):
            return True
    return False


def invoker_identity_peer_fork(envelope: dict) -> bool:
    """Two hypotheses share proposed_edge.relation + parent_vertex.classification
    AND their predictions[].claim sets are subset-equal modulo authorization_contract."""
    hyps = _hypotheses(envelope)
    if len(hyps) < 2:
        return False
    for i in range(len(hyps)):
        for j in range(i + 1, len(hyps)):
            a, b = hyps[i], hyps[j]
            ea = a.get("proposed_edge") or {}
            eb = b.get("proposed_edge") or {}
            if ea.get("relation") != eb.get("relation"):
                continue
            pa_class = (ea.get("parent_vertex") or {}).get("classification")
            pb_class = (eb.get("parent_vertex") or {}).get("classification")
            if pa_class != pb_class:
                continue
            pred_a = {_claim_text(p) for p in (a.get("predictions") or [])}
            pred_b = {_claim_text(p) for p in (b.get("predictions") or [])}
            if pred_a == pred_b or pred_a.issubset(pred_b) or pred_b.issubset(pred_a):
                return True
    return False


def sideways_pivot_after_plus_plus(envelope: dict, prior_investigation: str | None = None) -> bool:
    """Prior loop graded ++ and current output proposes a competitor for the
    same attached_to_vertex. Without prior investigation_md, returns False."""
    if not prior_investigation or "++" not in prior_investigation:
        return False
    plus_plus_attached: set[str] = set()
    # crude: find every "weight: ++" near an attached_to_vertex line
    for block in prior_investigation.split("- id:"):
        if "weight: ++" in block or "weight: \"++\"" in block:
            m = re.search(r"attached_to_vertex:\s*([\w-]+)", block)
            if m:
                plus_plus_attached.add(m.group(1))
    if not plus_plus_attached:
        return False
    for h in _hypotheses(envelope):
        attached = h.get("attached_to_vertex")
        if attached in plus_plus_attached:
            return True
    return False


def mechanism_spiral(envelope: dict) -> bool:
    """Peer hypotheses on the same vertex whose predictions all reference the
    same null/missing field (case-004 variant of speculative_peer_fork)."""
    hyps = _hypotheses(envelope)
    if len(hyps) < 2:
        return False
    null_field_predictions = 0
    for h in hyps:
        for p in (h.get("predictions") or []):
            text = _claim_text(p).lower()
            if "null" in text or "missing" in text or "absent" in text or "unknown" in text:
                null_field_predictions += 1
    return null_field_predictions >= 2 and len(hyps) >= 2


def speculative_peer_fork(envelope: dict) -> bool:
    """Peer hypotheses where no observable field grounds either — heuristic:
    multiple hypotheses + no comparison block on any prediction."""
    hyps = _hypotheses(envelope)
    if len(hyps) < 2:
        return False
    for h in hyps:
        for p in (h.get("predictions") or []):
            if p.get("comparison"):
                return False
    return True


def premature_fork(envelope: dict, loop_n: int = 1) -> bool:
    """Loop 1 emitting hypotheses when shape should be E."""
    if loop_n != 1:
        return False
    return envelope.get("predict", {}).get("shape") in ("A", "M") and len(_hypotheses(envelope)) > 0


def evaluation_packed_name(envelope: dict) -> bool:
    for h in _hypotheses(envelope):
        if EVAL_PACKED_NAME.search(str(h.get("name") or "")):
            return True
    return False


# -----------------------------------------------------------------------------
# Dispatch by name.
# -----------------------------------------------------------------------------


_DISPATCH = {
    "presence_test_refutation": lambda env, ctx: presence_test_refutation(env),
    "baseline_value_leak": lambda env, ctx: baseline_value_leak(env),
    "compound_claim": lambda env, ctx: compound_claim(env),
    "invoker_identity_peer_fork": lambda env, ctx: invoker_identity_peer_fork(env),
    "sideways_pivot_after_plus_plus": lambda env, ctx: sideways_pivot_after_plus_plus(
        env, ctx.get("prior_investigation")
    ),
    "mechanism_spiral": lambda env, ctx: mechanism_spiral(env),
    "speculative_peer_fork": lambda env, ctx: speculative_peer_fork(env),
    "premature_fork": lambda env, ctx: premature_fork(env, ctx.get("loop_n", 1)),
    "evaluation_packed_name": lambda env, ctx: evaluation_packed_name(env),
}


def detect(pattern: str, envelope: dict, ctx: dict | None = None) -> bool:
    fn = _DISPATCH.get(pattern)
    if fn is None:
        return False
    return bool(fn(envelope, ctx or {}))


def detect_all(patterns: list[str], envelope: dict, ctx: dict | None = None) -> dict[str, bool]:
    """Return {pattern: fired} for each requested pattern."""
    return {p: detect(p, envelope, ctx) for p in patterns}
