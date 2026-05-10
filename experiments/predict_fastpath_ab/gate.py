"""Exact-match IFF gate for the PREDICT fast-path experiment.

Pure function: (alert, current_prologue, signature_id, corpus, playbook) → decision.

A decision is one of:
    {"verdict": "exact",      "selected_lead": <lead>, "matched_case": <case_idx>, "evidence": {...}}
    {"verdict": "strong",     "candidate_lead": <lead>, "matched_cases": [...],   "evidence": {...}}
    {"verdict": "moderate"|"weak"|"none", "evidence": {...}}

The 11 IFF conditions are implemented as small predicates so the experiment
can ablate them. Once an arm wins, this same gate gets ported into
scripts/handlers/predict.py with the prod thresholds.

Intentional: this module does not import from scripts.handlers.predict —
it duplicates the prologue-extraction helpers so the experiment can run
without touching the live handler.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Decision-relevant classifications + discriminating-field policy
# ---------------------------------------------------------------------------
# Hand-curated for the fixture set. In production this would live alongside
# the playbook (e.g. playbook.discriminating_fields). For the experiment we
# inline it so we can iterate without touching plugin knowledge files.

# Map vertex.classification → list of regex patterns that an identifier must
# fall into to count as "same key-attribute class". For monitoring-pattern,
# both `nagios` and `sensu` fall into the sentinel-monitoring family.
KEY_ATTRIBUTE_PATTERNS: dict[str, list[str]] = {
    "monitoring-pattern": [r"^(nagios|sensu|monitor.*|probe.*|check.*|sentinel.*|testuser)$"],
    "service-account":    [r"^(svc-.*|backup-.*|cron-.*|ansible-.*|deploy-.*)$"],
    "internal-monitoring-host":  [r"^(172\.22\.0\.|10\.\d+\.\d+\.|192\.168\.)"],
    "unclassified-endpoint":     [r".*"],  # never load-bearing
}

# Subnet buckets for network-endpoint comparison
def _subnet_bucket(ip: str) -> str:
    if not ip:
        return "unknown"
    if ip.startswith(("172.22.0.", "10.", "192.168.")):
        return "internal-rfc1918"
    if ip.startswith("127."):
        return "loopback"
    return "external"


# ---------------------------------------------------------------------------
# Prologue parsing (duplicated from handlers/predict.py to keep gate self-contained)
# ---------------------------------------------------------------------------

_FIRST_FENCE_RE = re.compile(r"```yaml\s*\n(?P<body>.*?)\n```", re.DOTALL)


def parse_prologue(investigation_md: str) -> dict | None:
    for m in _FIRST_FENCE_RE.finditer(investigation_md):
        try:
            parsed = yaml.safe_load(m.group("body"))
        except yaml.YAMLError:
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("prologue"), dict):
            return parsed["prologue"]
    return None


def prologue_signature(prologue: dict) -> dict:
    vertices = prologue.get("vertices") or []
    edges = prologue.get("edges") or []
    return {
        "vertex_types": frozenset(v.get("type") for v in vertices if isinstance(v, dict) and v.get("type")),
        "vertex_classifications": frozenset(
            v.get("classification") for v in vertices if isinstance(v, dict) and v.get("classification")
        ),
        "edge_relations": frozenset(e.get("relation") for e in edges if isinstance(e, dict) and e.get("relation")),
    }


# ---------------------------------------------------------------------------
# Precedent shape (loaded from archetype JSON snapshots in the experiment)
# ---------------------------------------------------------------------------


@dataclass
class Precedent:
    """One past investigation worth comparing against."""
    case_id: str
    signature_id: str
    archetype: str
    disposition: str  # benign | true_positive | unclear
    prologue: dict   # same shape as live prologue
    selected_lead: str
    lead_kind: str   # branching | interpretive | trust | fail | mechanical
    fidelity_rate: float
    discriminating_attrs: dict[str, Any]  # key-attribute snapshot at fire time


@dataclass
class GateThresholds:
    min_lead_fidelity: float = 0.7
    allowed_lead_kinds: frozenset = field(
        default_factory=lambda: frozenset({"branching", "interpretive"})
    )
    benign_outcomes: frozenset = field(
        default_factory=lambda: frozenset({"benign", "true_positive"})
    )


# ---------------------------------------------------------------------------
# IFF condition predicates (each returns (passed: bool, evidence: str))
# ---------------------------------------------------------------------------


def _iff_1_signature(p: Precedent, current_sig: str) -> tuple[bool, str]:
    return (p.signature_id == current_sig, f"prior={p.signature_id} current={current_sig}")


def _iff_2_vertex_types(p_sig: dict, c_sig: dict) -> tuple[bool, str]:
    return (
        p_sig["vertex_types"] == c_sig["vertex_types"],
        f"prior={sorted(p_sig['vertex_types'])} current={sorted(c_sig['vertex_types'])}",
    )


def _iff_3_edge_relations(p_sig: dict, c_sig: dict) -> tuple[bool, str]:
    return (
        p_sig["edge_relations"] == c_sig["edge_relations"],
        f"prior={sorted(p_sig['edge_relations'])} current={sorted(c_sig['edge_relations'])}",
    )


def _iff_4_vertex_classifications(p_sig: dict, c_sig: dict) -> tuple[bool, str]:
    return (
        p_sig["vertex_classifications"] == c_sig["vertex_classifications"],
        f"prior={sorted(p_sig['vertex_classifications'])} current={sorted(c_sig['vertex_classifications'])}",
    )


def _matches_pattern_class(identifier: str, classification: str) -> bool:
    """Identifier falls into the key-attribute family declared for its classification."""
    patterns = KEY_ATTRIBUTE_PATTERNS.get(classification, [])
    if not patterns:
        return True  # no policy → not load-bearing → don't block
    return any(re.match(pat, identifier or "") for pat in patterns)


def _iff_5_key_attrs(p: Precedent, current_prologue: dict) -> tuple[bool, str]:
    """Every decision-relevant vertex in the current prologue falls into the
    same key-attribute class as the equivalent vertex in the precedent."""
    cur_vertices = current_prologue.get("vertices") or []
    pri_vertices = p.prologue.get("vertices") or []
    pri_by_class = {v.get("classification"): v for v in pri_vertices if isinstance(v, dict)}
    mismatches = []
    for v in cur_vertices:
        if not isinstance(v, dict):
            continue
        cls = v.get("classification")
        ident = v.get("identifier") or ""
        if cls not in KEY_ATTRIBUTE_PATTERNS:
            continue  # not decision-relevant
        # current must match its own classification's family
        if not _matches_pattern_class(ident, cls):
            mismatches.append(f"current v.{cls}={ident!r} fails {cls} family")
            continue
        # precedent (same classification slot) must also match
        pri_v = pri_by_class.get(cls)
        if pri_v is None:
            mismatches.append(f"precedent missing classification={cls}")
            continue
        pri_ident = pri_v.get("identifier") or ""
        if not _matches_pattern_class(pri_ident, cls):
            mismatches.append(f"precedent v.{cls}={pri_ident!r} fails {cls} family")
        # subnet bucket equality for endpoint classifications
        if cls in {"internal-monitoring-host", "unclassified-endpoint"}:
            if _subnet_bucket(ident) != _subnet_bucket(pri_ident):
                mismatches.append(
                    f"subnet bucket differs: current={_subnet_bucket(ident)} prior={_subnet_bucket(pri_ident)}"
                )
    return (not mismatches, "; ".join(mismatches) or "all key attrs aligned")


def _iff_6_no_novel_fields(p: Precedent, current_alert: dict, discriminating: list[str]) -> tuple[bool, str]:
    """Current alert carries no discriminating field that the precedent lacked."""
    novel = []
    for fld in discriminating:
        cur_val = _get_dotted(current_alert, fld)
        pri_val = _get_dotted(p.discriminating_attrs, fld) if p.discriminating_attrs else None
        if cur_val is not None and pri_val is None:
            novel.append(f"{fld}={cur_val!r}")
    return (not novel, ("novel: " + ", ".join(novel)) if novel else "no novel discriminating fields")


def _get_dotted(d: dict, path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _iff_7_outcome(p: Precedent, t: GateThresholds) -> tuple[bool, str]:
    return (p.disposition in t.benign_outcomes, f"disposition={p.disposition}")


def _iff_8_lead_in_catalog(p: Precedent, lead_catalog: set[str]) -> tuple[bool, str]:
    return (
        p.selected_lead in lead_catalog,
        f"lead={p.selected_lead} in_catalog={p.selected_lead in lead_catalog}",
    )


def _iff_9_lead_fidelity(p: Precedent, t: GateThresholds) -> tuple[bool, str]:
    return (
        p.fidelity_rate >= t.min_lead_fidelity,
        f"fidelity={p.fidelity_rate} threshold={t.min_lead_fidelity}",
    )


def _iff_11_lead_kind(p: Precedent, t: GateThresholds) -> tuple[bool, str]:
    return (
        p.lead_kind in t.allowed_lead_kinds,
        f"kind={p.lead_kind} allowed={sorted(t.allowed_lead_kinds)}",
    )


# ---------------------------------------------------------------------------
# Top-level decision
# ---------------------------------------------------------------------------


def evaluate(
    *,
    current_alert: dict,
    current_prologue: dict,
    signature_id: str,
    precedents: list[Precedent],
    lead_catalog: set[str],
    discriminating_fields: list[str],
    thresholds: GateThresholds | None = None,
) -> dict:
    """Run the IFF gate across all known precedents, return a single decision."""
    t = thresholds or GateThresholds()
    c_sig = prologue_signature(current_prologue)

    per_precedent: list[dict] = []
    exact_hits: list[Precedent] = []

    for p in precedents:
        p_sig = prologue_signature(p.prologue)
        checks = {
            "iff_1_signature":              _iff_1_signature(p, signature_id),
            "iff_2_vertex_types":           _iff_2_vertex_types(p_sig, c_sig),
            "iff_3_edge_relations":         _iff_3_edge_relations(p_sig, c_sig),
            "iff_4_vertex_classifications": _iff_4_vertex_classifications(p_sig, c_sig),
            "iff_5_key_attrs":              _iff_5_key_attrs(p, current_prologue),
            "iff_6_no_novel_fields":        _iff_6_no_novel_fields(p, current_alert, discriminating_fields),
            "iff_7_outcome":                _iff_7_outcome(p, t),
            "iff_8_lead_in_catalog":        _iff_8_lead_in_catalog(p, lead_catalog),
            "iff_9_lead_fidelity":          _iff_9_lead_fidelity(p, t),
            "iff_11_lead_kind":             _iff_11_lead_kind(p, t),
        }
        passed = {k: v[0] for k, v in checks.items()}
        all_pass = all(passed.values())
        per_precedent.append({
            "case_id": p.case_id,
            "selected_lead": p.selected_lead,
            "passed": passed,
            "evidence": {k: v[1] for k, v in checks.items()},
        })
        if all_pass:
            exact_hits.append(p)

    # IFF #10: consensus on selected_lead
    if exact_hits:
        leads = {p.selected_lead for p in exact_hits}
        if len(leads) == 1:
            chosen = exact_hits[0].selected_lead
            return {
                "verdict": "exact",
                "selected_lead": chosen,
                "matched_cases": [p.case_id for p in exact_hits],
                "per_precedent": per_precedent,
            }
        # disagreement → fall through (IFF 10 fails)
        return {
            "verdict": "strong",
            "candidate_leads": sorted(leads),
            "matched_cases": [p.case_id for p in exact_hits],
            "per_precedent": per_precedent,
            "note": "exact-match precedents disagreed on selected_lead",
        }

    # No exact hit. Surface "strong" if topology + outcome pass on ≥1 case.
    strong = [
        pp for pp in per_precedent
        if pp["passed"]["iff_1_signature"]
        and pp["passed"]["iff_2_vertex_types"]
        and pp["passed"]["iff_3_edge_relations"]
        and pp["passed"]["iff_4_vertex_classifications"]
        and pp["passed"]["iff_7_outcome"]
        and pp["passed"]["iff_8_lead_in_catalog"]
        and pp["passed"]["iff_9_lead_fidelity"]
    ]
    if strong:
        return {
            "verdict": "strong",
            "candidate_leads": sorted({s["selected_lead"] for s in strong}),
            "matched_cases": [s["case_id"] for s in strong],
            "per_precedent": per_precedent,
        }

    moderate = [pp for pp in per_precedent if pp["passed"]["iff_2_vertex_types"]]
    if moderate:
        return {"verdict": "moderate", "per_precedent": per_precedent}

    return {"verdict": "none" if not per_precedent else "weak", "per_precedent": per_precedent}


def load_precedent_from_archetype_json(json_path: Path) -> Precedent | None:
    """Load a `{TICKET-ID}.json` archetype snapshot into a Precedent.

    These snapshots are sparse (alert + anchors only). The experiment
    wraps them with a synthesized prologue + lead choice in
    `seed_precedents.py`; this loader is a stub for future extension.
    """
    try:
        data = yaml.safe_load(json_path.read_text())
    except Exception:
        return None
    if not isinstance(data, dict) or "ticket_id" not in data:
        return None
    return None  # actual conversion happens in seed_precedents.py
