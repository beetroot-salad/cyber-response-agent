"""Extract ad-hoc lead invocations from a completed run's invlang companion.

An ad-hoc lead is a GATHER-mode finding whose execution did not bind to a
catalogued vendor template. Two on-disk markers identify ad-hoc:

  1. `query_details.template == "ad-hoc"` (the agent declared the lead
     ad-hoc explicitly).
  2. `_lead_template_path(name, vendor).exists()` is False (the catalog
     directory or the per-vendor template is missing for this vendor).

These mirror gather's own dispatch rule (`scripts.handlers.gather`'s
ad-hoc routing) — if either holds, gather routes to `gather-composite`
in `mode=ad-hoc`. The post-mortem extractor uses the same bar so it
sees exactly the leads gather treated as ad-hoc.

Block-walking + YAML parsing reuses `scripts.invlang.corpus._merge_md_blocks`,
which already knows the canonical companion shape (and accepts both
`findings:` and `gather:` as aliases).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from scripts.invlang.corpus import _merge_md_blocks

CatalogStatus = Literal["template_explicit_adhoc", "template_missing"]
ResultShape = Literal["useful", "empty", "errored", "unknown"]

# Mirror gather.py — the on-disk catalog root. Slightly defensive: import
# at module load so the extractor reuses gather's helper rather than
# duplicating the path policy. If the helper signature ever changes, the
# extractor breaks loudly rather than drifting silently.
_SOC_AGENT_ROOT = Path(__file__).resolve().parents[3]


def _lead_template_path(lead_name: str, vendor: str) -> Path:
    """Catalog template path for `(lead, vendor)`.

    Mirrors `scripts.handlers.gather._lead_template_path`. Kept as a
    local copy because the post-mortem extractor must not import gather
    (heavy dependency tree, including the orchestrator). If the catalog
    layout changes, both copies move together.
    """
    return (
        _SOC_AGENT_ROOT
        / "knowledge"
        / "common-investigation"
        / "leads"
        / lead_name
        / "templates"
        / f"{vendor}.md"
    )


@dataclass(frozen=True)
class AdHocLead:
    """A single ad-hoc finding extracted from invlang `gather`/`findings`.

    `lead_name` is the value of the finding's `name` field (which may be
    a custom slug like `correlated-falco-events` or the literal
    `"ad-hoc"`). `catalog_status` distinguishes the two ad-hoc branches.
    `selection_rationale` is the per-finding intent prose persisted by
    PREDICT — the on-disk equivalent of `lead_hints`.
    """

    finding_id: str
    lead_name: str
    catalog_status: CatalogStatus
    data_source: str
    query: str
    selection_rationale: str
    result_shape: ResultShape
    substitutions: dict[str, str] = field(default_factory=dict)


def _findings(text: str) -> list[dict[str, Any]]:
    merged = _merge_md_blocks(text)
    findings = merged.get("findings", [])
    return [f for f in findings if isinstance(f, dict)]


def _classify_status(
    lead_name: str,
    template_value: Any,
    vendor: str,
) -> CatalogStatus | None:
    """Decide whether a finding is ad-hoc and which branch.

    Returns the ad-hoc branch label, or None if the finding bound to a
    real vendor template.
    """
    if isinstance(template_value, str) and template_value.strip() == "ad-hoc":
        return "template_explicit_adhoc"
    if not _lead_template_path(lead_name, vendor).exists():
        return "template_missing"
    return None


def _is_screen_mode(finding: dict[str, Any]) -> bool:
    return finding.get("mode") == "screen"


def _derive_result_shape(finding: dict[str, Any]) -> ResultShape:
    outcome = finding.get("outcome")
    if not isinstance(outcome, dict):
        return "unknown"
    if outcome.get("failure_reason"):
        return "errored"
    obs_raw = outcome.get("observations")
    obs = obs_raw if isinstance(obs_raw, dict) else None
    verts = (obs or {}).get("vertices") or []
    edges = (obs or {}).get("edges") or []
    attr_updates = outcome.get("attribute_updates") or []
    if verts or edges or attr_updates:
        return "useful"
    if obs is not None:
        return "empty"
    return "unknown"


def extract_ad_hoc_leads(
    run_dir: Path,
    vendor: str,
) -> list[AdHocLead]:
    """Walk `run_dir/investigation.md` and return one `AdHocLead` per
    ad-hoc finding (in source order).

    `vendor` is the SIEM/data vendor for ad-hoc-detection's template
    lookup — derived from the run's `meta.json["signature_id"]` via
    `gather._derive_vendor` at the orchestrator boundary.

    Returns an empty list if the file is missing, has no YAML blocks,
    or contains no ad-hoc findings.
    """
    inv_path = run_dir / "investigation.md"
    if not inv_path.exists():
        return []
    return _extract_from_text(inv_path.read_text(), vendor)


# Markdown-prose sidecar fallback. ANALYZE writes per-lead query/rationale prose
# under `**Lead:** <name>` sections; gather/handler bugs that leave invlang
# `query_details.query` empty (see gather.py:_append_lead_pick_findings) used
# to strand this data in prose-only form. The post-mortem extractor scrapes it
# back out so the consolidator agent has the discriminating context regardless
# of which path the run took. Belt-and-suspenders alongside the gather-handler
# fix — also covers historical runs whose invlang predates the fix.
_LEAD_PROSE_RE = re.compile(
    r"\*\*Lead:\*\*\s*([^\n]+?)\s*\n(.*?)(?=^\*\*Lead:\*\*|^##\s|^```|\Z)",
    re.DOTALL | re.MULTILINE,
)
_PROSE_FIELD_RE = re.compile(
    r"^\*\*([A-Za-z][A-Za-z0-9 _-]*?):\*\*\s*(.*?)(?=^\*\*[A-Za-z]|^```|\Z)",
    re.DOTALL | re.MULTILINE,
)


def _scrape_lead_prose(text: str) -> dict[str, dict[str, str]]:
    """Build {lead_name: {field_label_lower: value}} from `**Lead:**` blocks.

    Field values are stripped and de-tickified ("`x`" → "x"); only the most
    recent value per field per lead survives, matching the human reader's
    expectation that the latest section overrides earlier ones."""
    by_lead: dict[str, dict[str, str]] = {}
    for lm in _LEAD_PROSE_RE.finditer(text):
        name = lm.group(1).strip()
        body = lm.group(2)
        fields = by_lead.setdefault(name, {})
        for fm in _PROSE_FIELD_RE.finditer(body):
            label = fm.group(1).strip().lower()
            value = fm.group(2).strip()
            if value.startswith("`") and value.endswith("`") and len(value) >= 2:
                value = value[1:-1]
            fields[label] = value
    return by_lead


def _extract_from_text(text: str, vendor: str) -> list[AdHocLead]:
    prose_by_lead = _scrape_lead_prose(text)
    out: list[AdHocLead] = []
    for finding in _findings(text):
        if _is_screen_mode(finding):
            continue
        name = finding.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or not finding_id.strip():
            continue
        qd = finding.get("query_details")
        if not isinstance(qd, dict):
            qd = {}
        status = _classify_status(name, qd.get("template"), vendor)
        if status is None:
            continue
        substitutions = qd.get("substitutions")
        if not isinstance(substitutions, dict):
            substitutions = {}
        prose = prose_by_lead.get(name, {})
        # Prefer invlang values; fall back to prose-scraped fields.
        query = (qd.get("query") or "") or prose.get("query", "")
        data_source = (qd.get("system") or "") or prose.get("data source", "")
        rationale = (
            finding.get("selection_rationale", "")
            or prose.get("selection rationale", "")
            or prose.get("rationale", "")
        )
        out.append(
            AdHocLead(
                finding_id=finding_id,
                lead_name=name,
                catalog_status=status,
                data_source=data_source or "",
                query=query or "",
                selection_rationale=rationale or "",
                result_shape=_derive_result_shape(finding),
                substitutions={str(k): str(v) for k, v in substitutions.items()},
            )
        )
    return out


def has_ad_hoc_leads(text: str, vendor: str) -> bool:
    """Cheap pre-check used by stop_handler to decide whether to spawn the
    full pipeline. Equivalent to `extract_ad_hoc_leads(...)` returning a
    non-empty list, but skips dataclass construction.
    """
    for finding in _findings(text):
        if _is_screen_mode(finding):
            continue
        name = finding.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        qd = finding.get("query_details") if isinstance(finding.get("query_details"), dict) else {}
        if _classify_status(name, qd.get("template"), vendor) is not None:
            return True
    return False
