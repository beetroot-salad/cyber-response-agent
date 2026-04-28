"""Extract ad-hoc lead invocations from a completed run's invlang companion.

An ad-hoc lead is a GATHER-mode finding whose execution did not bind to a
catalogued vendor template. Two on-disk markers identify ad-hoc:

  1. `query_details.template == "ad-hoc"` (the agent declared the lead
     ad-hoc explicitly).
  2. `_lead_template_path(name, vendor).exists()` is False (the catalog
     directory or the per-vendor template is missing for this vendor).

These mirror gather's own dispatch rule at `gather.py:1635` — if either
holds, gather routes to `gather-composite` in `mode=ad-hoc`. The
post-mortem extractor uses the same bar so it sees exactly the leads
gather treated as ad-hoc.

The companion's top-level key is read as either `gather:` (older runs
and the current production schema as observed on disk) or `findings:`
(the schema spec target). They are alias keys — both contain the same
list of finding records.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

CatalogStatus = Literal["template_explicit_adhoc", "template_missing"]
ResultShape = Literal["useful", "empty", "errored", "unknown"]

# Mirror gather.py — the on-disk catalog root. Slightly defensive: import
# at module load so the extractor reuses gather's helper rather than
# duplicating the path policy. If the helper signature ever changes, the
# extractor breaks loudly rather than drifting silently.
_SOC_AGENT_ROOT = Path(__file__).resolve().parents[3]


def _lead_template_path(lead_name: str, vendor: str) -> Path:
    """Catalog template path for `(lead, vendor)`. Mirrors gather.py:162."""
    return (
        _SOC_AGENT_ROOT
        / "knowledge"
        / "common-investigation"
        / "leads"
        / lead_name
        / "templates"
        / f"{vendor}.md"
    )


_YAML_BLOCK_RE = re.compile(r"```yaml\n(.*?)\n```", re.DOTALL)


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


def _iter_yaml_blocks(text: str) -> list[dict[str, Any]]:
    """Parse every ```yaml fence in `text` into a dict list. Skip non-dict
    blocks and unparseable YAML silently — a malformed block in the middle
    of an investigation.md should not block extraction of the rest."""
    out: list[dict[str, Any]] = []
    for match in _YAML_BLOCK_RE.finditer(text):
        try:
            doc = yaml.safe_load(match.group(1))
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict):
            out.append(doc)
    return out


def _collect_findings(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten every `gather:` and `findings:` list across all blocks.

    Both keys are accepted as aliases — `gather:` is the on-disk shape in
    runs from at least April 17 onward; `findings:` is the schema-spec
    name and is used by some test fixtures. The extractor treats them as
    one stream.
    """
    out: list[dict[str, Any]] = []
    for doc in blocks:
        for key in ("gather", "findings"):
            entries = doc.get(key)
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        out.append(entry)
    return out


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
    obs = outcome.get("observations")
    if isinstance(obs, dict):
        verts = obs.get("vertices") or []
        edges = obs.get("edges") or []
        attr_updates = outcome.get("attribute_updates") or []
        if verts or edges or attr_updates:
            return "useful"
        # Some leads only update attributes on an existing vertex; that
        # already counts as useful above. If everything is empty AND no
        # failure_reason set, treat as a real empty result.
        return "empty"
    return "unknown"


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _safe_substitutions(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


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


def _extract_from_text(text: str, vendor: str) -> list[AdHocLead]:
    blocks = _iter_yaml_blocks(text)
    if not blocks:
        return []
    findings = _collect_findings(blocks)
    if not findings:
        return []
    out: list[AdHocLead] = []
    for finding in findings:
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
        out.append(
            AdHocLead(
                finding_id=finding_id,
                lead_name=name,
                catalog_status=status,
                data_source=_safe_str(qd.get("system")),
                query=_safe_str(qd.get("query")),
                selection_rationale=_safe_str(finding.get("selection_rationale")),
                result_shape=_derive_result_shape(finding),
                substitutions=_safe_substitutions(qd.get("substitutions")),
            )
        )
    return out


def has_ad_hoc_leads(text: str, vendor: str) -> bool:
    """Cheap pre-check used by stop_handler to decide whether to spawn the
    full pipeline. Equivalent to `extract_ad_hoc_leads(...)` returning a
    non-empty list, but skips dataclass construction.
    """
    blocks = _iter_yaml_blocks(text)
    if not blocks:
        return False
    for finding in _collect_findings(blocks):
        if _is_screen_mode(finding):
            continue
        name = finding.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        qd = finding.get("query_details") if isinstance(finding.get("query_details"), dict) else {}
        if _classify_status(name, qd.get("template"), vendor) is not None:
            return True
    return False
