"""Per-mode investigation.md trimmers.

Each phase handler renders `investigation.md` into its subagent's prompt
through `format_investigation_block(text, mode=...)`. The full file grows
multi-KB per loop (raw GATHER observations dominate); each mode trims
to what its subagent actually needs.

Pulled out of `_context_loader.py` because the trimming logic is a
self-contained sub-concern: parse sections → drop / summarize per mode →
re-render. The loader's other duties (run-dir + knowledge-tree reads,
prompt-tag formatting for non-investigation surfaces) stay there.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scripts.handlers._hypothesize_dense import emit_hypothesize_state_dense
from scripts.handlers._markdown import iter_companion_dicts

_PHASE_HEADER_RE = re.compile(
    r"^##\s+(?P<phase>[A-Za-z][A-Za-z\- ]*?)(?:\s*\(loop\s*(?P<loop>\d+)\))?\s*$"
)


def _parse_investigation_sections(text: str) -> list[dict]:
    """Split investigation.md into ordered `## `-delimited sections.

    Each section is `{header, phase, loop_n, body}`. `phase` is lowercased
    and dash-separated (e.g. `contextualize`, `predict`, `gather`,
    `analyze`, `self-report`). `loop_n` is int or None. `body` is the full
    section body including blank lines and fenced blocks, header line
    excluded. Leading content before the first header is dropped (current
    investigation.md format always opens with `## CONTEXTUALIZE`).

    Header matching is fence-aware — a `## ...` line inside a ``` fenced
    block is body content, not a new section.
    """
    lines = text.splitlines()
    sections: list[dict] = []
    current: dict | None = None
    in_fence = False
    for idx, line in enumerate(lines, start=1):
        if line.startswith("```"):
            in_fence = not in_fence
            if current is not None:
                current["body_lines"].append(line)
            continue
        if not in_fence and line.startswith("## "):
            m = _PHASE_HEADER_RE.match(line)
            if m:
                if current is not None:
                    current["end_line"] = idx - 1
                    sections.append(current)
                phase = m.group("phase").strip().lower().replace(" ", "-")
                current = {
                    "header": line,
                    "phase": phase,
                    "loop_n": int(m.group("loop")) if m.group("loop") else None,
                    "start_line": idx,
                    "body_lines": [],
                }
                continue
        if current is not None:
            current["body_lines"].append(line)
    if current is not None:
        current["end_line"] = len(lines)
        sections.append(current)
    return sections


def _section_text(section: dict) -> str:
    """Render a parsed section back to its markdown form."""
    return section["header"] + "\n" + "\n".join(section["body_lines"])


def _trim_gather_section(section: dict) -> str:
    """Render a GATHER section keeping only its structured top-matter
    (bolded `**Lead:**` / `**Status:**` / `**Query:**` lines) and any YAML
    fences. Raw-observation prose (multi-KB per lead in practice) is
    elided with a single placeholder line.

    This is the dominant bulk-contributor in `investigation.md` growth
    across loops: each GATHER can be 2-5KB of observation prose that
    PREDICT does not need for picking the next fork — the structured
    outcome lives either in a `gather:` YAML fence (when authored) or is
    summarized into the downstream ANALYZE block.
    """
    header = section["header"]
    kept: list[str] = []
    in_fence = False
    dropping_raw = False
    raw_dropped = False
    for line in section["body_lines"]:
        stripped = line.lstrip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            kept.append(line)
            continue
        if in_fence:
            kept.append(line)
            continue
        # Out of fence. Detect raw-observation boundary.
        if stripped.startswith("**Raw observation") or stripped.startswith("**Observations"):
            dropping_raw = True
            raw_dropped = True
            continue
        if dropping_raw:
            # End drop mode when we hit a new bolded field or a blank-then-
            # bolded pattern. Conservative: any `**...` line out of fence
            # ends the drop.
            if stripped.startswith("**") and stripped.endswith("**") or stripped.startswith("**") and ":**" in stripped:
                dropping_raw = False
                kept.append(line)
            # else: skip the observation bullet
            continue
        kept.append(line)
    body = "\n".join(kept).rstrip()
    if raw_dropped:
        body = body + "\n\n[raw-observation prose trimmed — see `gather:` YAML and downstream ANALYZE for structured outcome]"
    return header + "\n" + body


_INVLANG_OPEN_FENCES = {"```invlang"}


def _section_yaml_fences(section: dict) -> str:
    """Return only the structured fenced blocks from a section body,
    concatenated verbatim (fences included). Markdown prose outside fences
    is dropped.

    Accepts the dense ```` ```invlang ```` surface only. Used by the
    analyze mode to strip free-form prose surfaces (e.g. `**Playbook
    hypotheses:** ?foo, ?bar` enumerations in CONTEXTUALIZE, archetype-
    catalog prose in PREDICT) that analyze must not grade against. The
    only grading-valid hypothesis set lives inside a structured fence.

    Returns an empty string if the section has no structured fences.
    """
    kept: list[str] = []
    in_fence = False
    current: list[str] = []
    for line in section["body_lines"]:
        if line.startswith("```"):
            if not in_fence:
                if line.strip() in _INVLANG_OPEN_FENCES:
                    in_fence = True
                    current = [line]
            else:
                current.append(line)
                kept.extend(current)
                in_fence = False
                current = []
            continue
        if in_fence:
            current.append(line)
    return "\n".join(kept)


def _analyze_grade_summary(section: dict) -> str:
    """Render an ANALYZE section keeping only the per-hypothesis grade lines
    and the routing tail (`**Surviving hypotheses:**`, `**Next action:**`).
    Drops the per-hypothesis narrative bodies, which can be multi-KB.

    Used for prior-loop ANALYZEs in `analyze` mode — the current loop's
    ANALYZE doesn't exist yet (that's what the handler is about to produce).
    """
    header = section["header"]
    kept: list[str] = []
    for line in section["body_lines"]:
        stripped = line.lstrip()
        if stripped.startswith("- ") and ":" in stripped and ("`+`" in stripped or "`-`" in stripped or "`++`" in stripped or "`--`" in stripped):
            # Per-hypothesis grade line. Keep the first sentence only.
            kept.append(line.split(". ", 1)[0] + ("." if "." in line else ""))
        elif stripped.startswith("**Surviving hypotheses:**") or stripped.startswith("**Next action:**"):
            kept.append(line)
    if not kept:
        return header + "\n[analyze block — no grade lines parsed]"
    return header + "\n" + "\n".join(kept)


def _first_structured_section(sections: list[dict], phase: str) -> dict | None:
    for section in sections:
        if section["phase"] != phase:
            continue
        if _section_yaml_fences(section).strip():
            return section
    return None


def _latest_structured_section(sections: list[dict], phase: str) -> dict | None:
    for section in reversed(sections):
        if section["phase"] != phase:
            continue
        if _section_yaml_fences(section).strip():
            return section
    return None


def _collect_hypotheses_from_parsed(
    parsed: dict, hypotheses_by_id: dict[str, dict]
) -> None:
    """Merge hypotheses from one parsed companion dict into hypotheses_by_id."""
    hypothesize = parsed.get("hypothesize")
    if isinstance(hypothesize, dict):
        for h in hypothesize.get("hypotheses") or []:
            if not isinstance(h, dict):
                continue
            hid = h.get("id")
            if isinstance(hid, str) and hid:
                hypotheses_by_id[hid] = h


def _apply_resolution_signal(
    resolution: dict,
    weights_by_id: dict[str, str],
    refuted_ids: set[str],
) -> None:
    if not isinstance(resolution, dict):
        return
    hid = resolution.get("hypothesis")
    after = resolution.get("after")
    if not isinstance(hid, str) or not hid:
        return
    if isinstance(after, str) and after:
        weights_by_id[hid] = after
        if after == "--":
            refuted_ids.add(hid)
        else:
            refuted_ids.discard(hid)


def _collect_findings_signals(
    lead: dict,
    hypotheses_by_id: dict[str, dict],
    weights_by_id: dict[str, str],
    refuted_ids: set[str],
    shelved_ids: set[str],
) -> None:
    """Apply one lead's signals (new_hypotheses, resolutions, shelved) to state."""
    for h in lead.get("new_hypotheses") or []:
        if not isinstance(h, dict):
            continue
        hid = h.get("id")
        if isinstance(hid, str) and hid:
            hypotheses_by_id[hid] = h
    for resolution in lead.get("resolutions") or []:
        _apply_resolution_signal(resolution, weights_by_id, refuted_ids)
    for hid in lead.get("shelved") or []:
        if isinstance(hid, str) and hid:
            shelved_ids.add(hid)


def _materialize_frontier(
    hypotheses_by_id: dict[str, dict],
    weights_by_id: dict[str, str],
    refuted_ids: set[str],
    shelved_ids: set[str],
) -> list[dict]:
    """Filter and decorate survivors into the active frontier."""
    frontier: list[dict] = []
    for hid, hypothesis in hypotheses_by_id.items():
        if hid in shelved_ids or hid in refuted_ids:
            continue
        current = dict(hypothesis)
        if hid in weights_by_id:
            current["weight"] = weights_by_id[hid]
            if weights_by_id[hid] == "++":
                current["status"] = "confirmed"
        frontier.append(current)
    return frontier


def _section_for_loop(
    sections: list[dict],
    phase: str,
    loop_n: int,
) -> dict | None:
    """Return the structured section for a specific phase/loop, falling back
    to the latest structured section for the phase.

    ANALYZE should not have to read the current PREDICT block just to recover
    the canonical hypothesis set. This helper lets the frontier prefer the
    current loop's PREDICT fence, but still emits useful state for malformed
    legacy runs where loop numbers are missing.
    """
    for section in reversed(sections):
        if section["phase"] != phase:
            continue
        if section.get("loop_n") != loop_n:
            continue
        if _section_yaml_fences(section).strip():
            return section
    return _latest_structured_section(sections, phase)


def _section_line_ranges(sections: list[dict]) -> dict[int, tuple[int, int]]:
    """Return inclusive 1-indexed line ranges for parsed sections.

    `_parse_investigation_sections` intentionally stores only section bodies.
    The frontier needs cheap pointers back to the source sections, so recompute
    ranges from body length. This is close enough because parsed sections always
    render as one header line plus the captured body lines.
    """
    ranges: dict[int, tuple[int, int]] = {}
    for section in sections:
        start = section.get("start_line")
        end = section.get("end_line")
        if isinstance(start, int) and isinstance(end, int):
            ranges[id(section)] = (start, end)
            continue
        line_count = 1 + len(section.get("body_lines") or [])
        prior_ranges = list(ranges.values())
        cursor = (prior_ranges[-1][1] + 1) if prior_ranges else 1
        ranges[id(section)] = (cursor, cursor + line_count - 1)
    return ranges


def _section_pointer(
    section: dict | None,
    ranges: dict[int, tuple[int, int]],
    inv_path: Path | None,
) -> dict[str, Any] | None:
    if section is None:
        return None
    start, end = ranges.get(id(section), (None, None))
    out: dict[str, Any] = {
        "section": section.get("header", "").removeprefix("## ").strip(),
    }
    if inv_path is not None:
        out["path"] = str(inv_path)
    if start is not None and end is not None:
        out["lines"] = f"{start}-{end}"
    return out


def _companion_doc_from_section(section: dict | None) -> dict[str, Any]:
    if section is None:
        return {}
    fences = _section_yaml_fences(section)
    if not fences.strip():
        return {}
    for doc in iter_companion_dicts(fences):
        return doc
    return {}


def _short_text(value: Any, *, max_len: int = 260) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "…"


def _compact_nested(value: Any, *, max_len: int = 260) -> Any:
    if isinstance(value, str):
        return _short_text(value, max_len=max_len)
    if isinstance(value, list):
        return [_compact_nested(v, max_len=max_len) for v in value]
    if isinstance(value, dict):
        return {
            str(k): _compact_nested(v, max_len=max_len)
            for k, v in value.items()
        }
    return value


def _dump_yaml_no_aliases(value: Any) -> str:
    try:
        import yaml  # Local import: handler-side dependency
    except ImportError:
        return repr(value)

    class _NoAliasDumper(yaml.SafeDumper):
        def ignore_aliases(self, data):  # type: ignore[override]
            return True

    return yaml.dump(value, Dumper=_NoAliasDumper, sort_keys=False).rstrip()


def _compact_query_details(query_details: Any) -> dict[str, Any]:
    if not isinstance(query_details, dict):
        return {}
    keep = {}
    for key in ("system", "template", "query", "time_window", "substitutions"):
        if key not in query_details:
            continue
        value = query_details[key]
        if isinstance(value, str):
            keep[key] = _short_text(value, max_len=240)
        else:
            keep[key] = value
    return keep


def _compact_hypothesis(hypothesis: dict[str, Any]) -> dict[str, Any]:
    """Keep the contract/prediction surface ANALYZE grades against.

    Full `story` prose stays in the PREDICT section pointer. The frontier
    carries enough to make the next comparison mechanical: hypothesis id/name,
    current weight/status, p/r literals, and open contracts.
    """
    out: dict[str, Any] = {}
    for key in ("id", "name", "weight", "status"):
        if key in hypothesis:
            out[key] = hypothesis[key]

    for src_key, dst_key in (
        ("predictions", "predictions"),
        ("attribute_predictions", "attribute_predictions"),
        ("refutation_shape", "refutations"),
        ("authorization_contract", "authorization_contracts"),
        ("impact_predictions", "impact_predictions"),
    ):
        entries = hypothesis.get(src_key)
        if not isinstance(entries, list) or not entries:
            continue
        compact_entries: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            compact: dict[str, Any] = {}
            for key in (
                "id",
                "subject",
                "kind",
                "claim",
                "comparison",
                "refutes_predictions",
                "edge_ref",
                "anchor_kind",
                "predicate",
                "on_unauthorized",
                "on_indeterminate",
                "dimension",
            ):
                if key not in entry:
                    continue
                value = entry[key]
                compact[key] = _compact_nested(value)
            compact_entries.append(compact)
        if compact_entries:
            out[dst_key] = compact_entries
    return out


def _compact_predict_hypothesis(hypothesis: dict[str, Any]) -> dict[str, Any]:
    out = _compact_hypothesis(hypothesis)
    for key in ("attached_to_vertex", "proposed_edge", "integrity_waived"):
        if key in hypothesis:
            out[key] = _compact_nested(hypothesis[key])
    story = hypothesis.get("story")
    if isinstance(story, str) and story.strip():
        out["story"] = _short_text(story, max_len=700)
    return out


def _compact_resolution(resolution: Any) -> dict[str, Any] | None:
    if not isinstance(resolution, dict):
        return None
    out: dict[str, Any] = {}
    for src, dst in (
        ("hypothesis", "hypothesis"),
        ("hypothesis_id", "hypothesis"),
        ("before", "before"),
        ("before_weight", "before"),
        ("after", "after"),
        ("severity_of_test", "severity"),
        ("severity", "severity"),
        ("matched_prediction_ids", "matched_predictions"),
        ("matched_refutation_ids", "matched_refutations"),
        ("supporting_marker", "supporting_marker"),
    ):
        if dst in out or src not in resolution:
            continue
        out[dst] = resolution[src]
    if resolution.get("reasoning"):
        out["reasoning"] = _short_text(resolution["reasoning"], max_len=320)
    return out or None


def _compact_authz_resolution(resolution: Any) -> dict[str, Any] | None:
    if not isinstance(resolution, dict):
        return None
    out: dict[str, Any] = {}
    for key in (
        "edge",
        "edge_id",
        "verdict",
        "fulfills_contract",
        "anchor_kind",
        "anchor_id",
        "grounding_kind",
        "authority_for_question",
        "as_of",
        "resolved_by_lead",
        "reasoning",
    ):
        if key in resolution:
            out[key] = _compact_nested(resolution[key], max_len=240)
    return out or None


def _compact_impact_resolution(resolution: Any) -> dict[str, Any] | None:
    if not isinstance(resolution, dict):
        return None
    out: dict[str, Any] = {}
    for key in (
        "prediction_ref",
        "dimension",
        "verdict",
        "grounding_kind",
        "authority_for_question",
        "as_of",
        "grounded_by_lead",
        "reasoning",
    ):
        if key in resolution:
            out[key] = _compact_nested(resolution[key], max_len=240)
    return out or None


def _compact_consultation(consultation: Any) -> dict[str, Any] | None:
    if not isinstance(consultation, dict):
        return None
    out: dict[str, Any] = {}
    for key in (
        "anchor_id",
        "anchor_kind",
        "grounding_kind",
        "result",
        "authority_for_question",
        "as_of",
        "anchor_query",
        "reasoning",
    ):
        if key not in consultation:
            continue
        value = consultation[key]
        out[key] = _short_text(value) if isinstance(value, str) else value
    return out or None


def _compact_attr_update(update: Any) -> dict[str, Any] | None:
    if not isinstance(update, dict):
        return None
    out: dict[str, Any] = {}
    if update.get("target"):
        out["target"] = update["target"]
    updates = update.get("updates")
    if isinstance(updates, dict) and updates:
        out["updates"] = {
            str(k): _short_text(v, max_len=160) if isinstance(v, str) else v
            for k, v in updates.items()
        }
    return out or None


def _compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("id", "loop", "name", "mode", "status", "screen_result", "target"):
        if key in finding:
            out[key] = finding[key]
    query_details = _compact_query_details(finding.get("query_details"))
    if query_details:
        out["query"] = query_details

    outcome = finding.get("outcome") if isinstance(finding.get("outcome"), dict) else {}
    consultations = [
        c for c in (
            _compact_consultation(c)
            for c in outcome.get("anchor_consultations", [])
        )
        if c
    ]
    if consultations:
        out["consultations"] = consultations

    attr_updates = [
        a for a in (
            _compact_attr_update(a)
            for a in outcome.get("attribute_updates", [])
        )
        if a
    ]
    if attr_updates:
        out["attribute_updates"] = attr_updates

    authz = [
        a for a in (
            _compact_authz_resolution(a)
            for a in outcome.get("authorization_resolutions", [])
        )
        if a
    ]
    if authz:
        out["authorization_resolutions"] = authz

    impact = [
        i for i in (
            _compact_impact_resolution(i)
            for i in outcome.get("impact_resolutions", [])
        )
        if i
    ]
    if impact:
        out["impact_resolutions"] = impact

    resolutions = [
        r for r in (
            _compact_resolution(r)
            for r in finding.get("resolutions", [])
        )
        if r
    ]
    if resolutions:
        out["resolutions"] = resolutions
    return out


def _finding_is_negative_or_gap(finding: dict[str, Any]) -> bool:
    if finding.get("screen_result") == "no_match":
        return True
    status = finding.get("status")
    if isinstance(status, str) and status not in {"ok", "complete", "active"}:
        return True
    outcome = finding.get("outcome")
    if isinstance(outcome, dict):
        for c in outcome.get("anchor_consultations", []) or []:
            if not isinstance(c, dict):
                continue
            if c.get("result") in {"refuted", "partial", "no-data"}:
                return True
    for r in finding.get("resolutions", []) or []:
        if isinstance(r, dict) and r.get("after") in {"-", "--"}:
            return True
    return False


def _gather_frontier(gather_out: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(gather_out, dict):
        return {}
    out: dict[str, Any] = {}

    prescribed = gather_out.get("prescribed_leads")
    executed = gather_out.get("executed_leads")
    if isinstance(prescribed, list):
        out["prescribed_leads"] = prescribed
    if isinstance(executed, list):
        out["executed_leads"] = executed
    if isinstance(prescribed, list) and isinstance(executed, list):
        executed_set = set(x for x in executed if isinstance(x, str))
        missing = [x for x in prescribed if isinstance(x, str) and x not in executed_set]
        if missing:
            out["unresolved_prescribed_leads"] = missing

    raw_paths = gather_out.get("raw_details_paths")
    if isinstance(raw_paths, list) and raw_paths:
        out["raw_detail_paths"] = [str(p) for p in raw_paths]

    leads = gather_out.get("leads")
    if isinstance(leads, list) and leads:
        lead_digests: list[dict[str, Any]] = []
        for lead in leads:
            if not isinstance(lead, dict):
                continue
            digest: dict[str, Any] = {}
            for key in ("id", "name", "status", "status_detail", "target"):
                if key in lead:
                    digest[key] = lead[key]
            query = _compact_query_details(lead.get("query"))
            if query:
                digest["query"] = query
            characterization = lead.get("characterization")
            if isinstance(characterization, dict) and characterization:
                digest["characterization"] = {
                    str(k): _short_text(v, max_len=200) if isinstance(v, str) else v
                    for k, v in characterization.items()
                }
            consultations = [
                c for c in (
                    _compact_consultation(c)
                    for c in lead.get("consultations", [])
                )
                if c
            ]
            if consultations:
                digest["consultations"] = consultations
            lead_digests.append(digest)
        if lead_digests:
            out["current_leads"] = lead_digests
    return out


def format_analyze_frontier_block(
    investigation_md: str,
    loop_n: int,
    *,
    run_dir: Path | None = None,
    gather_out: dict[str, Any] | None = None,
) -> str:
    """Render a compact, state-oriented frontier for ANALYZE.

    ANALYZE previously received `<current_gather>` plus a manifest and was
    instructed to Read the current PREDICT block. That kept the prompt small
    but made the next logical step expensive and error-prone: the subagent had
    to retrieve history, identify the canonical hypothesis set, remember prior
    refutations/gaps, and only then grade.

    This block keeps the immediate grading frontier inline while leaving long
    prose and raw payloads as pointers:
      - current loop's declared hypotheses/predictions/refutations/contracts
      - compact current gather digest
      - compact prior findings, including failed/refuted/partial leads
      - section pointers for targeted Read when details are genuinely needed
    """
    body_raw = investigation_md.rstrip()
    inv_path = (run_dir / "investigation.md") if run_dir is not None else None
    frontier: dict[str, Any] = {
        "loop_n": loop_n,
        "objective": (
            "Grade current_gather against active_hypotheses, close any "
            "contracts this lead actually resolves, then route halt/continue."
        ),
        "discipline": [
            (
                "active_hypotheses is the canonical grading set; do not grade "
                "hypothesis names seen only in prose."
            ),
            (
                "prior_findings includes successes and failures; do not rerun "
                "or reinterpret a resolved authority unless current_gather "
                "directly changes it."
            ),
            (
                "authorization_contract anchor_kind is load-bearing for "
                "sanction; classification/context anchors do not override a "
                "full sanction-anchor result."
            ),
        ],
    }

    if not body_raw:
        frontier["pointers"] = {"investigation": "empty"}
    else:
        sections = _parse_investigation_sections(body_raw)
        ranges = _section_line_ranges(sections)
        predict_section = _section_for_loop(sections, "predict", loop_n)
        prologue_section = _first_structured_section(sections, "contextualize")
        latest_analyze = _latest_structured_section(sections, "analyze")

        pointers: dict[str, Any] = {}
        prologue_ptr = _section_pointer(prologue_section, ranges, inv_path)
        if prologue_ptr:
            pointers["prologue"] = prologue_ptr
        predict_ptr = _section_pointer(predict_section, ranges, inv_path)
        if predict_ptr:
            pointers["current_predict"] = predict_ptr
        analyze_ptr = _section_pointer(latest_analyze, ranges, inv_path)
        if analyze_ptr:
            pointers["latest_prior_analyze"] = analyze_ptr
        if pointers:
            frontier["pointers"] = pointers

        predict_doc = _companion_doc_from_section(predict_section)
        hypotheses = (
            (predict_doc.get("hypothesize") or {}).get("hypotheses")
            if isinstance(predict_doc.get("hypothesize"), dict)
            else None
        )
        if isinstance(hypotheses, list) and hypotheses:
            frontier["active_hypotheses"] = [
                _compact_hypothesis(h)
                for h in hypotheses
                if isinstance(h, dict)
            ]
        else:
            fallback = predict_frontier_hypotheses(investigation_md)
            if fallback:
                frontier["active_hypotheses"] = [
                    _compact_hypothesis(h)
                    for h in fallback
                    if isinstance(h, dict)
                ]
            else:
                frontier["active_hypotheses"] = []
                frontier.setdefault("gaps", []).append(
                    "No structured active hypotheses parsed; read current_predict pointer."
                )

        for doc in iter_companion_dicts(investigation_md):
            findings = doc.get("findings")
            if not isinstance(findings, list):
                continue
            prior = [
                _compact_finding(f)
                for f in findings
                if isinstance(f, dict)
                and (
                    not isinstance(f.get("loop"), int)
                    or f.get("loop") < loop_n
                )
            ]
            if prior:
                frontier["prior_findings"] = prior[-24:]
            gaps = [
                _compact_finding(f)
                for f in findings
                if isinstance(f, dict)
                and (
                    not isinstance(f.get("loop"), int)
                    or f.get("loop") < loop_n
                )
                and _finding_is_negative_or_gap(f)
            ]
            if gaps:
                frontier["prior_failures_or_gaps"] = gaps[-12:]
            break

    gather_digest = _gather_frontier(gather_out)
    if gather_digest:
        frontier["current_gather_digest"] = gather_digest

    body = _dump_yaml_no_aliases(frontier)
    return f"<analysis_frontier>\n{body}\n</analysis_frontier>"


def _predict_frontier_hypotheses(sections: list[dict]) -> list[dict]:
    """Materialize the currently-active hypothesis frontier.

    The predict prompt needs the live frontier, not just the latest
    `## PREDICT` markdown section. We therefore accumulate hypotheses across
    all structured fences, then apply later ANALYZE findings' `resolutions`
    and `shelved` signals to suppress refuted / shelved entries and surface
    the latest known weight on the survivors.
    """
    hypotheses_by_id: dict[str, dict] = {}
    weights_by_id: dict[str, str] = {}
    refuted_ids: set[str] = set()
    shelved_ids: set[str] = set()

    for section in sections:
        fences = _section_yaml_fences(section)
        if not fences.strip():
            continue
        for parsed in iter_companion_dicts(fences):
            _collect_hypotheses_from_parsed(parsed, hypotheses_by_id)
            findings = parsed.get("findings")
            if isinstance(findings, list):
                for lead in findings:
                    if isinstance(lead, dict):
                        _collect_findings_signals(
                            lead, hypotheses_by_id, weights_by_id,
                            refuted_ids, shelved_ids,
                        )
    return _materialize_frontier(hypotheses_by_id, weights_by_id, refuted_ids, shelved_ids)


def _first_companion_doc(raw: str) -> dict[str, Any]:
    for doc in iter_companion_dicts(raw):
        return doc
    return {}


def _findings_before_loop(
    findings: Any,
    loop_n: int,
) -> list[dict[str, Any]]:
    if not isinstance(findings, list):
        return []
    out: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        loop = finding.get("loop")
        if not isinstance(loop, int) or loop < loop_n:
            out.append(finding)
    return out


def _latest_loop_findings(
    findings: list[dict[str, Any]],
) -> tuple[int | None, list[dict[str, Any]]]:
    loop_values = [
        f.get("loop")
        for f in findings
        if isinstance(f.get("loop"), int)
    ]
    if not loop_values:
        return None, []
    latest_loop = max(loop_values)
    return latest_loop, [
        f for f in findings
        if f.get("loop") == latest_loop
    ]


def _iter_authz_resolutions(finding: dict[str, Any]):
    outcome = finding.get("outcome")
    if not isinstance(outcome, dict):
        return
    for entry in outcome.get("authorization_resolutions") or []:
        if isinstance(entry, dict):
            yield entry
    observations = outcome.get("observations")
    if isinstance(observations, dict):
        for edge in observations.get("edges") or []:
            if not isinstance(edge, dict):
                continue
            for entry in edge.get("authorization_resolutions") or []:
                if isinstance(entry, dict):
                    yield entry
    for update in outcome.get("attribute_updates") or []:
        if not isinstance(update, dict):
            continue
        updates = update.get("updates")
        if not isinstance(updates, dict):
            continue
        for entry in updates.get("authorization_resolutions") or []:
            if isinstance(entry, dict):
                yield entry


def _resolved_contract_refs(
    findings: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    resolved: dict[str, dict[str, Any]] = {}
    for finding in findings:
        for entry in _iter_authz_resolutions(finding):
            ref = entry.get("fulfills_contract") or entry.get("fulfills")
            if isinstance(ref, str) and ref:
                resolved[ref] = entry
    return resolved


def _impact_prediction_refs(
    findings: list[dict[str, Any]],
) -> tuple[set[str], set[str]]:
    declared: set[str] = set()
    resolved: set[str] = set()
    for finding in findings:
        lead_id = finding.get("id")
        for prediction in finding.get("impact_predictions") or []:
            if not isinstance(prediction, dict):
                continue
            pid = prediction.get("id")
            if isinstance(lead_id, str) and isinstance(pid, str) and pid:
                declared.add(f"{lead_id}.{pid}")
        outcome = finding.get("outcome")
        if not isinstance(outcome, dict):
            continue
        for resolution in outcome.get("impact_resolutions") or []:
            if not isinstance(resolution, dict):
                continue
            ref = resolution.get("prediction_ref")
            if isinstance(ref, str) and ref:
                resolved.add(ref)
    return declared, resolved


def _predict_open_obligations(
    active_hypotheses: list[dict],
    findings: list[dict[str, Any]],
    analyze_out: dict[str, Any] | None,
) -> dict[str, Any]:
    obligations: dict[str, Any] = {}
    if isinstance(analyze_out, dict):
        unresolved = analyze_out.get("unresolved_prescribed_set")
        if isinstance(unresolved, list) and unresolved:
            obligations["unresolved_prescribed_leads"] = [
                str(x) for x in unresolved
                if isinstance(x, str) and x
            ]

    resolved_contracts = _resolved_contract_refs(findings)
    open_authz: list[dict[str, Any]] = []
    for hypothesis in active_hypotheses:
        hid = hypothesis.get("id")
        if not isinstance(hid, str) or not hid:
            continue
        contracts = hypothesis.get("authorization_contract") or []
        if isinstance(contracts, dict):
            contracts = [contracts]
        if not isinstance(contracts, list):
            continue
        for contract in contracts:
            if not isinstance(contract, dict):
                continue
            cid = contract.get("id")
            if not isinstance(cid, str) or not cid:
                continue
            full_ref = f"{hid}.{cid}"
            if full_ref in resolved_contracts:
                continue
            open_authz.append({
                "contract_ref": full_ref,
                "hypothesis": hid,
                "anchor_kind": contract.get("anchor_kind"),
                "predicate": _short_text(contract.get("predicate"), max_len=220),
                "edge_ref": contract.get("edge_ref", "proposed"),
            })
    if open_authz:
        obligations["open_authorization_contracts"] = open_authz

    attr_predictions: list[dict[str, Any]] = []
    for hypothesis in active_hypotheses:
        hid = hypothesis.get("id")
        if not isinstance(hid, str) or not hid:
            continue
        for prediction in hypothesis.get("attribute_predictions") or []:
            if not isinstance(prediction, dict):
                continue
            pid = prediction.get("id")
            attr_predictions.append({
                "prediction_ref": f"{hid}.{pid}" if isinstance(pid, str) and pid else hid,
                "target": prediction.get("target"),
                "attribute": prediction.get("attribute"),
                "claim": _short_text(prediction.get("claim"), max_len=220),
            })
    if attr_predictions:
        obligations["attribute_predictions_to_account_for"] = attr_predictions

    declared_impact, resolved_impact = _impact_prediction_refs(findings)
    unresolved_impact = sorted(declared_impact - resolved_impact)
    if unresolved_impact:
        obligations["unresolved_impact_predictions"] = unresolved_impact

    return obligations


def _latest_resolution_after(
    findings: list[dict[str, Any]],
    target_weight: str,
) -> tuple[str, dict[str, Any]] | None:
    latest: tuple[str, dict[str, Any]] | None = None
    for finding in findings:
        lead_id = finding.get("id")
        for resolution in finding.get("resolutions") or []:
            if not isinstance(resolution, dict):
                continue
            if resolution.get("after") != target_weight:
                continue
            if isinstance(lead_id, str):
                latest = (lead_id, resolution)
    return latest


def _hypothesis_by_id(active_hypotheses: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for hypothesis in active_hypotheses:
        hid = hypothesis.get("id")
        if isinstance(hid, str) and hid:
            out[hid] = hypothesis
    return out


def _predict_decision_frame(
    active_hypotheses: list[dict],
    latest_findings: list[dict[str, Any]],
    open_obligations: dict[str, Any],
    analyze_out: dict[str, Any] | None,
) -> dict[str, Any]:
    frame: dict[str, Any] = {}
    if isinstance(analyze_out, dict) and analyze_out.get("route"):
        frame["continue_reason"] = f"ANALYZE routed {analyze_out.get('route')}"
    elif latest_findings:
        frame["continue_reason"] = "latest findings left at least one planning question open"
    else:
        frame["continue_reason"] = "initial predict pass or no prior structured findings"

    if open_obligations.get("unresolved_prescribed_leads"):
        frame["recommended_posture"] = "re_prescribe_unresolved"
        frame["why"] = "GATHER did not resolve one or more prescribed leads."
        frame["attachment_point"] = {
            "kind": "same_question",
            "leads": open_obligations["unresolved_prescribed_leads"],
        }
        return frame

    if open_obligations.get("open_authorization_contracts"):
        frame["recommended_posture"] = "resolve_authorization"
        frame["why"] = "A live hypothesis still has an unfulfilled authorization contract."
        first = open_obligations["open_authorization_contracts"][0]
        frame["attachment_point"] = {
            "kind": "authorization_contract",
            "contract_ref": first.get("contract_ref"),
            "hypothesis": first.get("hypothesis"),
            "edge_ref": first.get("edge_ref"),
        }
        return frame

    by_id = _hypothesis_by_id(active_hypotheses)
    confirmed = _latest_resolution_after(latest_findings, "++")
    if confirmed is not None:
        lead_id, resolution = confirmed
        hid = resolution.get("hypothesis") or resolution.get("hypothesis_id")
        hypothesis = by_id.get(hid) if isinstance(hid, str) else None
        frame["recommended_posture"] = "extend_upstream"
        frame["why"] = "Latest ANALYZE confirmed the current edge at ++; next PREDICT should not relitigate it."
        frame["attachment_point"] = {
            "kind": "confirmed_parent_vertex",
            "confirmed_by_lead": lead_id,
            "hypothesis": hid,
            "attached_to_vertex": hypothesis.get("attached_to_vertex") if hypothesis else None,
            "proposed_edge": _compact_nested(hypothesis.get("proposed_edge")) if hypothesis else None,
        }
        return frame

    if not active_hypotheses:
        frame["recommended_posture"] = "enrich_observed_vertex"
        frame["why"] = "No live hypothesis frontier exists yet."
        frame["attachment_point"] = {"kind": "prologue_observed_vertex"}
        return frame

    if any(h.get("weight") == "+" for h in active_hypotheses):
        frame["recommended_posture"] = "strengthen_or_refute_current_edge"
        frame["why"] = "A live hypothesis is only partially supported; pick the lead that can promote it to ++ or refute it."
    else:
        frame["recommended_posture"] = "select_next_discriminator"
        frame["why"] = "Live hypotheses remain, but no higher-priority open obligation was detected."
    frame["attachment_point"] = {
        "kind": "active_hypothesis_frontier",
        "hypotheses": [
            h.get("id") for h in active_hypotheses
            if isinstance(h.get("id"), str)
        ],
    }
    return frame


def format_predict_frontier_block(
    investigation_md: str,
    loop_n: int,
    *,
    run_dir: Path | None = None,
    analyze_out: dict[str, Any] | None = None,
) -> str:
    """Render a state-machine handoff for PREDICT.

    The block is loop-count stable: it carries live state, latest outcomes,
    open obligations, and pointers. Historical detail stays available through
    the manifest instead of accumulating inline.
    """
    body_raw = investigation_md.rstrip()
    inv_path = (run_dir / "investigation.md") if run_dir is not None else None
    frontier: dict[str, Any] = {
        "loop_n": loop_n,
        "objective": (
            "Choose the next GATHER lead and, only when earned, author the "
            "next hypothesis scaffold."
        ),
        "attention_priority": [
            "decision_frame",
            "open_obligations",
            "latest_outcome_digest",
            "active_hypotheses",
            "advisory_recent_gaps",
            "pointers",
        ],
    }

    state_parts: list[str] = []
    if not body_raw:
        frontier["decision_frame"] = {
            "recommended_posture": "enrich_observed_vertex",
            "continue_reason": "initial predict pass",
            "attachment_point": {"kind": "alert_summary"},
        }
        frontier["pointers"] = {"investigation": "empty"}
    else:
        sections = _parse_investigation_sections(body_raw)
        ranges = _section_line_ranges(sections)
        companion = _first_companion_doc(body_raw)
        findings = _findings_before_loop(companion.get("findings"), loop_n)
        latest_loop, latest_findings = _latest_loop_findings(findings)
        active = predict_frontier_hypotheses(investigation_md)
        open_obligations = _predict_open_obligations(active, findings, analyze_out)

        frontier["decision_frame"] = _predict_decision_frame(
            active,
            latest_findings,
            open_obligations,
            analyze_out,
        )
        if open_obligations:
            frontier["open_obligations"] = open_obligations
        if latest_findings:
            digest: dict[str, Any] = {
                "loop_n": latest_loop,
                "findings": [_compact_finding(f) for f in latest_findings[-12:]],
            }
            if isinstance(analyze_out, dict):
                handler_payload: dict[str, Any] = {}
                for key in (
                    "route",
                    "termination_category",
                    "disposition",
                    "confidence",
                    "surviving_hypotheses",
                    "unresolved_prescribed_set",
                    "anomalies",
                    "data_wishes",
                ):
                    if key in analyze_out:
                        handler_payload[key] = _compact_nested(analyze_out[key])
                if handler_payload:
                    digest["handler_payload"] = handler_payload
            frontier["latest_outcome_digest"] = digest
        if active:
            frontier["active_hypotheses"] = [
                _compact_predict_hypothesis(h)
                for h in active
                if isinstance(h, dict)
            ]
        gaps = [
            _compact_finding(f)
            for f in findings
            if _finding_is_negative_or_gap(f)
        ]
        if gaps:
            frontier["advisory_recent_gaps"] = gaps[-8:]

        pointers: dict[str, Any] = {}
        for key, section in (
            ("prologue", _first_structured_section(sections, "contextualize")),
            ("latest_predict", _latest_structured_section(sections, "predict")),
            ("latest_gather", _latest_structured_section(sections, "gather")),
            ("latest_analyze", _latest_structured_section(sections, "analyze")),
        ):
            ptr = _section_pointer(section, ranges, inv_path)
            if ptr:
                pointers[key] = ptr
        if pointers:
            frontier["pointers"] = pointers

        prologue_section = _first_structured_section(sections, "contextualize")
        if prologue_section is not None:
            prologue_fences = _section_yaml_fences(prologue_section)
            if prologue_fences.strip():
                state_parts.append(prologue_section["header"] + "\n" + prologue_fences)

        if active:
            state_parts.append(
                "## Active Hypothesis Frontier\n"
                "```invlang\n"
                f"{emit_hypothesize_state_dense(active, block_name='hypotheses')}\n"
                "```"
            )

        latest_analyze = _latest_structured_section(sections, "analyze")
        if latest_analyze is not None:
            analyze_fences = _section_yaml_fences(latest_analyze)
            if analyze_fences.strip():
                state_parts.append(latest_analyze["header"] + "\n" + analyze_fences)

    summary = _dump_yaml_no_aliases(frontier)

    parts = [summary, *[p.rstrip() for p in state_parts if p.strip()]]
    return "<predict_frontier>\n" + "\n\n".join(parts).rstrip() + "\n</predict_frontier>"


def format_predict_state_block(investigation_md: str) -> str:
    """Render the compact predict-time investigation state block.

    This is intentionally state-oriented rather than history-oriented:
      - the prologue fence from CONTEXTUALIZE
      - the currently-active hypothesis frontier
      - the latest ANALYZE section's structured fence

    Markdown prose, GATHER observations, prior-loop narrative, and
    self-report text are excluded. The resulting block is the minimal
    structured state PREDICT needs before it reads additional files on
    demand via `available_context`.
    """
    body_raw = investigation_md.rstrip()
    if not body_raw:
        return (
            "<investigation_state>\n"
            "(empty — no prior phases recorded)\n"
            "</investigation_state>"
        )

    sections = _parse_investigation_sections(body_raw)
    if not sections:
        return (
            "<investigation_state>\n"
            "(no structured investigation state parsed)\n"
            "</investigation_state>"
        )

    parts: list[str] = []

    prologue_section = _first_structured_section(sections, "contextualize")
    if prologue_section is not None:
        prologue_fences = _section_yaml_fences(prologue_section)
        if prologue_fences.strip():
            parts.append(prologue_section["header"] + "\n" + prologue_fences)

    frontier = predict_frontier_hypotheses(investigation_md)
    if frontier:
        parts.append(
            "## Active Hypothesis Frontier\n"
            "```invlang\n"
            f"{emit_hypothesize_state_dense(frontier, block_name='hypotheses')}\n"
            "```"
        )

    latest_analyze = _latest_structured_section(sections, "analyze")
    if latest_analyze is not None:
        analyze_fences = _section_yaml_fences(latest_analyze)
        if analyze_fences.strip():
            parts.append(latest_analyze["header"] + "\n" + analyze_fences)

    body = "\n\n".join(p.rstrip() for p in parts if p.strip())
    if not body:
        body = "(no structured investigation state available)"
    return f"<investigation_state>\n{body}\n</investigation_state>"


def _format_predict_mode(sections: list[dict]) -> str:
    """Emit CONTEXTUALIZE + all PREDICT + trimmed GATHER + latest ANALYZE/Self-report."""
    analyze_sections = [s for s in sections if s["phase"] == "analyze"]
    selfreport_sections = [s for s in sections if s["phase"] == "self-report"]
    latest_analyze_idx = sections.index(analyze_sections[-1]) if analyze_sections else -1
    latest_selfreport_idx = (
        sections.index(selfreport_sections[-1]) if selfreport_sections else -1
    )
    parts: list[str] = []
    for i, s in enumerate(sections):
        if s["phase"] in ("contextualize", "predict"):
            parts.append(_section_text(s))
        elif s["phase"] == "gather":
            parts.append(_trim_gather_section(s))
        elif s["phase"] == "analyze" and i == latest_analyze_idx:
            parts.append(_section_text(s))
        elif s["phase"] == "self-report" and i == latest_selfreport_idx:
            parts.append(_section_text(s))
    body = "\n\n".join(p.rstrip() for p in parts if p.strip())
    return f"<investigation mode=\"predict\">\n{body}\n</investigation>"


def _format_analyze_mode(sections: list[dict]) -> str:
    """Emit structured fences only — drop all prose to prevent grading confusion."""
    parts = []
    for s in sections:
        fences = _section_yaml_fences(s)
        if fences.strip():
            parts.append(s["header"] + "\n" + fences)
    body = "\n\n".join(parts)
    return f"<investigation mode=\"analyze\">\n{body}\n</investigation>"


def _format_report_narrative_mode(sections: list[dict]) -> str:
    """Emit CONTEXTUALIZE + latest PREDICT + latest ANALYZE only."""
    predict_sections = [s for s in sections if s["phase"] == "predict"]
    analyze_sections = [s for s in sections if s["phase"] == "analyze"]
    latest_hyp = predict_sections[-1] if predict_sections else None
    latest_ana = analyze_sections[-1] if analyze_sections else None
    parts = []
    for s in sections:
        if s["phase"] == "contextualize" or s is latest_hyp or s is latest_ana:
            parts.append(_section_text(s))
    body = "\n\n".join(p.rstrip() for p in parts if p.strip())
    return f"<investigation mode=\"report-narrative\">\n{body}\n</investigation>"


def format_investigation_block(
    investigation_md: str,
    *,
    mode: str = "full",
) -> str:
    """Render investigation.md content as a tagged `<investigation>` block.

    `mode` controls how much of the file is emitted — each phase handler
    uses a subset tuned to what its subagent needs. This is the single
    entrypoint for reading `investigation.md` from a handler; trimming
    decisions live here, not in the handlers or subagent prompts.

    Modes:

    - `full` — entire file verbatim. Default. Used by REPORT, which
      needs access to every phase for citation resolution.

    - `predict` — CONTEXTUALIZE + every PREDICT block verbatim +
      every GATHER block with its raw-observation prose elided (top-matter
      and YAML fences kept) + the latest ANALYZE block + the latest
      Self-report. Prior loops' GATHER raw observations are the dominant
      bulk-contributor; dropping them makes the loop-N prompt independent
      of N for the next-fork decision. Typical reduction: 50-70% on
      2-loop-deep investigations.

    - `analyze` — CONTEXTUALIZE + current loop's PREDICT and GATHER
      verbatim (needed to grade against pre-declared predictions /
      refutation shapes) + prior ANALYZE blocks summarized to grade lines
      only (for weight-carryover / rollup-discipline). Current loop is
      the highest loop_n found across PREDICT/GATHER.

    - `report-narrative` — CONTEXTUALIZE + the latest PREDICT and
      latest ANALYZE blocks verbatim. GATHER sections, Self-report
      sections, and prior-loop PREDICT/ANALYZE blocks are dropped
      entirely. Used by the narrow narrative subagent that authors
      `## Summary` / `## For Analyst` prose; it doesn't need raw GATHER
      observations because the final ANALYZE already summarizes what
      was found.

    Unknown modes fall back to `full` to be safe.
    """
    body_raw = investigation_md.rstrip()
    if not body_raw:
        return "<investigation>\n(empty — no prior phases recorded)\n</investigation>"

    if mode not in {"predict", "analyze", "report-narrative"}:
        return f"<investigation>\n{body_raw}\n</investigation>"

    sections = _parse_investigation_sections(body_raw)
    if not sections:
        return f"<investigation>\n{body_raw}\n</investigation>"

    if mode == "predict":
        return _format_predict_mode(sections)
    if mode == "analyze":
        return _format_analyze_mode(sections)
    return _format_report_narrative_mode(sections)


def predict_frontier_hypotheses(investigation_md: str) -> list[dict]:
    """Return the currently-active hypothesis frontier from investigation.md."""
    body_raw = investigation_md.rstrip()
    if not body_raw:
        return []
    sections = _parse_investigation_sections(body_raw)
    if not sections:
        return []
    return _predict_frontier_hypotheses(sections)
