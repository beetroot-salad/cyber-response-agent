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
    for line in lines:
        if line.startswith("```"):
            in_fence = not in_fence
            if current is not None:
                current["body_lines"].append(line)
            continue
        if not in_fence and line.startswith("## "):
            m = _PHASE_HEADER_RE.match(line)
            if m:
                if current is not None:
                    sections.append(current)
                phase = m.group("phase").strip().lower().replace(" ", "-")
                current = {
                    "header": line,
                    "phase": phase,
                    "loop_n": int(m.group("loop")) if m.group("loop") else None,
                    "body_lines": [],
                }
                continue
        if current is not None:
            current["body_lines"].append(line)
    if current is not None:
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
            if stripped.startswith("**") and stripped.endswith("**"):
                dropping_raw = False
                kept.append(line)
            elif stripped.startswith("**") and ":**" in stripped:
                dropping_raw = False
                kept.append(line)
            # else: skip the observation bullet
            continue
        kept.append(line)
    body = "\n".join(kept).rstrip()
    if raw_dropped:
        body = body + "\n\n[raw-observation prose trimmed — see `gather:` YAML and downstream ANALYZE for structured outcome]"
    return header + "\n" + body


def _section_yaml_fences(section: dict) -> str:
    """Return only the ```yaml ... ``` fenced blocks from a section body,
    concatenated verbatim (fences included). Markdown prose outside fences
    is dropped.

    Used by the analyze mode to strip free-form prose surfaces (e.g.
    `**Playbook hypotheses:** ?foo, ?bar` enumerations in CONTEXTUALIZE,
    archetype-catalog prose in PREDICT) that analyze must not grade
    against. The only grading-valid hypothesis set is `hypothesize.hypotheses[]`
    inside a YAML fence.

    Returns an empty string if the section has no YAML fences.
    """
    kept: list[str] = []
    in_fence = False
    current: list[str] = []
    for line in section["body_lines"]:
        if line.startswith("```"):
            if not in_fence:
                # Opening fence — only keep if it's YAML.
                if line.strip() in {"```yaml", "```yml"}:
                    in_fence = True
                    current = [line]
            else:
                # Closing fence.
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
        # Latest ANALYZE + Self-report carry the routing rationale for why
        # we're back in PREDICT — always include those in full.
        analyze_sections = [s for s in sections if s["phase"] == "analyze"]
        selfreport_sections = [s for s in sections if s["phase"] == "self-report"]
        latest_analyze_idx = (
            sections.index(analyze_sections[-1]) if analyze_sections else -1
        )
        latest_selfreport_idx = (
            sections.index(selfreport_sections[-1]) if selfreport_sections else -1
        )
        parts: list[str] = []
        for i, s in enumerate(sections):
            if s["phase"] == "contextualize":
                parts.append(_section_text(s))
            elif s["phase"] == "predict":
                parts.append(_section_text(s))
            elif s["phase"] == "gather":
                parts.append(_trim_gather_section(s))
            elif s["phase"] == "analyze":
                if i == latest_analyze_idx:
                    parts.append(_section_text(s))
                # else: drop older ANALYZE narrative (its grades are already
                # rolled into the downstream predict/gather YAML state)
            elif s["phase"] == "self-report":
                if i == latest_selfreport_idx:
                    parts.append(_section_text(s))
            # Unknown phase sections are dropped.
        body = "\n\n".join(p.rstrip() for p in parts if p.strip())
        return f"<investigation mode=\"predict\">\n{body}\n</investigation>"

    if mode == "analyze":
        # YAML-only: drop every markdown-prose surface that could be mistaken
        # for a grading target. The canonical hypothesis set lives inside
        # `hypothesize.hypotheses[]` in the PREDICT YAML fence; archetype
        # catalogs and playbook-hypothesis enumerations that appear in prose
        # must not be visible to the analyze subagent. Prior-loop grades
        # live inside prior `findings[]` YAML fences — those are kept.
        parts = []
        for s in sections:
            fences = _section_yaml_fences(s)
            if fences.strip():
                parts.append(s["header"] + "\n" + fences)
        body = "\n\n".join(parts)
        return f"<investigation mode=\"analyze\">\n{body}\n</investigation>"

    # mode == "report-narrative"
    predict_sections = [s for s in sections if s["phase"] == "predict"]
    analyze_sections = [s for s in sections if s["phase"] == "analyze"]
    latest_hyp = predict_sections[-1] if predict_sections else None
    latest_ana = analyze_sections[-1] if analyze_sections else None
    parts = []
    for s in sections:
        if s["phase"] == "contextualize":
            parts.append(_section_text(s))
        elif s is latest_hyp or s is latest_ana:
            parts.append(_section_text(s))
        # Everything else (GATHER, self-report, prior PREDICT/ANALYZE) dropped.
    body = "\n\n".join(p.rstrip() for p in parts if p.strip())
    return f"<investigation mode=\"report-narrative\">\n{body}\n</investigation>"
