"""Deterministic context loading for phase handlers.

Phase subagents traditionally Read a predictable set of files — investigation.md,
alert.json, per-archetype story.md / trust-anchors.md, precedent snapshots.
Those are all path-deterministic lookups; there is no reasoning in the Read
itself. Pulling them into handler-side Python preloads lets us:

1. Ship all context to the subagent in one prompt — no Read/Glob round-trips
   consuming the subagent's wall-clock budget.
2. Shrink the subagent's tool surface (often to the point of `tools: []`).
3. Collapse the subagent's job to narrative synthesis + structured output
   emission — which is the only part that requires a language model.

This module is the single source of truth for "what's deterministically
loadable for a handler." Individual handlers import the relevant loaders
and format functions. Keep it narrow — anything that requires a decision
about what to load (e.g. which precedent to cite) stays in the handler, not
here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Run-dir artifacts
# ---------------------------------------------------------------------------


def load_alert(run_dir: Path) -> dict:
    """Read `{run_dir}/alert.json` and return the parsed dict.

    Missing file raises FileNotFoundError — alerts are required; a missing
    alert is an orchestration-level bug, not a recoverable runtime state.
    """
    return json.loads((run_dir / "alert.json").read_text())


def load_investigation_md(run_dir: Path) -> str:
    """Read `{run_dir}/investigation.md`; empty string if the file doesn't
    exist yet (valid early-phase state)."""
    path = run_dir / "investigation.md"
    return path.read_text() if path.exists() else ""


def load_run_salt(run_dir: Path) -> str:
    """Return the per-run salt from `{run_dir}/meta.json`.

    Fails fast if meta.json or its `salt` field is missing — the salt is
    required to wrap untrusted alert content in unguessable delimiters. A
    missing salt is an orchestration-level bug (setup_run.py always writes
    one), not a recoverable runtime state.
    """
    meta = json.loads((run_dir / "meta.json").read_text())
    salt = meta.get("salt")
    if not salt or not isinstance(salt, str):
        raise RuntimeError(
            f"meta.json at {run_dir} is missing a non-empty 'salt' field"
        )
    return salt


# ---------------------------------------------------------------------------
# Archetype shapes
# ---------------------------------------------------------------------------


def load_archetype_shapes(
    signature_id: str,
    soc_agent_root: Path,
    *,
    archetype_names: list[str] | None = None,
    include_precedents: bool = False,
) -> list[dict]:
    """Read story.md + trust-anchors.md (+ precedent JSONs) for each named
    archetype under `knowledge/signatures/{signature_id}/archetypes/`.

    If `archetype_names` is None, load every archetype directory. Otherwise
    load only the named ones, preserving the order given (so the handler can
    surface ranking order inline).

    Each entry is `{name, story_md, trust_anchors_md?, precedents?}`. Missing
    story.md/trust-anchors.md files are skipped silently — an archetype may
    legitimately lack a trust-anchors file (no required_anchors). Missing
    directories are dropped entirely (caller's job to validate archetype
    names upstream).
    """
    base = soc_agent_root / "knowledge" / "signatures" / signature_id / "archetypes"
    if not base.is_dir():
        return []

    if archetype_names is None:
        names = sorted(d.name for d in base.iterdir() if d.is_dir())
    else:
        names = [n for n in archetype_names if (base / n).is_dir()]

    out: list[dict] = []
    for name in names:
        d = base / name
        entry: dict[str, Any] = {"name": name}
        story = d / "story.md"
        if story.exists():
            entry["story_md"] = story.read_text()
        ta = d / "trust-anchors.md"
        if ta.exists():
            entry["trust_anchors_md"] = ta.read_text()
        if include_precedents:
            precedents: dict[str, dict] = {}
            for p in sorted(d.glob("*.json")):
                try:
                    precedents[p.stem] = json.loads(p.read_text())
                except json.JSONDecodeError:
                    continue
            if precedents:
                entry["precedents"] = precedents
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Signature-level knowledge (playbook + context)
# ---------------------------------------------------------------------------


def load_signature_text(signature_id: str, soc_agent_root: Path) -> dict[str, str]:
    """Read the signature's top-level markdown — playbook.md + context.md.

    Returns `{"playbook_md": ..., "context_md": ...}`. Missing files map to
    empty strings — a signature may legitimately lack context.md while
    playbook.md is required in practice (but not enforced here — caller
    decides how to treat an empty playbook).
    """
    base = soc_agent_root / "knowledge" / "signatures" / signature_id
    out = {"playbook_md": "", "context_md": ""}
    if (base / "playbook.md").exists():
        out["playbook_md"] = (base / "playbook.md").read_text()
    if (base / "context.md").exists():
        out["context_md"] = (base / "context.md").read_text()
    return out


# ---------------------------------------------------------------------------
# Lead catalog (common-investigation leads used by PREDICT)
# ---------------------------------------------------------------------------


def _lead_definition_path(soc_agent_root: Path, lead_name: str) -> Path:
    return (
        soc_agent_root
        / "knowledge"
        / "common-investigation"
        / "leads"
        / lead_name
        / "definition.md"
    )


def load_lead_definition(soc_agent_root: Path, lead_name: str) -> Optional[str]:
    """Return the contents of one lead's `definition.md`, or `None` if the
    file does not exist (lead is ad-hoc / signature-local).

    Same path semantics as `load_lead_definitions` so the two cannot drift.
    """
    try:
        return _lead_definition_path(soc_agent_root, lead_name).read_text()
    except FileNotFoundError:
        return None


def load_lead_definitions(soc_agent_root: Path) -> dict[str, str]:
    """Return `{lead_name: definition_md}` for every lead under
    `knowledge/common-investigation/leads/{lead_name}/definition.md`.

    Directories without a `definition.md` (e.g. `_template`) are skipped.
    Non-directory entries (e.g. `TAGS.md`) are skipped.
    """
    base = soc_agent_root / "knowledge" / "common-investigation" / "leads"
    if not base.is_dir():
        return {}
    out: dict[str, str] = {}
    for d in sorted(base.iterdir()):
        if not d.is_dir():
            continue
        if d.name.startswith("_"):
            continue
        defn = d / "definition.md"
        if defn.exists():
            out[d.name] = defn.read_text()
    return out


# ---------------------------------------------------------------------------
# Prompt block formatters (XML-style tags — LLM-friendly, unambiguous)
# ---------------------------------------------------------------------------


def format_alert_block(alert: dict, salt: str) -> str:
    """Render the alert JSON as a salted-tag block for inline prompt inclusion.

    The outer tag carries a per-run salt (`<alert-{salt}>…</alert-{salt}>`)
    so an attacker-controlled alert field cannot forge a tag close. Matches
    the `<run-{salt}-{tag}>` pattern in hooks/scripts/tag_tool_results.py,
    which wraps untrusted SIEM/MCP output at PostToolUse time. Handlers
    resolve the salt via `load_run_salt(run_dir)`.
    """
    if not salt:
        raise ValueError("format_alert_block requires a non-empty salt")
    return f"<alert-{salt}>\n{json.dumps(alert, indent=2)}\n</alert-{salt}>"


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
        parts: list[str] = []
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
    parts: list[str] = []
    for s in sections:
        if s["phase"] == "contextualize":
            parts.append(_section_text(s))
        elif s is latest_hyp or s is latest_ana:
            parts.append(_section_text(s))
        # Everything else (GATHER, self-report, prior PREDICT/ANALYZE) dropped.
    body = "\n\n".join(p.rstrip() for p in parts if p.strip())
    return f"<investigation mode=\"report-narrative\">\n{body}\n</investigation>"


def format_current_gather_block(leads: list[dict]) -> str:
    """Render the current loop's gather envelope as a `<current_gather>`
    YAML block for the analyze prompt.

    Input: the `leads[]` list from `ctx.outputs[Phase.GATHER]["leads"]`
    (the same shape the gather subagent emitted). Raw SIEM payloads
    (`lead.raw`) are stripped — those are preloaded verbatim under
    `<raw_details>` and do not belong in this block.

    Returns an empty string when `leads` is empty.
    """
    if not leads:
        return ""
    try:
        import yaml  # Local import: handler-only dependency
    except ImportError:
        return ""
    pruned: list[dict] = []
    for lead in leads:
        if not isinstance(lead, dict):
            continue
        pruned.append({k: v for k, v in lead.items() if k != "raw"})
    if not pruned:
        return ""
    body = yaml.safe_dump({"leads": pruned}, sort_keys=False).rstrip()
    return f"<current_gather>\n{body}\n</current_gather>"


_ARCHETYPES_SECTION_RE = re.compile(
    r"^##\s+Archetypes\s*\n.*?(?=^##\s|\Z)",
    re.DOTALL | re.MULTILINE,
)


def _strip_archetype_catalog(playbook_md: str) -> str:
    """Remove the `## Archetypes` section from a playbook.

    Archetype labels are a disposition-routing concern consumed by REPORT;
    they confuse PREDICT's mechanism-layer reasoning by presenting named
    buckets (`ci-pipeline-exec`, `operator-runtime-debug`, ...) as
    first-class shape candidates. Composition rules and hypothesis seeds
    stay because they encode escalation policy + mechanism-class structure
    that PREDICT legitimately consumes.
    """
    return _ARCHETYPES_SECTION_RE.sub("", playbook_md).rstrip() + "\n"


def format_signature_text_block(
    texts: dict[str, str],
    *,
    exclude_archetype_catalog: bool = False,
) -> str:
    """Render the signature's playbook.md + context.md as a tagged block.

    Missing files render as empty `<playbook/>` / `<context/>` tags so the
    subagent can still recognize them as absent rather than failing silently.

    `exclude_archetype_catalog=True` strips the `## Archetypes` section — use
    from PREDICT (archetypes are a REPORT concern and confuse shape choice).
    """
    lines = ["<signature-knowledge>"]
    playbook = (texts.get("playbook_md") or "").rstrip()
    if playbook and exclude_archetype_catalog:
        playbook = _strip_archetype_catalog(playbook).rstrip()
    context = (texts.get("context_md") or "").rstrip()
    if playbook:
        lines.append("  <playbook>")
        lines.append(playbook)
        lines.append("  </playbook>")
    else:
        lines.append("  <playbook/>")
    if context:
        lines.append("  <context>")
        lines.append(context)
        lines.append("  </context>")
    else:
        lines.append("  <context/>")
    lines.append("</signature-knowledge>")
    return "\n".join(lines)


def format_lead_definitions_block(defs: dict[str, str]) -> str:
    """Render the lead catalog (name → definition.md) as a tagged block.

    Empty catalog → `<lead-catalog/>` (self-closing).
    """
    if not defs:
        return "<lead-catalog/>"
    lines = ["<lead-catalog>"]
    for name in sorted(defs):
        lines.append(f'  <lead name="{name}">')
        lines.append(defs[name].rstrip())
        lines.append("  </lead>")
    lines.append("</lead-catalog>")
    return "\n".join(lines)


_GOAL_RE = re.compile(r"^##\s+Goal\s*\n(?P<body>.*?)(?=^##\s|\Z)", re.DOTALL | re.MULTILINE)
_FRONTMATTER_RE = re.compile(r"\A---\n(?P<fm>.*?)\n---\n(?P<body>.*)\Z", re.DOTALL)


def _lead_summary(defn: str) -> tuple[str, str]:
    """Extract (data_tags_csv, goal_body) from a lead definition.md.

    Returns empty strings when the respective section is missing — callers
    tolerate absent data.
    """
    fm_m = _FRONTMATTER_RE.match(defn)
    data_tags = ""
    body = defn
    if fm_m:
        body = fm_m.group("body")
        # crude data_tags extraction — avoid yaml import here
        for line in fm_m.group("fm").splitlines():
            if line.startswith("data_tags:"):
                data_tags = line.split(":", 1)[1].strip()
                break
    goal_m = _GOAL_RE.search(body)
    goal = goal_m.group("body").strip() if goal_m else ""
    return data_tags, goal


def format_lead_definitions_summary_block(defs: dict[str, str]) -> str:
    """Render the lead catalog as {name, data_tags, Goal body} only — omits
    pitfalls, variants, and per-vendor templates.

    Use from PREDICT where the subagent picks a lead name and the
    downstream GATHER handler has the full definition. Empty catalog →
    `<lead-catalog/>` (self-closing).
    """
    if not defs:
        return "<lead-catalog/>"
    lines = ["<lead-catalog>"]
    for name in sorted(defs):
        data_tags, goal = _lead_summary(defs[name])
        attrs = f' name="{name}"'
        if data_tags:
            attrs += f' data_tags="{data_tags}"'
        lines.append(f"  <lead{attrs}>")
        if goal:
            lines.append(goal)
        lines.append("  </lead>")
    lines.append("</lead-catalog>")
    return "\n".join(lines)


def format_archetype_shapes_block(
    shapes: list[dict], *, with_precedents: bool = False,
) -> str:
    """Render a list of archetype shapes as tagged blocks.

    Output shape:
        <archetypes>
          <archetype name="X">
            <story>...</story>
            <trust-anchors>...</trust-anchors>
            <precedents>                (only when with_precedents=True)
              <precedent id="TICKET-1">{"...": "..."}</precedent>
            </precedents>
          </archetype>
          ...
        </archetypes>

    Empty list → `<archetypes/>` (self-closing).
    """
    if not shapes:
        return "<archetypes/>"

    lines = ["<archetypes>"]
    for a in shapes:
        lines.append(f'  <archetype name="{a["name"]}">')
        if "story_md" in a:
            lines.append("    <story>")
            lines.append(a["story_md"].rstrip())
            lines.append("    </story>")
        if "trust_anchors_md" in a:
            lines.append("    <trust-anchors>")
            lines.append(a["trust_anchors_md"].rstrip())
            lines.append("    </trust-anchors>")
        if with_precedents and "precedents" in a:
            lines.append("    <precedents>")
            for ticket_id, payload in a["precedents"].items():
                lines.append(
                    f'      <precedent id="{ticket_id}">'
                    f"{json.dumps(payload, separators=(',', ':'))}</precedent>"
                )
            lines.append("    </precedents>")
        lines.append("  </archetype>")
    lines.append("</archetypes>")
    return "\n".join(lines)
