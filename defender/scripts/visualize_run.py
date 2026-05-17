#!/usr/bin/env python3
"""Render a defender run as two self-contained HTML pages.

A run serves two first-class concerns:

    transcript.html — Judge evaluation (default landing).
        Optimized for assessing the learning loop's judgment: what did
        the defender produce, what counterfactual story did the actor
        write, what did the judge conclude. Surfaces report.md + a
        compact lead list (the judge's *input*), the actor story, then
        judge outcome + findings + encounter analysis. Oracle and raw
        artifacts collapse below the fold.

    runtime.html — Defender run inspection.
        Optimized for inspecting the runtime agent: investigation.md is
        split per ``## PHASE`` header so each is a TOC entry; gather
        subagents pair with their gather_raw/ payloads; raw stream-json
        events sit collapsed at the bottom.

The two pages cross-link via a header tab strip and share their CSS.

Usage:
    python3 defender/scripts/visualize_run.py <run_dir>
"""
from __future__ import annotations

import datetime as _dt
import html
import json
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover — yaml is in defender deps
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[2]
JUDGE_FILENAME = "transcript.html"
RUNTIME_FILENAME = "runtime.html"


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def esc(s) -> str:
    return html.escape(s if isinstance(s, str) else json.dumps(s, indent=2))


def load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    events: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"type": "_parse_error", "raw": line})
    return events


def load_yaml(path: Path) -> dict | list | None:
    if not path.is_file() or yaml is None:
        return None
    try:
        return yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        return None


def block(kind: str, title: str, body: str, *, open_: bool = False, anchor: str | None = None) -> str:
    open_attr = " open" if open_ else ""
    id_attr = f' id="{esc(anchor)}"' if anchor else ""
    return (
        f'<details class="block {kind}"{open_attr}{id_attr}>'
        f'<summary>{esc(title)}</summary>'
        f'<div class="body">{body}</div>'
        f'</details>'
    )


def pre_text(text: str) -> str:
    return f'<pre class="text">{esc(text)}</pre>'


def pre_json(obj) -> str:
    try:
        rendered = json.dumps(obj, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        rendered = str(obj)
    return f'<pre class="json">{esc(rendered)}</pre>'


def slugify(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "section"


# ---------------------------------------------------------------------------
# Raw transcript event helpers (used by the Runtime view's § Raw section)
# ---------------------------------------------------------------------------


def render_tool_use(blk: dict) -> str:
    return block(
        "tool-use",
        f"→ {blk.get('name', '?')}  ({blk.get('id', '')})",
        pre_json(blk.get("input", {})),
    )


def _flatten_tool_result_content(content) -> str:
    if isinstance(content, list):
        parts: list[str] = []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                parts.append(c.get("text", ""))
            else:
                parts.append(json.dumps(c))
        return "\n".join(parts)
    return str(content)


def render_tool_result(blk: dict) -> str:
    is_error = blk.get("is_error", False)
    body = _flatten_tool_result_content(blk.get("content", ""))
    label = "← tool_result" + (" [error]" if is_error else "")
    return block(
        "tool-result" + (" error" if is_error else ""),
        f"{label}  ({blk.get('tool_use_id', '')})",
        pre_text(body),
    )


def render_thinking(blk: dict) -> str:
    return block("thinking", "thinking", pre_text(blk.get("thinking", "")))


def render_text_block(blk: dict) -> str:
    return f'<div class="text-block">{esc(blk.get("text", ""))}</div>'


def render_assistant(message: dict) -> str:
    parts: list[str] = []
    for blk in message.get("content", []):
        t = blk.get("type")
        if t == "text":
            parts.append(render_text_block(blk))
        elif t == "thinking":
            parts.append(render_thinking(blk))
        elif t == "tool_use":
            parts.append(render_tool_use(blk))
        else:
            parts.append(pre_json(blk))
    return "\n".join(parts)


def render_user(message: dict) -> str:
    content = message.get("content", [])
    if isinstance(content, str):
        return pre_text(content)
    parts: list[str] = []
    for blk in content:
        if not isinstance(blk, dict):
            parts.append(pre_json(blk))
            continue
        if blk.get("type") == "tool_result":
            parts.append(render_tool_result(blk))
        else:
            parts.append(pre_json(blk))
    return "\n".join(parts)


def render_event(event: dict) -> str:
    t = event.get("type", "?")
    if t == "system":
        return block(
            "system",
            f"system: {event.get('subtype', '')}",
            pre_json({k: v for k, v in event.items() if k != "type"}),
        )
    if t == "assistant":
        return block("assistant", "assistant", render_assistant(event.get("message", {})), open_=True)
    if t == "user":
        return block("user", "user / tool results", render_user(event.get("message", {})), open_=True)
    if t == "result":
        cost = event.get("total_cost_usd")
        usage = event.get("usage") or {}
        title = f"result: {event.get('subtype', '')}"
        if cost is not None:
            title += f"  ${cost:.4f}"
        if usage:
            title += (
                f"  in={usage.get('input_tokens', 0)}"
                f" out={usage.get('output_tokens', 0)}"
                f" cache_r={usage.get('cache_read_input_tokens', 0)}"
                f" cache_w={usage.get('cache_creation_input_tokens', 0)}"
            )
        body = pre_text(event.get("result", "")) + pre_json(
            {k: v for k, v in event.items() if k not in ("type", "result")}
        )
        return block("result", title, body, open_=True)
    if t == "hook":
        return block("hook", f"hook: {event.get('hook_event_name', '')}", pre_json(event))
    return block(t, t, pre_json(event))


# ---------------------------------------------------------------------------
# Shared content fragments
# ---------------------------------------------------------------------------


def parse_report(run_dir: Path) -> dict:
    p = run_dir / "report.md"
    if not p.is_file():
        return {}
    text = p.read_text()
    if not text.startswith("---\n"):
        return {"body": text}
    end = text.find("\n---", 4)
    if end == -1:
        return {"body": text}
    fm_text = text[4:end]
    body = text[end + 4 :].lstrip("\n")
    fm: dict = {}
    if yaml is not None:
        try:
            loaded = yaml.safe_load(fm_text)
            if isinstance(loaded, dict):
                fm = loaded
        except yaml.YAMLError:
            fm = {}
    return {**fm, "body": body}


def load_judge_findings(run_id: str) -> dict | None:
    learn_dir = REPO_ROOT / "defender" / "learning" / "runs" / run_id
    data = load_yaml(learn_dir / "judge_findings.yaml")
    return data if isinstance(data, dict) else None


def render_alert_block(run_dir: Path, *, open_: bool = False, anchor: str = "sec-alert") -> str:
    p = run_dir / "alert.json"
    if not p.is_file():
        body = '<div class="empty">no alert.json</div>'
    else:
        try:
            text = json.dumps(json.loads(p.read_text()), indent=2)
        except json.JSONDecodeError:
            text = p.read_text()
        body = pre_text(text)
    return f"""
<section id="{esc(anchor)}" class="stage stage-alert">
  <h2>§ Alert <span class="stage-sub">— input to the defender runtime</span></h2>
  {body}
</section>
"""


def render_lead_sequence_compact(run_dir: Path) -> str:
    """Compact lead list — position, goal one-liner, queries[].id + params.

    This is the judge's view of "what did the defender measure?". Raw
    payloads stay collapsed under § Runtime.
    """
    p = run_dir / "lead_sequence.yaml"
    data = load_yaml(p)
    if not isinstance(data, dict):
        return '<div class="empty">no lead_sequence.yaml</div>'
    entries = data.get("entries") or []
    if not entries:
        return '<div class="empty">lead_sequence has no entries</div>'
    rows: list[str] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        pos = e.get("position", "?")
        ld = e.get("lead_description") or {}
        goal = ld.get("goal", "") if isinstance(ld, dict) else ""
        queries = e.get("queries") or []
        q_html = ""
        if isinstance(queries, list):
            q_rows: list[str] = []
            for q in queries:
                if not isinstance(q, dict):
                    continue
                qid = q.get("id", "?")
                params = q.get("params") or {}
                params_str = json.dumps(params, ensure_ascii=False) if params else ""
                q_rows.append(
                    f'<div class="lead-query"><span class="qid">{esc(qid)}</span> '
                    f'<span class="qparams">{esc(params_str)}</span></div>'
                )
            q_html = "".join(q_rows)
        rows.append(
            f'<div class="lead-row">'
            f'<div class="lead-head"><span class="lead-pos">#{esc(str(pos))}</span></div>'
            f'<div class="lead-body">'
            f'<div class="lead-goal">{esc(goal)}</div>'
            f'{q_html}'
            f'</div>'
            f'</div>'
        )
    return f'<div class="lead-list">{"".join(rows)}</div>'


def render_report_card(run_dir: Path) -> str:
    """Report disposition + body, presented as a card (judge view)."""
    report = parse_report(run_dir)
    disposition = str(report.get("disposition", "?"))
    confidence = str(report.get("confidence", "?"))
    body = report.get("body", "").strip() or "(no report body)"
    return (
        f'<div class="report-card">'
        f'<div class="report-meta">'
        f'<span class="rm-key">disposition:</span> '
        f'<span class="rm-val disp-{esc(disposition)}">{esc(disposition)}</span>'
        f'  ·  <span class="rm-key">confidence:</span> '
        f'<span class="rm-val">{esc(confidence)}</span>'
        f'</div>'
        f'<div class="report-body">{esc(body)}</div>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Gather subagents (used by both views, configured differently)
# ---------------------------------------------------------------------------


def extract_main_subagents(events: list[dict]) -> list[dict]:
    calls: dict[str, dict] = {}
    order: list[str] = []
    for ev in events:
        if ev.get("type") == "assistant":
            for blk in (ev.get("message") or {}).get("content", []):
                if (
                    isinstance(blk, dict)
                    and blk.get("type") == "tool_use"
                    and blk.get("name") in ("Task", "Agent")
                ):
                    calls[blk["id"]] = {
                        "id": blk["id"],
                        "name": blk["name"],
                        "input": blk.get("input", {}),
                        "result": None,
                        "is_error": False,
                    }
                    order.append(blk["id"])
        elif ev.get("type") == "user":
            c = (ev.get("message") or {}).get("content", [])
            if not isinstance(c, list):
                continue
            for blk in c:
                if not isinstance(blk, dict) or blk.get("type") != "tool_result":
                    continue
                tid = blk.get("tool_use_id")
                if tid in calls:
                    calls[tid]["result"] = _flatten_tool_result_content(blk.get("content", ""))
                    calls[tid]["is_error"] = blk.get("is_error", False)
    return [calls[i] for i in order]


# ---------------------------------------------------------------------------
# Investigation.md phase split (runtime view)
# ---------------------------------------------------------------------------


def split_investigation_phases(run_dir: Path) -> list[dict]:
    """Split investigation.md on ``## `` headers into ordered phase blocks.

    Returns ``[{name, anchor, body}, ...]`` in source order. The text
    before the first ``## `` (preamble / frontmatter) is included as a
    leading entry named "preamble" if non-empty.
    """
    p = run_dir / "investigation.md"
    if not p.is_file():
        return []
    text = p.read_text()
    parts = re.split(r"(?m)^(## .*)$", text)
    # re.split with one capturing group yields: [pre, header1, body1, header2, body2, ...]
    out: list[dict] = []
    pre = parts[0].strip()
    if pre:
        out.append({"name": "preamble", "anchor": "phase-preamble", "body": pre})
    used_anchors: set[str] = set()
    for i in range(1, len(parts), 2):
        header_line = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""
        name = header_line[3:].strip() or f"phase-{i}"
        slug = slugify(name)
        anchor = f"phase-{slug}"
        n = 2
        while anchor in used_anchors:
            anchor = f"phase-{slug}-{n}"
            n += 1
        used_anchors.add(anchor)
        out.append({"name": name, "anchor": anchor, "body": body.strip()})
    return out


# ---------------------------------------------------------------------------
# Judge findings rendering (judge view)
# ---------------------------------------------------------------------------


def render_judge_finding(idx: int, f: dict) -> str:
    ftype = str(f.get("type", "?"))
    topic = str(f.get("subject_topic", ""))
    anchor = str(f.get("subject_anchor", ""))
    finding_text = str(f.get("finding", "")).strip()
    citations = f.get("citations") or []

    citation_html = ""
    if isinstance(citations, list) and citations:
        rows: list[str] = []
        for c in citations:
            if not isinstance(c, dict):
                continue
            src = str(c.get("source", "?"))
            quote = str(c.get("quote", "")).strip()
            rows.append(
                f'<div class="citation citation-{esc(src)}">'
                f'<div class="cite-src">{esc(src)}</div>'
                f'<pre class="text">{esc(quote)}</pre>'
                f'</div>'
            )
        citation_html = f'<div class="citations">{"".join(rows)}</div>'

    return (
        f'<div class="finding-card finding-{esc(ftype)}" id="finding-{idx}">'
        f'<div class="finding-head">'
        f'<span class="ftype">{esc(ftype)}</span>'
        f'<span class="ftopic">{esc(topic)}</span>'
        f'<span class="fanchor">{esc(anchor)}</span>'
        f'</div>'
        f'<div class="finding-body">{esc(finding_text)}</div>'
        f'{citation_html}'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# Judge view sections
# ---------------------------------------------------------------------------


def render_judge_defender_summary(run_dir: Path) -> str:
    """The judge's input: report.md + compact lead list. No raw invlang.

    investigation.md is the agent's working memory and reads as dense
    invlang; it is the wrong surface for evaluating judgment. The judge
    is grading whether the disposition is supportable given the leads
    that ran — those two pieces (report + lead list) are sufficient.
    """
    return f"""
<section id="sec-defender-summary" class="stage stage-defender">
  <h2>§ Defender summary <span class="stage-sub">— what the judge graded</span></h2>

  <h3>report.md</h3>
  {render_report_card(run_dir)}

  <h3>lead sequence ({_lead_count(run_dir)} lead(s))</h3>
  {render_lead_sequence_compact(run_dir)}
</section>
"""


def _lead_count(run_dir: Path) -> int:
    data = load_yaml(run_dir / "lead_sequence.yaml")
    if isinstance(data, dict):
        e = data.get("entries") or []
        if isinstance(e, list):
            return len(e)
    return 0


def render_judge_actor_section(run_id: str) -> str:
    learn_dir = REPO_ROOT / "defender" / "learning" / "runs" / run_id
    archetype = learn_dir / "actor_archetype.txt"
    menu = learn_dir / "actor_menu.txt"
    story = learn_dir / "actor_story.md"

    if not story.is_file():
        body = '<div class="empty">no actor_story.md</div>'
        return f"""
<section id="sec-actor" class="stage stage-actor">
  <h2>§ Actor <span class="stage-sub">— adversarial counterfactual</span></h2>
  {body}
</section>
"""
    arch = archetype.read_text().strip() if archetype.is_file() else "?"
    menu_txt = menu.read_text().strip() if menu.is_file() else ""
    meta_html = (
        f'<div class="actor-meta"><span class="key">archetype:</span> '
        f'<span class="val">{esc(arch)}</span></div>'
    )
    menu_block = ""
    if menu_txt:
        menu_block = block("actor-menu", "MITRE technique menu (sampled)", pre_text(menu_txt))

    story_html = f'<pre class="text story">{esc(story.read_text())}</pre>'

    return f"""
<section id="sec-actor" class="stage stage-actor">
  <h2>§ Actor <span class="stage-sub">— adversarial counterfactual</span></h2>
  {meta_html}
  {menu_block}
  <h3>actor_story.md</h3>
  {story_html}
</section>
"""


def render_judge_judge_section(judge: dict | None) -> str:
    if not judge:
        return """
<section id="sec-judge" class="stage stage-judge">
  <h2>§ Judge <span class="stage-sub">— outcome + findings</span></h2>
  <div class="empty">no judge_findings.yaml — learning loop did not run or aborted</div>
</section>
"""
    outcome = str(judge.get("outcome", "?"))
    rationale = str(judge.get("outcome_rationale", "")).strip()
    encounter = str(judge.get("encounter_analysis", "")).strip()
    findings = judge.get("defender_findings") or []

    if isinstance(findings, list) and findings:
        cards = "\n".join(render_judge_finding(i, f) for i, f in enumerate(findings) if isinstance(f, dict))
    else:
        cards = '<div class="empty">judge emitted no findings</div>'

    encounter_html = (
        f'<pre class="text encounter">{esc(encounter)}</pre>'
        if encounter
        else '<div class="empty">no encounter_analysis</div>'
    )

    return f"""
<section id="sec-judge" class="stage stage-judge">
  <h2>§ Judge <span class="stage-sub">— outcome + findings</span></h2>

  <h3 id="sec-judge-outcome">Outcome</h3>
  <div class="judge-outcome out-{esc(outcome)}">
    <div class="outcome-value">{esc(outcome)}</div>
    <div class="outcome-rationale">{esc(rationale)}</div>
  </div>

  <h3 id="sec-judge-findings">Findings ({len(findings) if isinstance(findings, list) else 0})</h3>
  <div class="findings-grid">{cards}</div>

  <h3 id="sec-judge-encounter">Encounter analysis</h3>
  {encounter_html}
</section>
"""


def render_judge_oracle_section(run_id: str) -> str:
    learn_dir = REPO_ROOT / "defender" / "learning" / "runs" / run_id
    proj = learn_dir / "projected_telemetry.yaml"
    proj_raw = learn_dir / "projected_telemetry.raw.txt"
    inner = ""
    if proj.is_file():
        inner += block("oracle-yaml", "projected_telemetry.yaml", pre_text(proj.read_text()))
    if proj_raw.is_file():
        inner += block("oracle-raw", "projected_telemetry.raw.txt (raw fallback)", pre_text(proj_raw.read_text()))
    if not inner:
        inner = '<div class="empty">no oracle artifacts</div>'
    return f"""
<section id="sec-oracle" class="stage stage-oracle">
  <h2>§ Oracle <span class="stage-sub">— projected telemetry (collapsed by default)</span></h2>
  {inner}
</section>
"""


def render_judge_raw_bundle(run_id: str) -> str:
    learn_dir = REPO_ROOT / "defender" / "learning" / "runs" / run_id
    if not learn_dir.is_dir():
        return ""
    panels: list[str] = []
    for fname in ("actor_input.yaml", "source_refs.yaml", "lead_sequence.yaml", "alert.json"):
        p = learn_dir / fname
        if p.is_file():
            panels.append(block("artifact", fname, pre_text(p.read_text())))
    for raw in sorted(learn_dir.glob("*.raw.txt")):
        panels.append(block("artifact raw", raw.name, pre_text(raw.read_text())))
    trace = learn_dir / "actor_trace.jsonl"
    if trace.is_file():
        panels.append(block("artifact", "actor_trace.jsonl", pre_text(trace.read_text())))
    if not panels:
        return ""
    return f"""
<section id="sec-raw-bundle" class="stage stage-raw">
  <h2>§ Raw bundle <span class="stage-sub">— learning-loop inputs &amp; fallbacks</span></h2>
  {"".join(panels)}
</section>
"""


def render_judge_toc(n_findings: int) -> str:
    finding_links = "".join(
        f'<li class="item"><a href="#finding-{i}">finding #{i}</a></li>'
        for i in range(n_findings)
    )
    if n_findings == 0:
        finding_links = '<li class="item muted">(none)</li>'
    return f"""
<nav class="toc">
  <ul>
    <li class="section">Headline</li>
    <li class="item"><a href="#top">summary tiles</a></li>

    <li class="section">§ Alert</li>
    <li class="item"><a href="#sec-alert">alert.json</a></li>

    <li class="section">§ Defender summary</li>
    <li class="item"><a href="#sec-defender-summary">report + leads</a></li>

    <li class="section">§ Actor</li>
    <li class="item"><a href="#sec-actor">archetype + story</a></li>

    <li class="section">§ Judge</li>
    <li class="item"><a href="#sec-judge-outcome">outcome</a></li>
    <li class="item"><a href="#sec-judge-findings">findings</a></li>
    {finding_links}
    <li class="item"><a href="#sec-judge-encounter">encounter analysis</a></li>

    <li class="section">§ Oracle</li>
    <li class="item"><a href="#sec-oracle">projected telemetry</a></li>

    <li class="section">§ Raw bundle</li>
    <li class="item"><a href="#sec-raw-bundle">inputs &amp; fallbacks</a></li>
  </ul>
</nav>
"""


# ---------------------------------------------------------------------------
# Runtime view sections
# ---------------------------------------------------------------------------


def render_runtime_investigation(run_dir: Path) -> tuple[str, list[dict]]:
    phases = split_investigation_phases(run_dir)
    if not phases:
        body = '<div class="empty">no investigation.md or empty</div>'
        return (
            f"""
<section id="sec-investigation" class="stage stage-defender">
  <h2>§ Investigation <span class="stage-sub">— investigation.md split by phase</span></h2>
  {body}
</section>
""",
            [],
        )
    blocks: list[str] = []
    for ph in phases:
        title = ph["name"]
        body_html = f'<pre class="text invlang">{esc(ph["body"])}</pre>'
        blocks.append(block("phase", title, body_html, open_=True, anchor=ph["anchor"]))
    return (
        f"""
<section id="sec-investigation" class="stage stage-defender">
  <h2>§ Investigation <span class="stage-sub">— investigation.md split by phase</span></h2>
  {"".join(blocks)}
</section>
""",
        phases,
    )


def render_runtime_gather(run_dir: Path, events: list[dict]) -> tuple[str, int]:
    calls = extract_main_subagents(events)
    gather_dir = run_dir / "gather_raw"
    payloads_by_pos: dict[str, Path] = {}
    if gather_dir.is_dir():
        for entry in sorted(gather_dir.iterdir()):
            if entry.is_file() and entry.suffix in (".json", ".txt"):
                # match by leading position prefix (e.g. "0.json", "0a.json")
                stem = entry.stem
                payloads_by_pos.setdefault(stem, entry)

    if not calls:
        body = '<div class="empty">(no Task/Agent calls)</div>'
        return (
            f"""
<section id="sec-gather" class="stage stage-defender">
  <h2>§ Gather subagents <span class="stage-sub">— prompt → query → raw payload</span></h2>
  {body}
</section>
""",
            0,
        )
    blocks: list[str] = []
    for i, call in enumerate(calls):
        inp = call.get("input", {}) or {}
        description = inp.get("description") or "(no description)"
        subagent_type = inp.get("subagent_type") or "(default)"
        prompt = inp.get("prompt", "")
        result = call.get("result")
        err = " [error]" if call.get("is_error") else ""
        title = f"#{i} [{subagent_type}] {description}{err}"
        inner = block("subagent-input", "input prompt", pre_text(prompt))
        if result is not None:
            inner += block(
                "subagent-output",
                "subagent output (summary back to defender)",
                pre_text(result if isinstance(result, str) else json.dumps(result, indent=2)),
                open_=True,
            )
        else:
            inner += '<div class="empty">(no result captured)</div>'

        # Pair with gather_raw payload by position prefix
        if gather_dir.is_dir():
            for entry in sorted(gather_dir.iterdir()):
                if not entry.is_file() or entry.suffix not in (".json", ".txt"):
                    continue
                stem = entry.stem
                if stem == str(i) or stem.startswith(f"{i}-") or stem.startswith(f"{i}.") or stem.startswith(f"{i}a") or stem.startswith(f"{i}b"):
                    try:
                        raw = entry.read_text()
                        if entry.suffix == ".json":
                            raw = json.dumps(json.loads(raw), indent=2)
                    except (OSError, json.JSONDecodeError):
                        raw = "<unreadable>"
                    inner += block("gather-raw", f"gather_raw/{entry.name}", pre_text(raw))
        blocks.append(block("subcall gather", title, inner, anchor=f"gather-{i}"))
    return (
        f"""
<section id="sec-gather" class="stage stage-defender">
  <h2>§ Gather subagents · {len(calls)} call(s) <span class="stage-sub">— each paired with its gather_raw/ payload</span></h2>
  {"".join(blocks)}
</section>
""",
        len(calls),
    )


def render_runtime_lead_sequence(run_dir: Path) -> str:
    raw = ""
    p = run_dir / "lead_sequence.yaml"
    if p.is_file():
        raw = block("artifact", "lead_sequence.yaml (raw)", pre_text(p.read_text()))
    return f"""
<section id="sec-lead-sequence" class="stage stage-defender">
  <h2>§ Lead sequence</h2>
  {render_lead_sequence_compact(run_dir)}
  {raw}
</section>
"""


def render_runtime_report(run_dir: Path) -> str:
    return f"""
<section id="sec-report" class="stage stage-defender">
  <h2>§ Report</h2>
  {render_report_card(run_dir)}
</section>
"""


def render_runtime_raw(events: list[dict]) -> str:
    inner = "\n".join(render_event(e) for e in events) or '<div class="empty">(no events)</div>'
    body = block("raw-stream", f"stream-json events ({len(events)})", inner)
    return f"""
<section id="sec-raw" class="stage stage-raw">
  <h2>§ Raw transcript <span class="stage-sub">— full stream-json, for debugging</span></h2>
  {body}
</section>
"""


def render_runtime_toc(phases: list[dict], n_gather: int) -> str:
    phase_links = "".join(
        f'<li class="item"><a href="#{esc(ph["anchor"])}">{esc(ph["name"])}</a></li>'
        for ph in phases
    )
    if not phases:
        phase_links = '<li class="item muted">(no phases)</li>'
    gather_links = "".join(
        f'<li class="item"><a href="#gather-{i}">gather #{i}</a></li>'
        for i in range(n_gather)
    )
    if n_gather == 0:
        gather_links = '<li class="item muted">(no calls)</li>'
    return f"""
<nav class="toc">
  <ul>
    <li class="section">Headline</li>
    <li class="item"><a href="#top">disposition + report</a></li>

    <li class="section">§ Alert</li>
    <li class="item"><a href="#sec-alert">alert.json</a></li>

    <li class="section">§ Investigation</li>
    {phase_links}

    <li class="section">§ Gather</li>
    {gather_links}

    <li class="section">§ Lead sequence</li>
    <li class="item"><a href="#sec-lead-sequence">leads</a></li>

    <li class="section">§ Report</li>
    <li class="item"><a href="#sec-report">report.md</a></li>

    <li class="section">§ Raw</li>
    <li class="item"><a href="#sec-raw">stream-json</a></li>

    <li class="section">Footer</li>
    <li class="item"><a href="#sec-footer">lesson commits</a></li>
  </ul>
</nav>
"""


# ---------------------------------------------------------------------------
# Footer (lesson commits, queue-decoupled — runtime view only)
# ---------------------------------------------------------------------------


def lesson_changes(run_dir: Path, run_id: str) -> dict:
    trace = run_dir / "tool_trace.jsonl"
    if not trace.is_file():
        return {"available": False, "reason": "no tool_trace.jsonl"}
    since_iso = (
        _dt.datetime.fromtimestamp(trace.stat().st_mtime, tz=_dt.timezone.utc)
        .isoformat()
    )
    try:
        log = subprocess.run(
            [
                "git", "-C", str(REPO_ROOT), "log",
                f"--since={since_iso}",
                "--pretty=format:%H%x09%cI%x09%s",
                "--name-status",
                "--", "defender/lessons/",
            ],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"available": False, "reason": f"git unavailable: {e}"}
    if log.returncode != 0:
        return {"available": False, "reason": log.stderr.strip() or "git log failed"}

    commits: list[dict] = []
    cur: dict | None = None
    for line in log.stdout.splitlines():
        if not line.strip():
            if cur:
                commits.append(cur)
                cur = None
            continue
        if "\t" in line and len(line.split("\t")) >= 3 and len(line.split("\t")[0]) == 40:
            sha, when, subject = line.split("\t", 2)
            if cur:
                commits.append(cur)
            cur = {"sha": sha, "when": when, "subject": subject, "files": []}
        elif cur is not None:
            cur["files"].append(line)
    if cur:
        commits.append(cur)

    for c in commits:
        diff = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "show", c["sha"],
             "--pretty=format:", "--", "defender/lessons/"],
            capture_output=True, text=True,
        )
        c["diff"] = diff.stdout if diff.returncode == 0 else ""

    return {"available": True, "since": since_iso, "commits": commits, "run_id": run_id}


def render_footer(run_dir: Path, run_id: str) -> str:
    lc = lesson_changes(run_dir, run_id)
    if not lc.get("available"):
        body = f'<div class="empty">lesson change tracking unavailable ({esc(lc.get("reason", "?"))})</div>'
    elif not lc.get("commits"):
        body = f'<div class="empty">no lesson commits since this run started ({esc(lc["since"])})</div>'
    else:
        rows: list[str] = []
        for c in lc["commits"]:
            files = "\n".join(c.get("files", []))
            diff = c.get("diff", "")
            inner = (
                f'<div class="commit-meta">{esc(c["when"])} · {esc(c["sha"][:10])}</div>'
                f'<pre class="text files">{esc(files)}</pre>'
            )
            if diff.strip():
                inner += f'<pre class="json diff">{esc(diff)}</pre>'
            rows.append(block("lesson-commit", c["subject"], inner))
        body = "\n".join(rows)
    return f"""
<footer id="sec-footer" class="footer">
  <h2>concurrent lesson commits</h2>
  <div class="footer-caveat">
    The author flushes the pending-findings queue when it crosses the threshold,
    so commits below were authored during this run's wall-clock window but may
    fold in findings from earlier runs.
  </div>
  {body}
</footer>
"""


# ---------------------------------------------------------------------------
# Header + tabs + CSS (shared)
# ---------------------------------------------------------------------------


def render_header(case_id: str, n_events: int, n_tool_calls: int, cost: float, run_dir: Path, active: str) -> str:
    judge_active = " active" if active == "judge" else ""
    runtime_active = " active" if active == "runtime" else ""
    return f"""
<header class="top">
  <div class="top-row">
    <h1>defender run: {esc(case_id)}</h1>
    <nav class="tabs">
      <a class="tab{judge_active}" href="{JUDGE_FILENAME}">Judge eval</a>
      <a class="tab{runtime_active}" href="{RUNTIME_FILENAME}">Runtime inspection</a>
    </nav>
  </div>
  <div class="meta">events={n_events} · tool_calls={n_tool_calls} · cost=${cost:.4f} · run_dir={esc(str(run_dir))}</div>
</header>
"""


def render_judge_headline(run_dir: Path, judge: dict | None) -> str:
    report = parse_report(run_dir)
    disposition = str(report.get("disposition", "?"))
    confidence = str(report.get("confidence", "?"))
    outcome = str((judge or {}).get("outcome", "—"))
    n_findings = len((judge or {}).get("defender_findings") or []) if judge else 0
    return f"""
<section class="headline">
  <div class="tiles">
    <div class="tile tile-out out-{esc(outcome)}">
      <div class="tile-label">judge outcome</div>
      <div class="tile-value">{esc(outcome)}</div>
      <div class="tile-sub">{n_findings} finding(s)</div>
    </div>
    <div class="tile tile-disp disp-{esc(disposition)}">
      <div class="tile-label">defender disposition</div>
      <div class="tile-value">{esc(disposition)}</div>
      <div class="tile-sub">confidence: {esc(confidence)}</div>
    </div>
  </div>
</section>
"""


def render_runtime_headline(run_dir: Path) -> str:
    report = parse_report(run_dir)
    disposition = str(report.get("disposition", "?"))
    confidence = str(report.get("confidence", "?"))
    body = report.get("body", "").strip() or "(no report body)"
    return f"""
<section class="headline">
  <div class="tiles">
    <div class="tile tile-disp disp-{esc(disposition)}">
      <div class="tile-label">defender disposition</div>
      <div class="tile-value">{esc(disposition)}</div>
      <div class="tile-sub">confidence: {esc(confidence)}</div>
    </div>
  </div>
  <div class="headline-body">
    <div class="hb-label">report.md</div>
    <div class="hb-text">{esc(body)}</div>
  </div>
</section>
"""


CSS = """
:root {
  --bg: #0d1117;
  --bg-2: #161b22;
  --bg-3: #0f1620;
  --bg-4: #1c2128;
  --border: #30363d;
  --border-2: #21262d;
  --text: #c9d1d9;
  --text-dim: #8b949e;
  --text-bright: #f0f6fc;
  --accent: #58a6ff;
  --accent-defender: #58a6ff;
  --accent-learning: #a371f7;
  --accent-actor: #f85149;
  --accent-judge: #3fb950;
  --accent-oracle: #d29922;
  --accent-alert: #d29922;
  --accent-raw: #6e7681;
  --good: #3fb950;
  --warn: #d29922;
  --bad: #f85149;
  --code: #79c0ff;
}

* { box-sizing: border-box; scrollbar-color: #30363d #0d1117; scrollbar-width: thin; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 5px; border: 2px solid var(--bg); }
::-webkit-scrollbar-thumb:hover { background: #484f58; }
::-webkit-scrollbar-corner { background: var(--bg); }

html, body { margin: 0; padding: 0; }
body {
  font: 13px/1.55 -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: var(--bg);
  color: var(--text);
  scroll-behavior: smooth;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ----- Top header + tabs ----- */
header.top {
  padding: 12px 24px 0;
  background: var(--bg-2);
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 20;
}
.top-row { display: flex; align-items: center; gap: 24px; }
header.top h1 { margin: 0; font-size: 15px; font-weight: 600; color: var(--text-bright); flex-shrink: 0; }
nav.tabs { display: flex; gap: 4px; margin-left: auto; }
nav.tabs .tab {
  padding: 8px 16px;
  font-size: 12px;
  color: var(--text-dim);
  border: 1px solid transparent;
  border-bottom: none;
  border-radius: 4px 4px 0 0;
  text-decoration: none;
  position: relative;
  top: 1px;
}
nav.tabs .tab:hover { color: var(--text-bright); text-decoration: none; background: var(--bg-3); }
nav.tabs .tab.active {
  color: var(--text-bright);
  background: var(--bg);
  border-color: var(--border);
  border-bottom-color: var(--bg);
  font-weight: 600;
}
header.top .meta {
  font-size: 11px;
  color: var(--text-dim);
  font-family: 'SF Mono', Menlo, Consolas, monospace;
  padding: 8px 0 10px;
}

/* ----- Headline ----- */
section.headline {
  padding: 20px 24px;
  background: var(--bg-3);
  border-bottom: 1px solid var(--border);
}
.tiles { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.tile {
  padding: 12px 16px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-2);
  border-left-width: 4px;
}
.tile-label { text-transform: uppercase; font-size: 10px; color: var(--text-dim); letter-spacing: 0.6px; }
.tile-value { font-size: 22px; font-weight: 600; margin: 4px 0; color: var(--text-bright); text-transform: uppercase; letter-spacing: 0.5px; }
.tile-sub { font-size: 11px; color: var(--text-dim); }
.tile-disp.disp-benign { border-left-color: var(--good); }
.tile-disp.disp-inconclusive { border-left-color: var(--warn); }
.tile-disp.disp-malicious { border-left-color: var(--bad); }
.tile-out.out-caught { border-left-color: var(--good); }
.tile-out.out-survived { border-left-color: var(--bad); }
.tile-out.out-undecidable { border-left-color: var(--warn); }
.tile-out.out-incoherent { border-left-color: var(--bad); }
.tile-out.out-skip-passthrough { border-left-color: var(--text-dim); }

.headline-body {
  padding: 12px 16px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-2);
  margin-top: 12px;
}
.hb-label { text-transform: uppercase; font-size: 10px; color: var(--text-dim); letter-spacing: 0.6px; margin-bottom: 8px; }
.hb-text { white-space: pre-wrap; color: var(--text); font-size: 13px; line-height: 1.6; }

/* ----- Layout ----- */
.layout {
  display: grid;
  grid-template-columns: 240px 1fr;
  align-items: start;
}
nav.toc {
  position: sticky;
  top: 84px;
  align-self: start;
  height: calc(100vh - 84px);
  overflow-y: auto;
  padding: 16px 12px 24px 20px;
  border-right: 1px solid var(--border);
  background: var(--bg);
}
nav.toc ul { list-style: none; padding: 0; margin: 0; }
nav.toc li.section {
  margin: 14px 0 4px;
  text-transform: uppercase;
  font-size: 10px;
  color: var(--text-dim);
  letter-spacing: 0.6px;
  font-weight: 600;
}
nav.toc li.section:first-child { margin-top: 0; }
nav.toc li.item a {
  display: block;
  padding: 3px 0 3px 12px;
  color: var(--text);
  text-decoration: none;
  font-size: 12px;
  border-left: 2px solid transparent;
  margin-left: 2px;
}
nav.toc li.item a:hover { color: var(--text-bright); border-left-color: var(--accent); background: var(--bg-2); }
nav.toc li.item.muted { padding: 3px 0 3px 14px; color: var(--text-dim); font-size: 11px; font-style: italic; }

article.content {
  padding: 24px 32px 80px;
  max-width: 1200px;
  min-width: 0;
}

/* ----- Stages ----- */
section.stage {
  margin-bottom: 32px;
  padding: 16px 18px;
  border: 1px solid var(--border);
  border-left-width: 4px;
  border-radius: 6px;
  background: var(--bg-2);
  scroll-margin-top: 96px;
}
section.stage h2 {
  margin: 0 0 4px;
  font-size: 17px;
  font-weight: 600;
  color: var(--text-bright);
}
section.stage h2 .stage-sub {
  font-size: 12px;
  font-weight: 400;
  color: var(--text-dim);
  margin-left: 6px;
}
section.stage h3 {
  margin: 18px 0 8px;
  font-size: 12px;
  text-transform: uppercase;
  color: var(--text-dim);
  letter-spacing: 0.6px;
  border-bottom: 1px solid var(--border-2);
  padding-bottom: 4px;
  scroll-margin-top: 96px;
}
section.stage .stage-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 8px; }
section.stage-alert { border-left-color: var(--accent-alert); }
section.stage-defender { border-left-color: var(--accent-defender); }
section.stage-actor { border-left-color: var(--accent-actor); }
section.stage-judge { border-left-color: var(--accent-judge); }
section.stage-oracle { border-left-color: var(--accent-oracle); }
section.stage-raw { border-left-color: var(--accent-raw); }

/* ----- Report card ----- */
.report-card {
  background: var(--bg-3);
  border: 1px solid var(--border-2);
  border-radius: 5px;
  padding: 12px 14px;
  margin: 6px 0 12px;
}
.report-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 8px; font-family: 'SF Mono', Menlo, Consolas, monospace; }
.report-meta .rm-key { text-transform: uppercase; letter-spacing: 0.4px; }
.report-meta .rm-val { color: var(--text-bright); font-weight: 500; padding: 0 4px; }
.report-meta .rm-val.disp-benign { color: var(--good); }
.report-meta .rm-val.disp-inconclusive { color: var(--warn); }
.report-meta .rm-val.disp-malicious { color: var(--bad); }
.report-body { white-space: pre-wrap; line-height: 1.6; }

/* ----- Compact lead list ----- */
.lead-list { display: flex; flex-direction: column; gap: 8px; }
.lead-row {
  display: grid;
  grid-template-columns: 48px 1fr;
  gap: 12px;
  padding: 8px 10px;
  background: var(--bg-3);
  border: 1px solid var(--border-2);
  border-radius: 4px;
}
.lead-pos {
  font-family: 'SF Mono', Menlo, Consolas, monospace;
  color: var(--text-dim);
  font-size: 12px;
  font-weight: 600;
}
.lead-goal { color: var(--text); margin-bottom: 4px; }
.lead-query { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px; line-height: 1.5; }
.lead-query .qid { color: var(--code); }
.lead-query .qparams { color: var(--text-dim); margin-left: 6px; }

/* ----- Actor ----- */
.actor-meta { font-size: 12px; color: var(--text-dim); margin: 4px 0 8px; }
.actor-meta .key { text-transform: uppercase; letter-spacing: 0.4px; }
.actor-meta .val { color: var(--text-bright); margin-left: 4px; font-family: 'SF Mono', Menlo, Consolas, monospace; }
pre.story { background: var(--bg-3); }

/* ----- Judge outcome ----- */
.judge-outcome {
  padding: 12px 14px;
  border-radius: 5px;
  background: var(--bg-3);
  border: 1px solid var(--border-2);
  border-left: 4px solid var(--border);
  margin: 6px 0 12px;
}
.judge-outcome.out-caught { border-left-color: var(--good); }
.judge-outcome.out-survived { border-left-color: var(--bad); }
.judge-outcome.out-undecidable { border-left-color: var(--warn); }
.judge-outcome.out-incoherent { border-left-color: var(--bad); }
.judge-outcome.out-skip-passthrough { border-left-color: var(--text-dim); }
.outcome-value {
  font-size: 16px;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--text-bright);
  margin-bottom: 6px;
  letter-spacing: 0.4px;
}
.outcome-rationale { white-space: pre-wrap; line-height: 1.55; }

/* ----- Findings ----- */
.findings-grid { display: flex; flex-direction: column; gap: 12px; margin: 8px 0; }
.finding-card {
  background: var(--bg-3);
  border: 1px solid var(--border-2);
  border-left: 4px solid var(--border);
  border-radius: 5px;
  padding: 12px 14px;
  scroll-margin-top: 96px;
}
.finding-detection-confirmed { border-left-color: var(--good); }
.finding-observability { border-left-color: var(--warn); }
.finding-lead-set { border-left-color: var(--accent); }
.finding-head {
  display: grid;
  grid-template-columns: 180px 1fr 200px;
  gap: 12px;
  padding-bottom: 8px;
  margin-bottom: 8px;
  border-bottom: 1px solid var(--border-2);
  align-items: baseline;
}
.finding-head .ftype { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px; color: var(--code); }
.finding-detection-confirmed .ftype { color: var(--good); }
.finding-observability .ftype { color: var(--warn); }
.finding-lead-set .ftype { color: var(--accent); }
.finding-head .ftopic { color: var(--text-bright); font-weight: 500; font-size: 13px; }
.finding-head .fanchor { font-family: 'SF Mono', Menlo, Consolas, monospace; color: var(--text-dim); font-size: 11px; text-align: right; }
.finding-body { white-space: pre-wrap; line-height: 1.6; color: var(--text); }
.citations { margin-top: 10px; display: flex; flex-direction: column; gap: 6px; }
.citation {
  background: var(--bg-4);
  border: 1px solid var(--border-2);
  border-left: 3px solid var(--text-dim);
  border-radius: 3px;
  padding: 8px 10px;
}
.citation .cite-src {
  font-size: 10px;
  text-transform: uppercase;
  color: var(--text-dim);
  letter-spacing: 0.5px;
  margin-bottom: 4px;
  font-family: 'SF Mono', Menlo, Consolas, monospace;
}
.citation pre { margin: 0; background: transparent; border: none; padding: 0; }
.citation.citation-investigation { border-left-color: var(--accent-defender); }
.citation.citation-actor { border-left-color: var(--accent-actor); }
.citation.citation-projected_telemetry { border-left-color: var(--accent-oracle); }

pre.encounter { background: var(--bg-3); line-height: 1.55; }
pre.invlang { background: var(--bg-3); }

/* ----- Footer ----- */
footer.footer {
  border-top: 1px solid var(--border);
  padding: 24px 32px 80px;
  background: var(--bg-3);
  color: var(--text);
  margin-left: 240px;
}
footer.footer h2 { font-size: 12px; text-transform: uppercase; color: var(--text-dim); margin: 0 0 8px; letter-spacing: 0.6px; }
footer.footer .footer-caveat { font-size: 12px; color: var(--text-dim); margin-bottom: 12px; max-width: 760px; line-height: 1.5; }

/* ----- Collapsibles ----- */
details.block { margin: 4px 0; }
details.block > summary {
  cursor: pointer;
  padding: 4px 8px;
  font-weight: 500;
  user-select: none;
  border-radius: 3px;
  color: var(--text);
  list-style: revert;
}
details.block > summary:hover { background: var(--bg-3); color: var(--text-bright); }
details.block > .body { padding: 6px 0 6px 14px; }

details.block.phase > summary {
  background: var(--bg-3);
  border-left: 3px solid var(--accent-defender);
  padding: 6px 10px;
  font-weight: 600;
  color: var(--text-bright);
}

details.block.subcall > summary { background: var(--bg-3); border-left: 3px solid var(--border); padding-left: 10px; }
details.block.subcall.gather > summary { border-left-color: var(--accent-learning); }

details.block.lesson-commit > summary { color: var(--text-bright); font-weight: 500; }
.commit-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 4px; font-family: 'SF Mono', Menlo, Consolas, monospace; }

/* ----- Code ----- */
pre {
  background: var(--bg);
  border: 1px solid var(--border-2);
  border-radius: 4px;
  padding: 8px 12px;
  margin: 4px 0;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font: 12px/1.5 'SF Mono', Menlo, Consolas, monospace;
}
pre.json { color: var(--code); }
pre.text { color: var(--text); }
pre.files { font-size: 11px; color: var(--text-dim); }
.text-block { padding: 4px 0; white-space: pre-wrap; }

.empty { font-size: 11px; color: var(--text-dim); padding: 6px 0; font-style: italic; }
"""


# ---------------------------------------------------------------------------
# Page renderers
# ---------------------------------------------------------------------------


def _stats(events: list[dict]) -> tuple[int, int, float]:
    n_events = len(events)
    cost = sum(e.get("total_cost_usd") or 0 for e in events if e.get("type") == "result")
    n_tool_calls = sum(
        1
        for e in events
        if e.get("type") == "assistant"
        for blk in (e.get("message") or {}).get("content", [])
        if isinstance(blk, dict) and blk.get("type") == "tool_use"
    )
    return n_events, n_tool_calls, cost


def render_judge_page(run_dir: Path) -> str:
    case_id = run_dir.name
    events = load_jsonl(run_dir / "tool_trace.jsonl")
    n_events, n_tool_calls, cost = _stats(events)
    judge = load_judge_findings(case_id)
    n_findings = len((judge or {}).get("defender_findings") or []) if judge else 0

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>judge eval — {esc(case_id)}</title>
<style>{CSS}</style></head><body id="top">
{render_header(case_id, n_events, n_tool_calls, cost, run_dir, active="judge")}
{render_judge_headline(run_dir, judge)}
<div class="layout">
  {render_judge_toc(n_findings)}
  <article class="content">
    {render_alert_block(run_dir, open_=True)}
    {render_judge_defender_summary(run_dir)}
    {render_judge_actor_section(case_id)}
    {render_judge_judge_section(judge)}
    {render_judge_oracle_section(case_id)}
    {render_judge_raw_bundle(case_id)}
  </article>
</div>
</body></html>
"""


def render_runtime_page(run_dir: Path) -> str:
    case_id = run_dir.name
    events = load_jsonl(run_dir / "tool_trace.jsonl")
    n_events, n_tool_calls, cost = _stats(events)
    investigation_html, phases = render_runtime_investigation(run_dir)
    gather_html, n_gather = render_runtime_gather(run_dir, events)

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>runtime — {esc(case_id)}</title>
<style>{CSS}</style></head><body id="top">
{render_header(case_id, n_events, n_tool_calls, cost, run_dir, active="runtime")}
{render_runtime_headline(run_dir)}
<div class="layout">
  {render_runtime_toc(phases, n_gather)}
  <article class="content">
    {render_alert_block(run_dir, open_=False)}
    {investigation_html}
    {gather_html}
    {render_runtime_lead_sequence(run_dir)}
    {render_runtime_report(run_dir)}
    {render_runtime_raw(events)}
  </article>
</div>
{render_footer(run_dir, case_id)}
</body></html>
"""


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: visualize_run.py <run_dir>", file=sys.stderr)
        return 64
    run_dir = Path(argv[1]).resolve()
    if not run_dir.is_dir():
        print(f"not a directory: {run_dir}", file=sys.stderr)
        return 1
    judge_out = run_dir / JUDGE_FILENAME
    runtime_out = run_dir / RUNTIME_FILENAME
    judge_out.write_text(render_judge_page(run_dir))
    runtime_out.write_text(render_runtime_page(run_dir))
    print(f"wrote {judge_out}")
    print(f"wrote {runtime_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
