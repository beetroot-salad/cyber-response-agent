"""Judge view sections (transcript.html).

The judge view answers "did the learning loop's judgment hold up?" —
report.md + compact lead list (the judge's *input*), then the actor's
adversarial story, then the judge's outcome + findings + encounter
analysis. Oracle and raw artifacts collapse below the fold.
"""
from __future__ import annotations

from pathlib import Path

from visualize_primitives import (  # noqa: F401 — load_yaml kept for API parity
    _learning_run_dir,
    block,
    esc,
    lead_repository,
    load_yaml,
    pre_text,
    render_lead_sequence_compact,
    render_report_card,
)


# ---------------------------------------------------------------------------
# Judge finding card
# ---------------------------------------------------------------------------


def render_judge_finding(idx: int, f: dict, anchor_prefix: str = "finding") -> str:
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
        f'<div class="finding-card finding-{esc(ftype)}" id="{esc(anchor_prefix)}-{idx}">'
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
# Sections
# ---------------------------------------------------------------------------


def _lead_count(run_dir: Path) -> int:
    return len(lead_repository.joined(run_dir))


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


def render_judge_actor_section(run_id: str) -> str:
    learn_dir = _learning_run_dir(run_id)
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
    learn_dir = _learning_run_dir(run_id)
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


# ---------------------------------------------------------------------------
# Benign (FP-direction) sections — mirror the adversarial trio above, but
# self-gate to "" when the *_benign artifacts are absent so adversarial-only
# runs render unchanged. Shown for runs whose disposition triggers the benign
# direction (malicious → benign-only; inconclusive → both directions).
# ---------------------------------------------------------------------------


def render_env_observation(idx: int, o: dict) -> str:
    fact = str(o.get("fact", "")).strip()
    criteria = str(o.get("relevance_criteria", "")).strip()
    rule_ids = o.get("alert_rule_ids") or []
    rule_str = ", ".join(str(r) for r in rule_ids) if isinstance(rule_ids, list) else str(rule_ids)
    entities = o.get("entities") or []
    ent_rows = ""
    if isinstance(entities, list) and entities:
        sels = [
            f'{esc(str(s.get("type", "?")))}/{esc(str(s.get("class", "?")))}'
            for s in entities if isinstance(s, dict)
        ]
        ent_rows = f'<div class="env-obs-ents">entities: {" · ".join(sels)}</div>'
    return (
        f'<div class="finding-card env-obs" id="env-obs-{idx}">'
        f'<div class="finding-head">'
        f'<span class="ftype">environment fact</span>'
        f'<span class="fanchor">{esc(rule_str)}</span>'
        f'</div>'
        f'<div class="finding-body">{esc(fact)}</div>'
        f'<div class="env-obs-crit"><span class="key">relevance:</span> {esc(criteria)}</div>'
        f'{ent_rows}'
        f'</div>'
    )


def render_judge_actor_benign_section(run_id: str) -> str:
    learn_dir = _learning_run_dir(run_id)
    story = learn_dir / "actor_benign_story.md"
    if not story.is_file():
        return ""
    story_html = f'<pre class="text story">{esc(story.read_text())}</pre>'
    return f"""
<section id="sec-actor-benign" class="stage stage-actor">
  <h2>§ Actor (benign) <span class="stage-sub">— routine-operation counterfactual</span></h2>
  <h3>actor_benign_story.md</h3>
  {story_html}
</section>
"""


def render_judge_benign_section(judge: dict | None) -> str:
    if not judge:
        return ""
    outcome = str(judge.get("outcome", "?"))
    rationale = str(judge.get("outcome_rationale", "")).strip()
    encounter = str(judge.get("encounter_analysis", "")).strip()
    findings = judge.get("defender_findings") or []
    env_obs = judge.get("environment_observations") or []

    if isinstance(findings, list) and findings:
        cards = "\n".join(
            render_judge_finding(i, f, anchor_prefix="benign-finding")
            for i, f in enumerate(findings) if isinstance(f, dict)
        )
    else:
        cards = '<div class="empty">judge emitted no findings</div>'

    if isinstance(env_obs, list) and env_obs:
        env_cards = "\n".join(
            render_env_observation(i, o) for i, o in enumerate(env_obs) if isinstance(o, dict)
        )
    else:
        env_cards = '<div class="empty">no environment observations queued</div>'

    encounter_html = (
        f'<pre class="text encounter">{esc(encounter)}</pre>'
        if encounter
        else '<div class="empty">no encounter_analysis</div>'
    )

    return f"""
<section id="sec-judge-benign" class="stage stage-judge">
  <h2>§ Judge (benign) <span class="stage-sub">— FP-direction outcome + findings</span></h2>

  <h3 id="sec-judge-benign-outcome">Outcome</h3>
  <div class="judge-outcome out-{esc(outcome)}">
    <div class="outcome-value">{esc(outcome)}</div>
    <div class="outcome-rationale">{esc(rationale)}</div>
  </div>

  <h3 id="sec-judge-benign-findings">Findings ({len(findings) if isinstance(findings, list) else 0})</h3>
  <div class="findings-grid">{cards}</div>

  <h3 id="sec-judge-benign-env">Environment observations ({len(env_obs) if isinstance(env_obs, list) else 0})</h3>
  <div class="findings-grid">{env_cards}</div>

  <h3 id="sec-judge-benign-encounter">Encounter analysis</h3>
  {encounter_html}
</section>
"""


def render_judge_oracle_benign_section(run_id: str) -> str:
    learn_dir = _learning_run_dir(run_id)
    proj = learn_dir / "projected_telemetry_benign.yaml"
    proj_raw = learn_dir / "projected_telemetry_benign.raw.txt"
    inner = ""
    if proj.is_file():
        inner += block("oracle-yaml", "projected_telemetry_benign.yaml", pre_text(proj.read_text()))
    if proj_raw.is_file():
        inner += block("oracle-raw", "projected_telemetry_benign.raw.txt (raw fallback)", pre_text(proj_raw.read_text()))
    if not inner:
        return ""
    return f"""
<section id="sec-oracle-benign" class="stage stage-oracle">
  <h2>§ Oracle (benign) <span class="stage-sub">— projected telemetry, FP direction (collapsed by default)</span></h2>
  {inner}
</section>
"""


def render_judge_raw_bundle(run_id: str) -> str:
    learn_dir = _learning_run_dir(run_id)
    if not learn_dir.is_dir():
        return ""
    panels: list[str] = []
    for fname in ("actor_input.yaml", "source_refs.yaml", "executed_queries.jsonl", "alert.json"):
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


def render_judge_toc(n_findings: int, n_benign_findings: int | None = None) -> str:
    finding_links = "".join(
        f'<li class="item"><a href="#finding-{i}">finding #{i}</a></li>'
        for i in range(n_findings)
    )
    if n_findings == 0:
        finding_links = '<li class="item muted">(none)</li>'

    # Benign block only when the FP direction ran (n_benign_findings is not None).
    benign_block = ""
    if n_benign_findings is not None:
        benign_finding_links = "".join(
            f'<li class="item"><a href="#benign-finding-{i}">finding #{i}</a></li>'
            for i in range(n_benign_findings)
        )
        if n_benign_findings == 0:
            benign_finding_links = '<li class="item muted">(none)</li>'
        benign_block = f"""
    <li class="section">§ Actor (benign)</li>
    <li class="item"><a href="#sec-actor-benign">routine-op story</a></li>

    <li class="section">§ Judge (benign)</li>
    <li class="item"><a href="#sec-judge-benign-outcome">outcome</a></li>
    <li class="item"><a href="#sec-judge-benign-findings">findings</a></li>
    {benign_finding_links}
    <li class="item"><a href="#sec-judge-benign-env">environment observations</a></li>
    <li class="item"><a href="#sec-judge-benign-encounter">encounter analysis</a></li>

    <li class="section">§ Oracle (benign)</li>
    <li class="item"><a href="#sec-oracle-benign">projected telemetry</a></li>
"""

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
    {benign_block}
    <li class="section">§ Raw bundle</li>
    <li class="item"><a href="#sec-raw-bundle">inputs &amp; fallbacks</a></li>
  </ul>
</nav>
"""
