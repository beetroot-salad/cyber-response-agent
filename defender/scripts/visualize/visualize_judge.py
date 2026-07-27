from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from defender.learning.core.directions import (
    ADVERSARIAL,
    BENIGN,
    Direction,
    directions_for,
    normalized_disposition,
    raw_fallback_name,
)
from defender.scripts.visualize.visualize_primitives import (
    _learning_run_dir,
    block,
    esc,
    lead_repository,
    pre_text,
    render_lead_sequence_compact,
    render_report_card,
    section,
)


# The direction that owns the page's unsuffixed ids — `#sec-judge`, `#finding-0`. It is the
# one that predates the second direction, so it kept the anchors the page already emitted;
# every other direction namespaces its ids by name.
UNSUFFIXED_DIRECTION = ADVERSARIAL.name


@dataclass(frozen=True)
class DirectionView:
    """How one `Direction` presents on the judge page. Neither the artifact NAMES nor the
    anchor ids are written out here — the names come off `direction`, the ids off `anchor()`
    — so the loop's declaration and the view cannot drift (#716) and a third direction
    cannot typo its way into an id collision. What lives here is prose: titles and
    subtitles."""

    direction: Direction
    actor_subtitle: str
    judge_subtitle: str
    oracle_subtitle: str
    actor_toc_label: str

    @property
    def suffix(self) -> str:
        return "" if self.direction.name == UNSUFFIXED_DIRECTION else f"-{self.direction.name}"

    @property
    def label(self) -> str:
        """`""` | `" (benign)"` → `Actor{label}` in headings."""
        return f" ({self.direction.name})" if self.suffix else ""

    def anchor(self, base: str) -> str:
        """ONE mechanism for every per-direction id on the page — section ids, finding cards
        and env-obs cards alike are `{base}{suffix}`. Findings used to prefix the direction
        name while env observations suffixed it, which put `benign-finding-0` next to
        `env-obs-benign-0` on the same page (#716)."""
        return f"{base}{self.suffix}"


ADVERSARIAL_VIEW = DirectionView(
    direction=ADVERSARIAL,
    actor_subtitle="— adversarial counterfactual",
    judge_subtitle="— outcome + findings",
    oracle_subtitle="— projected telemetry (collapsed by default)",
    actor_toc_label="archetype + story",
)

BENIGN_VIEW = DirectionView(
    direction=BENIGN,
    actor_subtitle="— routine-operation counterfactual",
    judge_subtitle="— FP-direction outcome + findings",
    oracle_subtitle="— projected telemetry, FP direction (collapsed by default)",
    actor_toc_label="routine-op story",
)

VIEWS: tuple[DirectionView, ...] = (ADVERSARIAL_VIEW, BENIGN_VIEW)


def _left_artifacts(run_id: str, direction: Direction) -> bool:
    learn_dir = _learning_run_dir(run_id)
    return any((learn_dir / name).is_file() for name in direction.artifact_names())


def active_views(run_id: str, disposition: str) -> tuple[DirectionView, ...]:
    """The direction sections this page renders: the ones this run's disposition selected,
    PLUS any that left artifacts on disk.

    Selection runs through the same `directions_for` the loop dispatches on, so the two
    cannot disagree (including on a disposition carrying a zero-width character, #722). A
    direction the disposition never selected is OMITTED rather than rendered as "the loop did
    not run or aborted", which is what the page used to claim of the adversarial direction on
    every `malicious` run (#716).

    Presence is the other half of the rule, because `report.md` is mutable while the learning
    run dir accumulates: a run learned under `inconclusive` (both legs ran) whose disposition
    is later corrected to `malicious` still holds the adversarial story, judge doc and
    findings. Selection alone would drop them from the page while the Raw bundle's `*.raw.txt`
    glob went on showing that leg — the page contradicting itself. Present beats selected.

    An unreadable or unrecognized disposition (no `report.md`, bad frontmatter) selects
    ALL directions: with nothing to gate on, showing every section with its
    missing-artifact placeholder is the honest fallback."""
    if not normalized_disposition(disposition):
        return VIEWS
    selected = {d.name for d in directions_for(disposition)}
    return tuple(
        v for v in VIEWS
        if v.direction.name in selected or _left_artifacts(run_id, v.direction)
    )


def judge_finding_count(judge: dict) -> int:
    """How many finding cards `render_judge_judge_section` will emit for this doc — the ONE
    place the `defender_findings`-is-a-list guard lives, so the TOC and the headline can
    never count anchors the section does not emit (or blow up on a scalar)."""
    findings = judge.get("defender_findings") or []
    return len(findings) if isinstance(findings, list) else 0




def render_judge_finding(idx: int, f: dict, anchor_prefix: str) -> str:
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




def _lead_count(run_dir: Path) -> int:
    return len(lead_repository.joined(run_dir))


def render_judge_defender_summary(run_dir: Path) -> str:
    body = f"""<h3>report.md</h3>
  {render_report_card(run_dir)}

  <h3>lead sequence ({_lead_count(run_dir)} lead(s))</h3>
  {render_lead_sequence_compact(run_dir)}"""
    return section("sec-defender-summary", "defender", "Defender summary", "— what the judge graded", body)


def render_judge_actor_section(run_id: str, view: DirectionView) -> str:
    learn_dir = _learning_run_dir(run_id)
    story_name = view.direction.story_name
    story = learn_dir / story_name
    anchor, title = view.anchor("sec-actor"), f"Actor{view.label}"

    if not story.is_file():
        return section(
            anchor, "actor", title, view.actor_subtitle,
            f'<div class="empty">no {esc(story_name)}</div>',
        )

    meta_html = ""
    if view.direction.archetype_name is not None:
        archetype = learn_dir / view.direction.archetype_name
        arch = archetype.read_text(encoding="utf-8").strip() if archetype.is_file() else "?"
        meta_html = (
            f'<div class="actor-meta"><span class="key">archetype:</span> '
            f'<span class="val">{esc(arch)}</span></div>'
        )

    menu_block = ""
    if view.direction.menu_name is not None:
        menu = learn_dir / view.direction.menu_name
        menu_txt = menu.read_text(encoding="utf-8").strip() if menu.is_file() else ""
        if menu_txt:
            menu_block = block("actor-menu", "MITRE technique menu (sampled)", pre_text(menu_txt))

    story_html = f'<pre class="text story">{esc(story.read_text(encoding="utf-8"))}</pre>'

    body = f"""{meta_html}
  {menu_block}
  <h3>{esc(story_name)}</h3>
  {story_html}"""
    return section(anchor, "actor", title, view.actor_subtitle, body)


def render_judge_judge_section(judge: dict | None, view: DirectionView) -> str:
    anchor, title = view.anchor("sec-judge"), f"Judge{view.label}"
    if not judge:
        return section(
            anchor, "judge", title, view.judge_subtitle,
            f'<div class="empty">no {esc(view.direction.judge_name)} — '
            f'learning loop did not run or aborted</div>',
        )
    outcome = str(judge.get("outcome", "?"))
    rationale = str(judge.get("outcome_rationale", "")).strip()
    encounter = str(judge.get("encounter_analysis", "")).strip()
    findings = judge.get("defender_findings") or []
    # Both judge docs may carry `environment_observations` — `validate_judge_doc` accepts it
    # on the adversarial doc too, and judge/malicious.md asks for it. The view used to render
    # it for the benign direction only, silently dropping the adversarial ones (#716).
    env_obs = judge.get("environment_observations") or []

    if isinstance(findings, list) and findings:
        cards = "\n".join(
            render_judge_finding(i, f, anchor_prefix=view.anchor("finding"))
            for i, f in enumerate(findings) if isinstance(f, dict)
        )
    else:
        cards = '<div class="empty">judge emitted no findings</div>'

    if isinstance(env_obs, list) and env_obs:
        env_cards = "\n".join(
            render_env_observation(i, o, anchor_prefix=view.anchor("env-obs"))
            for i, o in enumerate(env_obs) if isinstance(o, dict)
        )
    else:
        env_cards = '<div class="empty">no environment observations queued</div>'

    encounter_html = (
        f'<pre class="text encounter">{esc(encounter)}</pre>'
        if encounter
        else '<div class="empty">no encounter_analysis</div>'
    )

    body = f"""<h3 id="{anchor}-outcome">Outcome</h3>
  <div class="judge-outcome out-{esc(outcome)}">
    <div class="outcome-value">{esc(outcome)}</div>
    <div class="outcome-rationale">{esc(rationale)}</div>
  </div>

  <h3 id="{anchor}-findings">Findings ({judge_finding_count(judge)})</h3>
  <div class="findings-grid">{cards}</div>

  <h3 id="{anchor}-env">Environment observations ({len(env_obs) if isinstance(env_obs, list) else 0})</h3>
  <div class="findings-grid">{env_cards}</div>

  <h3 id="{anchor}-encounter">Encounter analysis</h3>
  {encounter_html}"""
    return section(anchor, "judge", title, view.judge_subtitle, body)


def render_judge_oracle_section(run_id: str, view: DirectionView) -> str:
    learn_dir = _learning_run_dir(run_id)
    proj_name = view.direction.telemetry_name
    raw_name = raw_fallback_name(proj_name)
    proj = learn_dir / proj_name
    proj_raw = learn_dir / raw_name
    inner = ""
    if proj.is_file():
        inner += block("oracle-yaml", proj_name, pre_text(proj.read_text(encoding="utf-8")))
    if proj_raw.is_file():
        inner += block("oracle-raw", f"{raw_name} (raw fallback)", pre_text(proj_raw.read_text(encoding="utf-8")))
    if not inner:
        inner = '<div class="empty">no oracle artifacts</div>'
    return section(
        view.anchor("sec-oracle"), "oracle", f"Oracle{view.label}", view.oracle_subtitle, inner,
    )




def render_env_observation(idx: int, o: dict, anchor_prefix: str) -> str:
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
        f'<div class="finding-card env-obs" id="{esc(anchor_prefix)}-{idx}">'
        f'<div class="finding-head">'
        f'<span class="ftype">environment fact</span>'
        f'<span class="fanchor">{esc(rule_str)}</span>'
        f'</div>'
        f'<div class="finding-body">{esc(fact)}</div>'
        f'<div class="env-obs-crit"><span class="key">relevance:</span> {esc(criteria)}</div>'
        f'{ent_rows}'
        f'</div>'
    )



def render_judge_raw_bundle(run_id: str) -> str:
    learn_dir = _learning_run_dir(run_id)
    if not learn_dir.is_dir():
        return ""
    panels: list[str] = []
    for fname in ("actor_input.yaml", "source_refs.yaml", "executed_queries.jsonl", "alert.json"):
        p = learn_dir / fname
        if p.is_file():
            panels.append(block("artifact", fname, pre_text(p.read_text(encoding="utf-8"))))
    for raw in sorted(learn_dir.glob("*.raw.txt")):
        panels.append(block("artifact raw", raw.name, pre_text(raw.read_text(encoding="utf-8"))))
    trace = learn_dir / "actor_trace.jsonl"
    if trace.is_file():
        panels.append(block("artifact", "actor_trace.jsonl", pre_text(trace.read_text(encoding="utf-8"))))
    if not panels:
        return ""
    return section("sec-raw-bundle", "raw", "Raw bundle", "— learning-loop inputs &amp; fallbacks", "".join(panels))


def _toc_judge_links(view: DirectionView, n_findings: int | None) -> str:
    judge_anchor = view.anchor("sec-judge")
    if n_findings is None:
        # The direction was selected but its judge doc is missing: the section renders as a
        # placeholder and carries no sub-anchors, so linking them would be four dead links.
        return f'<li class="item muted"><a href="#{judge_anchor}">(no findings)</a></li>'
    finding_links = "".join(
        f'<li class="item"><a href="#{view.anchor("finding")}-{i}">finding #{i}</a></li>'
        for i in range(n_findings)
    )
    if n_findings == 0:
        finding_links = '<li class="item muted">(none)</li>'
    return f"""<li class="item"><a href="#{judge_anchor}-outcome">outcome</a></li>
    <li class="item"><a href="#{judge_anchor}-findings">findings</a></li>
    {finding_links}
    <li class="item"><a href="#{judge_anchor}-env">environment observations</a></li>
    <li class="item"><a href="#{judge_anchor}-encounter">encounter analysis</a></li>"""


def _toc_direction_block(view: DirectionView, n_findings: int | None) -> str:
    return f"""
    <li class="section">Actor{view.label}</li>
    <li class="item"><a href="#{view.anchor("sec-actor")}">{view.actor_toc_label}</a></li>

    <li class="section">Judge{view.label}</li>
    {_toc_judge_links(view, n_findings)}

    <li class="section">Oracle{view.label}</li>
    <li class="item"><a href="#{view.anchor("sec-oracle")}">projected telemetry</a></li>
"""


def render_judge_toc(sections: list[tuple[DirectionView, int | None]]) -> str:
    """`sections` is one (view, finding count) per direction the page actually rendered —
    so the TOC never links a section the disposition did not select. A `None` count means
    the direction was selected but produced no judge doc (#716)."""
    direction_blocks = "".join(_toc_direction_block(v, n) for v, n in sections)
    return f"""
<nav class="toc">
  <ul>
    <li class="section">Headline</li>
    <li class="item"><a href="#top">summary tiles</a></li>

    <li class="section">Alert</li>
    <li class="item"><a href="#sec-alert">alert.json</a></li>

    <li class="section">Defender summary</li>
    <li class="item"><a href="#sec-defender-summary">report + leads</a></li>
    {direction_blocks}
    <li class="section">Raw bundle</li>
    <li class="item"><a href="#sec-raw-bundle">inputs &amp; fallbacks</a></li>
  </ul>
</nav>
"""
