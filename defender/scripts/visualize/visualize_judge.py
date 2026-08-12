from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from defender._run_paths import WIRE_LOG_DIR
from defender._vocab import normalized_disposition
from defender.learning.core.directions import (
    ADVERSARIAL,
    BENIGN,
    Direction,
    directions_for,
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


#: The actor stage's trace, named once for the two locations this page looks in.
ACTOR_TRACE = "actor_trace.jsonl"

# The leg's own terminal status (#791 R2/R15) — the one place a run dir written before the
# field existed reads as its stated default rather than as a leg that never ran.
LEG_COMPLETED = "completed"
LEG_NEVER_SELECTED = "never-selected"
LEG_STARTED_AND_DIED = "started-and-died"
LEG_UNRECORDED = "unrecorded"


def leg_status(run_id: str, direction: Direction) -> str:
    """The status FILE is authoritative when it exists — it is written before the leg's
    first call, so a leg that dies before its own story write still reads as
    started-and-died rather than never-selected. Only a run dir with no status file at all
    falls back to story presence: never-selected (no story either) or unrecorded (a story
    from before the field existed, R15's stated default)."""
    learn_dir = _learning_run_dir(run_id)
    status_file = learn_dir / direction.status_name
    if status_file.is_file():
        return (
            LEG_COMPLETED
            if status_file.read_text(encoding="utf-8").strip() == "completed"
            else LEG_STARTED_AND_DIED
        )
    story = learn_dir / direction.story_name
    return LEG_UNRECORDED if story.is_file() else LEG_NEVER_SELECTED


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


@dataclass(frozen=True)
class CardGroup:
    """One `<h3>` + card grid inside the Judge section, driven off the judge-doc key it
    renders. The section, the heading count and the TOC all read this table, so a group
    cannot appear on the page without its TOC link or vice versa (#748)."""

    key: str
    # `#sec-judge{suffix}-{sub}` — the sub-anchor the TOC links; `anchor_base` is the per-card
    # id, namespaced per direction by `DirectionView.anchor`.
    sub: str
    anchor_base: str
    heading: str
    empty: str
    render: Callable[..., str]

    def toc_label(self) -> str:
        return self.heading.lower()


ADVERSARIAL_VIEW = DirectionView(
    direction=ADVERSARIAL,
    actor_subtitle="— adversarial counterfactual",
    judge_subtitle="— outcome + findings",
    actor_toc_label="archetype + story",
)

BENIGN_VIEW = DirectionView(
    direction=BENIGN,
    actor_subtitle="— routine-operation counterfactual",
    judge_subtitle="— FP-direction outcome + findings",
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
    if normalized_disposition(disposition) is None:
        return VIEWS
    selected = {d.name for d in directions_for(disposition)}
    return tuple(
        v for v in VIEWS
        if v.direction.name in selected or _left_artifacts(run_id, v.direction)
    )


def _card_items(judge: dict, key: str) -> list[dict]:
    """The mappings a card group under `key` will render, and nothing else — the ONE place
    the is-it-a-list-of-mappings guard lives for findings and both observation groups. A
    heading count, a TOC link and a card all read this, so none of them can claim an anchor
    the section does not emit (or blow up on a scalar)."""
    value = judge.get(key) or []
    if not isinstance(value, list):
        return []
    return [o for o in value if isinstance(o, dict)]


def judge_finding_count(judge: dict) -> int:
    """How many finding cards `render_judge_judge_section` will emit for this doc — read by
    the TOC and the headline tile."""
    return len(_card_items(judge, "defender_findings"))




def _render_subject_card(
    idx: int, o: dict, anchor_prefix: str, *, body_key: str, type_prefix: str,
) -> str:
    """The card shape shared by judge findings and actor observations: the same
    `type` / `subject_topic` / `subject_anchor` head over one prose body, plus the citation
    rows when the mapping carries any — only findings do, so no flag is needed to tell the
    two apart. Written ONCE because `actor_observations` would otherwise have arrived as a
    third near-twin of this markup (#748); environment observations are the second and stay
    separate, their head and body genuinely differ."""
    otype = str(o.get("type", "?"))
    topic = str(o.get("subject_topic", ""))
    anchor = str(o.get("subject_anchor", ""))
    body_text = str(o.get(body_key, "")).strip()
    citations = o.get("citations") or []

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
        f'<div class="finding-card {esc(type_prefix)}-{esc(otype)}" id="{esc(anchor_prefix)}-{idx}">'
        f'<div class="finding-head">'
        f'<span class="ftype">{esc(otype)}</span>'
        f'<span class="ftopic">{esc(topic)}</span>'
        f'<span class="fanchor">{esc(anchor)}</span>'
        f'</div>'
        f'<div class="finding-body">{esc(body_text)}</div>'
        f'{citation_html}'
        f'</div>'
    )


def render_judge_finding(idx: int, f: dict, anchor_prefix: str) -> str:
    return _render_subject_card(
        idx, f, anchor_prefix, body_key="finding", type_prefix="finding",
    )


def render_actor_observation(idx: int, o: dict, anchor_prefix: str) -> str:
    """One `actor_observations` entry — what the judge learned about the ACTOR's own story
    (`misprediction` / `framing-choice` / `discarded-class`, `config.ACTOR_OBSERVATION_TYPES`)
    rather than about the defender. `validate_judge_doc` has accepted these on the
    adversarial doc all along and `judge/malicious.md` asks for them; the page dropped them
    silently until #748."""
    return _render_subject_card(
        idx, o, anchor_prefix, body_key="observation", type_prefix="actor-obs",
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
    # The leg's status is RENDERED, not merely computable: "no story" is the one state a
    # reader cannot resolve on their own — a leg that was never selected and one that died
    # inside the actor call look identical on disk without it.
    status = leg_status(run_id, view.direction)
    status_html = (
        f'<div class="actor-meta"><span class="key">leg:</span> '
        f'<span class="val">{esc(status)}</span></div>'
    )

    if not story.is_file():
        return section(
            anchor, "actor", title, view.actor_subtitle,
            f'{status_html}<div class="empty">no {esc(story_name)}</div>',
        )

    meta_html = status_html
    if view.direction.archetype_name is not None:
        archetype = learn_dir / view.direction.archetype_name
        arch = archetype.read_text(encoding="utf-8").strip() if archetype.is_file() else "?"
        meta_html += (
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

  {"".join(_render_card_group(judge, view, g) for g in active_card_groups(view))}
  {_render_resolution_method(judge, view)}
  <h3 id="{anchor}-encounter">Encounter analysis</h3>
  {encounter_html}"""
    return section(anchor, "judge", title, view.judge_subtitle, body)


def _render_card_group(judge: dict, view: DirectionView, group: CardGroup) -> str:
    items = _card_items(judge, group.key)
    cards = (
        "\n".join(
            group.render(i, o, anchor_prefix=view.anchor(group.anchor_base))
            for i, o in enumerate(items)
        )
        if items
        else f'<div class="empty">{group.empty}</div>'
    )
    return f"""<h3 id="{view.anchor("sec-judge")}-{group.sub}">{group.heading} ({len(items)})</h3>
  <div class="findings-grid">{cards}</div>
"""


def _render_resolution_method(judge: dict, view: DirectionView) -> str:
    """`resolution_method` renders as the one plain line the judge emitted, not a card: it is
    the compact citable form a future benign judge reads back when this case is cited as a
    covering policy (#338), and it reaches the case-history ticket through
    `tickets/ticket_enrichment.py` whether or not the page shows it — here it is an auditing
    convenience (#748).

    Absence is the NORMAL case even for the direction that declares the key: the adversarial
    judge emits it on `benign` dispositions only, so the placeholder says which case it is
    rather than reading as a missing artifact."""
    if not renders_resolution_method(view):
        return ""
    method = str(judge.get("resolution_method", "")).strip()
    inner = (
        f'<div class="resolution-method">{esc(method)}</div>'
        if method
        else '<div class="empty">no resolution_method — '
             'emitted on benign dispositions only</div>'
    )
    return f"""<h3 id="{view.anchor("sec-judge")}-resolution">Resolution method</h3>
  {inner}
"""


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


# The card-group table lives down here because it names the three card renderers above.
FINDINGS_GROUP = CardGroup(
    key="defender_findings",
    sub="findings",
    anchor_base="finding",
    heading="Findings",
    empty="judge emitted no findings",
    render=render_judge_finding,
)

# The card groups only some directions carry, in page order. Membership is NOT decided here
# — `Direction.judge_optional_keys` declares which keys a direction's judge doc may hold and
# `validate.py` enforces the same sets, so a key cannot be accepted by the schema and stay
# invisible on the page (#748).
OPTIONAL_CARD_GROUPS: tuple[CardGroup, ...] = (
    CardGroup(
        key="actor_observations",
        sub="actor-obs",
        anchor_base="actor-obs",
        heading="Actor observations",
        empty="no actor observations queued",
        render=render_actor_observation,
    ),
    CardGroup(
        key="environment_observations",
        sub="env",
        anchor_base="env-obs",
        heading="Environment observations",
        empty="no environment observations queued",
        render=render_env_observation,
    ),
)


def active_card_groups(view: DirectionView) -> tuple[CardGroup, ...]:
    """The card groups this direction's Judge section emits — findings plus whichever
    optional groups its judge doc may carry. The section and the TOC both read this."""
    return (FINDINGS_GROUP,) + tuple(
        g for g in OPTIONAL_CARD_GROUPS if g.key in view.direction.judge_optional_keys
    )


def renders_resolution_method(view: DirectionView) -> bool:
    """Whether this direction's Judge section carries the `resolution_method` line — the one
    optional key that is not card-shaped, so it sits beside `active_card_groups` rather than
    inside it. Read by the section AND the TOC, so neither can emit without the other."""
    return "resolution_method" in view.direction.judge_optional_keys


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
    # `wire_logs/actor_trace.jsonl`, with the pre-move root path as a fallback so an older
    # learning run dir still renders its bundle. Host code, outside the gate: the directory is
    # where `permission.files.names_wire_log_dir` refuses AGENTS, and this page is for an operator.
    for trace in (learn_dir / WIRE_LOG_DIR / ACTOR_TRACE, learn_dir / ACTOR_TRACE):
        if trace.is_file():
            # Labelled with the path RELATIVE TO THE LEARNING RUN DIR, not the bare name: the
            # two candidates differ only in their directory, so a shared label would leave an
            # operator unable to tell a current bundle from a pre-`wire_logs/` one.
            panels.append(block(
                "artifact", str(trace.relative_to(learn_dir)),
                pre_text(trace.read_text(encoding="utf-8")),
            ))
            break
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
    # Every group but findings links its heading only — the per-card links below findings are
    # the one place the count is known here. The groups come off `active_card_groups`, so a
    # direction that carries no `actor_observations` gets no link to a section it never emits.
    group_links = "".join(
        f'<li class="item"><a href="#{judge_anchor}-{g.sub}">{g.toc_label()}</a></li>\n    '
        for g in active_card_groups(view) if g is not FINDINGS_GROUP
    )
    resolution_link = (
        f'<li class="item"><a href="#{judge_anchor}-resolution">resolution method</a></li>\n    '
        if renders_resolution_method(view)
        else ""
    )
    return f"""<li class="item"><a href="#{judge_anchor}-outcome">outcome</a></li>
    <li class="item"><a href="#{judge_anchor}-{FINDINGS_GROUP.sub}">{FINDINGS_GROUP.toc_label()}</a></li>
    {finding_links}
    {group_links}{resolution_link}<li class="item"><a href="#{judge_anchor}-encounter">encounter analysis</a></li>"""


def _toc_direction_block(view: DirectionView, n_findings: int | None) -> str:
    return f"""
    <li class="section">Actor{view.label}</li>
    <li class="item"><a href="#{view.anchor("sec-actor")}">{view.actor_toc_label}</a></li>

    <li class="section">Judge{view.label}</li>
    {_toc_judge_links(view, n_findings)}
"""


def render_judge_toc(
    sections: list[tuple[DirectionView, int | None]], *, raw_bundle: bool,
) -> str:
    """`sections` is one (view, finding count) per direction the page actually rendered —
    so the TOC never links a section the disposition did not select. A `None` count means
    the direction was selected but produced no judge doc (#716).

    `raw_bundle` is whether `render_judge_raw_bundle` produced a section for this run. It is
    passed rather than recomputed so the caller's ONE render decides both the link and the
    section: a run with no raw-bundle artifacts used to carry a dead `#sec-raw-bundle` entry
    (noted in #716, fixed in #748)."""
    direction_blocks = "".join(_toc_direction_block(v, n) for v, n in sections)
    raw_block = """<li class="section">Raw bundle</li>
    <li class="item"><a href="#sec-raw-bundle">inputs &amp; fallbacks</a></li>""" if raw_bundle else ""
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
    {raw_block}
  </ul>
</nav>
"""
