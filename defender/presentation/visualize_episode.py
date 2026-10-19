"""The episode page: `render_episode(runs, episode_id) -> Path` renders `learning.html` beside
`judge.yaml`, the episode opened by id through the request's tenant's repository
(`runs.episode(episode_id)`, #1105 PR 2); `main(argv)` is the standalone CLI
(`--tenant T <episode_id>`). The launcher (`branch/cli.py::_render_page`) calls `render_episode`
after the judge frame closes, under its own non-fatal boundary.

The episode is reached only through its tenant's walk, so another tenant's episode, a link at
any level and an id that is not a UUID (`latest` included) are refused before anything is read.
The manifest must name the episode it was read from (#1187 R5). The arms are the arm roster's
(`arms.json`, `view.arm_ids()`), each opened by its roster id; an entry in `runs/` the roster
does not name is never shown. No roster means the episode never reached RUNS: no world
sections and no arm links. A roster the reader refuses is the arms' `refused` state, with its
reason; the rest of the page renders. An unreadable container reads as absent.

Two phases. `load_episode` reads every record the page shows exactly once, through the package
readers, into a typed model (`_Episode`), and runs the findings walk once over it. Section
renderers take the model and never touch the directory. Only `family.yaml` refuses the whole
page; any other unreadable record or malformed field lands in its own slot (a `_Record.error`,
an empty list, a `None`) and renders as that slot's sentence, so one bad file cannot take the
page down and no two renderers can read a record differently.

The page shows the decisions passes wrote down (`judge.yaml.dispositions`, the enqueue ledger),
never a re-run of a pass's rule over the rows: re-deriving them disagrees with the pass at the
edges the page exists to explain. If a decision is not recorded, fix the writer.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if __name__ == "__main__" and (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender.tenancy._tenant import TenantRefused, requested_tenant, resolve_data_root
from defender.episodes._episode_handle import Episode, EpisodeRefused
from defender._io import Bound
from defender.episodes._episode_paths import LAYOUT, EpisodePaths
from defender.run_repository import RUN_LAYOUT, WIRE_LOG_NAMES, RunRefused
from defender.learning.branch import archive
from defender.learning.branch import outcome as outcome_mod
from defender.learning.branch import timing as timing_mod
from defender.learning.branch.steps import Step
from defender.learning.judge import (
    JudgeRefused,
    read_grade,
    recorded_draws,
)
from defender.learning.judge import family
from defender.learning.judge.enqueue import (
    DrawsSkipReport,
    draws_on_disk_report,
)
from defender.learning.judge.render import episode_alert
from defender.runtime.branch._family import (
    FamilyError, ManifestPredatesOracle,
)
from defender.presentation.visualize_primitives import (
    CSS,
    UsageParser,
    UsageRefused,
    esc,
    fmt_duration,
)

if TYPE_CHECKING:
    from defender.run_repository import EpisodeRuns, Run, RunId, RunsRepository

from defender.presentation.episode_verdict import (
    EPISODE_CSS as EPISODE_CSS,
    _draw_sort_key as _draw_sort_key,
    _normalized_disposition as _normalized_disposition,
    _render_header as _render_header,
    _render_queue_accounting as _render_queue_accounting,
    _render_refusal as _render_refusal,
    _render_verdict as _render_verdict,
)


from defender.presentation.episode_transcript import (
    _FAMILY_LABEL as _FAMILY_LABEL,
    _count as _count,
    _draw_key_stem as _draw_key_stem,
    _message_parts as _message_parts,
    _money as _money,
    _no_response_html as _no_response_html,
    _page_section as _page_section,
    _render_stages as _render_stages,
    _role_cost_text as _role_cost_text,
    _safe_id as _safe_id,
    _stem_names_label as _stem_names_label,
    _transcript_block as _transcript_block,
    _transcript_blocks_for_step as _transcript_blocks_for_step,
    _unattributed_traces as _unattributed_traces,
    _unnameable as _unnameable,
    _uv as _uv,
)

from defender.presentation.episode_worlds import (
    _BUCKET_CLASS as _BUCKET_CLASS,
    _LANE_HEADING as _LANE_HEADING,
    _bucket_html as _bucket_html,
    _calls_html as _calls_html,
    _commit_state_html as _commit_state_html,
    _declared_for as _declared_for,
    _disposition_heading_raw as _disposition_heading_raw,
    _facts_html as _facts_html,
    _finding_row_html as _finding_row_html,
    _raw as _raw,
    _render_findings_body as _render_findings_body,
    _render_findings_section as _render_findings_section,
    _render_leads_section as _render_leads_section,
    _render_one_world as _render_one_world,
    _render_roster_item as _render_roster_item,
    _render_world_leads as _render_world_leads,
    _render_worlds as _render_worlds,
)


from defender.presentation.episode_models import (
    ROSTER_UNNAMEABLE as ROSTER_UNNAMEABLE,
    RosterItem as RosterItem,
    WorldEntry as WorldEntry,
    _Episode as _Episode,
    _Finding as _Finding,
    _Findings as _Findings,
    _Record as _Record,
    _ResultEvent as _ResultEvent,
    _RoleCost as _RoleCost,
    _Timing as _Timing,
    _Trace as _Trace,
    _WireLogs as _WireLogs,
    _WorldArchive as _WorldArchive,
    _WorldLeads as _WorldLeads,
    _duration as _duration,
    _finite as _finite,
    _items as _items,
    _mapping as _mapping,
    _priced as _priced,
    _wall_between as _wall_between,
    _wall_span as _wall_span,
)


def _read_outcome(bound: Bound) -> _Record:
    """Pre-flight's outcome record with the worlds O5 counts as failed, as
    `{"record": <record or None>, "failed": {label: entry}}`. An absent or torn record is the
    "no record" state: `error` names it, and the failed worlds' own records still show."""
    try:
        record = outcome_mod.read_outcome(bound)
    except outcome_mod.OutcomeUnreadable as missing:
        return _Record({"record": None, "failed": outcome_mod.failed_worlds(bound, {})},
                       present=True, error=f"{outcome_mod.NO_RECORD} — {missing}")
    return _Record({"record": record, "failed": outcome_mod.failed_worlds(bound, record)},
                   present=True)


def _strict_samples_reader(bound: Bound, name: str) -> dict[str, Any] | None:
    """The page's strict reading of `samples.yaml`, via `read_samples_record`'s `reader=` seam.

    The default reader stays permissive; this one refuses what it cannot read so "unreadable" is
    distinguishable from "absent" (`None`). `empty_ok=True`: an empty file means nothing
    recorded yet."""
    return family.screened_yaml_mapping(bound, name, what="the samples record", empty_ok=True)


def _read_samples(bound: Bound) -> _Record:
    try:
        doc = family.read_samples_record(bound, reader=_strict_samples_reader)
    except JudgeRefused as bad:
        return _Record(present=True, error=f"samples record unreadable: {bad}")
    return _Record(doc or {}, present=doc is not None)


def _read_timing(bound: Bound) -> _Record:
    try:
        rows = timing_mod.read_stage_timings(bound)
    except ValueError as bad:
        return _Record(present=True, error=f"timing record unreadable: {bad}")
    return _Record(rows or [], present=rows is not None)


def _read_family_stamp(bound: Bound) -> _Record:
    try:
        doc = archive.read_family_stamp(bound)
    except ValueError as bad:
        return _Record(present=True, error=f"provenance record unreadable: {bad}")
    return _Record(doc, present=doc is not None)


def _read_grade(episode: Episode) -> _Record:
    # `read_grade`'s refusal never quotes the root, so no scrub is needed.
    try:
        grade = read_grade(episode)
    except JudgeRefused as bad:
        return _Record(present=True, error=f"grade record unreadable: {bad}")
    return _Record(grade, present=grade is not None)


#: The three shapes a roster item takes, decided once at load (`_build_roster`) so the worlds
#: and leads sections and their headings all count the same list.
ROSTER_WORLD = "world"


# =========================================================================================
# Loading — the one pass over the directory
# =========================================================================================


def _read_roster(view: EpisodeRuns) -> _Record:
    """The arm roster (`view.arm_ids()`, `{label: RunId}`): absent when the episode never
    reached RUNS; a roster the reader refuses — or a manifest its label check cannot load — is
    present with the refusal as its error, the arms' `refused` state."""
    try:
        arms = view.arm_ids()
    except (RunRefused, FamilyError) as refused:
        return _Record(present=True, error=f"refused — {refused}")
    return _Record(arms, present=arms is not None)


def load_episode(view: EpisodeRuns) -> _Episode:
    """Every record the page shows, read once, through `view` — the episode's view in its
    tenant's repository, reached by the tenant's walk. Raises `JudgeRefused` for the manifest
    alone; every other refusal is a slot on the model."""
    episode = view.episode
    return _load_episode(Path(episode.dir), episode.view(), view)


def _load_episode(episode_dir: Path, bound: Bound, view: EpisodeRuns) -> _Episode:
    ep = _Episode(episode_dir, family.read_manifest(bound, expected_episode_id=view.episode_id))

    ep.grade_rec = _read_grade(view.episode)
    ep.roster_rec = _read_roster(view)
    ep.outcome_rec = _read_outcome(bound)
    ep.samples_rec = _read_samples(bound)
    ep.stamp_rec = _read_family_stamp(bound)
    ep.timing_rec = _read_timing(bound)
    ep.timing = _Timing(ep.timing_rec)

    grade = ep.grade
    grade_rows = [r for r in (_items(grade.worlds) if grade is not None else [])
                  if isinstance(r, dict) and isinstance(r.get("world"), str)]
    ep.archived_world_dirs = [
        name for name in bound.under(LAYOUT.worlds).entries().dirs()
        if name != _FAMILY_LABEL]
    ep.entries, ep.roster, ep.off_roster = _build_roster(
        ep, [r["world"] for r in grade_rows], reached_runs=ep.roster_rec.present)
    for row in grade_rows:
        w = ep.entries.get(row["world"])
        if w is not None:
            w.row = row

    ep.alert = episode_alert(bound)

    for label in [*ep.entries, _FAMILY_LABEL]:
        docs, skipped = (_load_draws(bound, label)
                         if label == _FAMILY_LABEL or ep.entries[label].nameable
                         else ({}, DrawsSkipReport()))
        # Only the draws judge.yaml records for this row (A6): a file a stopped or wider
        # earlier pass left on disk is never shown as this record's.
        recorded = recorded_draws(grade, label)
        ep.draws[label] = ({n: d for n, d in docs.items() if n in recorded}, skipped)
    nameable_worlds = [w for w in ep.entries.values() if w.nameable]
    if ep.roster_rec.ok and ep.roster_rec.value is not None:
        _load_arms(nameable_worlds, view, episode_dir, ep.roster_rec.value)
    for w in nameable_worlds:
        w.archive = _load_world_archive(bound, w.label)
    for item in ep.sectioned:
        entry = ep.entries.get(item.label)
        ep.leads[item.label] = (_load_world_leads(ep, bound, item.label)
                                if entry is None or entry.nameable else _WorldLeads())

    ep.wire = _load_wire_logs(bound.under(RUN_LAYOUT.wire_log_dir))
    ep.findings = _walk_findings(ep)
    ep.total_cost, ep.runs_costed, ep.costed, ep.worlds_wall, ep.lower_bound = _cost_totals(ep)
    return ep


def _load_arms(worlds: list[WorldEntry], view: EpisodeRuns, episode_dir: Path,
               arm_ids: dict[str, RunId]) -> None:
    """Every world's arm, from ONE hold of the episode's container (`view.arms`), each opened
    by its roster id (`arm_ids`, never a name composed from the label; an entry rule that
    takes only a real directory): its run folder's name, its run page's link relative to the
    episode page, and its result event, read through a no-follow reader walked from that same
    hold. Anything refused for an arm — nothing at the id, a link or a file there, a container
    gone since the view opened — leaves that arm absent."""
    ids = {w.label: arm_ids[w.label] for w in worlds if w.label in arm_ids}
    with view.arms(list(ids.values())) as handout:
        for w in worlds:
            if w.label not in ids:
                continue
            run = handout[ids[w.label]]
            if isinstance(run, RunRefused):
                continue
            try:
                w.result = _result_event(handout.reader(ids[w.label]))
            except (RunRefused, OSError):
                continue
            w.run_dir_name = run.run_dir.name
            w.run_page = _run_page_link(run, episode_dir)


def _run_page_link(run: Run, episode_dir: Path) -> str:
    """The arm's run page (`run.observability.runtime_html`), as a link relative to the
    episode page beside `judge.yaml`."""
    return Path(run.observability.runtime_html.path).relative_to(episode_dir).as_posix()


def _load_draws(bound: Bound, label: str) -> tuple[dict[int, dict[str, Any]], DrawsSkipReport]:
    """The draws under `worlds/<label>/judge/`, through the enqueue's reader over this pass's
    root handle (a link anywhere on the way lists nothing)."""
    return draws_on_disk_report(bound, label)


def _build_roster(ep: _Episode, grade_row_labels: list[str], *,
                  reached_runs: bool) -> tuple[dict[str, WorldEntry], list[RosterItem], int]:
    """Every world label that gets a section: manifest worlds — once the episode reached RUNS,
    which the arm roster's presence is (`reached_runs`; a refused roster was still written) —
    ∪ `judge.yaml` rows. Each one's arm is opened by its roster id later (`_load_arms`); an
    entry in `runs/` that is neither is never shown (#1105 J3: the worlds are the manifest's,
    not a listing of the container).

    Returns the entries by label (manifest order first), the classified roster, and the count
    of `worlds/` dirs on neither the manifest nor the record (reported on one line, never
    rendered)."""
    entries: dict[str, WorldEntry] = {}
    order: list[str] = []

    def entry(label: str) -> WorldEntry:
        if label not in entries:
            entries[label] = WorldEntry(label)
            entries[label].nameable = family.world_label_names_directory(label)
            order.append(label)
        return entries[label]

    # A manifest world with no grade row gets a section only once the episode reached RUNS:
    # its arm roster is written (#1187 R2). `runs/` alone is not RUNS — `start_runs` makes it
    # before the roster — and an episode rejected or aborted before then has no world to show.
    # `family` is not a world: it is the reserved label for the family-level draws. The judge
    # refuses such a manifest, but the page reads whatever tree it is given, and treating it as
    # a world would walk its draws twice under duplicate ids.
    for w in ep.manifest_worlds:
        label = w.get("world_id")
        if not isinstance(label, str) or label == _FAMILY_LABEL:
            continue
        if label not in entries and not reached_runs:
            continue
        entry(label)
        entries[label].in_manifest = True
        # The first manifest entry is the section's own.
        if entries[label].manifest_doc is None:
            entries[label].manifest_doc = w

    for label in grade_row_labels:
        if label != _FAMILY_LABEL:
            entry(label)

    off_roster = sum(1 for name in ep.archived_world_dirs if name not in entries)

    roster = [RosterItem(label, ROSTER_WORLD if _safe_id(label) is not None else ROSTER_UNNAMEABLE)
              for label in order]
    return entries, roster, off_roster


def _result_event(run: Bound) -> _ResultEvent:
    # Through the arm reader's JSONL reader: absent/refused are its own states, and a link or
    # FIFO is refused at the open rather than raising `PermissionError`.
    rows, _bad, rec = run.read_jsonl(RUN_LAYOUT.tool_trace)
    if rec.absent:
        return _ResultEvent(None, None, "absent")
    if rec.refusal is not None:
        return _ResultEvent(None, None, "refused")
    if not rows or rows[-1].get("type") != "result":
        return _ResultEvent(None, None, "none")
    last = rows[-1]
    cost = _finite(last.get("total_cost_usd"))
    wall = _duration(last.get("duration_ms"))
    if cost is None or cost < 0:
        return _ResultEvent(None, wall, "unusable")
    return _ResultEvent(cost, wall, "ok")


def _load_world_archive(bound: Bound, label: str) -> _WorldArchive:
    # No pre-check of `worlds/<label>`: each leaf reads through the bind and reports its own
    # absent/refused state, whichever path component was missing or a link.
    world_rel = LAYOUT.world(label)
    report = family.read_archived_report(bound, world_rel.report)
    investigation = bound.read(world_rel.investigation)
    return _WorldArchive(
        report=report,
        investigation_present=not investigation.absent,
        provenance=family.json_mapping(bound, world_rel.provenance),
        scrub=family.json_mapping(bound, world_rel.scrub_verdict))


def _load_world_leads(ep: _Episode, bound: Bound, label: str) -> _WorldLeads:  # noqa: C901, PLR0912 — the served ledger, the archive notes and every lead's chain are one world's leads block
    leads = _WorldLeads()
    world = bound.under(LAYOUT.world(label).dir)

    # Read through the judge's own reader so `malformed_rows` matches the count on the
    # `judge.yaml` row (torn lines and out-of-vocabulary `source` values). Its refusal is the
    # ledger note only and does not affect the investigation read below.
    if ep.episode_token is None:
        leads.ledger_note = "served ledger: not readable — the episode id names no token"
    else:
        try:
            rows, malformed, ledger_read = family.read_world_ledger(
                bound, label, episode_token=ep.episode_token)
        except JudgeRefused as bad:
            leads.ledger_note = f"served ledger unreadable: {bad}"
        else:
            leads.calls = rows
            if ledger_read.absent:
                leads.ledger_note = "served ledger: absent"
            elif malformed:
                leads.ledger_note = f"{malformed} malformed row"

    # Off the bind's listing, never a stat. Wholly absent: nothing to chain. Present but not a
    # real listable directory (a link, a file): refused once here, nothing rostered. Missing
    # individual records: every other leaf still renders.
    listing = world.entries()
    leads.archived = not listing.absent
    if not leads.archived:
        return leads
    if listing.refusal is not None:
        leads.dir_error = listing.refusal
        return leads
    facts = None
    try:
        read_facts = family.read_investigation_facts(bound, world=label)
    except JudgeRefused as bad:
        leads.facts_error = str(bad)
    except Exception as bad:  # noqa: BLE001 — a model-written document is parsed here; whatever the parser raises is this slot's, never the page's
        leads.facts_error = f"{LAYOUT.world(label).investigation}: {bad!r}"
    else:
        if not read_facts.absent:
            facts = read_facts

    # `leads_by_id` takes a path, handed over only after the listing judged it a real directory.
    try:
        all_leads = family.leads_by_id(EpisodePaths(ep.dir).world(label).dir)
    except Exception:  # noqa: BLE001
        all_leads = {}

    # Only `.md` plain files are summaries; `summary_lead_ids` is shared with the judge prompt.
    summary_stems = family.summary_lead_ids(world)

    if facts is not None:
        roster = set(facts.referenced_leads) | summary_stems
        resolutions_by_lead = facts.resolutions_by_lead
        leads.moved = bool(facts.resolution_moved)
    else:
        roster = set(all_leads) | summary_stems
        resolutions_by_lead = {}

    for lead_id in sorted(roster):
        # `lead_chain` answers a refused summary as its own sentence; nothing is caught here so
        # the page and the grading pass share one reader.
        chain = family.lead_chain(world, lead_id, resolutions_by_lead, leads=all_leads)
        leads.chains.append((lead_id, chain))
    return leads


def _load_wire_logs(wire: Bound) -> _WireLogs:
    logs = _WireLogs()
    listing = wire.entries()
    if listing.entries is None:
        return logs
    logs.present = True
    for name in sorted(listing.entries):
        if not name.endswith(".jsonl"):
            continue
        # Both a trace and its framed twin take their stem from `WIRE_LOG_NAMES.trace_key`, so
        # they always pair on the same key.
        if WIRE_LOG_NAMES.is_framed(name):
            stem = WIRE_LOG_NAMES.trace_key(name)
            trace = logs.traces.setdefault(stem, _Trace(stem))
            frows, _bad, _rec = wire.read_jsonl(name)
            if frows:
                trace.framed = frows[0]
            continue
        if not WIRE_LOG_NAMES.is_agent_trace(name):
            continue
        stem = WIRE_LOG_NAMES.trace_key(name)
        trace = logs.traces.setdefault(stem, _Trace(stem))
        # `wire_logs/` is box-writable: the bound reader refuses a link or FIFO at the open and
        # answers a permission fault as a refusal.
        rows, unreadable, rec = wire.read_jsonl(name)
        if rec.text is None:
            trace.plain = "refused" if rec.refusal is not None else "absent"
            continue
        trace.plain = "ok"
        trace.rows, trace.unreadable = rows, unreadable
    return logs


def _cost_totals(ep: _Episode) -> tuple[float, bool, bool, str, str]:
    total = 0.0
    runs_costed = False
    walls = []
    for w in ep.entries.values():
        if w.result is None:
            continue
        if w.result.cost is not None and w.result.costed:
            runs_costed = True
            total += w.result.cost
        if w.result.wall_ms:
            walls.append(w.result.wall_ms)
    q = ep.role_costs["questioner"] = ep.wire.role_cost("questioner")
    j = ep.role_costs[str(Step.JUDGE)] = ep.wire.role_cost(Step.JUDGE)
    ep.review_cost, ep.review_calls = ep.wire.comparator_cost()
    total += q.cost + j.cost
    # Priced calls, not trace files: a role whose only trace is refused or unpriceable has
    # spent nothing the page can name, so it must not produce a "$0.0000" total.
    costed = runs_costed or bool(q.priced) or bool(j.priced)
    if walls:
        wall_range = f"{fmt_duration(min(walls))}–{fmt_duration(max(walls))}"
        lower_bound = f"≈ {fmt_duration(q.wall_ms + j.wall_ms + max(walls))} lower bound on wall: model calls + longest world"
    else:
        wall_range = ""
        lower_bound = ""
    return total, runs_costed, costed, wall_range, lower_bound

from defender.presentation.episode_findings import (
    SUBJECT_USER as SUBJECT_USER,
    _DROPPED_LANES as _DROPPED_LANES,
    _FILED_LISTS as _FILED_LISTS,
    _LANE_WORD as _LANE_WORD,
    _bump as _bump,
    _coordinate_of as _coordinate_of,
    _filed as _filed,
    _finding_fields as _finding_fields,
    _group_numbering as _group_numbering,
    _ledger_of as _ledger_of,
    _off_ledger_disposition as _off_ledger_disposition,
    _walk_findings as _walk_findings,
)



# =========================================================================================
# The rendered document
# =========================================================================================


def _encode_page(html_text: str) -> bytes:
    """The document's bytes. `errors="replace"` handles lone surrogates but not NUL (a plain
    0x00 in UTF-8), so NUL is replaced with U+FFFD first."""
    return html_text.replace("\x00", "�").encode("utf-8", errors="replace")


def _write_page(episode: Episode, html_text: str) -> Path:
    page = episode.learning_html
    page.write(_encode_page(html_text))
    return page.path


def render_episode(runs: RunsRepository, episode_id: str) -> Path:
    """Render episode `episode_id` of `runs`'s tenant into its own folder. The door is the
    episode view (`open_episode_view`): a missing episode, an id that is not a UUID, a link or
    a file at any level of the walk is `JudgeRefused` before anything else is read, and
    nothing is made."""
    with open_episode_view(runs, episode_id) as view:
        try:
            html_text = build_page(view)
        except JudgeRefused as bad:
            # An archive of the pre-oracle design gets a page saying so; any other manifest
            # refusal stays a refusal.
            if not isinstance(bad.__cause__, ManifestPredatesOracle):
                raise
            html_text = _render_refusal(view.episode_id, bad)
        return _write_page(view.episode, html_text)


def open_episode_view(runs: RunsRepository, episode_id: str) -> EpisodeRuns:
    """`runs.episode(episode_id)`, every refusal of its door as the page's `JudgeRefused`: an
    id that is not a UUID (`latest` included), a missing episode, a link or a file at any
    level of the tenant's walk; nothing is created. The caller closes the view."""
    try:
        return runs.episode(episode_id)
    except FileNotFoundError as missing:
        raise JudgeRefused(f"episode {episode_id}: no such episode directory") from missing
    except (EpisodeRefused, TenantRefused, OSError) as refused:
        raise JudgeRefused(f"episode {episode_id}: {refused}") from refused


def build_page(view: EpisodeRuns) -> str:
    return _render_document(load_episode(view))


def _render_document(ep: _Episode) -> str:
    body = "".join([
        _render_header(ep),
        _render_verdict(ep),
        _render_worlds(ep),
        _render_findings_section(ep),
        _render_user_section(ep),
        _render_stages(ep),
        _render_leads_section(ep),
        _render_records(ep),
    ])
    nav = _render_nav(body)

    title = f"episode — {esc(ep.episode_id)}"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>{CSS}
{EPISODE_CSS}</style></head><body id="top">
<div class="layout">
{nav}
<article class="content episode">
{body}
</article>
</div>
</body></html>
"""


def _render_nav(body: str) -> str:
    ids = re.findall(r'id="([^"]+)"', body)
    items = []
    for i in ids:
        if i.startswith("world-") or i.startswith("fg-") or i.startswith("sec-"):
            items.append(f'<li class="item"><a href="#{esc(i)}">{esc(i)}</a></li>')
    # The shared stylesheet's nav classes, so the sticky layout matches the run pages.
    return f'<nav class="toc"><ul>{"".join(items)}</ul></nav>'


# =========================================================================================
# The user section (judge.yaml's `user`: design M7, A2, A7, R1 (c))
# =========================================================================================

#: The user record's lists as the page titles them, in the record's own keys.
_USER_LISTS = (
    ("named_gaps", "deployment gaps the judge named (every completed draw names the call)"),
    ("unkeyed_named_gaps", "named gaps with no blocked call, flagged as why the facts never "
                           "reached the investigator"),
    ("found_gaps", "blocked calls the code found in the archive"),
    ("serving_findings", "serving findings"),
    ("gap_findings", "findings resting only on blocked calls"),
)


def _user_value(value: Any) -> str:
    """One field of a user-record entry as text: a string as it is, a mapping as `k=v` pairs
    and a list item by item (so a quoted string reaches the page unchanged, never re-quoted),
    escaped once by the caller."""
    if isinstance(value, dict):
        return ", ".join(f"{_raw(k)}={_user_value(v)}" for k, v in value.items())
    if isinstance(value, list):
        return "; ".join(_user_value(v) for v in value)
    return _raw(value)


def _user_entry_html(entry: Any) -> str:
    """One entry: a found gap's call and count, or an unread input with its cause; any other
    entry field by field. Every value is the record's, rendered as text."""
    if not isinstance(entry, dict):
        return f'<div class="us-entry">{_uv(_user_value(entry))}</div>'
    if entry.get("unread"):
        return (f'<div class="us-entry us-unread">run {_uv(_user_value(entry.get("run")))}: '
                f'unread — {_uv(_user_value(entry.get("unread")))}</div>')
    head = ""
    if "system" in entry:
        head = (f'run {_user_value(entry.get("run"))}: {_user_value(entry.get("system"))} '
                f'{_user_value(entry.get("verb"))} {_user_value(entry.get("params"))}')
        if "count" in entry:
            head += f' — {_user_value(entry.get("count"))} time(s)'
    rest = [f"{_raw(k)}: {_user_value(v)}" for k, v in entry.items()
            if k not in ("run", "system", "verb", "params", "count")]
    text = " · ".join(part for part in (head, *rest) if part)
    return f'<div class="us-entry">{_uv(text)}</div>'


def _render_user_section(ep: _Episode) -> str:
    """judge.yaml's user section, every list whole (no cap: N13), each entry as data."""
    grade = ep.grade
    if grade is None:
        return ""
    user = _mapping(grade.user)
    parts = []
    for key, title in _USER_LISTS:
        entries = _items(user.get(key))
        body = "".join(_user_entry_html(e) for e in entries) or \
            '<div class="us-entry">none</div>'
        parts.append(f'<div class="us-list"><h3>{esc(title)} ({len(entries)})</h3>{body}</div>')
    return _page_section("sec-user", "User record", "".join(parts))


# =========================================================================================
# Records section
# =========================================================================================


def _render_records(ep: _Episode) -> str:  # noqa: C901, PLR0912 — every episode-level record's own slot in one section
    samples_rec, stamp_rec = ep.samples_rec, ep.stamp_rec
    bits = [f'<div class="rc-story">{_uv(ep.manifest.get("base_story"))}</div>']
    discriminator = ep.manifest.get("discriminator")
    if isinstance(discriminator, dict):
        bits.append(f'<div class="rc-predicate">{_uv(discriminator.get("predicate"))}</div>')
    served = _items(ep.manifest.get("served_systems"))
    bits.append(f'<div class="rc-served">served systems: {_uv(", ".join(map(str, served)))}'
                '</div>')

    for w in ep.manifest_worlds:
        if isinstance(w.get("world_id"), str):
            bits.append(f'<div class="rc-world">{_uv(w["world_id"])}</div>')

    bits.append(_outcome_html(ep))

    if samples_rec.error:
        bits.append(f'<div class="rc-samples">{_uv(samples_rec.error)}</div>')
    elif not samples_rec.present:
        bits.append('<div class="rc-samples">absent</div>')
    else:
        bits.append(_samples_html(_mapping(samples_rec.value)))

    if stamp_rec.error:
        bits.append(f'<div class="rc-provenance">{_uv(stamp_rec.error)}</div>')
    elif not stamp_rec.present:
        bits.append('<div class="rc-provenance">absent</div>')
    else:
        stamp = _mapping(stamp_rec.value)
        agreed = stamp.get("agreed")
        if isinstance(agreed, dict):
            bits.append(f'<div class="rc-commit">{_uv(agreed.get("commit"))}</div>')
            bits.append(f'<div class="rc-model">{_uv(agreed.get("model"))}</div>')
            for path_ in _items(agreed.get("dirty_paths")):
                bits.append(f'<div class="rc-dirty">{_uv(path_)}</div>')
        bits.append(f'<div class="rc-allow-dirty">allow_dirty: '
                   f'{_uv(stamp.get("allow_dirty"))}</div>')

    return _page_section("sec-records", "Records", "".join(bits))


def _record_call_text(call: Any) -> str:
    call = _mapping(call)
    return f'{_uv(call.get("system"))} {_uv(call.get("verb"))} {_uv(call.get("params"))}'


def _outcome_html(ep: _Episode) -> str:
    """Pre-flight's outcome record — its word and reason, the worlds it found unservable, the
    calls it could not replay and the calls that drifted — and every world's own record."""
    rec = ep.outcome_rec
    record = _mapping(_mapping(rec.value).get("record"))
    bits = []
    if rec.error:
        bits.append(f'<div class="rc-outcome">{_uv(rec.error)}</div>')
    else:
        bits.append(f'<div class="rc-outcome">outcome: {_uv(record.get("outcome"))} — '
                    f'{_uv(record.get("reason"))}</div>')
    for key, what in (("unservable_worlds", "unservable in pre-flight"),
                      ("not_replayable", "not replayable"), ("drift", "drift")):
        for entry in _items(record.get(key)):
            entry = _mapping(entry)
            extra = entry.get("world") if key == "unservable_worlds" else None
            note = entry.get("status") or entry.get("reason")
            bits.append(f'<div class="rc-outcome-call">{esc(what)}: '
                        f'{_uv(extra) + " " if extra is not None else ""}{_record_call_text(entry.get("call") if key == "unservable_worlds" else entry)}'
                        f' ({_uv(note)})</div>')
    for label, entry in sorted(ep.failed_worlds.items()):
        entry = _mapping(entry)
        bits.append(f'<div class="rc-world-record">world {_uv(label)}: {_uv(entry.get("reason"))}'
                    f' — {_record_call_text(entry.get("call"))} — {_uv(entry.get("detail"))}</div>')
    return "".join(bits)


def _samples_html(samples: dict[str, Any]) -> str:
    """The samples record, one section per system: its verbs' real example answers, or the
    reason the system has none."""
    bits = []
    for system, section in samples.items():
        section = _mapping(section)
        if "unavailable" in section:
            bits.append(f'<div class="rc-sample-system">{_uv(system)}: unavailable — '
                        f'{_uv(section.get("unavailable"))}</div>')
            continue
        answers = "".join(
            f'<div class="rc-sample">{_uv(verb)}: {_uv(answer)}</div>'
            for verb, listed in _mapping(section.get("verbs")).items()
            for answer in _items(listed))
        bits.append(f'<div class="rc-sample-system">{_uv(system)}{answers}</div>')
    return "".join(bits)


# =========================================================================================
# CLI
# =========================================================================================


def _diagnostics(ep: _Episode) -> list[str]:
    """The stderr lines the CLI echoes beside the page path, from the model's refusal slots —
    never a scan of the rendered bytes, which include model-authored text."""
    lines = []
    for name, rec in (("grade", ep.grade_rec), ("timing", ep.timing_rec),
                      ("outcome", ep.outcome_rec), ("samples", ep.samples_rec),
                      ("provenance", ep.stamp_rec)):
        if rec.error:
            lines.append(f"{name} record unreadable")
    if ep.roster_rec.error:
        lines.append("arm roster refused")
    if ep.grade_rec.ok and ep.grade is None:
        lines.append("no grade record")
    return lines


def _parse_page_args(argv: list[str]) -> argparse.Namespace:
    """`--tenant T <episode_id>` (#1105 declared change 4, J8): the tenant is required, with
    no default, and the episode is named by its UUID under that tenant's `episodes/`."""
    p = UsageParser(prog="visualize_episode.py", description=__doc__)
    p.add_argument("--tenant", required=True,
                   help="the tenant whose episode is rendered; required, with no default")
    p.add_argument("episode_id", help="the episode, by its id")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        ns = _parse_page_args(argv)
    except UsageRefused as bad:
        print(f"usage: visualize_episode.py --tenant T <episode_id> ({bad})", file=sys.stderr)
        return 1
    try:
        tenant = requested_tenant(resolve_data_root(), ns.tenant)
        view = open_episode_view(tenant.runs_repository(), ns.episode_id)
    except (TenantRefused, JudgeRefused) as bad:
        # One line: the refusal may wrap a multi-line YAML parser error.
        print(" ".join(str(bad).split()), file=sys.stderr)
        return 1
    with view:
        try:
            ep = load_episode(view)
        except JudgeRefused as bad:
            print(" ".join(str(bad).split()), file=sys.stderr)
            return 1
        try:
            page_path = _write_page(view.episode, _render_document(ep))
        except OSError as bad:
            print(str(bad), file=sys.stderr)
            return 1
    print(page_path)
    for line in _diagnostics(ep):
        print(line, file=sys.stderr)
    return 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
