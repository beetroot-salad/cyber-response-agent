"""World, finding, and lead sections of the episode page."""
from __future__ import annotations






from typing import Any




from defender._episode_paths import WORLD_LEAVES







from defender.learning.judge import (
    QUEUED,
    QUEUEING,
    STATE_KEY,
)

from defender.learning.judge import family


from defender.learning.judge.route import (
    LANE_DRAWS_DISAGREE,
    LANE_DROPPED_NO_PAIR,
    LANE_DROPPED_OTHER_RUN,
    LANE_DROPPED_UNRESOLVED,
    LANE_GAP_NOT_UNANIMOUS,
    LANE_GAP_UNKEYED,
    LANE_NOT_MEASURED,
    LANE_UNAUTHORED,
    LANE_USER_RECORD,
)


from defender.learning.judge.run import (
    SUBJECT_DEFENDER,
)


from defender.scripts.visualize.visualize_primitives import (
    esc,
    fmt_duration,
)

from defender.scripts.visualize.episode_transcript import _money as _money, _page_section as _page_section, _safe_id as _safe_id, _unnameable as _unnameable, _uv as _uv

from defender.scripts.visualize.episode_models import ROSTER_UNNAMEABLE as ROSTER_UNNAMEABLE, RosterItem as RosterItem, WorldEntry as WorldEntry, _Episode as _Episode, _Finding as _Finding, _Findings as _Findings, _WorldLeads as _WorldLeads, _items as _items, _mapping as _mapping




#: The judge model's world buckets (O11, M19=A), each with its own colour; any other word (a
#: world-subject finding's free-text bucket) is `bucket-other`.
_BUCKET_CLASS = {
    "lead-set": "bucket-lead-set",
    "decision-discipline": "bucket-decision-discipline",
    "analyze-discipline": "bucket-analyze-discipline",
    "lead-quality": "bucket-lead-quality",
}




def _raw(x: Any) -> str:
    """`x` as plain text, unescaped, for a string another function escapes once."""
    if x is None:
        return "—"
    if isinstance(x, bool):
        return "True" if x else "False"
    return x if isinstance(x, str) else str(x)



#: The heading of every lane that sends a finding to no queue (A13), one per lane: no two
#: lanes share one, and none quotes the finding's reason, so a lane's rows share theirs.
_LANE_HEADING = {
    LANE_USER_RECORD: "user record — listed for the user, not queued",
    LANE_NOT_MEASURED: "not queued — the world is not measured",
    LANE_UNAUTHORED: "not queued — the draw named no bucket",
    LANE_DRAWS_DISAGREE: "not queued — the world's draws disagree",
    LANE_GAP_NOT_UNANIMOUS: "not listed — a gap not every draw names",
    LANE_GAP_UNKEYED: "not listed — a gap naming no blocked call",
    LANE_DROPPED_UNRESOLVED: "dropped — no pointer resolves",
    LANE_DROPPED_OTHER_RUN: "dropped — names only another run",
    LANE_DROPPED_NO_PAIR: "dropped — no two-run contrast pair",
}




def _disposition_heading_raw(f: _Finding) -> str:
    """The group heading's plain text, never pre-escaped: the caller escapes it once, so a
    record-field `reason` cannot be double-escaped into an irreversible `&amp;#x27;`."""
    if f.disposition == "defender":
        return "defender: enqueued"
    if f.disposition == "world_author":
        return "world author: enqueued"
    if f.disposition == "unqueueable":
        addressee = "defender" if f.subject == SUBJECT_DEFENDER else "world author"
        return f"{addressee}: unqueueable — {_raw(f.reason)}"
    if f.disposition in _LANE_HEADING:
        return _LANE_HEADING[f.disposition]
    if f.disposition == "world_ungradable":
        return f"not enqueued — world ungradable: {_raw(f.reason)}"
    if f.disposition == "no_grade_row":
        return "not enqueued — no grade row"
    if f.disposition == "never_on_record":
        return "not on the record — never enqueued"
    if f.disposition == "no_ledger":
        return "record carries no disposition ledger — not enqueued"
    return "no grade record — not enqueued"




# =========================================================================================
# Worlds section
# =========================================================================================


def _render_worlds(ep: _Episode) -> str:
    guide_rows = []
    for w in ep.manifest_worlds:
        label = w.get("world_id")
        if not isinstance(label, str):
            guide_rows.append(_unnameable(str(label), what="world label"))
            continue
        safe = _safe_id(label)
        if safe is None:
            guide_rows.append(_unnameable(label, what="world label"))
            continue
        declared = _declared_for(label, w, ep.entries)
        if label == ep.control_label:
            guide_rows.append(f'<div class="vd-guide-row">{esc(label)} — '
                             f'the branch point untouched, not graded · {_uv(declared)}</div>')
            continue
        axis = w.get("axis")
        axis_html = (f'<q class="verbatim">{_uv(axis)}</q>' if isinstance(axis, str)
                    else "<em>null</em>")
        guide_rows.append(f'<div class="vd-guide-row">{esc(label)} '
                         f'({esc(str(w.get("role")))}) {_uv(declared)} {axis_html}</div>')

    # The roster as loaded: the heading counts the sectioned items; unnameable ones render one
    # line and are not counted.
    sections = [_render_roster_item(ep, item) for item in ep.roster]

    body = f'<div class="vd-guide">{"".join(guide_rows)}</div>{"".join(sections)}'
    return _page_section("sec-worlds", f"Worlds ({len(ep.sectioned)})", body)




def _declared_for(label: str, manifest_world: dict[str, Any],
                  entries: dict[str, WorldEntry]) -> Any:
    entry = entries.get(label)
    if entry is not None and entry.row is not None and entry.row.get("declared") is not None:
        return entry.row["declared"]
    return manifest_world.get("disposition_declared")




def _render_roster_item(ep: _Episode, item: RosterItem) -> str:
    """One roster line, by the shape the loader gave it."""
    if item.kind == ROSTER_UNNAMEABLE:
        return _unnameable(item.label, what="world directory")
    return _render_one_world(ep, item.label)




def _commit_state_html(label: str, row: dict[str, Any] | None) -> str:
    """The world's A6 commit state as judge.yaml records it — read off the row, never the
    queue: `queueing` is in progress (a pass stopped between this world's appends and its
    commit; the next grade refuses it until reconciled), `queued` is graded (its commit is
    complete), and a planted world with no committed row is ungraded. The control is judged
    against, never graded, so it carries no such line."""
    state = (row or {}).get(STATE_KEY)
    if state == QUEUEING:
        text = (f"in progress — a pass stopped while committing world {label}: its findings "
                "may be partly on the queues; reconcile them before the next grade")
    elif state == QUEUED:
        text = "graded — its commit is complete"
    else:
        text = "ungraded — no committed grade for this world"
    return f'<div class="w-commit">{_uv(text)}</div>'




def _render_one_world(ep: _Episode, label: str) -> str:  # noqa: C901, PLR0912, PLR0915 — one world's whole section (state, bucket, facts, calls, archive)
    entry = ep.entries[label]
    # A `not_graded` stamp voids the family's word: every record-derived part (ladder,
    # bucket, systems) renders as "not graded" even though the row exists. Run-dir and
    # archive parts are unaffected.
    row = None if ep.not_graded else entry.row
    bits = []

    _docs, draws_report = ep.draws[label]
    if draws_report.unreadable:
        bits.append(f'<div class="w-unreadable">{draws_report.unreadable} draw documents '
                   f'unreadable</div>')
    if draws_report.skipped:
        bits.append(f'<div class="w-skipped">{draws_report.skipped} skipped</div>')
    if label != ep.control_label:
        bits.append(_commit_state_html(label, entry.row))

    manifest_world = ep.manifest_world(label)
    if row is None:
        bits.append('<div class="w-state">not graded</div>')
        if manifest_world is not None:
            declared = _declared_for(label, manifest_world, ep.entries)
            bits.append(f'<div class="w-declared">{_uv(declared)}</div>')
    elif row.get("ungradable"):
        bits.append('<div class="w-state">ungradable</div>')
        bits.append(f'<div class="w-reason">{_uv(row.get("ungradable_reason"))}</div>')
    else:
        bits.append(f'<div class="w-verdict">{_uv(row.get("verdict"))}</div>')
        bits.append(f'<span class="w-ladder">verdict = declared: {_uv(row.get("verdict"))} == '
                    f'{_uv(row.get("declared"))}</span>')
        bits.append(_bucket_html(row))
    failed = ep.failed_worlds.get(label)
    if isinstance(failed, dict) and row is None:
        bits.append(f'<div class="w-reason">{_uv(failed.get("reason"))} — '
                    f'{_uv(failed.get("detail"))}</div>')

    if manifest_world is not None:
        axis = manifest_world.get("axis")
        if isinstance(axis, str):
            bits.append(f'<div class="w-axis"><q class="verbatim">{_uv(axis)}</q></div>')
        bits.append(_facts_html(manifest_world))

    leads = ep.leads.get(label)
    if leads is not None and leads.calls:
        bits.append(_calls_html(leads.calls))

    result = entry.result
    # Both checked: `result` is only set alongside `run_page`, but nothing enforces that.
    if result is not None and entry.run_page is not None:
        bits.append(f'<a href="{esc(entry.run_page)}">runtime</a>')
        if result.cost is not None and result.costed:
            bits.append(f'<span class="w-cost">{_money(result.cost)}</span>')
            if result.wall_ms:
                bits.append(f'<span class="w-wall">{fmt_duration(result.wall_ms)}</span>')
        else:
            bits.append(f'<span class="w-cost">{esc(result.text)}</span>')
    else:
        bits.append('<div class="w-archive">run directory absent</div>')

    # Each archived leaf is its own line and names its leaf.
    archived = entry.archive
    if archived is None:
        bits.append('<div class="w-archive">not archived</div>')
    else:
        if archived.report.absent:
            bits.append(
                f'<div class="w-archive">{esc(str(WORLD_LEAVES.report))}: not archived</div>')
        else:
            headline = archived.report.disposition_or_unknown
            if archived.report.disposition is None and archived.report.reason:
                # No headline: show the reader's own reason beside the placeholder.
                headline += f" — {archived.report.reason}"
            bits.append(f'<div class="w-report">{_uv(headline)}</div>')
        if not archived.investigation_present:
            bits.append(
                f'<div class="w-archive">{esc(str(WORLD_LEAVES.investigation))}: '
                'not archived</div>')
        if archived.provenance is not None:
            bits.append(f'<div class="w-prov">{_uv(archived.provenance.get("commit"))}</div>')
        else:
            bits.append('<div class="w-prov">absent</div>')
        if archived.scrub is None:
            bits.append('<div class="w-scrub">not recorded</div>')
        else:
            bits.append(f'<div class="w-scrub">{_uv(archived.scrub)}</div>')

    return f'<div id="world-{esc(label)}" class="w-section">{"".join(bits)}</div>'




def _bucket_html(row: dict[str, Any]) -> str:
    """The judge model's own answer for a world: its bucket and the systems its facts touch,
    or every draw's answer where the draws disagree (never reduced to one here)."""
    bits = []
    bucket = row.get("bucket")
    if bucket:
        cls = _BUCKET_CLASS.get(bucket, "bucket-other")
        bits.append(f'<span class="w-bucket {cls}">{_uv(bucket)}</span>')
    else:
        bits.append('<span class="w-bucket bucket-other">no bucket</span>')
    systems = row.get("systems")
    if isinstance(systems, list):
        bits.append(f'<span class="w-chip">systems: {_uv(", ".join(map(str, systems)))}</span>')
    if row.get("draws_disagree"):
        for draw in _items(row.get("draws")):
            draw = _mapping(draw)
            bits.append(f'<span class="w-chip">draw {_uv(draw.get("draw"))}: '
                        f'{_uv(draw.get("bucket"))} {_uv(draw.get("systems"))}</span>')
    return " ".join(bits)




def _facts_html(manifest_world: dict[str, Any]) -> str:
    """A world's natural-language facts, each statement and its entities as text."""
    facts = [f for f in _items(manifest_world.get("facts")) if isinstance(f, dict)]
    if not facts:
        return '<div class="w-facts">no facts (the capture\'s own answers)</div>'
    items = "".join(
        f'<div class="w-fact">{_uv(f.get("fact_id"))}: {_uv(f.get("statement"))} '
        f'<span class="w-entities">{_uv(", ".join(map(str, _items(f.get("entities")))))}'
        f'</span></div>' for f in facts)
    return f'<div class="w-facts">{items}</div>'




def _calls_html(calls: list[dict[str, Any]]) -> str:
    """The world's own served-ledger rows: each call with the decision word that answered it
    (`passthrough`, `oracle`, `real-error`, `refused`, `fault`)."""
    items = "".join(
        f'<div class="w-call">[{_uv(c.get("source"))}] {_uv(c.get("system"))} '
        f'{_uv(c.get("verb"))} {_uv(c.get("params"))}</div>' for c in calls)
    return f'<div class="w-calls">{items}</div>'




# =========================================================================================
# Findings section
# =========================================================================================


def _finding_row_html(f: _Finding) -> str:  # noqa: C901 — one row's worth of optional fields, each independently absent
    bits = [f'<span class="fr-world">{_uv(f.label)}</span>']
    if f.bucket is not None:
        cls = _BUCKET_CLASS.get(f.bucket, "bucket-other")
        bits.append(f'<span class="fr-bucket {cls}">{_uv(f.bucket)}</span>')
    if f.subject is not None:
        bits.append(f'<span class="fr-subject">{_uv(f.subject)}</span>')
    if f.stub:
        bits.append('<div class="fr-stub">draw document absent</div>')
        if f.claim:
            bits.append(f'<div class="fr-claim">{_uv(f.claim)}</div>')
    else:
        if f.claim is not None:
            bits.append(f'<div class="fr-claim">{_uv(f.claim)}</div>')
        if f.root_cause is not None:
            bits.append(f'<div class="fr-root">{_uv(f.root_cause)}</div>')
        if f.anchor is not None:
            bits.append(f'<span class="fr-anchor">{_uv(f.anchor)}</span>')
        if f.topic is not None:
            bits.append(f'<span class="fr-topic">{_uv(f.topic)}</span>')
        for e in _items(f.evidence):
            bits.append(f'<span class="fr-evidence">{_uv(e)}</span>')
        if f.world_field is not None:
            bits.append(f'<span class="fr-world-field">{_uv(f.world_field)}</span>')
    if f.recorded_id is not None:
        bits.append(f'<span class="fr-recorded-id">{_uv(f.recorded_id)}</span>')
    # The row id embeds the world label, so a label failing the id grammar gets no id at all.
    id_attr = f' id="{esc(f.row_id)}"' if _safe_id(f.label) else ""
    # Joined with a space: adjacent inline spans would otherwise glue their words together in
    # whitespace-collapsing text extraction.
    return f'<div{id_attr} class="fr-row">{" ".join(bits)}</div>'




def _render_findings_body(findings: _Findings) -> str:
    groups: dict[str, list[_Finding]] = {}
    for f in findings.rows:
        groups.setdefault(_disposition_heading_raw(f), []).append(f)

    parts = []
    for heading, group_rows in groups.items():
        rows_html = "".join(_finding_row_html(f) for f in group_rows)
        n = findings.group_index[heading]
        parts.append(f'<details id="fg-{n}" class="fg"><summary>{_uv(heading)}</summary>'
                    f'{rows_html}</details>')
    body = "".join(parts)

    dropped_bits = []
    for label, draw, dropped in findings.dropped:
        dropped_bits.append(f'<div class="fr-dropped">draw {_uv(draw)} of {_uv(label)}: '
                           f'{_uv(dropped)} dropped</div>')
    for label, draw, failure_reason in findings.draw_failures:
        dropped_bits.append(f'<div class="fr-dropped">draw {_uv(draw)} of {_uv(label)}: '
                           f'{_uv(failure_reason)} —</div>')
    body += "".join(dropped_bits)

    unreadable_total = sum(r.unreadable for r in findings.world_reports.values())
    skipped_total = sum(r.skipped for r in findings.world_reports.values())
    if unreadable_total:
        body += f'<div class="fr-unreadable">{unreadable_total} draw documents unreadable</div>'
    if skipped_total:
        body += f'<div class="fr-skipped">{skipped_total} skipped</div>'
    return body




def _render_findings_section(ep: _Episode) -> str:
    if ep.not_graded:
        return _page_section("sec-findings", "Findings (0)", "")
    body = _render_findings_body(ep.findings)
    if ep.off_roster:
        body += (f'<div class="fr-off-roster">{ep.off_roster} entries under worlds/ are not on '
                f'the record</div>')
    n = len(ep.findings.rows)
    return _page_section("sec-findings", f"Findings ({n})", body)




# =========================================================================================
# Leads section
# =========================================================================================


def _render_leads_section(ep: _Episode) -> str:
    # The same sectioned roster the worlds heading counts.
    blocks = [_render_world_leads(item.label, ep.leads[item.label]) for item in ep.sectioned]
    return _page_section("sec-leads", f"Leads ({len(ep.sectioned)})", "".join(blocks))




def _render_world_leads(label: str, leads: _WorldLeads) -> str:
    bits = []
    if leads.ledger_note is not None:
        bits.append(f'<div class="ld-served">{_uv(leads.ledger_note)}</div>')

    if not leads.archived:
        return f'<div id="leads-{esc(label)}" class="leads-section">not archived' \
              f'{"".join(bits)}</div>'

    if leads.dir_error is not None:
        bits.append(f'<div class="ld-dir">world directory unreadable: {_uv(leads.dir_error)}</div>')
    if leads.facts_error is not None:
        bits.append(f'<div class="ld-investigation">investigation record unavailable: '
                   f'{_uv(leads.facts_error)}</div>')
    if leads.moved:
        bits.append('<div class="ld-moved">the hand-off was revisited after the branch</div>')

    for lead_id, chain in leads.chains:
        safe = _safe_id(lead_id)
        # `names_one_file` is the path-traversal screen; `lead_chain` already answered unsafe
        # ids. An id that names a real file but is not HTML-id-safe is neutralized here,
        # discarding its content.
        file_safe = isinstance(lead_id, str) and family.names_one_file(lead_id)
        if file_safe and safe is None:
            bits.append(_unnameable(lead_id, what="lead id"))
            continue
        id_attr = f' id="ld-{esc(label)}-{esc(safe)}"' if safe is not None else ""
        payload = _items(chain.get("payload"))
        resolutions = _items(chain.get("resolutions"))
        resolutions_html = "".join(f'<div class="ld-resolution">{_uv(r)}</div>'
                                  for r in resolutions)
        bits.append(f'<div{id_attr} class="ld-lead">'
                   f'<span class="ld-id">{_uv(lead_id)}</span>'
                   f'<span class="ld-goal">{_uv(chain.get("goal"))}</span>'
                   f'<span class="ld-params">{_uv(chain.get("params"))}</span>'
                   f'<span class="ld-payload">{"".join(_uv(str(d)) for d in payload)}</span>'
                   f'<span class="ld-summary">{_uv(chain.get("summary"))}</span>'
                   f'{resolutions_html}'
                   f'</div>')

    return f'<div id="leads-{esc(label)}" class="leads-section">{"".join(bits)}</div>'
