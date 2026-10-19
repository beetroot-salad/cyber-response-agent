"""Episode identity, verdict, and refusal presentation."""
from __future__ import annotations






from typing import Any



from defender._io import read_text_utf8



from defender._vocab import normalized_disposition





from defender.learning.judge import (
    JudgeRefused,
)





from defender.learning.judge.run import (
    SUBJECT_DEFENDER,
)


from defender.scripts.visualize.visualize_primitives import (
    ASSETS,
    CSS,
    esc,
)

from defender.scripts.visualize.episode_transcript import _FAMILY_LABEL as _FAMILY_LABEL, _money as _money, _page_section as _page_section, _uv as _uv

from defender.scripts.visualize.episode_worlds import _bucket_html as _bucket_html, _disposition_heading_raw as _disposition_heading_raw

from defender.scripts.visualize.episode_models import _Episode as _Episode, _Finding as _Finding, _items as _items, _mapping as _mapping



#: The page's own stylesheet, inlined after the shared run-page `CSS`, which knows nothing of
#: this page's classes. `test_1025_every_class_the_page_emits_has_a_rule` keeps them in step.
EPISODE_CSS = read_text_utf8(ASSETS / "episode.css")




def _render_refusal(episode_id: str, refusal: JudgeRefused) -> str:
    """The whole page for an episode the manifest reader refused: the reason, as text, and
    nothing read from the archive."""
    title = f"episode — {esc(episode_id)}"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>{CSS}
{EPISODE_CSS}</style></head><body id="top">
<div class="layout">
<article class="content episode">
<h1>{title}</h1>
<div class="refusal">{_uv(str(refusal))}</div>
</article>
</div>
</body></html>
"""




# =========================================================================================
# Header
# =========================================================================================


def _render_header(ep: _Episode) -> str:
    manifest = ep.manifest
    grade = ep.grade
    alert = ep.alert
    rule = alert.get("rule") if isinstance(alert, dict) else None
    rule_name = rule.get("name") if isinstance(rule, dict) else None
    alert_bits = []
    if isinstance(alert, dict) and alert.get("alert_id") is not None and rule_name:
        alert_bits.append(f'<span class="hd-alert">{_uv(rule_name)}</span>')
    else:
        alert_bits.append('<span class="hd-alert">alert rule: not on the record</span>')

    source_run_id = manifest.get("source_run_id")
    branch_message_id = manifest.get("branch_message_id")
    meta_bits = list(alert_bits)
    if isinstance(source_run_id, str):
        meta_bits.append(f'<span class="hd-source">source {_uv(source_run_id)}</span>')
    if branch_message_id is not None:
        meta_bits.append(f'<span class="hd-branch">branch message {_uv(branch_message_id)}</span>')

    if grade is not None:
        knobs = _mapping(grade.knobs)
        draws = _mapping(grade.draws)
        model = knobs.get("model", "?")
        effort = knobs.get("effort", "?")
        cap = knobs.get("payload_cap", "?")
        configured = draws.get("configured", "?")
        completed = draws.get("completed", "?")
        knob_line = (f"{_uv(model)} / {_uv(effort)} / cap {_uv(cap)} / "
                    f"draws {_uv(configured)}/{_uv(completed)}")
        meta_bits.append(f'<span class="hd-knobs">{knob_line}</span>')
        if grade.lessons_commit:
            meta_bits.append(f'<span class="hd-commit">{_uv(str(grade.lessons_commit)[:8])}</span>')

    meta = '<span class="hd-sep"> · </span>'.join(meta_bits)
    return f"""
<header class="top" id="sec-case">
  <h1>episode {_uv(ep.episode_id)}</h1>
  <div class="byline">{meta}</div>
</header>
"""




# =========================================================================================
# Verdict section: band, lede, tiles, cards
# =========================================================================================


def _render_verdict(ep: _Episode) -> str:  # noqa: C901, PLR0912, PLR0915 — the band, lede, four tiles and cards are one section
    grade = ep.grade
    if ep.not_graded:
        stamp = grade.not_graded
        band = (f'<div class="vd-band">not graded: {_uv(stamp.outcome)} — '
               f'<span class="vd-reason">{_uv(stamp.reason)}</span></div>')
        return _page_section("sec-verdict", "Verdict", band)

    if not ep.grade_rec.ok:
        band = f'<div class="vd-band">{_uv(ep.grade_rec.error)}</div>'
        return _page_section("sec-verdict", "Verdict", band)
    if grade is None:
        band = '<div class="vd-band">no grade record</div>'
        return _page_section("sec-verdict", "Verdict", band)

    entries = ep.entries
    rows = ep.findings.rows
    counts = ep.findings.counts

    lede_parts = []
    family_groups: dict[Any, list[_Finding]] = {}
    for f in rows:
        if f.label == _FAMILY_LABEL and f.disposition != "never_on_record":
            family_groups.setdefault(f.draw, []).append(f)
    # Draw keys may be `int` (document), `str` (stub) or `None`; the sort key
    # compares across them so a mixed set cannot raise `TypeError` out of the page.
    for draw in sorted(family_groups, key=_draw_sort_key):
        items = "".join(f'<div class="vd-family-item">{_uv(f.topic)}: {_uv(f.claim)}</div>'
                        for f in family_groups[draw])
        lede_parts.append(f'<div class="vd-family-draw">{items}</div>')

    family_failed = (grade.family or {}).get("draws_failed_reason")
    if family_failed:
        lede_parts.append(f'<div class="vd-family-failed">{_uv(family_failed)}</div>')

    # #1234 retired the family word: the badge is the record's own validity (O5).
    queued = grade.enqueued_rows + grade.world_enqueued_rows
    lede_parts.append(f'<div class="vd-lede">{queued} findings queued</div>')

    badge = f'<span class="vd-badge">{_uv(grade.validity)}</span>'
    meta = f'<span class="vd-meta">validity {_uv(grade.validity)}</span>'

    # The record's own partition, never re-derived here.
    graded = grade.graded_worlds
    agree = 0
    for label in sorted(graded):
        entry = entries.get(label)
        row = entry.row if entry is not None else None
        if row is not None and _normalized_disposition(row.get("verdict")) == \
                _normalized_disposition(row.get("declared")):
            agree += 1
    tile1 = (
        f'<div class="vd-tile" id="vd-tile-1">{len(graded)} worlds judged · verdict = '
        f'declared on {agree} of {len(graded)}</div>')

    unjudged_captions = [f"{_uv(w.label)} — {_uv(w.row.get('ungradable_reason'))}"
                         for w in entries.values()
                         if w.row is not None and w.row.get("ungradable")]
    tile2 = (
        f'<div class="vd-tile" id="vd-tile-2">{len(graded)} of '
        f'{sum(1 for w in entries.values() if w.row is not None)}'
        f'<div class="vd-caption">{"; ".join(unjudged_captions)}</div></div>')

    findings_total = len(rows)
    split_parts = [f"{counts['defender']} defender", f"{counts['world_author']} world author",
                  f"{counts['unqueueable']} unqueueable", f"{counts['dropped']} dropped"]
    # The walk's own count, not `grade.enqueued_rows` (the record's figure, shown separately in
    # the queue accounting).
    tile_queued = counts["defender"] + counts["world_author"]
    tile3 = (
        f'<div class="vd-tile" id="vd-tile-3">{tile_queued} of '
        f'{findings_total} <div class="vd-caption">{" / ".join(split_parts)}</div></div>')

    # Without a real wall (absent, unreadable, or every row inverted) this tile shows the
    # lower-bound estimate. `measured` is decided once at load, so this agrees with the stages
    # header, which carries the figure when there is one.
    bound_html = f'<br>{ep.lower_bound}' if not ep.timing.measured else ""
    tile4 = (
        f'<div class="vd-tile" id="vd-tile-4">{_money(ep.total_cost)}'
        f'<div class="vd-caption">{ep.worlds_wall}{bound_html}</div></div>')

    cards = []
    for w in entries.values():
        if w.label == ep.control_label or w.row is None or w.row.get("ungradable"):
            continue
        row = w.row
        header = f"{_uv(row.get('declared'))} → {_uv(row.get('verdict'))}"
        heading = _bucket_html(row)
        # The footer counts this world's defender rows and links the group of the first one, so
        # the count and the anchor refer to the same rows.
        world_group = [f for f in rows if f.label == w.label and f.subject == SUBJECT_DEFENDER]
        n_findings = len(world_group)
        footer_word = ("not measured" if row.get("measured") is False else
                       "enqueued" if all(f.disposition == "defender" for f in world_group)
                       else "not queued")
        group_n = (ep.findings.group_index.get(_disposition_heading_raw(world_group[0]), 1)
                   if world_group else 1)
        off_roster_note = ("" if w.in_manifest or w.run_dir_name is not None
                          else '<div class="vd-off-roster">not in the manifest</div>')
        cards.append(
            f'<div class="vd-cause">{_uv(w.label)} {header} {heading}{off_roster_note}'
            f'<a href="#fg-{group_n}">{n_findings} findings · {footer_word}</a>'
            f'</div>')

    body = (f'<div class="vd-band">{badge}{meta}</div>'
           f'{"".join(lede_parts)}{tile1}{tile2}{tile3}{tile4}'
           f'<div class="vd-cards">{"".join(cards)}</div>'
           f'{_render_queue_accounting(grade, counts)}')
    return _page_section("sec-verdict", "Verdict", body)




def _draw_sort_key(draw: Any) -> tuple[int, Any]:
    if isinstance(draw, int):
        return (0, draw)
    if isinstance(draw, str):
        return (1, draw)
    return (2, "")




def _normalized_disposition(value: Any) -> Any:
    """A disposition through the vocabulary's normalizer, or the raw value if it knows none."""
    if not isinstance(value, str):
        return value
    return normalized_disposition(value) or value




def _render_queue_accounting(grade: Any, counts: dict[str, int]) -> str:
    lines = [
        f'defender: {grade.enqueued_rows} enqueued to {_uv(grade.enqueued_to)}',
        f'questioner: {grade.world_enqueued_rows} enqueued to {_uv(grade.world_enqueued_to)}',
        f'unqueueable {counts["unqueueable"]}',
        f'dropped {counts["dropped"]}',
        f'family malformed replies {_uv(_mapping(grade.family).get("malformed_replies"))}',
    ]
    record_vs_page = f'record: {grade.enqueued_rows} enqueued · page found: {counts["defender"]}'
    if grade.enqueued_rows != counts["defender"]:
        record_vs_page += (f' <span class="vd-disagree">record and page disagree by '
                          f'{abs(grade.enqueued_rows - counts["defender"])}</span>')
    lines.append(record_vs_page)

    for line in _items(getattr(grade, "unqueueable_findings", None)):
        lines.append(_uv(str(line)))

    return f'<details class="vd-acct"><summary>Queue accounting</summary>' \
          f'{"".join(f"<div>{line_}</div>" for line_ in lines)}</details>'
