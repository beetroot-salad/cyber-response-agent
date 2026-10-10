"""#1025 — the episode page reads the directory ONCE into a typed model and renders from it.

What the split buys, pinned behavior by behavior: a stray scalar where a record's writer produces
a list or a mapping degrades THAT slot and never the render (d01: only `family.yaml` refuses the
whole page); the findings walk runs once, so the tiles, the cards' footers and the findings
section cannot disagree about a count or a group number; the page's disposition rule reads an
absent `subject` exactly as `enqueue_report` does; the stage clock's whole-second stamps make a zero-length step a
real step; and the CLI's diagnostics come off the model's refusal slots, never a scan of the
rendered bytes. Each of these was a finding of the PR #1042 review, verified by probe against
the section-reads-its-own-records shape this model replaced.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from defender.tests import _episode_1025 as E
from defender.tests import _triplet_947 as T
from defender.tests import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

S = E.SAMPLE


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def visualize_episode():
    return E.page_module()


def render(ep) -> E.Page:
    return E.render(ep, module=visualize_episode())


def _heading_of(page: E.Page, row_id: str) -> str:
    group = page.group_of(row_id)
    for n in group.descendants():
        if n.tag == "summary":
            return n.text()
    return group.text()


def _tile(page: E.Page, index: int) -> str:
    tiles = page.elements(cls="vd-tile")
    assert len(tiles) == 4, f"expected four tiles, found {len(tiles)}"
    return tiles[index].text()


def _card(page: E.Page, label: str) -> E.Node:
    cards = [c for c in page.elements(cls="vd-cause") if c.text().startswith(label)]
    assert len(cards) == 1, [c.text() for c in page.elements(cls="vd-cause")]
    return cards[0]


def _card_link(card: E.Node) -> tuple[str, str]:
    """The footer link's `(href, text)`."""
    links = [n for n in card.find_all("a") if "href" in n.attrs]
    assert len(links) == 1, [n.attrs for n in card.find_all("a")]
    return links[0].attrs["href"], links[0].text()


# ---------------------------------------------------------------------------------------
# One boundary: a scalar where the writer produces a list or a mapping degrades one slot
# ---------------------------------------------------------------------------------------


def test_1025_a_scalar_worlds_field_in_the_manifest_is_refused_by_the_loader_gate(tmp_path):
    """`family.yaml` with `worlds: 5` is a manifest the runtime loader refuses (the page reads
    the manifest through the loader's own gate, `family.read_manifest`), so it is the one record
    that refuses the whole page (d01): `render_episode` raises the reader's `JudgeRefused`
    naming the field, and no page is written."""
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"] = 5
    T.write_family(ep.dir, manifest)
    with pytest.raises(E.sym("learning.judge", "JudgeRefused"), match="worlds"):
        E.render_episode(ep.dir, module=visualize_episode())
    assert not ep.page.exists(), "a page was written for a manifest the loader refused"


def test_1025_a_scalar_findings_field_in_a_draw_document_is_that_draws_own_absence(tmp_path):
    """`worlds/<label>/judge/1.yaml` with `findings: 5` contributes no rows; the other draws'
    rows render as usual and the page is written."""
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, 1, {"episode_outcome": "gradable", "findings": 5})
    page = render(ep)
    rows = [i for i in page.ids if i.startswith(f"f-{E.GRADED_WORLD}-")]
    assert not [r for r in rows if r.startswith(f"f-{E.GRADED_WORLD}-1-")], rows
    assert f"f-{E.GRADED_WORLD}-0-0" in rows


def test_1025_non_numeric_usage_and_odd_message_shapes_in_a_wire_log_leave_that_call_unpriced(tmp_path):
    """A judge trace whose response `usage` counts are text, whose request `message` is a
    list, and whose response `message.parts` is a number renders its block with the call
    unpriced — the judge row prices the other calls and the page is written."""
    ep = E.sample_episode(tmp_path)
    agent_id = f"judge:{E.GRADED_WORLD}:1"
    rows = E.trace_rows(agent_id)
    for row in rows:
        if row.get("kind") == "request":
            row["message"] = ["x"]
        if row.get("kind") == "response":
            row["usage"] = {"input_tokens": "abc", "output_tokens": None}
            row["message"] = {"parts": 5}
    E.write_trace(ep.dir, agent_id, rows)
    page = render(ep)
    block = page.text_of(f"tx-{E.trace_stem(agent_id)}")
    assert "unpriced" in block, block
    judge = page.text_of("stage-judge")
    assert "partial" in judge, judge


def test_1025_a_scalar_list_field_in_the_outcome_or_the_provenance_record_degrades_its_own_slot(tmp_path):
    """`outcome.yaml` with `unservable_worlds: 5`, `not_replayable: 5` and `drift: 5`, and
    `provenance.json` with `agreed.dirty_paths: 5`, render the records section with those lists
    empty and every other record intact — the outcome's word and reason still show."""
    ep = E.sample_episode(tmp_path)
    outcome_path = ep.dir / "outcome.yaml"
    outcome = yaml.safe_load(outcome_path.read_text(encoding="utf-8"))
    outcome.update(unservable_worlds=5, not_replayable=5, drift=5)
    outcome_path.write_text(yaml.safe_dump(outcome, sort_keys=False), encoding="utf-8")
    stamp_path = ep.dir / "provenance.json"
    stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    stamp["agreed"]["dirty_paths"] = 5
    stamp_path.write_text(json.dumps(stamp), encoding="utf-8")
    page = render(ep)
    records = page.text_of("sec-records")
    assert "no record" not in records, records
    assert f"outcome: accepted — {E.OUTCOME_REASON}" in records, records
    assert "provenance record unreadable" not in records, records
    assert E.LESSONS_COMMIT[:8] in records or "allow_dirty" in records, records
    assert not page.elements(cls="rc-outcome-call")
    assert not page.elements(cls="rc-world-record")
    assert not page.elements(cls="rc-dirty")


# ---------------------------------------------------------------------------------------
# One walk: the tiles, the cards and the findings section agree by construction
# ---------------------------------------------------------------------------------------


def test_1025_a_finding_with_no_subject_key_is_the_defenders_as_the_enqueue_read_it(tmp_path):
    """A draw finding that carries no `subject` at all (the pre-#1007 shape the live archive
    holds) sits in the "defender: enqueued" group and counts among tile 3's defender rows —
    `enqueue_report` defaults an absent subject to the defender and queued it, and the page's
    disposition mirrors the enqueue's reading rather than calling the absence a subject that
    names neither channel."""
    ep = E.sample_episode(tmp_path)
    findings = E._world_findings_rows()
    findings[0].pop("subject")
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=findings))
    page = render(ep)
    heading = _heading_of(page, f"f-{E.GRADED_WORLD}-0-0")
    assert heading == "defender: enqueued", heading
    assert f"{S.defender_enqueued} defender" in _tile(page, 2), _tile(page, 2)
    assert "0 unqueueable" in _tile(page, 2), _tile(page, 2)


def test_1025_the_card_footer_counts_and_links_the_same_defender_rows(tmp_path):
    """A graded world whose FIRST draw finding is addressed to the world author still has its
    card footer "4 findings · enqueued" link the group its defender rows sit in — the count
    and the anchor are one list of rows, never the first row of any subject."""
    ep = E.sample_episode(tmp_path)
    findings = E._world_findings_rows()
    findings.insert(0, findings.pop())  # the world-author finding now comes first
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=findings))
    doc = E.sample_grade()
    doc["world_findings"] = [r for r in doc["world_findings"]
                             if not r["finding_id"].endswith(f"/{E.GRADED_WORLD}/0/4")]
    doc["world_findings"].append(E.world_finding_queue_row(
        f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/0", "the world-author claim"))
    E.set_lane(doc, E.GRADED_WORLD, 0, 0, "world")
    for i in range(1, 5):
        E.set_lane(doc, E.GRADED_WORLD, 0, i, "defender")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    href, text = _card_link(_card(page, E.GRADED_WORLD))
    assert text == "4 findings · enqueued", text
    defender_group = page.group_of(f"f-{E.GRADED_WORLD}-0-1").id
    assert href == f"#{defender_group}", (href, defender_group)
    assert page.group_of(f"f-{E.GRADED_WORLD}-0-0").id != defender_group


def test_1025_a_discarded_episodes_card_says_never_eligible_not_enqueued(tmp_path):
    """With `verdict_word: discard` the graded world's defender rows are never eligible (O7),
    and its card's footer says so — "4 findings · never eligible" — rather than "enqueued"."""
    ep = E.sample_episode(tmp_path)
    E.write_judge(ep.dir, E.block_defender_lane(E.sample_grade(), "discard"))
    page = render(ep)
    href, text = _card_link(_card(page, E.GRADED_WORLD))
    assert text == "4 findings · never eligible", text
    assert "never eligible" in _heading_of(page, f"f-{E.GRADED_WORLD}-0-0")
    assert href == f"#{page.group_of(f'f-{E.GRADED_WORLD}-0-0').id}"


def test_1025_the_dropped_count_on_the_tile_and_in_the_accounting_is_the_draw_documents_own(tmp_path):
    """A draw document with `dropped_findings: 2` is counted on tile 3's split ("2 dropped")
    and in the queue accounting ("dropped 2"), the same figure the findings section shows per
    draw — never a literal zero."""
    ep = E.sample_episode(tmp_path)
    graded = E._world_findings_rows()
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=graded, dropped=2))
    page = render(ep)
    assert "2 dropped" in _tile(page, 2), _tile(page, 2)
    assert "dropped 2" in page.one(cls="vd-acct").text()
    assert "2 dropped" in page.text_of("sec-findings")


# ---------------------------------------------------------------------------------------
# The stage clock, the report slot, the CLI's diagnostics
# ---------------------------------------------------------------------------------------


def test_1025_a_step_that_starts_and_ends_within_one_second_still_bounds_the_header_wall(tmp_path):
    """`now_iso()` stamps whole seconds, so `verify` starting and ending on the same stamp is
    a real zero-length step, not an inverted pair: its endpoints feed the header span. With
    `verify` as the LAST step and its stamp at 10:11:00, the header reads the full 11m00s from
    the questioner's start, not the 9m00s that dropping it would leave."""
    ep = E.sample_episode(tmp_path)
    steps = E.every_step()
    names = [s for s, _a, _b in steps]
    verify = names.index("verify")
    steps[verify] = ("verify", "2026-09-09T10:11:00Z", "2026-09-09T10:11:00Z")
    steps[names.index("judge")] = ("judge", "2026-09-09T10:08:00Z", "2026-09-09T10:09:00Z")
    E.write_timing(ep.dir, steps)
    page = render(ep)
    assert "11m00s" in page.text, page.text_of("sec-stages")


def test_1025_a_world_report_with_no_headline_shows_the_readers_reason_in_its_slot(tmp_path):
    """`worlds/<label>/report.md` that is a symlink reads through the world-archive screen:
    the world's report slot shows the placeholder headline with the reader's own refusal
    beside it, and the page is written."""
    ep = E.sample_episode(tmp_path)
    target = tmp_path / "elsewhere.md"
    target.write_text("---\ndisposition: malicious\n---\nnot this world's\n", encoding="utf-8")
    E.plant_link(ep.world(E.GRADED_WORLD) / "report.md", target)
    page = render(ep)
    slot = page.section(f"world-{E.GRADED_WORLD}").find_all(cls="w-report")
    assert len(slot) == 1
    assert "could not be read" in slot[0].text(), slot[0].text()
    assert "malicious" not in slot[0].text(), slot[0].text()


def test_1025_the_cli_diagnostic_is_the_records_refusal_not_a_phrase_on_the_page(tmp_path, capsys):
    """An episode WITH a readable `judge.yaml` whose draw finding claim contains the words "no
    grade record" exits 0 with nothing on stderr: the diagnostics come off the record slots
    the page was built from, never a substring scan of the rendered bytes."""
    ep = E.sample_episode(tmp_path)
    graded = E._world_findings_rows()
    graded[0]["claim"] = "the run left no grade record behind"
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=graded))
    rc, out, err = E.cli_on(ep.dir, capsys, module=visualize_episode())
    assert rc == 0, (rc, out, err)
    assert str(ep.page) in out
    assert "no grade record" not in err, err
    assert "grade record unreadable" not in err, err
    E.plant_raw(ep.dir / "judge.yaml", "worlds: [\n")
    rc, _out, err = E.cli_on(ep.dir, capsys, module=visualize_episode())
    assert rc == 0
    assert "grade record unreadable" in err, err


# -----------------------------------------------------------------------------------------
# Second pass of the #1042 review: what the load boundary must refuse or degrade on its own
# -----------------------------------------------------------------------------------------


def _outside_world(tmp_path, ep) -> tuple[Path, str]:
    """A world-shaped directory OUTSIDE the episode tree carrying a planted draw finding and a
    planted alert, and the label that would reach it from `worlds/` by relative path."""
    outside = tmp_path / "outside_world"
    (outside / "judge").mkdir(parents=True)
    (outside / "judge" / "0.yaml").write_text(yaml.safe_dump(
        E.draw_doc(findings=[E.finding(claim="PLANTED-OUTSIDE-CLAIM")]), sort_keys=False),
        encoding="utf-8")
    (outside / "alert.json").write_text(json.dumps(
        {"alert_id": "planted", "rule": {"id": "planted-rule", "name": "PLANTED-OUTSIDE-RULE"}}),
        encoding="utf-8")
    label = os.path.relpath(outside, ep.dir / "worlds")
    assert label.startswith(".."), label
    return outside, label


def test_1025_a_manifest_label_off_the_directory_grammar_reads_nothing_from_disk(tmp_path):
    """A manifest world whose label carries `..` names a directory OUTSIDE the episode; the
    manifest reader (the runtime loader's own gate, `family.read_manifest`) refuses the label
    before anything is joined into a path, so the page refuses as a whole (d01) — the refusal
    names the world-token alphabet, and neither the planted draw finding nor the planted alert
    reaches it or any page."""
    ep = E.sample_episode(tmp_path)
    _outside, label = _outside_world(tmp_path, ep)
    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc(label, role="B", axis="planted"))
    T.write_family(ep.dir, manifest)
    with pytest.raises(E.sym("learning.judge", "JudgeRefused"),
                       match="world-token alphabet") as refused:
        E.render_episode(ep.dir, module=visualize_episode())
    assert "PLANTED-OUTSIDE" not in str(refused.value)
    assert not ep.page.exists(), "a page was written for a manifest the loader refused"


def test_1025_a_grade_row_label_off_the_directory_grammar_reads_nothing_from_disk(tmp_path):
    """The same for a `judge.yaml` row — the record is a tree a box can write — with the
    manifest clean: the planted finding is not walked."""
    ep = E.sample_episode(tmp_path)
    _outside, label = _outside_world(tmp_path, ep)
    grade = E.sample_grade()
    grade["worlds"].append(E.world_row(label, declared="malicious"))
    E.write_judge(ep.dir, grade, check=False)
    page = render(ep)
    assert "PLANTED-OUTSIDE-CLAIM" not in page.text
    assert "PLANTED-OUTSIDE-RULE" not in page.text
    assert f"f-{E.GRADED_WORLD}-0-0" in page.ids


def test_1025_a_nan_or_infinite_duration_is_that_slots_own_absence(tmp_path):
    """`duration_ms: NaN` in a run's result event and `Infinity` on a judge response row —
    `json.loads` admits both — cost the world's wall and that call's wall, never the render:
    the page is written, the world's cost still reads, and the lower bound is still a number."""
    ep = E.sample_episode(tmp_path)
    rd = ep.dir / "runs" / f"{E.EPISODE_ID}-{E.GRADED_WORLD}"
    E.plant_raw(rd / "tool_trace.jsonl", json.dumps(E.result_event()).replace(
        "180000", "NaN") + "\n")
    agent_id = f"judge:{E.GRADED_WORLD}:1"
    text = "".join(json.dumps(r) + "\n" for r in E.trace_rows(agent_id))
    E.plant_raw(ep.dir / "wire_logs" / f"{E.trace_stem(agent_id)}.jsonl",
                text.replace("1000.0", "Infinity"))
    page = render(ep)
    world = page.text_of(f"world-{E.GRADED_WORLD}")
    assert "$0.25" in world, world
    assert "nan" not in page.text.lower()
    assert "inf" not in page.text_of("sec-stages").lower()


def test_1025_runs_pruned_and_the_grade_unreadable_keeps_every_archived_world(tmp_path):
    """`runs/` pruned (J8: disposable) AND `judge.yaml` unparseable: the manifest's worlds
    are still archived under `worlds/<label>/`, so each keeps its section and none is counted
    as an entry off the record — the archive is evidence the episode reached RUNS."""
    ep = E.sample_episode(tmp_path)
    shutil.rmtree(ep.dir / "runs")
    E.plant_raw(ep.dir / "judge.yaml", "worlds: [\n")
    page = render(ep)
    assert sorted(page.ids_with("world-")) == sorted(f"world-{w}" for w in E.WORLDS)
    assert page.elements(cls="fr-off-roster") == [], page.text_of("sec-findings")
    assert "grade record unreadable" in page.text


def test_1025_the_verdict_word_note_asks_the_outcome_normalizer_not_a_local_list(tmp_path):
    """`verdict_word: " Survived"` is the family word `survived` as `normalized_judge_outcome`
    reads it (case-insensitive, trimmed), so tile 1 carries no "not a family word" note; a word
    the normalizer refuses carries it."""
    ep = E.sample_episode(tmp_path)
    grade = E.sample_grade()
    grade["verdict_word"] = " Survived"
    E.write_judge(ep.dir, grade, check=False)
    assert "not a family word" not in _tile(render(ep), 0)
    grade["verdict_word"] = "survived-ish"
    E.write_judge(ep.dir, grade, check=False)
    assert "not a family word" in _tile(render(ep), 0)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permission bits")
@pytest.mark.parametrize("rel", [
    "runs", "worlds", "wire_logs", f"worlds/{E.GRADED_WORLD}/gather_summaries",
    f"worlds/{E.GRADED_WORLD}/judge",
])
def test_1025_an_unlistable_directory_is_its_own_slots_absence(tmp_path, rel):
    """A directory the page cannot LIST (mode 000, non-root) — at any of the names the loader
    walks — costs what that directory would have shown, never the page: the page is written and
    the header still reads."""
    ep = E.sample_episode(tmp_path)
    target = ep.dir / rel
    target.mkdir(parents=True, exist_ok=True)
    target.chmod(0)
    try:
        page = render(ep)
    finally:
        target.chmod(0o755)
    assert E.BASE_STORY in page.text_of("sec-records")
