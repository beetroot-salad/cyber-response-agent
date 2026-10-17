"""#1025 — the verdict section and the findings section: the band, the lede, the four tiles,
the per-sibling cards, the queue accounting, and every finding shown exactly once with the
enqueue's own disposition.

O1/O2 as the human resolved them (§7 Q3–Q8, J9a–f, J10, J11, J14): the roster the findings
walk takes is the manifest's labels ∪ labels with a `judge.yaml` row ∪ {family} — never a
`worlds/*` glob — with off-roster documents counted in one line and never rendered; the join is
on the `(world, draw, index)` suffix of the recorded `finding_id`; a recorded row whose draw
document is gone renders as a stub from the record's own text; the recorded counts and the
page's own walk are both shown and a disagreement is said out loud; the one draw reader reports
what it skipped and the page shows the count; findings on disk with no `judge.yaml` render under
one "no grade record — not enqueued" group; the unusual rows (unknown subject, non-mapping,
refused-for-sample, missing `findings` key, failure-only draw, over-index draw, a repeated
`finding_id` string) take the record's disposition; bound slots only, plus each draw's own
`episode_outcome` word; an off-vocabulary bucket / verdict / reason word renders as escaped text
with a neutral class and no gloss; a `not_graded` page keeps everything but the verdict layer.

Every count on the expected side is the fixture's declared figure (`E.SAMPLE`), never a number
the test computed from the records. RED AGAINST HEAD: the page module does not exist.
"""
from __future__ import annotations

import re
import shutil
import pathlib
from pathlib import Path

import pytest
import yaml

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests import test_1025_stage_timing as ST
from defender.tests import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

S = E.SAMPLE
LEDE_LINE = f"{S.queued} findings queued"
#: Neither sample sibling's report verdict (`inconclusive`) is its declared disposition.
TILE_ONE = f"{S.graded} worlds judged · verdict = declared on 0 of {S.graded}"


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def visualize_episode():
    """The target module, `defender.scripts.visualize.visualize_episode`, imported at call time
    (it does not exist at the spec's base — one failure per test, never a collection error)."""
    return E.page_module()


def render(ep) -> E.Page:
    """`visualize_episode().render_episode(runs, <episode id>)` — the real entry point — then
    the page it wrote, parsed."""
    return E.render(ep, module=visualize_episode())


def cli(argv, capsys):
    """`visualize_episode().main(argv)` with its stdout / stderr captured."""
    return E.cli(argv, capsys, module=visualize_episode())


def hook_page(episode_dir) -> E.Page:
    """The page the launcher's hook wrote, parsed — after checking it is byte-identical to a
    standalone `visualize_episode().render_episode` over the same directory: the hook is a
    plain call to the same function (d40) and the page is a pure function of the directory."""
    page = pathlib.Path(episode_dir) / E.PAGE_NAME
    assert page.is_file(), f"the launcher did not write {E.PAGE_NAME}"
    written = page.read_bytes()
    render(episode_dir)
    assert page.read_bytes() == written, "the hook's page differs from a standalone render"
    return E.Page.parse(written.decode("utf-8"))


def _rows(page: E.Page) -> list[str]:
    """Every finding row id `f-<world>-<draw>-<index>` on the page (groups are `fg-`)."""
    return [i for i in page.ids if i.startswith("f-")]


def _group_of(page: E.Page, row_id: str) -> E.Node:
    return page.group_of(row_id)


def _group_id(page: E.Page, row_id: str) -> str:
    group_id = page.group_of(row_id).id
    assert group_id is not None
    return group_id


def _heading(group: E.Node) -> str:
    """A group's own heading — its first `summary` / `h2` / `h3` — as text."""
    for n in group.descendants():
        if n.tag in ("summary", "h2", "h3", "h4"):
            return n.text()
    return group.text()


def _draw_findings(ep: E.Episode, label: str, draw: int = 0) -> list[dict]:
    """The findings a draw document on disk files, in filing order (investigator findings, then
    world findings), each tagged with its `subject` so `E.draw_doc` files it back in the same
    list — read back so a scenario can extend them."""
    doc = yaml.safe_load(
        (ep.world(label) / "judge" / f"{draw}.yaml").read_text(encoding="utf-8"))
    return ([dict(f, subject="defender") for f in doc.get("investigator_findings") or []]
            + [dict(f, subject="world") for f in doc.get("world_findings") or []])


def _tiles(page: E.Page) -> list[E.Node]:
    return page.elements(cls="vd-tile")


def _tile(page: E.Page, index: int) -> E.Node:
    """Tile `index` of the four — fewer tiles is the test's own failure."""
    tiles = _tiles(page)
    assert len(tiles) == 4, f"expected four tiles, found {len(tiles)}"
    return tiles[index]


def _cards(page: E.Page) -> list[E.Node]:
    return page.elements(cls="vd-cause")


#: The ungradable world's reason on the live-996 shape's record.
UNGRADABLE_REASON = E.ungradable_row(E.PASSTHROUGH_WORLD)["ungradable_reason"]


def _live996(tmp_path: Path, **kw) -> E.Episode:
    """The second archive's shape: no family draw, no `samples.yaml`, an ungradable row, a
    record with no family row (the family call never ran) and no ledger."""
    ep = E.sample_episode(tmp_path, family_draw=False, samples=False, judge=False, **kw)
    doc = E.sample_grade(family=False)
    doc["worlds"] = [E.ungradable_row(E.PASSTHROUGH_WORLD, declared="benign"),
                     E.world_row(E.GRADED_WORLD, declared="malicious")]
    for key in ("world_enqueued_rows", "world_enqueued_to", "dispositions"):
        del doc[key]
    E.write_judge(ep.dir, doc)
    return ep


# ---------------------------------------------------------------------------------------
# d16 / d17 / d18 / d19 / d20 / d21 — the band, the lede, the tiles
# ---------------------------------------------------------------------------------------


def test_1025_the_lede_lists_family_draw_findings_verbatim_grouped_by_draw_or_opens_with_the_templated_line_when_there_is_no_family_draw(
        tmp_path):
    """Sample: the lede's first line carries the three family findings as `topic: claim`
    escaped, then the templated line "13 findings queued"; a synthetic two-draw family renders two groups in draw order
    without merging; the live-996 shape (no `worlds/family/`) opens with the templated line; a
    family row's `draws_failed_reason` renders where the first line would be. (#1234 retired the
    family word the templated line used to open with.)
    """
    ep = E.sample_episode(tmp_path)
    band = render(ep).text_of("sec-verdict")
    for row in E.family_findings():
        assert f"{row['topic']}: {row['claim']}" in band, band
    assert LEDE_LINE in band, band
    assert band.index("family topic 0") < band.index(LEDE_LINE), "the templated line came first"

    E.draw_document(ep.dir, E.FAMILY, 1, E.family_draw_doc(
        findings=[E.finding(subject="world", topic="second-draw topic", claim="second-draw claim")]))
    two_draws = E.record_draws(E.sample_grade(), E.FAMILY, (0, 1))
    E.set_lane(two_draws, E.FAMILY, 1, 0, "world")
    E.write_judge(ep.dir, two_draws)
    band = render(ep).text_of("sec-verdict")
    assert band.index("family topic 2") < band.index("second-draw topic: second-draw claim")

    live = _live996(tmp_path / "live")
    live_band = render(live).text_of("sec-verdict")
    assert "family topic" not in live_band, live_band
    assert "findings queued" in live_band, live_band

    doc = E.sample_grade()
    doc["family"] = {"completed_draws": 0, "malformed_replies": 0,
                     "draws_failed_reason": "the family call faulted: TransportFault"}
    E.write_judge(ep.dir, doc)
    band = render(ep).text_of("sec-verdict")
    assert "the family call faulted: TransportFault" in band
    assert band.index("the family call faulted") < band.index("findings queued")


def test_1025_the_badge_is_the_records_validity_and_names_no_retired_family_word(tmp_path):
    """#1234 retired the family word (`family_outcome` / `verdict_word`, A4): the badge and the
    meta line carry the record's own O5 word, `validity` — `usable` on the sample — and no
    family word appears in the band. The live-996 shape (no family row) reads the same.
    """
    page = render(E.sample_episode(tmp_path))
    assert page.one(cls="vd-badge").text() == "usable", page.one(cls="vd-badge").text()
    assert "validity usable" in page.one(cls="vd-meta").text()
    band = page.text_of("sec-verdict")
    for retired in ("undecidable", "survived", "caught", "discard"):
        assert retired not in band, (retired, band)

    live = render(_live996(tmp_path / "live"))
    assert live.one(cls="vd-badge").text() == "usable"
    assert "survived" not in live.text_of("sec-verdict")


def test_1025_the_verdict_tile_carries_judged_and_verdict_equals_declared_counts_on_both_archives(
        tmp_path):
    """Sample tile 1: "2 worlds judged · verdict = declared on 0 of 2"; the live-996 shape (one
    row ungradable, so not judged): "1 worlds judged · verdict = declared on 0 of 1". (#1234
    retired the family word that sat beside the count.)
    """
    tile = _tile(render(E.sample_episode(tmp_path)), 0)
    assert TILE_ONE in tile.text(), tile.text()

    live = _tile(render(_live996(tmp_path / "live")), 0)
    assert "1 worlds judged · verdict = declared on 0 of 1" in live.text(), live.text()


def test_1025_tiles_two_to_four_carry_judged_of_rows_with_reasons_queued_of_total_split_and_cost_with_the_labelled_lower_bound(
        tmp_path):
    """Sample: tile 2 "2 of 2" (judged of the record's rows) with no caption; tile 3 "13 of
    13" split 8 defender / 5 world author / 0 unqueueable / 0 dropped; tile 4 "$3.5500" with
    the worlds' wall range 3m00s–10m00s and "≈ 16m00s lower bound on wall: model calls +
    longest world"; the live-996 shape's ungradable world is not in the judged count and is
    named with its reason in tile 2's caption.
    """
    page = render(E.sample_episode(tmp_path))
    two, three, four = (_tile(page, i).text() for i in (1, 2, 3))
    assert two == f"{S.graded} of {S.graded}", two
    assert f"{S.queued} of {S.findings}" in three, three
    for part in (f"{S.defender_enqueued} defender", f"{S.world_author} world author",
                 "0 unqueueable", "0 dropped"):
        assert part in three, (part, three)
    assert S.total_cost in four, four
    assert f"{S.shortest_world}–{S.longest_world}" in four, four
    assert f"≈ {S.lower_bound} lower bound on wall: model calls + longest world" in four, four

    live = render(_live996(tmp_path / "live"))
    assert "1 of 2" in _tile(live, 1).text(), _tile(live, 1).text()
    assert f"{E.PASSTHROUGH_WORLD} — {UNGRADABLE_REASON}" in _tile(live, 1).text(), (
        _tile(live, 1).text())


def test_1025_a_not_graded_stamp_renders_its_reason_and_no_tiles_cards_or_findings_table(tmp_path):
    """An episode whose `judge.yaml` carries `not_graded: {outcome, reason}` renders the reason
    in the verdict band and has no `vd-tile`, no card and no finding rows; positive control:
    the sample renders four tiles, two cards and thirteen rows.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    assert len(_tiles(page)) == 4
    assert len(_cards(page)) == 2
    assert len(_rows(page)) == S.findings

    doc = E.sample_grade()
    doc["not_graded"] = {"outcome": "unusable", "reason": "2 worlds could not be judged (b, c)"}
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "2 worlds could not be judged (b, c)" in page.text_of("sec-verdict")
    assert _tiles(page) == []
    assert _cards(page) == []
    assert _rows(page) == []


def test_1025_a_not_graded_page_below_the_band(tmp_path):
    """"Nothing below the band" is the verdict section's own layer (J14): a `not_graded` page
    carries no lede findings line, no tiles, no cards and no findings section rows — and the
    stage table, every world section (each "not graded"), every leads block and the records
    section still render as for any episode.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["not_graded"] = {"outcome": "unusable", "reason": "STAMP-REASON"}
    E.write_judge(ep.dir, doc)
    page = render(ep)
    band = page.text_of("sec-verdict")
    assert "STAMP-REASON" in band
    assert "findings queued" not in band
    assert "family topic" not in band
    assert _tiles(page) == []
    assert _cards(page) == []
    assert _rows(page) == []
    assert "stage-timing" in page.by_id
    for label in E.WORLDS:
        assert "not graded" in page.text_of(f"world-{label}")
        assert f"leads-{label}" in page.by_id
    assert E.BASE_STORY in page.text_of("sec-records")


def test_1025_an_episode_whose_judge_failed_at_the_enqueue_still_renders_its_stages_and_worlds_and_says_which_world_is_in_progress(
        tmp_path):
    """A launcher-produced episode whose judge pass failed at the enqueue — the findings queue's
    holding folder is a regular file, so the append is refused after the draws — still renders.
    #1234 A6 writes `judge.yaml` BEFORE the appends, with the world being committed in state
    `queueing` (before #1234 the record was written last and never landed): the page names that
    world "in progress", the world the pass never reached is ungraded, the stage table has a
    row per step, and the draw the record names renders its one row.
    """
    # The handle refuses a root that is not a folder up front (before any draw is paid for),
    # so the post-draw refusal this scenario needs is the queue's holding folder being a
    # regular file: the root opens, the draws run, and only the enqueue is refused.
    (tmp_path / "learning-state" / "_pending").write_text("not a directory", encoding="utf-8")
    # One investigator finding per world draw; the family scope refuses a world-scope reply,
    # so the family call completes no draw.
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc(
        bucket="lead-quality", systems=["idp"])))
    launch = ST._launch(tmp_path, judge=judge)
    assert launch.rc == 0
    assert launch.judge.calls > 0
    ep = launch.episode_dir
    record = J.judge_record(ep)
    assert J.world_rows(record)["b"]["state"] == "queueing", (
        "the control failed: the pass did not stop while committing world b")
    page = hook_page(ep)
    assert "in progress" in page.text_of("world-b"), page.text_of("world-b")
    assert "ungraded" in page.text_of("world-c"), page.text_of("world-c")
    timing = page.text_of("stage-timing")
    assert all(step in timing for step in ST.EXPECTED_STEPS)
    assert _rows(page) == ["f-b-0-0"], _rows(page)


def test_1025_draw_documents_exist_but_judge_yaml_does_not(tmp_path):
    """The failed-judge snapshot (J9a): every per-draw document is on disk and `judge.yaml` is
    not. #1234 A6: the page shows only the draws a record names (`judge.recorded_draws`), and
    with no record it names none — so no finding row renders and no disposition is claimed;
    the band says there is no grade record. (Before #1234 the rows rendered under one "no
    grade record — not enqueued" group.)
    """
    ep = E.sample_episode(tmp_path, judge=False)
    page = render(ep)
    assert "no grade record" in page.text_of("sec-verdict")
    assert _rows(page) == []
    assert "defender claim" not in page.raw


# ---------------------------------------------------------------------------------------
# d12 / d13 / d14 / d15 / d39 — the findings walk
# ---------------------------------------------------------------------------------------


def test_1025_every_finding_across_per_draw_docs_and_family_draws_renders_exactly_once_keyed_world_draw_index(
        tmp_path):
    """On the sample the page carries exactly 13 `f-<world>-<draw>-<index>` rows, each id once
    (8 defender enqueued, 5 world-author across `no_remote_session/0/4`,
    `prior_fake_key_precedent/0/4`, `family/0/{0,1,2}`); the grade row's own `findings` copy
    of its draws adds nothing.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    rows = _rows(page)
    assert len(rows) == S.findings, rows
    assert len(set(rows)) == S.findings, rows
    expected = {f"f-{E.PASSTHROUGH_WORLD}-0-{i}" for i in range(5)}
    expected |= {f"f-{E.GRADED_WORLD}-0-{i}" for i in range(5)}
    expected |= {f"f-{E.FAMILY}-0-{i}" for i in range(3)}
    assert set(rows) == expected, set(rows) ^ expected
    assert page.all_ids.count(f"f-{E.GRADED_WORLD}-0-4") == 1


def test_1025_a_findings_disposition_reproduces_the_enqueues_partition_unqueueable_blocked_by_verdict_or_enqueued(
        tmp_path):
    """Sample: both siblings' 4 defender findings read enqueued (the episode has
    the 5 world-author rows read enqueued; a ledger entry re-filed unqueueable marks that id
    unqueueable with its reason; the record of a pass whose worlds were not measured (#1234
    A7: the world gate's `not_measured` lane, which replaced the retired family-word block)
    groups every judged world's defender findings under "not queued — the world is not
    measured", never enqueued, and tile 3's split reads 0 defender / 5 world author / 0
    unqueueable.

    EVERY DISPOSITION IS THE RECORD'S LEDGER (`judge.yaml.dispositions`, what the enqueue pass
    wrote down as it filed each finding), never a rule the page runs over the rows: the page
    used to carry a copy of the enqueue's lane rule, then the rule itself fed with inputs it
    rebuilt from the record, and both drifted from the pass at the edges. The enqueue's
    precedence is therefore visible here only as the ledger the fixture writes in the pass's
    shape (`E.set_lane` re-files the defender entries), and
    `test_1025_the_fixture_ledger_is_the_passes_own` holds that fixture to the real pass.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    for label in (E.PASSTHROUGH_WORLD, E.GRADED_WORLD):
        for i in range(4):
            group = _group_of(page, f"f-{label}-0-{i}").text()
            assert "defender: enqueued" in group, group
            assert "not measured" not in group, group
    for row in (f"f-{E.PASSTHROUGH_WORLD}-0-4", f"f-{E.GRADED_WORLD}-0-4", f"f-{E.FAMILY}-0-0"):
        assert "world author: enqueued" in _group_of(page, row).text(), row

    doc = E.set_lane(E.sample_grade(), E.GRADED_WORLD, 0, 1, "unqueueable",
                     "the citation names no file")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    group = _group_of(page, f"f-{E.GRADED_WORLD}-0-1").text()
    assert "unqueueable" in group, group
    assert "the citation names no file" in group, group

    # the record as the pass writes it when no judged world is measured: `enqueued_rows` 0 and
    # the defender entries filed `not_measured`
    doc = E.sample_grade()
    doc["enqueued_rows"] = 0
    for row in doc["worlds"]:
        row.update(measured=False, not_measured_reason="a draw files unreachable")
    for label in (E.PASSTHROUGH_WORLD, E.GRADED_WORLD):
        for i in range(4):
            E.set_lane(doc, label, 0, i, "not_measured")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    for label in (E.PASSTHROUGH_WORLD, E.GRADED_WORLD):
        for i in range(4):
            group = _group_of(page, f"f-{label}-0-{i}").text()
            assert "not queued — the world is not measured" in group, group
            assert "enqueued" not in group, group
    three = _tile(page, 2).text()
    for part in ("0 defender", f"{S.world_author} world author", "0 unqueueable"):
        assert part in three, (part, three)


def test_1025_findings_render_one_table_per_addressee_with_the_seven_columns_family_rows_at_family_level_and_dropped_counts_per_draw(
        tmp_path):
    """Two addressee tables (defender / world author): the defender rows and the world-author
    rows sit in disjoint groups whose headings name their addressee, and every row carries its
    world, bucket, disposition (on the row or its group), claim, root cause, anchor and
    evidence; the three family rows sit under world `family` with their `anchor` verbatim and
    no parsed world. (#1234 A13 retired the draw's `dropped_findings` count: a dropped finding
    is its own ledger entry, so it renders as a row under its drop lane's group and tile 3
    counts it as dropped.)
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    defender = {_group_id(page, f"f-{E.GRADED_WORLD}-0-{i}") for i in range(4)}
    authors = {_group_id(page, f"f-{w}-0-4") for w in (E.PASSTHROUGH_WORLD, E.GRADED_WORLD)}
    authors |= {_group_id(page, f"f-{E.FAMILY}-0-{i}") for i in range(3)}
    assert defender.isdisjoint(authors), (defender, authors)
    assert all("defender" in _heading(page.section(g)) for g in defender)
    assert all("world author" in _heading(page.section(g)) for g in authors)
    graded_findings = _draw_findings(ep, E.GRADED_WORLD)
    for i, row in enumerate(graded_findings):
        text = page.text_of(f"f-{E.GRADED_WORLD}-0-{i}")
        pointers = row.get("contrast_evidence") or row["evidence"]
        for fact in (E.GRADED_WORLD, row["bucket"], row["claim"], row["root_cause"],
                     row["anchor"], pointers[0]):
            assert fact in text, (fact, text)
        assert "enqueued" in text or "enqueued" in _group_of(page, f"f-{E.GRADED_WORLD}-0-{i}").text()
    for i, row in enumerate(E.family_findings()):
        text = page.text_of(f"f-{E.FAMILY}-0-{i}")
        assert row["anchor"] in text, text
        assert "family" in text, text
        assert E.PASSTHROUGH_WORLD not in text.replace(row["anchor"], "").replace(
            row["evidence"][0], ""), text
    assert "0 dropped" in _tile(page, 2).text()

    doc = E.sample_grade()
    E.set_lane(doc, E.GRADED_WORLD, 0, 0, "dropped_unresolved")
    E.set_lane(doc, E.GRADED_WORLD, 0, 1, "dropped_no_pair")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "dropped — no pointer resolves" in _heading(_group_of(page, f"f-{E.GRADED_WORLD}-0-0"))
    assert "dropped — no two-run contrast pair" in _heading(
        _group_of(page, f"f-{E.GRADED_WORLD}-0-1"))
    assert "2 dropped" in _tile(page, 2).text(), _tile(page, 2).text()


def test_1025_a_world_drawn_twice_renders_both_draws_findings_once_each_in_numeric_draw_order_via_draws_on_disk(
        tmp_path):
    """A copied episode with `worlds/prior_fake_key_precedent/judge/{0,1,10}.yaml` renders that
    world's findings under draws 0, 1, 10 in that order (numeric, not `0, 10, 1` as text), each
    `f-…-<draw>-<i>` once, and an `01.yaml` planted beside them is ignored, as `draws_on_disk`
    ignores it.
    """
    ep = E.sample_episode(tmp_path)
    for draw in (1, 10):
        E.draw_document(ep.dir, E.GRADED_WORLD, draw, E.draw_doc(
            findings=[E.finding(subject="defender", claim=f"draw {draw} claim")]))
    E.draw_document(ep.dir, E.GRADED_WORLD, "01", E.draw_doc(
        findings=[E.finding(subject="defender", claim="NON-CANONICAL STEM")]), check=False)
    # #1234 A6: the page shows the draws the record names, so the record names all three
    E.write_judge(ep.dir, E.record_draws(E.sample_grade(), E.GRADED_WORLD, (0, 1, 10)))
    page = render(ep)
    rows = [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]
    assert f"f-{E.GRADED_WORLD}-1-0" in rows, rows
    assert f"f-{E.GRADED_WORLD}-10-0" in rows, rows
    assert len(rows) == len(set(rows)) == 7, rows
    order = [page.raw.index(f'id="f-{E.GRADED_WORLD}-{d}-0"') for d in (0, 1, 10)]
    assert order == sorted(order), "draws are not in numeric order"
    assert "NON-CANONICAL STEM" not in page.raw


# ---------------------------------------------------------------------------------------
# d22 / d23 / d24 — queue accounting, cards, no synthesis
# ---------------------------------------------------------------------------------------


def test_1025_queue_accounting_lists_per_queue_rows_destination_as_recorded_unqueueable_malformed_and_dropped_counts(
        tmp_path):
    """The collapsed details carry "defender: 8 enqueued to <the recorded path>" (the path as
    recorded, escaped, not a link), "questioner: 5 enqueued to …", unqueueable 0, the family
    row's malformed replies 0 and dropped 0. (#1234: the record's two queue-malformed counts
    are gone; the family row carries its own malformed replies.)
    """
    page = render(E.sample_episode(tmp_path))
    acct = page.elements(cls="vd-acct")
    assert acct, "no queue-accounting details"
    text = acct[0].text()
    assert f"defender: {S.defender_enqueued} enqueued to {E.ENQUEUED_TO}" in text, text
    assert f"questioner: {S.world_author} enqueued to {E.WORLD_ENQUEUED_TO}" in text, text
    assert "unqueueable 0" in text, text
    assert "family malformed replies 0" in text, text
    assert "dropped 0" in text, text
    assert not [h for h in page.hrefs if "_pending/findings.jsonl" in h], "the path became a link"


def test_1025_one_card_per_graded_world_with_declared_to_verdict_bucket_and_systems_heading_and_a_footer_linking_its_findings_group(
        tmp_path):
    """Sample: two cards; `no_remote_session`'s header "benign → inconclusive", heading the
    judge model's bucket "lead-set" and its systems, footer "4 findings · enqueued" linking to
    its `fg-<n>`; `prior_fake_key_precedent`'s heading "decision-discipline" and footer "4
    findings · enqueued"; the live-996 shape renders one card (none for the ungradable world or
    the control); no card contains a family finding's claim.
    """
    page = render(E.sample_episode(tmp_path))
    cards = {c.text(): c for c in _cards(page)}
    assert len(cards) == 2, list(cards)
    quiet = next(t for t in cards if E.PASSTHROUGH_WORLD in t)
    graded = next(t for t in cards if E.GRADED_WORLD in t)
    assert re.search(r"benign\s*→\s*(said\s+)?inconclusive", quiet), quiet
    assert "lead-set" in quiet, quiet
    assert f"systems: {E.SYSTEM}" in quiet, quiet
    assert "4 findings · enqueued" in quiet, quiet
    quiet_group = _group_id(page, f"f-{E.PASSTHROUGH_WORLD}-0-0")
    assert f"#{quiet_group}" in [a.attrs.get("href") for a in cards[quiet].find_all("a")]
    assert "decision-discipline" in graded, graded
    assert "4 findings · enqueued" in graded, graded
    graded_group = _group_id(page, f"f-{E.GRADED_WORLD}-0-0")
    assert f"#{graded_group}" in [a.attrs.get("href") for a in cards[graded].find_all("a")]
    for text in cards:
        assert "family claim" not in text

    live = render(_live996(tmp_path / "live"))
    assert len(_cards(live)) == 1
    assert E.GRADED_WORLD in _cards(live)[0].text()


def test_1025_no_hand_written_sentence_from_the_artifact_appears_while_every_templated_count_sentence_does(
        tmp_path):
    """The page has no `vd-thread` element and none of the artifact's synthesis sentences
    ("common to both", "the finding that matters here is what is missing"); positive control:
    the findings header, the leads header and the stages caption carry their substituted counts.
    """
    page = render(E.sample_episode(tmp_path))
    assert page.elements(cls="vd-thread") == []
    lowered = page.text.lower()
    for phrase in ("common to both", "the finding that matters here is what is missing",
                   "the family did not separate"):
        assert phrase not in lowered, phrase
    assert str(S.findings) in _heading(page.section("sec-findings")), _heading(page.section("sec-findings"))
    leads_heading = _heading(page.section("sec-leads")).lower()
    assert "3" in leads_heading or "three" in leads_heading, leads_heading
    stages_heading = _heading(page.section("sec-stages")).lower()
    assert str(len(ST.EXPECTED_STEPS)) in stages_heading, stages_heading


# ---------------------------------------------------------------------------------------
# J9b–e — identity, stubs, counts, skips, the suffix join
# ---------------------------------------------------------------------------------------


def test_1025_a_finding_id_recorded_in_judge_yaml_names_a_world_draw_index_triple_absent_from_every_draw_document(
        tmp_path):
    """A ledger entry whose draw document is gone (J9b): #1234's record carries lanes, never a
    finding's text (the retired `world_findings` copy), so no stub row is synthesised for it —
    tile 3 counts only what is on disk and the queue accounting says the record and the page
    disagree.

    THE GRAIN IS THE DOCUMENT (92-reconciliation F-5): a triple missing from a PRESENT document
    — a document rewritten with fewer findings than the record names — renders no row either.
    """
    ep = E.sample_episode(tmp_path)
    (ep.world(E.GRADED_WORLD) / "judge" / "0.yaml").unlink()
    (ep.world(E.PASSTHROUGH_WORLD) / "judge" / "0.yaml").unlink()
    page = render(ep)
    rows = _rows(page)
    assert not [r for r in rows if not r.startswith(f"f-{E.FAMILY}-")], rows
    assert "defender claim 0" not in page.text_of("sec-findings")
    assert "of 3" in _tile(page, 2).text(), _tile(page, 2).text()
    acct = page.one(cls="vd-acct").text()
    assert f"record and page disagree by {S.defender_enqueued}" in acct, acct

    # the grain: the graded world's document is back with ONE finding while the record still
    # names `<ep>/prior_fake_key_precedent/0/4` — a present document, a missing triple, no row
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(
        findings=[E.finding(subject="defender", claim="THE ONLY FINDING LEFT")]))
    page = render(ep)
    graded_rows = [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]
    assert graded_rows == [f"f-{E.GRADED_WORLD}-0-0"], graded_rows
    assert "THE ONLY FINDING LEFT" in page.text_of(f"f-{E.GRADED_WORLD}-0-0")
    # family 3 + the one row on disk
    assert "of 4" in _tile(page, 2).text(), _tile(page, 2).text()


def test_1025_top_level_enqueue_counts_disagree_with_the_rows_the_page_walks(tmp_path):
    """Both sources are shown labelled — "record: N enqueued · page found: M" — and, only when
    they differ, a templated "record and page disagree by K" line (J9c); the tiles keep the
    walk's numbers. Positive control: on the sample the two agree and no disagreement line
    exists.
    """
    ep = E.sample_episode(tmp_path)
    acct = render(ep).one(cls="vd-acct").text()
    assert f"record: {S.defender_enqueued} enqueued · page found: {S.defender_enqueued}" in acct, acct
    assert "disagree" not in acct, acct

    doc = E.sample_grade()
    doc["enqueued_rows"] = S.defender_enqueued + 3
    E.write_judge(ep.dir, doc)
    page = render(ep)
    acct = page.one(cls="vd-acct").text()
    assert (f"record: {S.defender_enqueued + 3} enqueued · page found: {S.defender_enqueued}"
            in acct), acct
    assert "record and page disagree by 3" in acct, acct
    assert f"{S.queued} of {S.findings}" in _tile(page, 2).text()


def test_1025_a_draw_document_is_torn_mid_write(tmp_path):
    """A torn draw document, an undecodable one and a non-canonical stem beside an intact one:
    the intact draw's rows render, the skipped ones are surfaced from the reader's own skip
    report (J9d, O8: the one reader returns what it skipped) — and no row is invented for them.
    "K draw documents unreadable" counts FAULTS only — torn, symlinked, undecodable — so the
    findings header and the world's draw line carry "2 draw documents unreadable"; the
    non-canonical `03.yaml`, readable but ignored by design (d39: no row, no error), is reported
    separately as skipped ("1 skipped") and never as unreadable (71-resolutions-f, F-7).
    """
    ep = E.sample_episode(tmp_path)
    draws = ep.world(E.GRADED_WORLD) / "judge"
    E.plant_raw(draws / "1.yaml", "findings:\n  - {claim: 'torn")
    E.plant_raw(draws / "2.yaml", b"\xff\xfe\x00 not utf-8")
    E.plant_raw(draws / "03.yaml", "findings: []\n")
    page = render(ep)
    rows = [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]
    assert len(rows) == 5, rows
    assert all(r.startswith(f"f-{E.GRADED_WORLD}-0-") for r in rows), rows
    for surface in (page.text_of("sec-findings"), page.text_of(f"world-{E.GRADED_WORLD}")):
        assert "2 draw documents unreadable" in surface, surface
        assert "3 draw documents unreadable" not in surface, surface
        assert "1 skipped" in surface, surface


def test_1025_one_draw_document_is_a_symlink_to_a_file_outside_the_episode(tmp_path):
    """A draw document that is a symlink to a file outside the episode is never followed: its
    target's findings appear nowhere on the page, and the skip is surfaced as "1 draw documents
    unreadable" rather than silently under-reporting O2's "exactly once" (J9d).
    """
    ep = E.sample_episode(tmp_path)
    outside = tmp_path / "outside-draw.yaml"
    outside.write_text(yaml.safe_dump(E.draw_doc(
        findings=[E.finding(subject="defender", claim="OUTSIDE-DRAW-CLAIM")])), encoding="utf-8")
    E.plant_link(ep.world(E.GRADED_WORLD) / "judge" / "1.yaml", outside)
    page = render(ep)
    assert "OUTSIDE-DRAW-CLAIM" not in page.raw
    assert f"f-{E.GRADED_WORLD}-1-0" not in _rows(page)
    assert "1 draw documents unreadable" in page.text_of("sec-findings"), page.text_of("sec-findings")
    assert "defender claim 0" in page.text_of(f"f-{E.GRADED_WORLD}-0-0")


def test_1025_recorded_finding_ids_carry_a_different_episode_prefix(tmp_path):
    """The join is on the `(world, draw, index)` suffix of the recorded `finding_id` (J9e): a
    record whose ids carry another directory name (a renamed, repaired, re-graded copy) still
    joins every row to its disposition, the recorded id is displayed verbatim, and the manifest
    id — never the recorded prefix — composes the links and run-dir names.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.set_lane(E.sample_grade(), E.GRADED_WORLD, 0, 1, "unqueueable", "a reason")
    for row in doc["dispositions"]:
        row["finding_id"] = row["finding_id"].replace(E.EPISODE_ID, "old-name-before-repair")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    text = page.text_of(f"f-{E.GRADED_WORLD}-0-4")
    assert f"old-name-before-repair/{E.GRADED_WORLD}/0/4" in text, text
    assert "enqueued" in _group_of(page, f"f-{E.GRADED_WORLD}-0-4").text()
    assert "unqueueable" in _group_of(page, f"f-{E.GRADED_WORLD}-0-1").text()
    assert f"runs/{E.EPISODE_ID}-{E.GRADED_WORLD}/runtime.html" in page.hrefs
    assert not [h for h in page.hrefs if "old-name-before-repair" in h]


# ---------------------------------------------------------------------------------------
# J9f — the unusual rows
# ---------------------------------------------------------------------------------------


def test_1025_a_draw_document_is_missing_its_findings_key_entirely(tmp_path):
    """A draw document without its finding lists (#1234: `investigator_findings` and
    `world_findings`) is zero findings for that draw — no distinct sentence, no error: tile 3's
    total drops by the five rows the document no longer carries.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.draw_doc()
    del doc["investigator_findings"], doc["world_findings"]
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, doc)
    page = render(ep)
    assert not [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]
    assert f"of {S.findings - 5}" in _tile(page, 2).text(), _tile(page, 2).text()
    assert "malformed" not in page.text_of("sec-findings").lower()


def test_1025_the_same_finding_id_string_appears_in_two_different_draw_documents(tmp_path):
    """Two draw documents whose rows carry the same `finding_id` string are two rows: the page
    keys on the path coordinate `(world, draw, index)` and never reads the row's own
    `finding_id` field (None on every archived row, c23/g11).
    """
    ep = E.sample_episode(tmp_path)
    for draw in (0, 1):
        E.draw_document(ep.dir, E.GRADED_WORLD, draw, E.draw_doc(findings=[
            E.finding(subject="defender", claim=f"draw {draw} claim", finding_id="SHARED-ID")]))
    E.write_judge(ep.dir, E.record_draws(E.sample_grade(), E.GRADED_WORLD, (0, 1)))
    rows = _rows(render(ep))
    assert f"f-{E.GRADED_WORLD}-0-0" in rows, rows
    assert f"f-{E.GRADED_WORLD}-1-0" in rows, rows


def test_1025_draw_index_beyond_the_recorded_completed_draw_count(tmp_path):
    """A draw document whose index exceeds `knobs.draws` / `draws.completed` renders like any
    other draw the world's row records (#1234 A6: the record's `draws` are what the page shows)
    — no cross-check against the knobs is made.
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, 5, E.draw_doc(
        findings=[E.finding(subject="defender", claim="OVER-INDEX CLAIM")]))
    E.write_judge(ep.dir, E.record_draws(E.sample_grade(), E.GRADED_WORLD, (0, 5)))
    page = render(ep)
    assert f"f-{E.GRADED_WORLD}-5-0" in _rows(page)
    assert "OVER-INDEX CLAIM" in page.text_of(f"f-{E.GRADED_WORLD}-5-0")


def test_1025_a_finding_that_is_not_a_mapping(tmp_path):
    """A scalar where a finding mapping belongs, whose ledger entry files it unqueueable ("not a
    mapping"), renders as the ledger has it: a row with no claim under the "unqueueable — not a
    mapping" group, counted on tile 3's total and its unqueueable part, and in the queue
    accounting's unqueueable count (#1234 retired the record's own `unqueueable_findings`
    line). Before the ledger the page skipped it in silence and tile 3 read "0 unqueueable"
    over a record line that said otherwise (#1042 review).
    """
    ep = E.sample_episode(tmp_path)
    draw = E.draw_doc(findings=_draw_findings(ep, E.GRADED_WORLD))
    draw["world_findings"].append("just a bare string, not a finding")
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, draw)
    doc = E.set_lane(E.sample_grade(), E.GRADED_WORLD, 0, 5, "unqueueable",
                     "the draw's finding[5] is str, not a mapping")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    row = f"f-{E.GRADED_WORLD}-0-5"
    assert row in _rows(page)
    assert "just a bare string" not in page.raw
    heading = _heading(_group_of(page, row))
    assert "unqueueable" in heading, heading
    assert "not a mapping" in heading, heading
    assert f"of {S.findings + 1}" in _tile(page, 2).text()
    assert "1 unqueueable" in _tile(page, 2).text()
    assert "unqueueable 1" in page.one(cls="vd-acct").text()


def test_1025_a_draw_document_that_is_only_a_failure_reason(tmp_path):
    """A `{failure_reason: …}` draw document is a draw that did not complete: the pass leaves it
    out of the world row's recorded `draws` (#1234 A6, `judge.recorded_draws`), so it
    contributes no rows and its text never reaches the page, while the recorded draw renders
    as usual. (Before #1234 the page walked every file and showed the reason on the draw's
    line; the failure now stays on the record's row.)
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, 1,
                    {"failure_reason": "the judge reply <b>did not parse</b>"})
    page = render(ep)
    assert "did not parse" not in page.raw
    assert not [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-1-")]
    assert len([r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-0-")]) == 5


def test_1025_a_world_finding_refused_for_citing_an_unavailable_sample(tmp_path):
    """A world finding the pass refused for citing a samples section the record marks
    `unavailable` (pointer assessment; its ledger entry `unqueueable` with that reason) renders in
    the world-author table under an "unqueueable — <reason>" group — never dropped from the
    table (O2).
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    reason = "cites samples.yaml#identity, whose section holds no real answers"
    E.set_lane(doc, E.GRADED_WORLD, 0, 4, "unqueueable", reason)
    doc["world_enqueued_rows"] = 4
    E.write_judge(ep.dir, doc)
    page = render(ep)
    row = f"f-{E.GRADED_WORLD}-0-4"
    assert row in _rows(page)
    heading = _heading(_group_of(page, row))
    assert "unqueueable" in heading, heading
    assert reason in heading, heading
    assert "world author" in heading, heading


# ---------------------------------------------------------------------------------------
# J10 / J11 — bound slots, per-draw words, open-vocabulary values
# ---------------------------------------------------------------------------------------


def test_1025_record_fields_no_slot_binds(tmp_path):
    """Bound slots only (J10): the record fields no slot names — the draw's `noise_floor_note`,
    the row's `integrity_notes` — do not reach the page; the raw-record fold is a
    recorded follow-up, not this page. Positive control: the draw's finding, which a slot binds,
    renders with its group. (#1234 retired the draw's `episode_outcome` word the positive
    control used to read.)
    """
    ep = E.sample_episode(tmp_path)
    doc = E.draw_doc(findings=[E.finding(subject="defender", claim="BOUND-CLAIM")],
                     noise_floor_note="NOISE-FLOOR-NOTE-UNBOUND")
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, doc)
    grade = E.sample_grade()
    grade["worlds"][1]["integrity_notes"] = ["INTEGRITY-NOTE-UNBOUND"]
    E.write_judge(ep.dir, grade)
    page = render(ep)
    for unbound in ("NOISE-FLOOR-NOTE-UNBOUND", "INTEGRITY-NOTE-UNBOUND"):
        assert unbound not in page.raw, unbound
    assert "BOUND-CLAIM" in _group_of(page, f"f-{E.GRADED_WORLD}-0-0").text()


def test_1025_family_drawn_several_times_with_a_dissenting_draw(tmp_path):
    """A family drawn twice whose draws file different findings renders two groups in draw
    order, never merged: each draw's findings under its own draw. (#1234 retired the per-draw
    outcome word and the family's majority badge word this pinned beside them; the family's
    draws combine by union, each finding its own ledger entry.)
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.FAMILY, 1, E.family_draw_doc(
        findings=[E.finding(subject="world", topic="dissent topic", claim="dissent claim")]))
    doc = E.record_draws(E.sample_grade(), E.FAMILY, (0, 1))
    E.set_lane(doc, E.FAMILY, 1, 0, "world")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    band = page.text_of("sec-verdict")
    first = band.index("family topic 0")
    second = band.index("dissent topic: dissent claim")
    assert first < second, band
    assert f"f-{E.FAMILY}-1-0" in _rows(page)
    assert f"f-{E.FAMILY}-0-0" in _rows(page)


def test_1025_manifest_fields_the_slot_bindings_never_name(tmp_path):
    """The manifest fields no slot binds — `source_run_dir` (an absolute path outside the
    archive), `as_of`, `fences_at` — stay off the
    page (`continuation_prompt` was a fourth until #1255 P4 retired it); `source_run_dir` is never a link source. Positive control: the bound `base_story` and
    each sibling's `axis` render.
    """
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest(source_run_dir="/runs/SOURCE-RUN-DIR-UNBOUND",
                                 as_of="2099-01-01T00:00:00Z",
                                 fences_at=98765)
    T.write_family(ep.dir, manifest)
    page = render(ep)
    for unbound in ("SOURCE-RUN-DIR-UNBOUND", "2099-01-01T00:00:00Z", "98765"):
        assert unbound not in page.raw, unbound
    assert E.BASE_STORY in page.text_of("sec-records")
    assert E.AXIS_GRADED in page.text_of("sec-worlds")


def _class_carries(page: E.Page, word: str) -> list[str]:
    return [n.attrs["class"] for n in page.root.descendants()
            if word.lower() in (n.attrs.get("class") or "").lower()]


def test_1025_validity_word_outside_the_known_values(tmp_path):
    """#1234 retired `verdict_word`; the band's one record word is `validity` (O5). A word
    outside {usable, unusable} renders as its raw word, escaped, in the badge and the meta
    line, and drives no class. Positive control: the sample's `usable`.
    """
    ep = E.sample_episode(tmp_path)
    assert render(ep).one(cls="vd-badge").text() == "usable"
    doc = E.sample_grade()
    doc["validity"] = "mystery<word>"
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "mystery<word>" in page.one(cls="vd-badge").text()
    assert "mystery<word>" in page.one(cls="vd-meta").text()
    assert "&lt;word&gt;" in page.raw
    assert _class_carries(page, "mystery") == []


def test_1025_bucket_value_outside_the_closed_or_open_vocabularies(tmp_path):
    """A bucket outside both the queueable vocabulary and the observed world-subject words
    renders as its raw word, escaped as text with no decoding gloss; its row's class is the
    closed map's neutral fallback `bucket-other`, and the word appears in no `class` attribute
    (J11/J5). Positive control: a known bucket's row is not `bucket-other`.
    """
    ep = E.sample_episode(tmp_path)
    findings = [E.finding(subject="defender", bucket="lead-set", claim="known bucket"),
                E.finding(subject="defender", bucket="strange<bucket>", claim="odd bucket")]
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=findings))
    page = render(ep)
    known, odd = page.section(f"f-{E.GRADED_WORLD}-0-0"), page.section(f"f-{E.GRADED_WORLD}-0-1")
    assert "strange<bucket>" in odd.text()
    assert "&lt;bucket&gt;" in page.raw
    assert "bucket-other" in odd.classes or any("bucket-other" in n.classes for n in odd.descendants()), odd.attrs
    assert "bucket-other" not in known.classes
    assert _class_carries(page, "strange") == []


# ---------------------------------------------------------------------------------------
# settled — record states the verdict / findings layer branches on
# ---------------------------------------------------------------------------------------


def test_1025_judge_yaml_is_a_symlink_whose_target_is_a_different_episodes_judge_yaml(tmp_path):
    """`read_grade` refuses the alias (`JudgeRefused`, F25/x16): the band renders "grade record
    unreadable" and NOTHING from the linked episode's grade appears on the page — positive
    control: the other episode's verdict word and world labels are absent from the bytes.
    """
    ep = E.sample_episode(tmp_path)
    other = tmp_path / "other-judge.yaml"
    other_doc = E.sample_grade()
    other_doc["verdict_word"] = "OTHER-EPISODE-VERDICT"
    other_doc["worlds"][0]["world"] = "OTHER_EPISODE_WORLD"
    other_doc["worlds"][1]["world"] = "OTHER_EPISODE_WORLD_TWO"
    other.write_text(yaml.safe_dump(other_doc, sort_keys=False), encoding="utf-8")
    E.plant_link(ep.dir / "judge.yaml", other)
    page = render(ep)
    assert "grade record unreadable" in page.text_of("sec-verdict")
    for leaked in ("OTHER-EPISODE-VERDICT", "OTHER_EPISODE_WORLD"):
        assert leaked not in page.raw, leaked


def test_1025_judge_yaml_is_present_with_an_empty_worlds_array_and_no_not_graded_stamp(tmp_path):
    """Renders as a graded record with zero rows: tile 1 "0 worlds judged · verdict =
    declared on 0 of 0", no cards, findings section carrying
    family-draw rows only, the control alone in the worlds guide — not the not_graded band.
    """
    ep = E.sample_episode(tmp_path)
    for label in (E.PASSTHROUGH_WORLD, E.GRADED_WORLD):
        shutil.rmtree(ep.world(label) / "judge")
    doc = E.sample_grade()
    doc["worlds"] = []
    doc["enqueued_rows"] = 0
    for label in (E.PASSTHROUGH_WORLD, E.GRADED_WORLD):
        E.drop_lanes(doc, label)
    doc["world_enqueued_rows"] = 3
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "0 worlds judged · verdict = declared on 0 of 0" in _tile(page, 0).text()
    assert _cards(page) == []
    assert set(_rows(page)) == {f"f-{E.FAMILY}-0-{i}" for i in range(3)}, _rows(page)
    assert "no grade record" not in page.text_of("sec-verdict")


def test_1025_judge_yaml_carries_a_top_level_field_this_readers_schema_has_never_seen(tmp_path):
    """`read_grade` tolerates an unknown top-level string key (dropped, not on the record —
    p8), so the page is UNCHANGED: no crash, the field rendered nowhere, the bytes equal to the
    same record without the key.
    """
    ep = E.sample_episode(tmp_path)
    assert "usable" in render(ep).text_of("sec-verdict"), "positive control: the record renders"
    baseline = ep.page.read_bytes()
    doc = E.sample_grade()
    doc["never_seen_field"] = {"planted": "NEVER-SEEN-VALUE"}
    E.write_judge(ep.dir, doc)
    render(ep)
    assert ep.page.read_bytes() == baseline
    assert "NEVER-SEEN-VALUE" not in ep.page.read_text(encoding="utf-8")


def test_1025_a_not_graded_stamp_carries_a_field_this_readers_schema_has_never_seen(tmp_path):
    """The same tolerance one level down: a `not_graded` stamp written by a newer pass with a
    key this reader's stamp schema does not name still reads as the stamp it is (#1067: the
    record's classes refuse an unknown keyword, so the reader drops it before constructing),
    the page byte-identical to the same stamp without the key.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["not_graded"] = {"outcome": "unusable", "reason": "STAMP-REASON"}
    E.write_judge(ep.dir, doc)
    render(ep)
    baseline = ep.page.read_bytes()
    assert "STAMP-REASON" in ep.page.read_text(encoding="utf-8"), "positive control: the stamp renders"
    doc["not_graded"]["never_seen_field"] = "NEVER-SEEN-VALUE"
    E.write_judge(ep.dir, doc)
    render(ep)
    assert ep.page.read_bytes() == baseline
    assert "NEVER-SEEN-VALUE" not in ep.page.read_text(encoding="utf-8")


def test_1025_draw_directory_holds_both_1_yaml_and_01_yaml(tmp_path):
    """`01.yaml` is ignored exactly as `draws_on_disk` ignores it (d39); draw 1 is read from
    `1.yaml` once; no error, no extra row.
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, 1, E.draw_doc(
        findings=[E.finding(subject="defender", claim="CANONICAL ONE")]))
    E.draw_document(ep.dir, E.GRADED_WORLD, "01", E.draw_doc(
        findings=[E.finding(subject="defender", claim="LEADING ZERO")]), check=False)
    E.write_judge(ep.dir, E.record_draws(E.sample_grade(), E.GRADED_WORLD, (0, 1)))
    page = render(ep)
    rows = [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-1-")]
    assert rows == [f"f-{E.GRADED_WORLD}-1-0"], rows
    assert "CANONICAL ONE" in page.raw
    assert "LEADING ZERO" not in page.raw


def test_1025_draw_directory_holds_a_file_stem_written_with_a_non_ascii_digit(tmp_path):
    """A stem written with a non-ASCII digit (`١.yaml`) is ignored by the reader's ASCII-digit
    stem filter (c27/g11); no row, no error — and, the human's F-7 decision, it falls in the
    reader's UNDECODABLE class: the world's draw line counts it in "1 draw documents
    unreadable", never as a "skipped" non-canonical stem.
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, "١", E.draw_doc(
        findings=[E.finding(subject="defender", claim="ARABIC-INDIC ONE")]), check=False)
    page = render(ep)
    assert "ARABIC-INDIC ONE" not in page.raw
    assert len([r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]) == 5
    world = page.text_of(f"world-{E.GRADED_WORLD}")
    assert "1 draw documents unreadable" in world, world
    assert "skipped" not in world, world


def test_1025_a_finding_row_carries_a_non_null_world_field_that_disagrees_with_its_directory(tmp_path):
    """The directory is the world (correction 2, F5): a row whose own `world` field names
    another world renders under its directory's world with the id
    `f-<dir-world>-<draw>-<i>`, the field is never read for addressing and, where rendered, is
    escaped text.
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=[
        E.finding(subject="defender", claim="MISFILED CLAIM", world="<b>elsewhere</b>")]))
    page = render(ep)
    row = f"f-{E.GRADED_WORLD}-0-0"
    assert row in _rows(page)
    assert "MISFILED CLAIM" in page.text_of(row)
    assert "f-elsewhere-0-0" not in page.all_ids
    assert "f-<b>elsewhere</b>-0-0" not in page.all_ids
    assert "<b>elsewhere</b>" not in page.raw


def test_1025_malformed_replies_and_gaps_in_draw_numbering(tmp_path):
    """Draws render under their real stems (0 and 2), ids `f-<world>-0-<i>` / `f-<world>-2-<i>`,
    never renumbered; tile 3 counts the rows on disk. The judge traces render for the draws the
    record names (0 and 2); draw 1's trace — a call that never completed a draw, so the record
    names no draw 1 — is not shown (#1234 A6: transcripts follow `judge.recorded_draws`; the
    failure stays on the row).
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, 2, E.draw_doc(
        findings=[E.finding(subject="defender", claim="DRAW TWO")]))
    for n in (1, 2):
        E.write_trace(ep.dir, f"judge:{E.GRADED_WORLD}:{n}")
        E.write_framed(ep.dir, f"judge:{E.GRADED_WORLD}:{n}")
    doc = E.record_draws(E.sample_grade(), E.GRADED_WORLD, (0, 2))
    doc["worlds"][1]["malformed_replies"] = 1
    E.write_judge(ep.dir, doc)
    page = render(ep)
    rows = [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]
    assert f"f-{E.GRADED_WORLD}-2-0" in rows, rows
    assert not [r for r in rows if r.startswith(f"f-{E.GRADED_WORLD}-1-")], rows
    assert f"of {S.findings + 1}" in _tile(page, 2).text()
    for n in (0, 2):
        assert f"tx-judge_{E.GRADED_WORLD}_{n}_trace" in page.by_id, page.ids_with("tx-")
    assert f"tx-judge_{E.GRADED_WORLD}_1_trace" not in page.by_id


def test_1025_unqueueable_reason_text_contains_the_page_join_delimiter(tmp_path):
    """A ledger reason carrying `": "` (the old `unqueueable_findings` line's join delimiter)
    is shown whole, escaped: #1234's ledger carries the reason in its own field, so nothing
    splits it. (The retired `unqueueable_findings` list, and its separator-less line in the
    queue accounting, are gone.)
    """
    ep = E.sample_episode(tmp_path)
    doc = E.set_lane(E.sample_grade(), E.GRADED_WORLD, 0, 1, "unqueueable",
                     "reason part one: part two <x>")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    group = _group_of(page, f"f-{E.GRADED_WORLD}-0-1").text()
    assert "unqueueable" in group, group
    assert "reason part one: part two <x>" in group, group
    assert "&lt;x&gt;" in page.raw


def test_1025_an_unqueueable_line_that_matches_no_rendered_finding(tmp_path):
    """A ledger entry naming a coordinate with no finding on disk synthesises no findings row
    (#1234: the record carries lanes, not text). Positive control: every finding on disk still
    renders.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.set_lane(E.sample_grade(), E.GRADED_WORLD, 0, 9, "unqueueable", "<no such row>")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert f"f-{E.GRADED_WORLD}-0-9" not in page.all_ids
    assert "<no such row>" not in page.raw
    assert len(_rows(page)) == S.findings


def test_1025_identical_findings_under_two_draws(tmp_path):
    """Two draws carrying byte-identical findings render two rows with distinct ids
    (`f-<world>-0-<i>`, `f-<world>-1-<i>`), each under its draw group; tile 3 counts two; no
    text-similarity dedup and no "duplicate" marker.
    """
    ep = E.sample_episode(tmp_path)
    same = [E.finding(subject="defender", claim="IDENTICAL CLAIM")]
    for draw in (0, 1):
        E.draw_document(ep.dir, E.GRADED_WORLD, draw, E.draw_doc(findings=same))
    E.write_judge(ep.dir, E.record_draws(E.sample_grade(), E.GRADED_WORLD, (0, 1)))
    page = render(ep)
    rows = [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]
    assert sorted(rows) == [f"f-{E.GRADED_WORLD}-0-0", f"f-{E.GRADED_WORLD}-1-0"], rows
    assert f"of {S.findings - 5 + 2}" in _tile(page, 2).text()
    assert "duplicate" not in page.text_of("sec-findings").lower()


def test_1025_family_call_faulted_after_writing_a_draw(tmp_path):
    """Both render: the family findings that were written (one line per row, grouped by draw in
    draw order) and the family row's `draws_failed_reason` (escaped) in the reason slot ahead
    of the templated line; neither suppresses the other.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["family"]["draws_failed_reason"] = "draw 1 failed: <TransportFault>"
    E.write_judge(ep.dir, doc)
    band = render(ep).text_of("sec-verdict")
    assert "draw 1 failed: <TransportFault>" in band
    assert "family topic 0: family claim 0" in band
    assert band.index("draw 1 failed") < band.index("findings queued")


def test_1025_a_gradable_row_whose_draws_never_ran(tmp_path):
    """A gradable row whose draws never ran (no draw document, no trace) is graded on the page
    (`is_gradable_row`): its verdict and a card render from the row; its combined verdict is
    the zero-draw one the pass writes (#1234 `combine_draws`: no bucket, no systems, not
    measured, no commit state), no transcript block for it and no findings rows.
    """
    ep = E.sample_episode(tmp_path)
    (ep.world(E.GRADED_WORLD) / "judge" / "0.yaml").unlink()
    for name in (f"judge_{E.GRADED_WORLD}_0_trace.jsonl", f"judge_{E.GRADED_WORLD}_0_framed_trace.jsonl"):
        (ep.dir / "wire_logs" / name).unlink()
    doc = E.drop_lanes(E.sample_grade(), E.GRADED_WORLD)
    row = doc["worlds"][1]
    row.update(completed_draws=0, draws=[], bucket=None, systems=None, measured=False,
               not_measured_reason="no draw completed",
               draws_failed_reason="no draw completed", world_label_doubted=False)
    del row["state"]
    doc["enqueued_rows"] = 4
    doc["world_enqueued_rows"] = 4
    E.write_judge(ep.dir, doc)
    page = render(ep)
    world = page.text_of(f"world-{E.GRADED_WORLD}")
    assert "inconclusive" in world
    assert "no bucket" in world
    assert any(E.GRADED_WORLD in c.text() for c in _cards(page))
    assert f"tx-judge_{E.GRADED_WORLD}_0_trace" not in page.by_id
    assert not [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]


def test_1025_an_episode_with_only_the_control(tmp_path):
    """Tile 1 "0 worlds judged · verdict = declared on 0 of 0"; no cards; the findings section carries family-draw rows
    only; the worlds guide names the control alone as "the branch point untouched, not
    graded"; renders without raising.
    """
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"] = manifest["worlds"][:1]
    T.write_family(ep.dir, manifest)
    for label in (E.PASSTHROUGH_WORLD, E.GRADED_WORLD):
        shutil.rmtree(ep.world(label))
        shutil.rmtree(ep.run(label))
    doc = E.sample_grade()
    doc["worlds"], doc["enqueued_rows"], doc["world_enqueued_rows"] = [], 0, 3
    for label in (E.PASSTHROUGH_WORLD, E.GRADED_WORLD):
        E.drop_lanes(doc, label)
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "0 worlds judged · verdict = declared on 0 of 0" in _tile(page, 0).text()
    assert _cards(page) == []
    assert set(_rows(page)) == {f"f-{E.FAMILY}-0-{i}" for i in range(3)}
    worlds = page.text_of("sec-worlds")
    assert "the branch point untouched, not graded" in worlds
    assert E.GRADED_WORLD not in worlds


def test_1025_render_when_family_judge_dir_exists_but_is_empty(tmp_path):
    """An empty `worlds/family/judge/` renders identically to no directory at all (g10/x14):
    `draws_on_disk` yields `{}` for both, so the lede's first line is absent and the templated
    line opens the page; no distinction is drawn or owed.
    """
    ep = E.sample_episode(tmp_path, family_draw=False)
    render(ep)
    absent = ep.page.read_bytes()
    (ep.world(E.FAMILY) / "judge").mkdir(parents=True)
    render(ep)
    assert ep.page.read_bytes() == absent
    band = E.read_page(ep.dir).text_of("sec-verdict")
    assert "family topic" not in band
    assert "findings queued" in band


def test_1025_render_reflects_a_not_graded_to_graded_transition_across_two_calls(tmp_path):
    """The second render reads only the current record: a full graded page with no trace of
    the earlier not_graded band (the page stores nothing). Positive control: the first render
    carried the band.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["not_graded"] = {"outcome": "unusable", "reason": "STAMP-REASON-EARLIER"}
    E.write_judge(ep.dir, doc)
    first = render(ep)
    assert "STAMP-REASON-EARLIER" in first.text_of("sec-verdict")
    assert _tiles(first) == []
    E.write_judge(ep.dir, E.sample_grade())
    second = render(ep)
    assert "STAMP-REASON-EARLIER" not in second.raw
    assert len(_tiles(second)) == 4
    assert len(_rows(second)) == S.findings


# ---------------------------------------------------------------------------------------
# The review of PR #1042 — one normalizer on tile 1; the record's own family outcome
# ---------------------------------------------------------------------------------------


def test_1025_tile_one_reads_verdict_and_declared_through_the_vocabularys_normalizer(tmp_path):
    """`verdict: ' benign '` against `declared: 'benign'` is the same disposition: tile 1's
    agreement count puts both sides through the vocabulary's normalizer (which strips) — it
    once compared the raw strings and read the pair as a disagreement."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    graded = next(w for w in doc["worlds"] if w["world"] == E.GRADED_WORLD)
    graded["declared"] = "benign"
    graded["verdict"] = " benign "
    E.write_judge(ep.dir, doc)
    tile = _tile(render(ep), 0).text()
    assert f"verdict = declared on 1 of {S.graded}" in tile, tile


def test_1025_an_empty_validity_is_the_badge_word_not_an_absence(tmp_path):
    """`validity` is the record's own `str | None`: the badge shows the recorded word whenever
    one is recorded, an empty string included — never the absence mark in its place (`is not
    None`, not `or`); an absent word is the absence mark. (#1234: `validity` replaced the
    retired `family_outcome` as the badge's word.)"""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["validity"] = ""
    E.write_judge(ep.dir, doc)
    assert render(ep).one(cls="vd-badge").text() == ""
    doc["validity"] = None
    E.write_judge(ep.dir, doc)
    assert render(ep).one(cls="vd-badge").text() == "—"


