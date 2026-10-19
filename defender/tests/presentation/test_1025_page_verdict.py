from __future__ import annotations

import re
import shutil
import pathlib
from pathlib import Path

import pytest
import yaml

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.presentation import test_1025_stage_timing as ST
from defender.tests.support.learning.core import _state1135

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
    """The target module, `defender.presentation.visualize_episode`, imported at call time
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


def test_1025_the_lede_lists_family_draw_findings_verbatim_grouped_by_draw_or_opens_with_the_templated_line_when_there_is_no_family_draw(
        tmp_path):
    """Sample: the lede's first line carries the three family findings as `topic: claim` escaped,
    then the templated line "13 findings queued"; a synthetic two-draw family."""
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


def test_1025_the_verdict_tile_carries_judged_and_verdict_equals_declared_counts_on_both_archives(
        tmp_path):
    """Sample tile 1: "2 worlds judged · verdict = declared on 0 of 2"; the live-996 shape (one row
    ungradable, so not judged): "1 worlds judged · verdict = declared on 0 of."""
    tile = _tile(render(E.sample_episode(tmp_path)), 0)
    assert TILE_ONE in tile.text(), tile.text()

    live = _tile(render(_live996(tmp_path / "live")), 0)
    assert "1 worlds judged · verdict = declared on 0 of 1" in live.text(), live.text()


def test_1025_tiles_two_to_four_carry_judged_of_rows_with_reasons_queued_of_total_split_and_cost_with_the_labelled_lower_bound(
        tmp_path):
    """Sample: tile 2 "2 of 2" (judged of the record's rows) with no caption; tile 3 "13 of 13"
    split 8 defender / 5 world author / 0 unqueueable / 0 dropped; tile 4 "$3.5500"."""
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
    """An episode whose `judge.yaml` carries `not_graded."""
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
    """"Nothing below the band" is the verdict section's own layer (J14)."""
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
    """A launcher-produced episode whose judge pass failed at the enqueue ."""
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
    """The failed-judge snapshot (J9a)."""
    ep = E.sample_episode(tmp_path, judge=False)
    page = render(ep)
    assert "no grade record" in page.text_of("sec-verdict")
    assert _rows(page) == []
    assert "defender claim" not in page.raw


def test_1025_every_finding_across_per_draw_docs_and_family_draws_renders_exactly_once_keyed_world_draw_index(
        tmp_path):
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
    """Sample: both siblings' 4 defender findings read enqueued (the episode has the 5 world-author
    rows read enqueued; a ledger entry re-filed unqueueable marks that id."""
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
    """Two addressee tables (defender / world author)."""
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
    world's findings under draws 0, 1, 10 in that order (numeric, not `0, 10, 1` as."""
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


def test_1025_queue_accounting_lists_per_queue_rows_destination_as_recorded_unqueueable_malformed_and_dropped_counts(
        tmp_path):
    """The collapsed details carry "defender."""
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
    """Sample: two cards; `no_remote_session`'s header "benign → inconclusive", heading the judge
    model's bucket "lead-set" and its systems, footer "4 findings · enqueued"."""
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


def test_1025_a_finding_id_recorded_in_judge_yaml_names_a_world_draw_index_triple_absent_from_every_draw_document(
        tmp_path):
    """A ledger entry whose draw document is gone (J9b)."""
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
    """Both sources are shown labelled ."""
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
    """A torn draw document, an undecodable one and a non-canonical stem beside an intact one."""
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
    """A draw document that is a symlink to a file outside the episode is never followed."""
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
    from defender.tests.storage.ids_1187._spec1187 import roster_for_arms

    ep = E.sample_episode(tmp_path)
    roster = roster_for_arms(ep.dir, {label: ep.run(label) for label in E.WORLDS})
    doc = E.set_lane(E.sample_grade(), E.GRADED_WORLD, 0, 1, "unqueueable", "a reason")
    for row in doc["dispositions"]:
        row["finding_id"] = row["finding_id"].replace(E.EPISODE_ID, "old-name-before-repair")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    text = page.text_of(f"f-{E.GRADED_WORLD}-0-4")
    assert f"old-name-before-repair/{E.GRADED_WORLD}/0/4" in text, text
    assert "enqueued" in _group_of(page, f"f-{E.GRADED_WORLD}-0-4").text()
    assert "unqueueable" in _group_of(page, f"f-{E.GRADED_WORLD}-0-1").text()
    assert f"runs/{roster[E.GRADED_WORLD]}/runtime.html" in page.hrefs
    assert not [h for h in page.hrefs if "old-name-before-repair" in h]



def test_1025_a_world_finding_refused_for_citing_an_unavailable_sample(tmp_path):
    """A world finding the pass refused for citing a samples section the record marks `unavailable`
    (pointer assessment."""
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


def _class_carries(page: E.Page, word: str) -> list[str]:
    return [n.attrs["class"] for n in page.root.descendants()
            if word.lower() in (n.attrs.get("class") or "").lower()]


def test_1025_judge_yaml_is_a_symlink_whose_target_is_a_different_episodes_judge_yaml(tmp_path):
    """`read_grade` refuses the alias (`JudgeRefused`, F25/x16)."""
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
    """Renders as a graded record with zero rows."""
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


def test_1025_a_finding_row_carries_a_non_null_world_field_that_disagrees_with_its_directory(tmp_path):
    """The directory is the world (correction 2, F5)."""
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


def test_1025_unqueueable_reason_text_contains_the_page_join_delimiter(tmp_path):
    """A ledger reason carrying `": "` (the old `unqueueable_findings` line's join delimiter) is
    shown whole, escaped: #1234's ledger carries the reason in its own field, so."""
    ep = E.sample_episode(tmp_path)
    doc = E.set_lane(E.sample_grade(), E.GRADED_WORLD, 0, 1, "unqueueable",
                     "reason part one: part two <x>")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    group = _group_of(page, f"f-{E.GRADED_WORLD}-0-1").text()
    assert "unqueueable" in group, group
    assert "reason part one: part two <x>" in group, group
    assert "&lt;x&gt;" in page.raw


def test_1025_a_gradable_row_whose_draws_never_ran(tmp_path):
    """A gradable row whose draws never ran (no draw document, no trace) is graded on the page
    (`is_gradable_row`)."""
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
