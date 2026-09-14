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

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

S = E.SAMPLE
LEDE_LINE = f"undecidable · {S.queued} findings queued · {S.defender_withheld} withheld ({S.withheld_reason})"
TILE_ONE = (f"{S.measuring} of {S.graded} graded measuring · {S.contrasting} of {S.measuring} "
            f"contrast the control · verdict = declared on 0 of {S.measuring}")


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def visualize_episode():
    """The target module, `defender.scripts.visualize.visualize_episode`, imported at call time
    (it does not exist at the spec's base — one failure per test, never a collection error)."""
    return E.page_module()


def render(ep) -> E.Page:
    """`visualize_episode().render_episode(<dir>)` — the real entry point — then the page it
    wrote, parsed."""
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
    """The findings a draw document on disk carries — read back so a scenario can extend them."""
    return yaml.safe_load(
        (ep.world(label) / "judge" / f"{draw}.yaml").read_text(encoding="utf-8"))["findings"]


def _tiles(page: E.Page) -> list[E.Node]:
    return page.elements(cls="vd-tile")


def _tile(page: E.Page, index: int) -> E.Node:
    """Tile `index` of the four — fewer tiles is the test's own failure."""
    tiles = _tiles(page)
    assert len(tiles) == 4, f"expected four tiles, found {len(tiles)}"
    return tiles[index]


def _cards(page: E.Page) -> list[E.Node]:
    return page.elements(cls="vd-cause")


def _live996(tmp_path: Path, **kw) -> E.Episode:
    """The second archive's shape: no family draw, no `samples.yaml`, an ungradable row, a
    pre-#1007 record (no `family_outcome`), the control declared `benign` so the one measuring
    world contrasts it."""
    ep = E.sample_episode(tmp_path, family_draw=False, samples=False, judge=False, **kw)
    manifest = E.sample_manifest()
    manifest["worlds"][0]["disposition_declared"] = "benign"
    T.write_family(ep.dir, manifest)
    doc = E.sample_grade()
    doc["worlds"] = [E.ungradable_row(E.WITHHELD_WORLD, declared="benign"),
                     E.world_row(E.GRADED_WORLD, declared="malicious", has_refused=None,
                                 world_findings=[E.finding(subject="world")])]
    doc["verdict_word"] = "survived"
    doc["world_findings"] = [E.world_finding_queue_row(
        f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/4", "the world finding")]
    for key in ("family_outcome", "family_failed_reason", "family_malformed_replies",
                "world_enqueued_rows", "world_enqueued_to", "withheld_findings"):
        del doc[key]
    E.write_judge(ep.dir, doc)
    return ep


# ---------------------------------------------------------------------------------------
# d16 / d17 / d18 / d19 / d20 / d21 — the band, the lede, the tiles
# ---------------------------------------------------------------------------------------


def test_1025_the_lede_lists_family_draw_findings_verbatim_grouped_by_draw_or_opens_with_the_templated_line_when_there_is_no_family_draw(
        tmp_path):
    """Sample: the lede's first line carries the three family findings as `topic: claim`
    escaped, then the templated line "undecidable · 9 findings queued · 4 withheld
    (reachability_unmeasured)"; a synthetic two-draw family renders two groups in draw order
    without merging; the live-996 shape (no `worlds/family/`) opens with the templated line; a
    synthetic `family_failed_reason` renders where the first line would be.
    """
    ep = E.sample_episode(tmp_path)
    band = render(ep).text_of("sec-verdict")
    for row in E.family_findings():
        assert f"{row['topic']}: {row['claim']}" in band, band
    assert LEDE_LINE in band, band
    assert band.index("family topic 0") < band.index(LEDE_LINE), "the templated line came first"

    E.draw_document(ep.dir, E.FAMILY, 1, E.draw_doc(
        findings=[E.finding(subject="world", topic="second-draw topic", claim="second-draw claim")],
        episode_outcome="discard"))
    two_draws = E.sample_grade()
    two_draws["world_findings"].append(E.family_queue_row(1, 0, topic="second-draw topic",
                                                          claim="second-draw claim"))
    E.write_judge(ep.dir, two_draws)
    band = render(ep).text_of("sec-verdict")
    assert band.index("family topic 2") < band.index("second-draw topic: second-draw claim")

    live = _live996(tmp_path / "live")
    live_band = render(live).text_of("sec-verdict")
    assert "family topic" not in live_band, live_band
    assert "findings queued" in live_band, live_band

    doc = E.sample_grade()
    doc["family_failed_reason"] = "the family call faulted: TransportFault"
    doc["family_outcome"] = None
    E.write_judge(ep.dir, doc)
    band = render(ep).text_of("sec-verdict")
    assert "the family call faulted: TransportFault" in band
    assert band.index("the family call faulted") < band.index("findings queued")


def test_1025_the_badge_is_family_outcome_falling_back_to_verdict_word_and_the_meta_line_carries_episode_outcome_and_verdict_word(
        tmp_path):
    """Sample badge reads `discard`, meta `gradable · undecidable`; the live-996 shape's badge
    reads `survived` (its `family_outcome` is None), meta `gradable · survived`.
    """
    page = render(E.sample_episode(tmp_path))
    badge = page.elements(cls="vd-badge")
    assert badge, [b.text() for b in badge]
    assert "discard" in badge[0].text(), [b.text() for b in badge]
    meta = page.elements(cls="vd-meta")
    assert meta, [m.text() for m in meta]
    assert "gradable · undecidable" in meta[0].text(), [m.text() for m in meta]

    live = render(_live996(tmp_path / "live"))
    assert "survived" in live.one(cls="vd-badge").text()
    assert "gradable · survived" in live.one(cls="vd-meta").text()


def test_1025_the_verdict_tile_carries_measuring_contrasting_and_verdict_equals_declared_counts_on_both_archives(
        tmp_path):
    """Sample tile 1: "1 of 2 graded measuring · 0 of 1 contrast the control · verdict =
    declared on 0 of 1" beside `undecidable`; the live-996 shape: "1 of 1 graded measuring ·
    1 of 1 contrast the control · verdict = declared on 0 of 1" beside `survived`, the
    control's declared disposition read from `family.yaml` role `A`.
    """
    tile = _tile(render(E.sample_episode(tmp_path)), 0)
    assert TILE_ONE in tile.text(), tile.text()
    assert "undecidable" in tile.text(), tile.text()

    live = _tile(render(_live996(tmp_path / "live")), 0)
    assert ("1 of 1 graded measuring · 1 of 1 contrast the control · verdict = declared on 0 of 1"
            in live.text()), live.text()
    assert "survived" in live.text()


def test_1025_tiles_two_to_four_carry_measuring_of_graded_with_reasons_queued_of_total_split_and_cost_with_the_labelled_lower_bound(
        tmp_path):
    """Sample: tile 2 "1 of 2" with caption "no_remote_session — reachability_unmeasured";
    tile 3 "9 of 13" split 4 defender / 5 world author / 4 withheld / 0 unqueueable / 0 dropped;
    tile 4 "$3.5500" with the worlds' wall range 3m00s–10m00s and "≈ 16m00s lower bound on
    wall: model calls + longest world"; the live-996 shape's ungradable world is in neither the
    measuring nor the withheld count and is named as ungradable in tile 2's caption.
    """
    page = render(E.sample_episode(tmp_path))
    two, three, four = (_tile(page, i).text() for i in (1, 2, 3))
    assert f"{S.measuring} of {S.graded}" in two, two
    assert f"{E.WITHHELD_WORLD} — {S.withheld_reason}" in two, two
    assert f"{S.queued} of {S.findings}" in three, three
    for part in (f"{S.defender_enqueued} defender", f"{S.world_author} world author",
                 f"{S.defender_withheld} withheld", "0 unqueueable", "0 dropped"):
        assert part in three, (part, three)
    assert S.total_cost in four, four
    assert f"{S.shortest_world}–{S.longest_world}" in four, four
    assert f"≈ {S.lower_bound} lower bound on wall: model calls + longest world" in four, four

    live = render(_live996(tmp_path / "live"))
    assert "1 of 1" in _tile(live, 1).text(), _tile(live, 1).text()
    assert E.WITHHELD_WORLD in _tile(live, 1).text()
    assert "ungradable" in _tile(live, 1).text()
    assert "0 withheld" in _tile(live, 2).text(), _tile(live, 2).text()


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
    doc["not_graded"] = {"outcome": "rejected", "reason": "the review rejected world b: contradiction"}
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "the review rejected world b: contradiction" in page.text_of("sec-verdict")
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
    doc["not_graded"] = {"outcome": "rejected", "reason": "STAMP-REASON"}
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


def test_1025_an_episode_with_no_judge_yaml_still_renders_its_stages_and_worlds_and_says_there_is_no_grade_record(
        tmp_path):
    """A launcher-produced episode whose judge pass failed after its draws — the findings queue
    root is a regular file, so the enqueue is refused and `judge.yaml` (written last, c10) never
    lands — still renders: the band says no grade record, every world is "not graded", the
    stage table has its six rows, and the draw documents the judge DID write before the enqueue
    failed (`worlds/b/judge/0.yaml`, `worlds/c/judge/0.yaml`, one `subject: defender` finding
    each — the state 92-reconciliation F-1 executed) render as J9a says: their rows under ONE
    group headed "no grade record — not enqueued", no disposition claimed, band unchanged.
    """
    (tmp_path / "learning-state").write_text("not a directory", encoding="utf-8")
    launch = ST._launch(tmp_path)
    assert launch.rc == 0
    assert launch.judge.calls > 0
    ep = launch.episode_dir
    assert not (ep / "judge.yaml").exists(), "the control failed: the judge did not fail"
    on_disk = sorted(p.parent.parent.name for p in ep.glob("worlds/*/judge/0.yaml"))
    assert on_disk == ["b", "c"], f"the control failed: draw documents on disk are {on_disk}"
    page = hook_page(ep)
    assert "no grade record" in page.text_of("sec-verdict")
    for label in launch.spawn.worlds:
        assert "not graded" in page.text_of(f"world-{label}")
    timing = page.text_of("stage-timing")
    assert all(step in timing for step in ST.EXPECTED_STEPS)
    rows = _rows(page)
    assert sorted(rows) == ["f-b-0-0", "f-c-0-0"], rows
    groups = {_group_id(page, r) for r in rows}
    assert len(groups) == 1, groups
    heading = _heading(page.section(groups.pop()))
    assert "no grade record — not enqueued" in heading, heading
    assert "enqueued" not in heading.replace("not enqueued", ""), heading
    assert "withheld" not in heading, heading


def test_1025_draw_documents_exist_but_judge_yaml_does_not(tmp_path):
    """The failed-judge snapshot (J9a): every per-draw document is on disk and `judge.yaml` is
    not. The findings render under ONE group headed "no grade record — not enqueued" with the
    addressee tables as usual and no disposition claimed; the band still says there is no grade
    record.
    """
    ep = E.sample_episode(tmp_path, judge=False)
    page = render(ep)
    assert "no grade record" in page.text_of("sec-verdict")
    rows = _rows(page)
    assert len(rows) == S.findings, rows
    groups = {_group_id(page, r) for r in rows}
    assert len(groups) == 1, groups
    heading = _heading(page.section(groups.pop()))
    assert "no grade record — not enqueued" in heading, heading
    assert "enqueued" not in heading.replace("not enqueued", ""), heading


# ---------------------------------------------------------------------------------------
# d12 / d13 / d14 / d15 / d39 — the findings walk
# ---------------------------------------------------------------------------------------


def test_1025_every_finding_across_per_draw_docs_family_draws_and_mechanical_rows_renders_exactly_once_keyed_world_draw_index(
        tmp_path):
    """On the sample the page carries exactly 13 `f-<world>-<draw>-<index>` rows, each id once
    (4 defender enqueued, 4 withheld, 5 world-author across `no_remote_session/0/4`,
    `prior_fake_key_precedent/0/4`, `family/0/{0,1,2}`); a synthetic episode adding a row-level
    `mechanical_world_findings` entry renders one more row at `f-<world>-mechanical-0`; the
    per-world `world_findings` copy on the row adds nothing.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    rows = _rows(page)
    assert len(rows) == S.findings, rows
    assert len(set(rows)) == S.findings, rows
    expected = {f"f-{E.WITHHELD_WORLD}-0-{i}" for i in range(5)}
    expected |= {f"f-{E.GRADED_WORLD}-0-{i}" for i in range(5)}
    expected |= {f"f-{E.FAMILY}-0-{i}" for i in range(3)}
    assert set(rows) == expected, set(rows) ^ expected
    assert page.all_ids.count(f"f-{E.GRADED_WORLD}-0-4") == 1

    doc = E.sample_grade()
    mechanical = E.finding(subject="world", bucket="unreachable-difference",
                           claim="MECHANICAL CLAIM", topic="unreachable difference")
    doc["worlds"][1]["mechanical_world_findings"] = [mechanical]
    doc["world_findings"].append(E.world_finding_queue_row(
        f"{E.EPISODE_ID}/{E.GRADED_WORLD}/mechanical/0", "MECHANICAL CLAIM — root"))
    E.write_judge(ep.dir, doc)
    rows = _rows(render(ep))
    assert len(rows) == S.findings + 1, rows
    assert f"f-{E.GRADED_WORLD}-mechanical-0" in rows, rows


def test_1025_a_findings_disposition_reproduces_the_enqueues_partition_withheld_unqueueable_blocked_by_verdict_or_enqueued(
        tmp_path):
    """Sample: `no_remote_session`'s 4 defender findings read "withheld —
    reachability_unmeasured", `prior_fake_key_precedent`'s 4 read enqueued (the episode has
    `family_outcome: discard` and `verdict_word: undecidable`, and the rows still read
    enqueued), the 5 world-author rows read enqueued; a synthetic `unqueueable_findings:
    ["<id>: reason"]` entry marks that id unqueueable with the reason; a synthetic
    `verdict_word: discard` marks the MEASURING world's defender findings "never eligible —
    verdict discard", neither enqueued nor withheld, while the withheld world's four stay
    "withheld — reachability_unmeasured" exactly as the record's `withheld_findings` carries
    them; counts equal `enqueued_rows`, `len(withheld_findings)`, `world_enqueued_rows`; on
    that discard episode tile 3's split reads 0 defender / 5 world author / 4 withheld /
    0 unqueueable and gains a fifth part, "4 never eligible" — the measuring world's count.

    The page's disposition rule is the enqueue's (amendment 3), and the enqueue's precedence for
    a defender finding is subject → withheld → blocked → enqueued (`enqueue.py:731-748`, g13):
    a withheld world's findings are appended to `withheld_findings` BEFORE the
    `if defender_blocked: continue` arm is reached, so on a `discard` / `corpus-contradiction`
    episode "never eligible" is only ever the measuring worlds' disposition (92-reconciliation
    F-2).
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    for i in range(4):
        group = _group_of(page, f"f-{E.WITHHELD_WORLD}-0-{i}").text()
        assert "withheld" in group, group
        assert S.withheld_reason in group, group
        group = _group_of(page, f"f-{E.GRADED_WORLD}-0-{i}").text()
        assert "enqueued" in group, group
        assert "withheld" not in group, group
    for row in (f"f-{E.WITHHELD_WORLD}-0-4", f"f-{E.GRADED_WORLD}-0-4", f"f-{E.FAMILY}-0-0"):
        assert "enqueued" in _group_of(page, row).text(), row

    doc = E.sample_grade()
    doc["unqueueable_findings"] = [f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/1: the citation names no file"]
    E.write_judge(ep.dir, doc)
    page = render(ep)
    group = _group_of(page, f"f-{E.GRADED_WORLD}-0-1").text()
    assert "unqueueable" in group, group
    assert "the citation names no file" in group, group

    # the record as the enqueue writes it on a discard episode: `enqueued_rows` 0, and the
    # withheld world's four findings STILL on `withheld_findings` (withheld before blocked)
    doc = E.sample_grade()
    doc["verdict_word"] = "discard"
    doc["enqueued_rows"] = 0
    assert len(doc["withheld_findings"]) == S.defender_withheld, "fixture: the withheld list"
    E.write_judge(ep.dir, doc)
    page = render(ep)
    for i in range(4):
        group = _group_of(page, f"f-{E.GRADED_WORLD}-0-{i}").text()
        assert "never eligible — verdict discard" in group, group
        assert "enqueued" not in group, group
        assert "withheld" not in group, group
        group = _group_of(page, f"f-{E.WITHHELD_WORLD}-0-{i}").text()
        assert "withheld" in group, group
        assert S.withheld_reason in group, group
        assert "never eligible" not in group, group
    acct = page.one(cls="vd-acct").text()
    assert f"withheld list: {S.defender_withheld} entries · {S.defender_withheld} matched" in acct, acct
    # tile 3's split on the discard episode (95-reconciliation-2 N-4, auto-resolved): the split
    # gains a fifth part, "never eligible", carrying the measuring world's count; the other four
    # parts are the record's — 0 defender enqueued / world author as recorded / withheld = the
    # withheld world's / unqueueable as recorded
    three = _tile(page, 2).text()
    for part in ("0 defender", f"{S.world_author} world author",
                 f"{S.defender_withheld} withheld", "0 unqueueable",
                 f"{S.defender_enqueued} never eligible"):
        assert part in three, (part, three)


def test_1025_a_non_canonically_spelled_verdict_word_still_blocks_the_measuring_worlds_defender_findings(
        tmp_path):
    """The O7 gate the page's disposition rule claims to mirror (`enqueue_report`,
    `enqueue.py:622`) reads `verdict_word` through `normalized_judge_outcome` — case-folded and
    trimmed — never a bare `in`; a record whose `verdict_word` is `"Discard"` (mixed case, still
    a legal value on a record a sibling box can write) blocks the enqueue pass exactly as
    `"discard"` does. The page must read the SAME gate: a bare-`in` implementation would show
    the measuring world's defender findings "enqueued" on a record the real pass blocked.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["verdict_word"] = "Discard"
    doc["enqueued_rows"] = 0
    E.write_judge(ep.dir, doc)
    page = render(ep)
    for i in range(4):
        group = _group_of(page, f"f-{E.GRADED_WORLD}-0-{i}").text()
        assert "never eligible — verdict Discard" in group, group
        assert "enqueued" not in group, group


def test_1025_withheld_findings_are_grouped_under_their_reason_apart_from_enqueued_rows_and_never_worded_as_rejected(
        tmp_path):
    """The withheld group's heading carries `reachability_unmeasured`, none of its rows share a
    group with an enqueued row, and the words "rejected" / "dropped" do not appear in a
    withheld row or its heading; positive control: the enqueued group exists with 4 rows.
    """
    page = render(E.sample_episode(tmp_path))
    withheld = {_group_id(page, f"f-{E.WITHHELD_WORLD}-0-{i}") for i in range(4)}
    enqueued = {_group_id(page, f"f-{E.GRADED_WORLD}-0-{i}") for i in range(4)}
    assert len(withheld) == 1
    assert len(enqueued) == 1
    assert withheld.isdisjoint(enqueued)
    heading = _heading(page.section(withheld.pop()))
    assert S.withheld_reason in heading, heading
    assert "rejected" not in heading.lower(), heading
    assert "dropped" not in heading.lower(), heading
    for i in range(4):
        row = page.text_of(f"f-{E.WITHHELD_WORLD}-0-{i}").lower()
        assert "rejected" not in row, row
        assert "dropped" not in row, row
    enqueued_group = page.section(enqueued.pop())
    assert len([n for n in enqueued_group.descendants() if n.id and n.id.startswith("f-")]) == 4


def test_1025_findings_render_one_table_per_addressee_with_the_seven_columns_family_rows_at_family_level_and_dropped_counts_per_draw(
        tmp_path):
    """Two addressee tables (defender / world author): the defender rows and the world-author
    rows sit in disjoint groups whose headings name their addressee, and every row carries its
    world, bucket, disposition (on the row or its group), claim, root cause, anchor and
    evidence; the three family rows sit under world `family` with their `anchor` verbatim and
    no parsed world; each draw's `dropped_findings` count (0 on the sample; 2 on a synthetic
    draw) is shown per draw.
    """
    ep = E.sample_episode(tmp_path)
    page = render(ep)
    defender = {_group_id(page, f"f-{E.GRADED_WORLD}-0-{i}") for i in range(4)}
    authors = {_group_id(page, f"f-{w}-0-4") for w in (E.WITHHELD_WORLD, E.GRADED_WORLD)}
    authors |= {_group_id(page, f"f-{E.FAMILY}-0-{i}") for i in range(3)}
    assert defender.isdisjoint(authors), (defender, authors)
    assert all("defender" in _heading(page.section(g)) for g in defender)
    assert all("world author" in _heading(page.section(g)) for g in authors)
    graded_findings = _draw_findings(ep, E.GRADED_WORLD)
    for i, row in enumerate(graded_findings):
        text = page.text_of(f"f-{E.GRADED_WORLD}-0-{i}")
        for fact in (E.GRADED_WORLD, row["bucket"], row["claim"], row["root_cause"],
                     row["anchor"], row["evidence"][0]):
            assert fact in text, (fact, text)
        assert "enqueued" in text or "enqueued" in _group_of(page, f"f-{E.GRADED_WORLD}-0-{i}").text()
    for i, row in enumerate(E.family_findings()):
        text = page.text_of(f"f-{E.FAMILY}-0-{i}")
        assert row["anchor"] in text, text
        assert "family" in text, text
        assert E.WITHHELD_WORLD not in text.replace(row["anchor"], ""), text
    assert "0 dropped" in page.text_of("sec-findings")

    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=graded_findings, dropped=2))
    findings = render(ep).text_of("sec-findings")
    assert "2 dropped" in findings, findings
    assert "0 dropped" in findings, findings


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


def test_1025_queue_accounting_lists_per_queue_rows_destination_as_recorded_withheld_reasons_unqueueable_malformed_and_dropped_counts(
        tmp_path):
    """The collapsed details carry "defender: 4 enqueued to <the recorded path>" (the path as
    recorded, escaped, not a link), "questioner: 5 enqueued to …", withheld 4
    (reachability_unmeasured), unqueueable 0, malformed 0 / 0, dropped 0 per draw, and
    `discard_evidence` rendered because `family_outcome` is discard.
    """
    page = render(E.sample_episode(tmp_path))
    acct = page.elements(cls="vd-acct")
    assert acct, "no queue-accounting details"
    text = acct[0].text()
    assert f"defender: {S.defender_enqueued} enqueued to {E.ENQUEUED_TO}" in text, text
    assert f"questioner: {S.world_author} enqueued to {E.WORLD_ENQUEUED_TO}" in text, text
    assert f"withheld {S.defender_withheld}" in text, text
    assert S.withheld_reason in text, text
    assert "unqueueable 0" in text, text
    assert "malformed 0 / 0" in text, text
    assert "dropped 0" in text, text
    assert "review.yaml#worlds.*.consistency.control_mismatch_keys" in text, text
    assert not [h for h in page.hrefs if "_pending/findings.jsonl" in h], "the path became a link"


def test_1025_one_card_per_graded_world_with_declared_to_verdict_reason_or_bucket_heading_chips_and_a_footer_linking_its_findings_group(
        tmp_path):
    """Sample: two cards; `no_remote_session`'s header "benign → inconclusive", heading
    "reachability_unmeasured", body the chips plus the first line of `envelope_failed`, footer
    "4 findings · withheld" linking to its `fg-<n>`; `prior_fake_key_precedent`'s heading
    "decision-discipline" and footer "4 findings · enqueued"; the live-996 shape renders one
    card (none for the ungradable world or the control); no card contains a family finding's
    claim.
    """
    page = render(E.sample_episode(tmp_path))
    cards = {c.text(): c for c in _cards(page)}
    assert len(cards) == 2, list(cards)
    withheld = next(t for t in cards if E.WITHHELD_WORLD in t)
    graded = next(t for t in cards if E.GRADED_WORLD in t)
    assert re.search(r"benign\s*→\s*(said\s+)?inconclusive", withheld), withheld
    assert S.withheld_reason in withheld, withheld
    assert "holding_queried" in withheld, withheld
    assert E.ENVELOPE_FAILED.splitlines()[0] in withheld, withheld
    assert E.ENVELOPE_FAILED.splitlines()[1] not in withheld, withheld
    assert "4 findings · withheld" in withheld, withheld
    withheld_group = _group_id(page, f"f-{E.WITHHELD_WORLD}-0-0")
    assert f"#{withheld_group}" in [a.attrs.get("href") for a in cards[withheld].find_all("a")]
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
    assert "6" in stages_heading or "six" in stages_heading, stages_heading


# ---------------------------------------------------------------------------------------
# J9b–e — identity, stubs, counts, skips, the suffix join
# ---------------------------------------------------------------------------------------


def test_1025_a_finding_id_recorded_in_judge_yaml_names_a_world_draw_index_triple_absent_from_every_draw_document(
        tmp_path):
    """A record row whose draw document is gone (J9b): `judge.yaml.world_findings` carries its
    own `finding` text and `withheld_findings` entries the whole finding dict, so the page
    renders a stub row from the record — that text, its recorded disposition, and a "draw
    document absent" marker — and tile 3 counts it; an `unqueueable_findings` line with no
    document renders in queue accounting only. A withheld entry carries no draw / index
    (amendment 1), so its stub is found by its text, under a withheld group; the recorded
    `world_findings` row keeps its `f-<world>-<draw>-<index>` id from the recorded id's suffix.

    THE GRAIN IS THE DOCUMENT (92-reconciliation F-5): a stub is rendered iff the draw DOCUMENT
    named by the recorded triple is absent; a triple missing from a PRESENT document — a
    document rewritten with fewer findings than the record names — renders no stub and no
    row, and tile 3 counts only what is on disk (the rule `identical_findings_under_two_draws`,
    `a_draw_document_is_missing_its_findings_key_entirely` and `the_same_finding_id_string…`
    already depend on).
    """
    ep = E.sample_episode(tmp_path)
    (ep.world(E.GRADED_WORLD) / "judge" / "0.yaml").unlink()
    (ep.world(E.WITHHELD_WORLD) / "judge" / "0.yaml").unlink()
    doc = E.sample_grade()
    doc["unqueueable_findings"] = [f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/7: no document either"]
    E.write_judge(ep.dir, doc)
    page = render(ep)
    stub = page.text_of(f"f-{E.GRADED_WORLD}-0-4")
    assert "draw document absent" in stub, stub
    assert doc["world_findings"][4]["finding"] in stub, stub
    assert "enqueued" in _group_of(page, f"f-{E.GRADED_WORLD}-0-4").text()
    withheld_stubs = [n for n in page.section("sec-findings").descendants()
                      if n.id and n.id.startswith("f-") and "defender claim 0" in n.text()]
    assert len(withheld_stubs) == 1, [n.id for n in withheld_stubs]
    assert "draw document absent" in withheld_stubs[0].text()
    assert "withheld" in page.group_of(withheld_stubs[0].id or "").text()
    rows = _rows(page)
    assert f"f-{E.GRADED_WORLD}-0-7" not in rows, rows
    # family 3 + the recorded prior/0/4 stub + no_remote_session's 0/4 stub + 4 withheld stubs
    assert f"of {3 + 1 + 1 + 4}" in _tile(page, 2).text(), _tile(page, 2).text()
    assert "no document either" in page.one(cls="vd-acct").text()

    # the grain: the graded world's document is back with ONE finding while the record still
    # names `<ep>/prior_fake_key_precedent/0/4` — a present document, a missing triple, no stub
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(
        findings=[E.finding(subject="defender", claim="THE ONLY FINDING LEFT")]))
    page = render(ep)
    graded_rows = [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]
    assert graded_rows == [f"f-{E.GRADED_WORLD}-0-0"], graded_rows
    assert "THE ONLY FINDING LEFT" in page.text_of(f"f-{E.GRADED_WORLD}-0-0")
    assert "draw document absent" not in page.text_of(f"f-{E.GRADED_WORLD}-0-0")
    # family 3 + the one row on disk + no_remote_session's 0/4 stub + 4 withheld stubs — not
    # 10: no stub for the recorded `prior_fake_key_precedent/0/4`
    assert f"of {3 + 1 + 1 + 4}" in _tile(page, 2).text(), _tile(page, 2).text()


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
    doc["enqueued_rows"] = 7
    E.write_judge(ep.dir, doc)
    page = render(ep)
    acct = page.one(cls="vd-acct").text()
    assert "record: 7 enqueued · page found: 4" in acct, acct
    assert "record and page disagree by 3" in acct, acct
    assert f"{S.queued} of {S.findings}" in _tile(page, 2).text()


def test_1025_withheld_cross_check_fails(tmp_path):
    """The withheld cross-check is run and reported the same way — "withheld list: N entries ·
    M matched" — with the disagreement line when the record's list and the page's walk differ;
    every defender finding of a withheld world still renders as withheld regardless (J9c).
    """
    ep = E.sample_episode(tmp_path)
    acct = render(ep).one(cls="vd-acct").text()
    assert f"withheld list: {S.defender_withheld} entries · {S.defender_withheld} matched" in acct, acct

    full = E.sample_grade()
    short = E.sample_grade(withheld_findings=full["withheld_findings"][:3])
    E.write_judge(ep.dir, short)
    page = render(ep)
    acct = page.one(cls="vd-acct").text()
    assert "withheld list: 3 entries · 3 matched" in acct, acct
    assert "record and page disagree by 1" in acct, acct
    for i in range(4):
        assert "withheld" in _group_of(page, f"f-{E.WITHHELD_WORLD}-0-{i}").text()


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
    doc = E.sample_grade()
    for row in doc["world_findings"]:
        row["finding_id"] = row["finding_id"].replace(E.EPISODE_ID, "old-name-before-repair")
    doc["unqueueable_findings"] = [f"old-name-before-repair/{E.GRADED_WORLD}/0/1: a reason"]
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
    """A draw document without a `findings` key is zero findings for that draw — no distinct
    sentence, no error: the world's other draw renders, tile 3's total drops by the five rows
    the document no longer carries.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.draw_doc()
    del doc["findings"]
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
    rows = _rows(render(ep))
    assert f"f-{E.GRADED_WORLD}-0-0" in rows, rows
    assert f"f-{E.GRADED_WORLD}-1-0" in rows, rows


def test_1025_draw_index_beyond_the_recorded_completed_draw_count(tmp_path):
    """A draw document whose index exceeds `knobs.draws` / `draws.completed` renders like any
    other draw — every per-draw file is a source and no cross-check against the knobs is made.
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, 5, E.draw_doc(
        findings=[E.finding(subject="defender", claim="OVER-INDEX CLAIM")]))
    page = render(ep)
    assert f"f-{E.GRADED_WORLD}-5-0" in _rows(page)
    assert "OVER-INDEX CLAIM" in page.text_of(f"f-{E.GRADED_WORLD}-5-0")


def test_1025_subject_field_holds_a_value_outside_defender_and_world(tmp_path):
    """A finding whose `subject` is neither `defender` nor `world` takes the record's
    disposition (the enqueue filed it unqueueable): it renders in its world's table under an
    "unqueueable — <reason>" group with the subject shown verbatim, and tile 3 counts it.
    """
    ep = E.sample_episode(tmp_path)
    findings = _draw_findings(ep, E.GRADED_WORLD)
    findings.append(E.finding(subject="oracle", claim="ORACLE CLAIM"))
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=findings))
    doc = E.sample_grade()
    doc["unqueueable_findings"] = [f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/5: subject 'oracle' is not an addressee"]
    E.write_judge(ep.dir, doc)
    page = render(ep)
    row = f"f-{E.GRADED_WORLD}-0-5"
    assert row in _rows(page)
    assert "oracle" in page.text_of(row)
    assert "ORACLE CLAIM" in page.text_of(row)
    heading = _heading(_group_of(page, row))
    assert "unqueueable" in heading, heading
    assert "subject 'oracle' is not an addressee" in heading, heading
    assert f"of {S.findings + 1}" in _tile(page, 2).text()


def test_1025_a_finding_that_is_not_a_mapping(tmp_path):
    """A scalar where a finding mapping belongs renders no row (there is no text to key a row
    from), stays in the queue accounting through the record's own unqueueable line, and tile 3's
    total counts mappings only.
    """
    ep = E.sample_episode(tmp_path)
    findings: list = _draw_findings(ep, E.GRADED_WORLD)
    findings.append("just a bare string, not a finding")
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=findings))
    doc = E.sample_grade()
    doc["unqueueable_findings"] = [f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/5: not a mapping"]
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert f"f-{E.GRADED_WORLD}-0-5" not in _rows(page)
    assert f"of {S.findings}" in _tile(page, 2).text()
    assert "not a mapping" in page.one(cls="vd-acct").text()


def test_1025_a_draw_document_that_is_only_a_failure_reason(tmp_path):
    """A `{failure_reason: …}` draw document renders its `failure_reason` verbatim-escaped on
    that draw's line with the dropped count shown as "—", contributes no rows, and the other
    draws render as usual.
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, 1,
                    {"failure_reason": "the judge reply <b>did not parse</b>"})
    page = render(ep)
    findings = page.text_of("sec-findings")
    assert "the judge reply <b>did not parse</b>" in findings, findings
    assert "&lt;b&gt;did not parse" in page.raw
    assert not [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-1-")]
    line = findings[findings.index("did not parse"):][:200]
    assert "—" in line, line


def test_1025_a_world_finding_refused_for_citing_an_unavailable_sample(tmp_path):
    """A world finding the enqueue refused for citing a pattern its row lists under
    `sample_unavailable_patterns` (absent from `world_findings`, present in
    `unqueueable_findings` with the A1(b) reason) renders in the world-author table under an
    "unqueueable — <reason>" group — never dropped from the table (O2).
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"][1]["sample_unavailable"] = True
    doc["worlds"][1]["sample_unavailable_patterns"] = ["logs-system.auth-*"]
    doc["worlds"][1]["world_findings"] = []
    doc["world_findings"] = [r for r in doc["world_findings"]
                             if not r["finding_id"].endswith(f"/{E.GRADED_WORLD}/0/4")]
    reason = "cites logs-system.auth-*, whose sample was unavailable"
    doc["unqueueable_findings"] = [f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/4: {reason}"]
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


def test_1025_the_episode_level_verdicts_justification(tmp_path):
    """The episode-level words are justified from record values only (J10): each draw group in
    the lede and in the findings section carries that draw's own `episode_outcome` word, and
    `discard_evidence` renders when it is set.
    """
    page = render(E.sample_episode(tmp_path))
    band = page.text_of("sec-verdict")
    assert "review.yaml#worlds.*.consistency.control_mismatch_keys" in band, band
    family_group = _group_of(page, f"f-{E.FAMILY}-0-0").text()
    assert "discard" in family_group, family_group
    world_group = _group_of(page, f"f-{E.GRADED_WORLD}-0-0").text()
    assert "gradable" in world_group, world_group
    lede = band[: band.index(LEDE_LINE)]
    assert "discard" in lede, lede


def test_1025_record_fields_no_slot_binds(tmp_path):
    """Bound slots only (J10): the record fields no slot names — the draw's `noise_floor_note`,
    the row's `spread` and `integrity_notes` — do not reach the page; the raw-record fold is a
    recorded follow-up, not this page. Positive control: the draw's own `episode_outcome` word,
    which the resolution binds, does render with its group.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.draw_doc(findings=[E.finding(subject="defender")],
                     noise_floor_note="NOISE-FLOOR-NOTE-UNBOUND",
                     episode_outcome="gradable")
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, doc)
    grade = E.sample_grade()
    grade["worlds"][1]["integrity_notes"] = ["INTEGRITY-NOTE-UNBOUND"]
    grade["worlds"][1]["spread"] = {"SPREAD-KEY-UNBOUND": 1}
    E.write_judge(ep.dir, grade)
    page = render(ep)
    for unbound in ("NOISE-FLOOR-NOTE-UNBOUND", "INTEGRITY-NOTE-UNBOUND", "SPREAD-KEY-UNBOUND"):
        assert unbound not in page.raw, unbound
    assert "gradable" in _group_of(page, f"f-{E.GRADED_WORLD}-0-0").text()


def test_1025_family_drawn_several_times_with_a_dissenting_draw(tmp_path):
    """A family drawn twice whose draws disagree on the outcome word renders two groups in draw
    order, each carrying its own `episode_outcome` word beside its findings, never merged; the
    badge stays the record's majority word `family_outcome`.
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.FAMILY, 1, E.draw_doc(
        findings=[E.finding(subject="world", topic="dissent topic", claim="dissent claim")],
        episode_outcome="gradable"))
    doc = E.sample_grade()
    doc["world_findings"].append(E.family_queue_row(1, 0, topic="dissent topic", claim="dissent claim"))
    E.write_judge(ep.dir, doc)
    page = render(ep)
    band = page.text_of("sec-verdict")
    first = band.index("family topic 0")
    second = band.index("dissent topic: dissent claim")
    assert first < second, band
    assert "discard" in band[first:second], band
    assert "gradable" in band[second:second + 400], band
    assert "discard" in page.one(cls="vd-badge").text()
    assert "gradable" in _group_of(page, f"f-{E.FAMILY}-1-0").text()
    assert "discard" in _group_of(page, f"f-{E.FAMILY}-0-0").text()


def test_1025_manifest_fields_the_slot_bindings_never_name(tmp_path):
    """The manifest fields no slot binds — `source_run_dir` (an absolute path outside the
    archive), `continuation_prompt`, `as_of`, `fences_at`, `captured_patterns` — stay off the
    page; `source_run_dir` is never a link source. Positive control: the bound `base_story` and
    each sibling's `axis` render.
    """
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest(source_run_dir="/runs/SOURCE-RUN-DIR-UNBOUND",
                                 continuation_prompt="CONTINUATION-PROMPT-UNBOUND",
                                 as_of="2099-01-01T00:00:00Z",
                                 captured_patterns=["CAPTURED-PATTERN-UNBOUND"])
    T.write_family(ep.dir, manifest)
    page = render(ep)
    for unbound in ("SOURCE-RUN-DIR-UNBOUND", "CONTINUATION-PROMPT-UNBOUND",
                    "2099-01-01T00:00:00Z", "CAPTURED-PATTERN-UNBOUND"):
        assert unbound not in page.raw, unbound
    assert E.BASE_STORY in page.text_of("sec-records")
    assert E.AXIS_GRADED in page.text_of("sec-worlds")


def _class_carries(page: E.Page, word: str) -> list[str]:
    return [n.attrs["class"] for n in page.root.descendants()
            if word.lower() in (n.attrs.get("class") or "").lower()]


def test_1025_withheld_reason_outside_the_four_known_values(tmp_path):
    """A `withheld_reason` outside the four members renders as its raw word, escaped, with no
    decoding gloss, in the withheld group's heading and the world's card; the class comes from
    the closed map's neutral fallback, so the word appears in no `class` attribute (J11/J5).
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"][0]["withheld_reason"] = "weird<reason>"
    for entry in doc["withheld_findings"]:
        entry["reason"] = "weird<reason>"
    E.write_judge(ep.dir, doc)
    page = render(ep)
    heading = _heading(_group_of(page, f"f-{E.WITHHELD_WORLD}-0-0"))
    assert "weird<reason>" in heading, heading
    assert "&lt;reason&gt;" in page.raw, heading
    assert _class_carries(page, "weird") == []


def test_1025_verdict_word_outside_the_five_known_values(tmp_path):
    """A `verdict_word` outside {undecidable, caught, survived, discard, corpus-contradiction}
    renders as its raw word, escaped, in the meta line and tile 1, tile 1 carries "(family
    outcome, not the ladder)" as it does for any non-ladder word (fk-9), and the word drives no
    class. Positive control: `undecidable` carries no such note.
    """
    ep = E.sample_episode(tmp_path)
    assert "(family outcome, not the ladder)" not in _tile(render(ep), 0).text()
    doc = E.sample_grade()
    doc["verdict_word"] = "mystery<word>"
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "mystery<word>" in page.one(cls="vd-meta").text()
    assert "mystery<word>" in _tile(page, 0).text()
    assert "(family outcome, not the ladder)" in _tile(page, 0).text(), _tile(page, 0).text()
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
    """Renders as a graded record with zero rows: tile 1 "0 of 0 graded measuring · 0 of 0
    contrast the control · verdict = declared on 0 of 0", no cards, findings section carrying
    family-draw rows only, the control alone in the worlds guide — not the not_graded band.
    """
    ep = E.sample_episode(tmp_path)
    for label in (E.WITHHELD_WORLD, E.GRADED_WORLD):
        shutil.rmtree(ep.world(label) / "judge")
    doc = E.sample_grade()
    doc["worlds"] = []
    doc["withheld_findings"] = []
    doc["enqueued_rows"] = 0
    doc["world_findings"] = doc["world_findings"][:3]
    doc["world_enqueued_rows"] = 3
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "0 of 0 graded measuring · 0 of 0 contrast the control · verdict = declared on 0 of 0" in _tile(page, 0).text()
    assert _cards(page) == []
    assert set(_rows(page)) == {f"f-{E.FAMILY}-0-{i}" for i in range(3)}, _rows(page)
    assert "no grade record" not in page.text_of("sec-verdict")


def test_1025_judge_yaml_carries_a_top_level_field_this_readers_schema_has_never_seen(tmp_path):
    """`read_grade` tolerates an unknown top-level string key (dropped, not on the record —
    p8), so the page is UNCHANGED: no crash, the field rendered nowhere, the bytes equal to the
    same record without the key.
    """
    ep = E.sample_episode(tmp_path)
    assert "undecidable" in render(ep).text_of("sec-verdict"), "positive control: the record renders"
    baseline = ep.page.read_bytes()
    doc = E.sample_grade()
    doc["never_seen_field"] = {"planted": "NEVER-SEEN-VALUE"}
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
    never renumbered; tile 3 counts the rows on disk; all three judge traces render — the trace
    for draw 1 exists and is enumerated as roster label × stems present even though draw 1 has
    no document.
    """
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, 2, E.draw_doc(
        findings=[E.finding(subject="defender", claim="DRAW TWO")]))
    for n in (1, 2):
        E.write_trace(ep.dir, f"judge:{E.GRADED_WORLD}:{n}")
        E.write_framed(ep.dir, f"judge:{E.GRADED_WORLD}:{n}")
    page = render(ep)
    rows = [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]
    assert f"f-{E.GRADED_WORLD}-2-0" in rows, rows
    assert not [r for r in rows if r.startswith(f"f-{E.GRADED_WORLD}-1-")], rows
    assert f"of {S.findings + 1}" in _tile(page, 2).text()
    for n in (0, 1, 2):
        assert f"tx-judge_{E.GRADED_WORLD}_{n}_trace" in page.by_id, page.ids_with("tx-")


def test_1025_a_worlds_row_mechanical_world_findings_entry_and_a_real_numeric_draw_coexist_for_the_same_world(
        tmp_path):
    """Both render: the numeric draws' rows at `f-<world>-<n>-<i>` and each
    `mechanical_world_findings` entry at `f-<world>-mechanical-<i>`; the sets are disjoint and
    additive (correction 1).
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"][1]["mechanical_world_findings"] = [
        E.finding(subject="world", bucket="unreachable-difference", claim=f"MECH {i}")
        for i in range(2)]
    for i in range(2):
        doc["world_findings"].append(E.world_finding_queue_row(
            f"{E.EPISODE_ID}/{E.GRADED_WORLD}/mechanical/{i}", f"MECH {i} — root"))
    E.write_judge(ep.dir, doc)
    rows = [r for r in _rows(render(ep)) if r.startswith(f"f-{E.GRADED_WORLD}-")]
    assert {f"f-{E.GRADED_WORLD}-mechanical-0", f"f-{E.GRADED_WORLD}-mechanical-1"} <= set(rows)
    assert {f"f-{E.GRADED_WORLD}-0-{i}" for i in range(5)} <= set(rows)
    assert len(rows) == 7, rows


def test_1025_unqueueable_reason_text_contains_the_page_join_delimiter(tmp_path):
    """The split is on the FIRST `": "` (a run id admits no `:`, F9): the reason keeps any later
    `": "`, rendered escaped; a line with no separator is rendered whole in the queue accounting
    and joins no row.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["unqueueable_findings"] = [
        f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/1: reason part one: part two <x>",
        "no separator in this line at all",
    ]
    E.write_judge(ep.dir, doc)
    page = render(ep)
    group = _group_of(page, f"f-{E.GRADED_WORLD}-0-1").text()
    assert "unqueueable" in group, group
    assert "reason part one: part two <x>" in group, group
    acct = page.one(cls="vd-acct").text()
    assert "no separator in this line at all" in acct, acct
    assert "&lt;x&gt;" in page.raw


def test_1025_an_unqueueable_line_that_matches_no_rendered_finding(tmp_path):
    """An `unqueueable_findings` line naming a coordinate with no text appears verbatim
    (escaped) in the queue-accounting details' unqueueable list; no findings row is synthesised
    for it. Positive control: the line's own text is on the page.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["unqueueable_findings"] = [f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/9: <no such row>"]
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert f"f-{E.GRADED_WORLD}-0-9" not in page.all_ids
    acct = page.one(cls="vd-acct").text()
    assert f"{E.GRADED_WORLD}/0/9: <no such row>" in acct, acct
    assert "&lt;no such row&gt;" in page.raw
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
    page = render(ep)
    rows = [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]
    assert sorted(rows) == [f"f-{E.GRADED_WORLD}-0-0", f"f-{E.GRADED_WORLD}-1-0"], rows
    assert f"of {S.findings - 5 + 2}" in _tile(page, 2).text()
    assert "duplicate" not in page.text_of("sec-findings").lower()


def test_1025_family_call_faulted_after_writing_a_draw(tmp_path):
    """Both render: the family findings that were written (one line per row, grouped by draw in
    draw order) and `family_failed_reason` (escaped) in the reason slot ahead of the templated
    line; neither suppresses the other.
    """
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["family_failed_reason"] = "draw 1 failed: <TransportFault>"
    doc["family_outcome"] = None
    E.write_judge(ep.dir, doc)
    band = render(ep).text_of("sec-verdict")
    assert "draw 1 failed: <TransportFault>" in band
    assert "family topic 0: family claim 0" in band
    assert band.index("draw 1 failed") < band.index("findings queued")


def test_1025_a_gradable_row_whose_draws_never_ran(tmp_path):
    """A gradable row whose draws never ran (no draw document, no trace) is graded on the page
    (`is_gradable_row`): verdict, bucket, ladder and a card render from the row; no transcript
    block for it and an empty findings group.
    """
    ep = E.sample_episode(tmp_path)
    (ep.world(E.GRADED_WORLD) / "judge" / "0.yaml").unlink()
    for name in (f"judge_{E.GRADED_WORLD}_0_trace.jsonl", f"judge_{E.GRADED_WORLD}_0_framed_trace.jsonl"):
        (ep.dir / "wire_logs" / name).unlink()
    doc = E.sample_grade()
    doc["worlds"][1]["completed_draws"] = 0
    doc["worlds"][1]["draws_failed_reason"] = "no draw completed"
    doc["worlds"][1]["world_findings"] = []
    doc["world_findings"] = [r for r in doc["world_findings"]
                             if not r["finding_id"].endswith(f"/{E.GRADED_WORLD}/0/4")]
    doc["world_enqueued_rows"] = 4
    E.write_judge(ep.dir, doc)
    page = render(ep)
    world = page.text_of(f"world-{E.GRADED_WORLD}")
    assert "inconclusive" in world
    assert "decision-discipline" in world
    assert "holding_queried" in world
    assert any(E.GRADED_WORLD in c.text() for c in _cards(page))
    assert f"tx-judge_{E.GRADED_WORLD}_0_trace" not in page.by_id
    assert not [r for r in _rows(page) if r.startswith(f"f-{E.GRADED_WORLD}-")]


def test_1025_an_episode_with_only_the_control(tmp_path):
    """Tile 1 "0 of 0 graded measuring · 0 of 0 contrast the control · verdict = declared on
    0 of 0" beside `undecidable`; no cards; the findings section carries family-draw rows
    only; the worlds guide names the control alone as "the branch point untouched, not
    graded"; renders without raising.
    """
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"] = manifest["worlds"][:1]
    T.write_family(ep.dir, manifest)
    for label in (E.WITHHELD_WORLD, E.GRADED_WORLD):
        shutil.rmtree(ep.world(label))
        shutil.rmtree(ep.run(label))
    doc = E.sample_grade()
    doc["worlds"], doc["withheld_findings"], doc["enqueued_rows"] = [], [], 0
    doc["world_findings"] = doc["world_findings"][:3]
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "0 of 0 graded measuring · 0 of 0 contrast the control · verdict = declared on 0 of 0" in _tile(page, 0).text()
    assert "undecidable" in _tile(page, 0).text()
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
    doc["not_graded"] = {"outcome": "rejected", "reason": "STAMP-REASON-EARLIER"}
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


def test_1025_tile_one_reads_verdict_and_declared_through_the_one_normalizer_the_contrast_uses(tmp_path):
    """`verdict: ' benign '` against `declared: 'benign'` is the same disposition on BOTH of
    tile 1's figures — the contrast count already put both sides through the vocabulary's
    normalizer (which strips); the agreement count compared the raw strings and read "verdict
    = declared on 0 of 1" beside a contrast figure that treated them as one word."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    graded = next(w for w in doc["worlds"] if w["world"] == E.GRADED_WORLD)
    graded["declared"] = "benign"
    graded["verdict"] = " benign "
    E.write_judge(ep.dir, doc)
    tile = _tile(render(ep), 0).text()
    assert "verdict = declared on 1 of 1" in tile, tile


def test_1025_an_empty_family_outcome_is_the_badge_word_not_an_absence(tmp_path):
    """`family_outcome` is the record's own `str | None`: the badge shows the recorded word
    whenever one is recorded, an empty string included — never the verdict word in its place
    (`is not None`, not `or`)."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["family_outcome"] = ""
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert page.one(cls="vd-badge").text() == "", page.one(cls="vd-badge").text()
    assert doc["verdict_word"] in page.one(cls="vd-meta").text()  # positive control
