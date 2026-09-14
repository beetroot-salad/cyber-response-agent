"""#1025 — the episode page reads the directory ONCE into a typed model and renders from it.

What the split buys, pinned behavior by behavior: a stray scalar where a record's writer produces
a list or a mapping degrades THAT slot and never the render (d01: only `family.yaml` refuses the
whole page); the findings walk runs once, so the tiles, the cards' footers and the findings
section cannot disagree about a count or a group number; the page's disposition rule reads an
absent `subject` exactly as `enqueue_report` does; the record-only withheld stubs are joined
per finding, not per world; the stage clock's whole-second stamps make a zero-length step a
real step; and the CLI's diagnostics come off the model's refusal slots, never a scan of the
rendered bytes. Each of these was a finding of the PR #1042 review, verified by probe against
the section-reads-its-own-records shape this model replaced.
"""
from __future__ import annotations

import json

import pytest
import yaml

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

S = E.SAMPLE


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


def visualize_episode():
    return E.page_module()


def render(ep) -> E.Page:
    return E.render(ep, module=visualize_episode())


def cli(argv, capsys):
    return E.cli(argv, capsys, module=visualize_episode())


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


def test_1025_a_scalar_worlds_field_in_the_manifest_renders_a_page_with_no_world_sections(tmp_path):
    """`family.yaml` with `worlds: 5` is a manifest the page can read (d01 refuses only an
    unreadable one): the page renders, the guide has no rows, the world sections are the
    record's and the run dirs' own (no manifest world contributes one), and the records section
    still lists the base story — the roster builder and every section that walks the manifest's
    worlds read the same typed list."""
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"] = 5
    T.write_family(ep.dir, manifest)
    page = render(ep)
    assert page.elements(cls="vd-guide-row") == []
    assert sorted(page.ids_with("world-")) == sorted(f"world-{w}" for w in E.WORLDS)
    assert "not graded" in page.text_of(f"world-{E.CONTROL}")
    assert E.BASE_STORY in page.text_of("sec-records")


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


def test_1025_a_scalar_list_field_in_the_review_or_the_provenance_record_degrades_its_own_slot(tmp_path):
    """`review.yaml` with `worlds.<label>.inventions: 5` and `provenance.json` with
    `agreed.dirty_paths: 5` render the records section with those two lists empty and every
    other record intact."""
    ep = E.sample_episode(tmp_path)
    review_path = ep.dir / "review.yaml"
    review = yaml.safe_load(review_path.read_text(encoding="utf-8"))
    review["worlds"][E.GRADED_WORLD]["inventions"] = 5
    review["teardown"] = {"at": "2026-09-09T10:00:00Z", "failures": 7}
    review_path.write_text(yaml.safe_dump(review, sort_keys=False), encoding="utf-8")
    stamp_path = ep.dir / "provenance.json"
    stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    stamp["agreed"]["dirty_paths"] = 5
    stamp_path.write_text(json.dumps(stamp), encoding="utf-8")
    page = render(ep)
    records = page.text_of("sec-records")
    assert "review record unreadable" not in records, records
    assert "provenance record unreadable" not in records, records
    assert E.LESSONS_COMMIT[:8] in records or "allow_dirty" in records, records
    assert not page.elements(cls="rc-invention")
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
    findings = E._world_findings_rows(withheld=False)
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
    findings = E._world_findings_rows(withheld=False)
    findings.insert(0, findings.pop())  # the world-author finding now comes first
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=findings))
    doc = E.sample_grade()
    doc["world_findings"] = [r for r in doc["world_findings"]
                             if not r["finding_id"].endswith(f"/{E.GRADED_WORLD}/0/4")]
    doc["world_findings"].append(E.world_finding_queue_row(
        f"{E.EPISODE_ID}/{E.GRADED_WORLD}/0/0", "the world-author claim"))
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
    E.write_judge(ep.dir, {**E.sample_grade(), "verdict_word": "discard"})
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
    graded = E._world_findings_rows(withheld=False)
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=graded, dropped=2))
    page = render(ep)
    assert "2 dropped" in _tile(page, 2), _tile(page, 2)
    assert "dropped 2" in page.one(cls="vd-acct").text()
    assert "2 dropped" in page.text_of("sec-findings")


def test_1025_a_recorded_withheld_finding_whose_document_is_gone_is_a_stub_beside_the_survivors(tmp_path):
    """The record lists four withheld findings for the withheld world; its only surviving
    draw document carries two of them. The page shows all four — the two on disk as rows, the
    two without a document as "draw document absent" stubs with the record's own claim — and
    the accounting reads "4 entries · 4 matched" with no disagreement."""
    ep = E.sample_episode(tmp_path)
    withheld = E._world_findings_rows(withheld=True)
    E.draw_document(ep.dir, E.WITHHELD_WORLD, 0, E.draw_doc(findings=withheld[:2]))
    page = render(ep)
    withheld_rows = [i for i in page.ids if i.startswith(f"f-{E.WITHHELD_WORLD}-")]
    assert len(withheld_rows) == 4, withheld_rows
    stubs = [i for i in withheld_rows if "-withheld-" in i]
    assert len(stubs) == 2, withheld_rows
    for row_id in stubs:
        text = page.text_of(row_id)
        assert "draw document absent" in text, text
        assert "withheld" in _heading_of(page, row_id)
    for i in (2, 3):
        assert withheld[i]["claim"] in page.text_of("sec-findings")
    acct = page.one(cls="vd-acct").text()
    assert "withheld list: 4 entries · 4 matched" in acct, acct
    assert "record and page disagree" not in acct, acct
    assert f"{S.defender_withheld} withheld" in _tile(page, 2), _tile(page, 2)


# ---------------------------------------------------------------------------------------
# The stage clock, the report slot, the CLI's diagnostics
# ---------------------------------------------------------------------------------------


def test_1025_a_step_that_starts_and_ends_within_one_second_still_bounds_the_header_wall(tmp_path):
    """`now_iso()` stamps whole seconds, so `verify` starting and ending on the same stamp is
    a real zero-length step, not an inverted pair: its endpoints feed the header span. With
    `verify` as the LAST step and its stamp at 10:11:00, the header reads the full 11m00s from
    the questioner's start, not the 9m00s that dropping it would leave."""
    ep = E.sample_episode(tmp_path)
    steps = E.six_steps()
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
    graded = E._world_findings_rows(withheld=False)
    graded[0]["claim"] = "the run left no grade record behind"
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=graded))
    rc, out, err = cli([str(ep.dir)], capsys)
    assert rc == 0, (rc, out, err)
    assert str(ep.page) in out
    assert "no grade record" not in err, err
    assert "grade record unreadable" not in err, err
    E.plant_raw(ep.dir / "judge.yaml", "worlds: [\n")
    rc, _out, err = cli([str(ep.dir)], capsys)
    assert rc == 0
    assert "grade record unreadable" in err, err
