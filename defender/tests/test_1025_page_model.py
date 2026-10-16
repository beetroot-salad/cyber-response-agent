"""#1025 — the episode page reads the directory ONCE into a typed model and renders from it."""
from __future__ import annotations

import json
import os
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
    """`family.yaml` with `worlds: 5` is a manifest the runtime loader refuses (the page reads the
    manifest through the loader's own gate, `family.read_manifest`), so it is the."""
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["worlds"] = 5
    T.write_family(ep.dir, manifest)
    with pytest.raises(E.sym("learning.judge", "JudgeRefused"), match="worlds"):
        E.render_episode(ep.dir, module=visualize_episode())
    assert not ep.page.exists(), "a page was written for a manifest the loader refused"


def test_1025_a_scalar_findings_field_in_a_draw_document_is_that_draws_own_absence(tmp_path):
    """`worlds/<label>/judge/1.yaml` with `investigator_findings: 5` (a recorded draw) contributes
    no rows; the other draws' rows render as usual and the page is written."""
    ep = E.sample_episode(tmp_path)
    E.draw_document(ep.dir, E.GRADED_WORLD, 1, {"bucket": "lead-set", "systems": [E.SYSTEM],
                                                "investigator_findings": 5})
    E.write_judge(ep.dir, E.record_draws(E.sample_grade(), E.GRADED_WORLD, (0, 1)))
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
    # #1234 A6: a transcript shows for a draw the record names
    E.write_judge(ep.dir, E.record_draws(E.sample_grade(), E.GRADED_WORLD, (0, 1)))
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
    """A draw finding that carries no `subject` at all (the pre-#1007 shape the live archive holds)
    sits in the "defender."""
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
    """A graded world whose FIRST finding row is addressed to the world author still has its card
    footer "4 findings · enqueued" link the group its defender rows sit in ."""
    ep = E.sample_episode(tmp_path)
    findings = E._world_findings_rows()
    E.draw_document(ep.dir, E.GRADED_WORLD, 0, E.draw_doc(findings=findings[4:]))
    E.draw_document(ep.dir, E.GRADED_WORLD, 1, E.draw_doc(findings=findings[:4]))
    doc = E.drop_lanes(E.sample_grade(), E.GRADED_WORLD)
    E.record_draws(doc, E.GRADED_WORLD, (0, 1))
    E.set_lane(doc, E.GRADED_WORLD, 0, 0, "world")
    for i in range(4):
        E.set_lane(doc, E.GRADED_WORLD, 1, i, "defender")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    href, text = _card_link(_card(page, E.GRADED_WORLD))
    assert text == "4 findings · enqueued", text
    defender_group = page.group_of(f"f-{E.GRADED_WORLD}-1-0").id
    assert href == f"#{defender_group}", (href, defender_group)
    assert page.group_of(f"f-{E.GRADED_WORLD}-0-0").id != defender_group


def test_1025_a_world_not_measured_card_does_not_say_enqueued(tmp_path):
    """#1234 retired the `discard` family word and its `never_eligible` lane."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"][1].update(measured=False, not_measured_reason="a draw files unreachable")
    for i in range(4):
        E.set_lane(doc, E.GRADED_WORLD, 0, i, "not_measured")
    doc["enqueued_rows"] = 4
    E.write_judge(ep.dir, doc)
    page = render(ep)
    href, text = _card_link(_card(page, E.GRADED_WORLD))
    assert "not measured" in _heading_of(page, f"f-{E.GRADED_WORLD}-0-0")
    assert href == f"#{page.group_of(f'f-{E.GRADED_WORLD}-0-0').id}"
    assert text.startswith("4 findings · "), text
    assert "enqueued" not in text, text


def test_1025_the_dropped_count_on_the_tile_and_in_the_accounting_is_the_ledgers_own(tmp_path):
    """Two findings the ledger files in drop lanes (#1234 A13: a drop is the finding's own
    ledger entry; the draw's `dropped_findings` count is retired) are counted on tile 3's split
    ("2 dropped") and in the queue accounting ("dropped 2") — never a literal zero."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    E.set_lane(doc, E.GRADED_WORLD, 0, 0, "dropped_unresolved")
    E.set_lane(doc, E.GRADED_WORLD, 0, 1, "dropped_other_run")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "2 dropped" in _tile(page, 2), _tile(page, 2)
    assert "dropped 2" in page.one(cls="vd-acct").text()


# ---------------------------------------------------------------------------------------
# The stage clock, the report slot, the CLI's diagnostics
# ---------------------------------------------------------------------------------------


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
    """A manifest world whose label carries `..` names a directory OUTSIDE the episode."""
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
