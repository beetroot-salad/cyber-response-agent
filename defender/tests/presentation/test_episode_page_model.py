"""#1025 — the episode page reads the directory ONCE into a typed model and renders from it.

#1025 — the page decides each presentation question ONCE, in the model, and every surface reads the
answer.

#1025 — a fact is decided where it is produced, once, so two surfaces of the page cannot disagree.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import uuid
import contextlib
import inspect

import pytest
import yaml

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.learning.branch import _triplet_947 as T


pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


S = E.SAMPLE


_tmp_roots = E.tmp_roots


visualize_episode = E.page_module


render = E.render


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


def test_1025_a_scalar_worlds_field_in_the_manifest_is_refused_by_the_loader_gate(tmp_path):
    """The loader's gate refuses `worlds: 5`, so `family.yaml` is the one record that refuses the whole page."""
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
    ep = E.sample_episode(tmp_path)
    agent_id = f"judge:{T.fixture_world_id(E.GRADED_WORLD)}:1"
    rows = E.trace_rows(agent_id)
    for row in rows:
        if row.get("kind") == "request":
            row["message"] = ["x"]
        if row.get("kind") == "response":
            row["usage"] = {"input_tokens": "abc", "output_tokens": None}
            row["message"] = {"parts": 5}
    E.write_trace(ep.dir, agent_id, rows)
    # A transcript shows only for a draw the record names
    E.write_judge(ep.dir, E.record_draws(E.sample_grade(), E.GRADED_WORLD, (0, 1)))
    page = render(ep)
    block = page.text_of(f"tx-{E.trace_stem(agent_id)}")
    assert "unpriced" in block, block
    judge = page.text_of("stage-judge")
    assert "partial" in judge, judge



def test_1025_a_non_string_model_in_a_wire_log_row_leaves_that_call_unpriced(tmp_path):
    """A wire log is box-writable: a response row naming `"model": 7` renders, and that call reads unpriced. (r7.3 F5)"""
    ep = E.sample_episode(tmp_path)
    agent_id = f"judge:{T.fixture_world_id(E.GRADED_WORLD)}:1"
    rows = E.trace_rows(agent_id)
    assert any(r.get("kind") == "response" for r in rows), "premise: the trace has a response row"
    for row in rows:
        if row.get("kind") == "response":
            row["model"] = 7
    E.write_trace(ep.dir, agent_id, rows)
    E.write_judge(ep.dir, E.record_draws(E.sample_grade(), E.GRADED_WORLD, (0, 1)))

    block = render(ep).text_of(f"tx-{E.trace_stem(agent_id)}")

    assert "unpriced" in block, block


def test_1025_a_scalar_list_field_in_the_outcome_or_the_provenance_record_degrades_its_own_slot(tmp_path):
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


def test_1025_a_finding_with_no_subject_key_is_the_defenders_as_the_enqueue_read_it(tmp_path):
    """A finding with no `subject` (the pre-#1007 shape) is the defender's, as the enqueue reads it."""
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
    """The footer's count and link come from one list of rows, even when the first row is the world author's."""
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
    """A card whose rows the ledger kept off the queue (`not_measured`) never says "enqueued"."""
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
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    E.set_lane(doc, E.GRADED_WORLD, 0, 0, "dropped_unresolved")
    E.set_lane(doc, E.GRADED_WORLD, 0, 1, "dropped_other_run")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "2 dropped" in _tile(page, 2), _tile(page, 2)
    assert "dropped 2" in page.one(cls="vd-acct").text()


def test_1025_the_cli_diagnostic_is_the_records_refusal_not_a_phrase_on_the_page(tmp_path, capsys):
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
    """A label carrying `..` is refused before it is joined into a path; nothing planted outside is read."""
    ep = E.sample_episode(tmp_path)
    _outside, label = _outside_world(tmp_path, ep)
    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc(label, role="B", axis="planted"))
    T.write_family(ep.dir, manifest)
    with pytest.raises(E.sym("learning.judge", "JudgeRefused"),
                       match="world-label alphabet") as refused:
        E.render_episode(ep.dir, module=visualize_episode())
    assert "PLANTED-OUTSIDE" not in str(refused.value)
    assert not ep.page.exists(), "a page was written for a manifest the loader refused"


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permission bits")
@pytest.mark.parametrize("rel", [
    "runs", "worlds", "wire_logs", f"worlds/{T.fixture_world_id(E.GRADED_WORLD)}/gather_summaries",
    f"worlds/{T.fixture_world_id(E.GRADED_WORLD)}/judge",
])
def test_1025_an_unlistable_directory_is_its_own_slots_absence(tmp_path, rel):
    ep = E.sample_episode(tmp_path)
    target = ep.dir / rel
    target.mkdir(parents=True, exist_ok=True)
    target.chmod(0)
    try:
        page = render(ep)
    finally:
        target.chmod(0o755)
    assert E.BASE_STORY in page.text_of("sec-records")


LOWER_BOUND = f"≈ {S.lower_bound} lower bound on wall: model calls + longest world"


def _inverted_steps() -> list[tuple[str, str, str]]:
    return [(step, ended, started) for step, started, ended in E.every_step()]


def test_1025_an_all_inverted_timing_record_is_unmeasured_on_every_surface(tmp_path):
    """Every row inverted leaves no wall: the stages header and the verdict tile BOTH fall back to the lower bound."""
    ep = E.sample_episode(tmp_path)
    E.write_timing(ep.dir, _inverted_steps())
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert "no timing record" not in stages, stages
    assert "no usable span" in page.text_of("stage-timing"), page.text_of("stage-timing")
    assert LOWER_BOUND in stages, stages
    assert LOWER_BOUND in page.text_of("vd-tile-4"), page.text_of("vd-tile-4")
    assert "timing record unreadable" not in stages


def test_1025_an_episode_whose_every_run_cost_nothing_still_owes_its_total(tmp_path):
    """Runs that all cost $0.0000 are still priced: the runs sub-total and the grand total both render."""
    ep = E.sample_episode(tmp_path, traces=False)
    for label in E.WORLDS:
        E.write_tool_trace(ep.run(label), [E.result_event(cost=0.0)])
    page = render(ep)
    runs = page.text_of("stage-runs")
    assert page.elements(cls="rn-total"), runs
    assert page.elements(cls="st-total"), page.text_of("stage-timing")
    assert "$0.0000" in page.text_of("stage-timing")


@pytest.mark.parametrize(("plant", "sentence"), [
    ("unusable", "unusable result event"),
    ("absent", "no cost recorded"),
    ("none", "no result event"),
])
def test_1025_a_runs_result_state_reads_the_same_sentence_in_both_sections(tmp_path, plant, sentence):
    """The world section and the stages table show the same trace's state."""
    ep = E.sample_episode(tmp_path)
    trace = ep.run(E.GRADED_WORLD) / "tool_trace.jsonl"
    if plant == "unusable":
        E.write_tool_trace(ep.run(E.GRADED_WORLD), [E.result_event(cost=-3.0)])
    elif plant == "absent":
        trace.unlink()
    else:
        E.write_tool_trace(ep.run(E.GRADED_WORLD), [{"type": "assistant", "message": {"content": []}}])
    page = render(ep)
    world = page.text_of(f"world-{E.GRADED_WORLD}")
    runs = page.text_of("stage-runs")
    assert sentence in world, (plant, world)
    graded_row = [r.text() for r in page.elements(cls="rn-row") if E.GRADED_WORLD in r.text()]
    assert graded_row, (plant, runs)
    assert sentence in graded_row[0], (plant, runs)
    other = {"unusable result event", "no cost recorded", "no result event"} - {sentence}
    for wrong in other:
        # "no result event" is a prefix of "no result event (refused)" — none of these three
        # plants is a refusal, so the bare check is exact enough.
        assert wrong not in world.replace(sentence, ""), (plant, wrong, world)


def test_1025_a_manifest_id_that_names_no_token_reads_no_ledger_outside_the_episode(tmp_path):
    """The manifest reader refuses `episode_id: ../../x`, so no ledger path is ever joined from it."""
    ep = E.sample_episode(tmp_path)
    manifest = E.sample_manifest()
    manifest["episode_id"] = "../../x"
    T.write_family(ep.dir, manifest)
    (ep.dir / "runs" / "stray").mkdir()
    outside = (ep.dir / "served" / ".." / ".." / "x.stray.jsonl").resolve()
    assert ep.dir.resolve() not in outside.parents or outside.parent == ep.dir.parent.resolve()
    outside.write_text("{torn\n{torn\n", encoding="utf-8")
    refused = E.sym("learning.judge", "JudgeRefused")
    with pytest.raises(refused, match=r"\.\./\.\./x") as caught:
        E.render_episode(ep.dir)
    assert "x.stray" not in str(caught.value), caught.value
    assert not ep.page.exists(), "a page was written for a manifest the reader refused"


def test_1025_a_runs_directory_wearing_a_worlds_label_is_sectioned_once(tmp_path):
    """A stray `runs/<label>/` is no roster line: every id stays unique and the world renders once."""
    ep = E.sample_episode(tmp_path)
    (ep.dir / "runs" / E.GRADED_WORLD).mkdir()
    page = render(ep)
    dupes = sorted({i for i in page.all_ids if page.all_ids.count(i) > 1})
    assert dupes == [], dupes
    assert page.all_ids.count(f"world-{E.GRADED_WORLD}") == 1
    assert page.all_ids.count(f"leads-{E.GRADED_WORLD}") == 1
    assert "l-001" in page.text_of(f"leads-{E.GRADED_WORLD}")
    assert page.elements(cls="fr-shadowed-runs") == []
    assert "not sectioned twice" not in page.text
    assert f"Worlds ({len(E.WORLDS)})" in page.text_of("sec-worlds")


def test_1025_a_dropped_count_covers_only_the_draws_the_findings_walk_opens(tmp_path):
    """A manifest world with no grade row gets a section but no findings, and its draw's `dropped` is not summed."""
    ep = E.sample_episode(tmp_path, extra_worlds=(T.world_doc("x", role="B", axis="ungraded"),))
    E.run_dir(ep.dir, "x", arm_id=str(uuid.uuid4()))
    E.draw_document(ep.dir, "x", 0, E.draw_doc(
        findings=[E.finding(claim="one"), E.finding(claim="two")], dropped=4))
    page = render(ep)
    tile = page.text_of("vd-tile-3")
    assert "4 dropped" not in tile, tile
    assert "0 dropped" in tile, tile
    assert not [d for d in page.elements(cls="fr-dropped") if " of x:" in d.text()], \
        page.text_of("sec-findings")
    assert f"Worlds ({len(E.WORLDS) + 1})" in page.text_of("sec-worlds")
    assert "world-x" in page.by_id


def test_1025_a_finding_row_refuses_an_unknown_field():
    """A misspelled `_Finding` field is a `TypeError` at construction, not a row rendered with no claim."""
    module = E.page_module()
    with pytest.raises(TypeError, match="clam"):
        module._Finding(row_id="f-x-0-0", clam="the claim")
    row = module._Finding(row_id="f-x-0-0", claim="the claim")
    assert row.claim == "the claim"
    assert row.topic is None


def test_1025_an_absent_archived_report_is_decided_after_the_guarded_read(tmp_path):
    """Absence is decided from the bound walk's own open, never via `read_report` (which follows a planted link)."""
    family = E.mod("learning.judge.family")
    bound = E.mod("_io").bind(tmp_path)
    got = family.read_archived_report(bound, "report.md")
    assert got.disposition is None, got
    assert got.absent is True, got
    target = tmp_path / "elsewhere.md"
    target.write_text("---\ndisposition: malicious\n---\nnot this world's\n", encoding="utf-8")
    (tmp_path / "report.md").symlink_to(target)
    got = family.read_archived_report(bound, "report.md")
    assert got.disposition is None, got
    assert "aliased" in got.reason, got
    assert "not this world" not in got.body
    # Structurally, since the race itself cannot be staged: the reader never delegates to
    # `read_report` on any branch.
    assert "read_report" not in family.read_archived_report.__code__.co_names


NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")


def _world(page: E.Page, label: str) -> str:
    return page.text_of(f"world-{label}")


def test_1025_a_short_relative_episode_dir_name_scrubs_only_itself(tmp_path):
    """Rendered from `re` (a substring of `report.md` and `read`), the refusal still reads whole:
    the reader formats the relative name and never holds the root, so nothing is scrubbed (#1049)."""
    ep = E.sample_episode(tmp_path)
    copy = E.copy_episode(ep, tmp_path / "re" / ep.dir.name)
    short = copy.dir
    (short / "worlds" / T.world_id(short, E.GRADED_WORLD) / "report.md").unlink()
    (short / "worlds" / T.world_id(short, E.GRADED_WORLD) / "report.md").mkdir()
    with contextlib.chdir(tmp_path):
        page = render(short)
    world = _world(page, E.GRADED_WORLD)
    assert "report.md could not be read" in world, world
    assert "<episode>port" not in world, world
    assert "<episode>ad" not in world, world
    assert f"worlds/{T.fixture_world_id(E.GRADED_WORLD)}/report.md" in world, world
    # said bare — never as a quoted filename cut down from an absolute path
    assert f"'worlds/{T.fixture_world_id(E.GRADED_WORLD)}/report.md'" not in world, world
    assert "re/worlds" not in page.raw


def test_1025_the_runs_launcher_line_and_the_runs_row_show_one_wall(tmp_path):
    """With a repeated `runs` step (first entry inverted), the row and the launcher line read one span."""
    ep = E.sample_episode(tmp_path)
    steps = [s for s in E.every_step() if s[0] != "runs"]
    steps += [("runs", "2026-09-09T10:20:00Z", "2026-09-09T10:19:00Z"),
              ("runs", "2026-09-09T10:21:00Z", "2026-09-09T10:25:00Z")]
    E.write_timing(ep.dir, steps)
    page = render(ep)
    timing = page.text_of("stage-timing")
    row = timing[timing.index("runs"):timing.index("judge")]
    assert "4m00s" in row, row
    assert "2 entries" in row, row
    launcher = page.one(cls="rn-launcher-wall").text()
    assert launcher == "4m00s launcher", launcher

    steps[-2], steps[-1] = steps[-1], steps[-2]
    E.write_timing(ep.dir, steps)
    page = render(ep)
    assert page.one(cls="rn-launcher-wall").text() == "4m00s launcher"
    assert "1m00s launcher" not in page.text_of("stage-runs")


def test_1025_the_stage_table_reads_the_role_costs_the_model_decided(tmp_path):
    """The stage table renders the `role_costs` filled at load; the renderer walks no wire log again."""
    module = visualize_episode()
    ep = E.sample_episode(tmp_path)
    loaded = E.load_episode(ep.dir, module=module)
    assert set(loaded.role_costs) == {"questioner", "judge"}
    assert f"${loaded.role_costs['questioner'].cost:.4f}" == S.questioner_cost
    assert f"${loaded.role_costs['judge'].cost:.4f}" == S.judge_cost
    render_src = inspect.getsource(module._render_stages)
    assert "role_cost(" not in render_src
    assert "comparator_cost(" not in render_src


def test_1025_a_framed_only_judge_trace_naming_no_roster_label_is_listed_as_unattributed(tmp_path):
    """A launcher-produced episode writes only the framed twin of a judge call, so the census walks those too."""
    ep = E.sample_episode(tmp_path)
    E.write_framed(ep.dir, "judge:zz_gone:0", prompt="a world removed after a re-grade")
    page = render(ep)
    stages = page.text_of("sec-stages")
    assert "unattributed traces" in stages, stages
    assert "judge_zz_gone_0_trace" in stages, stages
    assert "tx-judge_zz_gone_0_trace" not in page.by_id


def test_judge_trace_uuid_scope_is_shared_by_blocks_and_unattributed_list(tmp_path):
    """Declared UUID traces route once; unknown scopes stay separate from recorded draws."""
    ep = E.sample_episode(tmp_path)
    world_id = T.world_id(ep.dir, E.GRADED_WORLD)
    unknown_id = T.fixture_world_id("unknown_trace_world")
    grade_only_id = T.fixture_world_id("grade_only")
    grade = E.sample_grade()
    grade["worlds"].append(E.world_row("grade_only", declared="benign"))
    E.write_judge(ep.dir, grade)
    scopes = [(world_id, 0), ("family", 0), (world_id, 9),
              (unknown_id, 0), (grade_only_id, 0), ("grade_only", 0)]
    for scope, draw in scopes:
        E.write_framed(ep.dir, f"judge:{scope}:{draw}", prompt=f"scope {scope} draw {draw}")
    page = render(ep)
    blocks = [node.id for node in page.section("stage-judge").find_all(cls="tx-stream")]
    assert blocks[0] == "tx-judge_family_0_trace"
    assert f"tx-judge_{world_id}_0_trace" in blocks
    assert f"scope {world_id} draw 0" in page.text_of(f"tx-judge_{world_id}_0_trace")
    unmatched = page.one(cls="st-unattributed").text()
    assert f"judge_{world_id}_0_trace" not in unmatched
    assert "judge_family_0_trace" not in unmatched
    assert f"judge_{world_id}_9_trace" not in unmatched
    for scope in (unknown_id, grade_only_id, "grade_only"):
        assert f"judge_{scope}_0_trace" in unmatched
        assert f"tx-judge_{scope}_0_trace" not in page.by_id
    assert f"tx-judge_{world_id}_9_trace" not in page.by_id


def test_1025_the_draw_read_totals_count_every_directory_the_world_sections_count(tmp_path):
    """A world's unreadable-draw count is the same in its section and in the findings total."""
    ep = E.sample_episode(tmp_path)
    (ep.dir / "runs" / f"{E.EPISODE_ID}-orphan").mkdir()
    orphan = T.fixture_world_id("orphan")
    E.plant_raw(ep.dir / "worlds" / orphan / "judge" / "0.yaml", b"- not: [a mapping")
    with pytest.raises(T.sym("records._family", "FamilyError"), match="not declared"):
        render(ep)
    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc("orphan", role="B", axis="orphan fact"))
    T.write_family(ep.dir, manifest)
    (ep.dir / T.ROSTER_NAME).unlink()
    T.plant_roster(ep.dir)
    doc = E.sample_grade()
    doc["worlds"].append(E.world_row("orphan", declared="benign"))
    E.write_judge(ep.dir, doc)
    page = render(ep)
    assert "1 draw documents unreadable" in _world(page, "orphan"), _world(page, "orphan")
    findings = page.text_of("sec-findings")
    assert "1 draw documents unreadable" in findings, findings


def test_1025_a_negative_duration_is_that_slots_own_absence(tmp_path):
    """A negative `duration_ms` off a box-writable trace is gated like a negative cost."""
    ep = E.sample_episode(tmp_path)
    E.run_dir(ep.dir, E.CONTROL, cost=0.40, duration_ms=-600_000)
    page = render(ep)
    four = page.text_of("vd-tile-4")
    assert "3m00s–5m00s" in four, four
    assert "≈ 11m00s lower bound" in four, four
    assert "—–" not in four, four

    E.write_trace(ep.dir, "questioner", usage=(100_000, 10_000), duration_ms=-5_000_000.0)
    questioner = page_text = render(ep).text_of("stage-questioner")
    assert "$" in page_text, questioner
    assert "—" not in questioner.split("·")[2], questioner


def test_1025_a_refused_wire_trace_is_named_as_refused(tmp_path):
    """A link at a trace's name is refused and said ("trace refused"), never read as "no response recorded"."""
    ep = E.sample_episode(tmp_path)
    target = tmp_path / "elsewhere.jsonl"
    target.write_text("{}\n", encoding="utf-8")
    E.plant_link(ep.dir / "wire_logs" / "questioner_trace.jsonl", target)
    page = render(ep)
    block = page.text_of("tx-questioner_trace")
    assert "trace refused" in block, block
    assert "no response recorded" not in block, block
    assert "partial — 2 of 3 calls priced" in page.text_of("stage-questioner")


def test_1025_record_derived_refusals_take_the_untrusted_escape(tmp_path):
    """A refusal sentence quotes the record's own bytes, so it takes the untrusted escape like any field."""
    ep = E.sample_episode(tmp_path)
    hostile = "onerror=alert(1)"
    E.plant_raw(ep.dir / "judge.yaml", f"worlds:\n  - world: b\n   bad: {hostile}\n")
    E.plant_raw(ep.dir / "timing.json", f'{{"steps": [{{"x": "{hostile}"}}')
    E.plant_raw(ep.dir / "samples.yaml", f"- {hostile}\n  :")
    page = render(ep)
    assert "grade record unreadable" in page.text_of("sec-verdict")
    assert "onerror=" not in page.raw, "a record-derived sentence reached the page unsplit"
    assert hostile in page.text, page.text[:400]


@NOT_ROOT
def test_1025_an_unreadable_gather_summary_is_the_chains_own_sentence_for_the_judge_and_the_page(
        tmp_path):
    """`lead_chain` returns (never raises) a sentence for an unreadable gather summary; judge and page share it."""
    family = E.mod("learning.judge.family")
    ep = E.sample_episode(tmp_path)
    world = ep.world(E.GRADED_WORLD)
    summary = world / "gather_summaries" / "l-001.md"
    summary.chmod(0)
    try:
        chain = family.lead_chain(E.mod("_io").bind(ep.dir).under(f"worlds/{T.fixture_world_id(E.GRADED_WORLD)}"),
                                  "l-001", {}, leads=family.leads_by_id(world))
        page = render(ep)
    finally:
        summary.chmod(0o644)
    assert "gather_summaries/l-001.md could not be read" in chain["summary"], chain
    assert str(tmp_path) not in chain["summary"], chain
    leads = page.text_of(f"leads-{E.GRADED_WORLD}")
    assert "gather_summaries/l-001.md could not be read" in leads, leads
    assert "lead unreadable" not in leads, leads
    assert str(tmp_path) not in page.raw
