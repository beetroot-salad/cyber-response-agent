"""#1025 (PR #1042 review) — the page BORROWS what the judge owns rather than copying it, and READS
what the pass decided rather than deciding again."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")

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


def _restoring(paths: list[Path], mode: int):
    """chmod each path to `mode` for the body, then back to something the tmp-dir cleanup can
    remove — a `finally`, so a failing assertion never leaves a mode-000 tree behind."""
    class _Ctx:
        def __enter__(self):
            for p in paths:
                p.chmod(mode)

        def __exit__(self, *_):
            for p in paths:
                p.chmod(0o755 if p.is_dir() else 0o644)
            return False
    return _Ctx()


@NOT_ROOT
def test_1025_a_permission_denied_trace_or_tool_trace_is_that_slots_refusal_never_the_pages_crash(
        tmp_path):
    """A mode-000 `wire_logs/<stem>.jsonl` and a mode-000 `runs/<ep>-<label>/tool_trace.jsonl` each
    land in their own slot ."""
    ep = E.sample_episode(tmp_path)
    trace = ep.dir / "wire_logs" / f"{E.trace_stem('questioner')}.jsonl"
    tool_trace = ep.run(E.CONTROL) / "tool_trace.jsonl"
    with _restoring([trace, tool_trace], 0):
        page = render(ep)
    assert page.by_id, "no page"
    world = page.text_of(f"world-{E.CONTROL}")
    assert "no cost recorded" in world or "no result event" in world, world
    stages = page.text_of("sec-stages")
    refused = page.text_of("tx-questioner_trace")
    assert "You are the seat." not in refused, refused
    assert "$" not in refused, refused
    assert "You are the seat." in page.text_of("tx-questioner_b_trace")
    assert "partial — 2 of 3 calls priced" in page.text_of("stage-questioner"), stages
    assert "no result event (refused)" in stages, stages


@NOT_ROOT
def test_1025_a_world_directory_with_no_search_permission_is_that_worlds_refusal(tmp_path):
    """`worlds/<label>/` chmod 000: the world's archive block reads its refusal and every other
    section renders. Before: the archive loader asked `Path.exists()` of `report.md`."""
    ep = E.sample_episode(tmp_path)
    with _restoring([ep.world(E.GRADED_WORLD)], 0):
        page = render(ep)
    assert page.by_id, "no page"
    assert "Permission denied" in page.text_of(f"world-{E.GRADED_WORLD}") or \
        "could not be read" in page.text_of(f"world-{E.GRADED_WORLD}"), \
        page.text_of(f"world-{E.GRADED_WORLD}")
    assert f"f-{E.GRADED_WORLD}-0-0" not in page.ids  # its draws are unreadable too
    assert f"f-{E.PASSTHROUGH_WORLD}-0-0" in page.ids


@NOT_ROOT
def test_1025_an_unreadable_report_md_is_named_as_unreadable_not_as_an_alias(tmp_path):
    """`read_archived_report` on a mode-000 `report.md` says it could not be read and carries the
    errno."""
    family = E.mod("learning.judge.family")
    ep = E.sample_episode(tmp_path)
    bound = E.mod("_io").bind(ep.dir)
    report = ep.world(E.GRADED_WORLD) / "report.md"
    with _restoring([report], 0):
        got = family.read_archived_report(bound, f"worlds/{E.GRADED_WORLD}/report.md")
    assert got.disposition is None
    assert "Permission denied" in got.reason, got.reason
    assert "aliased" not in got.reason, got.reason

    target = tmp_path / "elsewhere.md"
    target.write_text("---\ndisposition: benign\n---\n", encoding="utf-8")
    link = ep.world(E.PASSTHROUGH_WORLD) / "report.md"
    link.unlink()
    link.symlink_to(target)
    got = family.read_archived_report(bound, f"worlds/{E.PASSTHROUGH_WORLD}/report.md")
    assert got.disposition is None
    assert got.reason.count("non-plain or aliased") == 1, got.reason


def test_1025_the_ledgers_malformed_row_count_is_the_judges_own(tmp_path):
    """A parseable ledger row whose `source` is outside the ledger's vocabulary is malformed to
    `read_world_facts` (p7."""
    ep = E.sample_episode(tmp_path)
    ledger = ep.dir / "served" / f"{T.world_token(E.GRADED_WORLD)}.jsonl"
    bogus = J.ledger_row(source="passthrough", world_label=E.GRADED_WORLD)
    bogus["source"] = "bogus-word"
    with ledger.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(bogus) + "\n")
    family = E.mod("learning.judge.family")
    facts = family.read_world_facts(E.mod("_io").bind(ep.dir), E.GRADED_WORLD,
                                    episode_token=E.EPISODE_TOKEN)
    assert facts.malformed_rows == 1
    block = render(ep).text_of(f"leads-{E.GRADED_WORLD}")
    assert "1 malformed row" in block, block


def test_1025_read_world_facts_refuses_an_absent_ledger_on_every_path(tmp_path):
    """p7: "only an ABSENT ledger refuses (JudgeRefused)". The guard is the reader's own, so the
    bare `render.render(..., facts=None)` path — which has no."""
    family = E.mod("learning.judge.family")
    ep = E.sample_episode(tmp_path)
    (ep.dir / "served" / f"{T.world_token(E.GRADED_WORLD)}.jsonl").unlink()
    with pytest.raises(J.sym("learning.judge", "JudgeRefused"), match="ledger"):
        family.read_world_facts(E.mod("_io").bind(ep.dir), E.GRADED_WORLD,
                                episode_token=E.EPISODE_TOKEN)
    block = render(ep).text_of(f"leads-{E.GRADED_WORLD}")
    assert "absent" in block, block


def test_1025_a_world_spelled_family_never_doubles_the_family_lane(tmp_path):
    """`family` is the reserved label the family-level draws live under, never a world."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"].append(E.world_row(E.FAMILY, declared="benign"))
    E.write_judge(ep.dir, doc)
    (ep.dir / "runs" / f"{E.EPISODE_ID}-{E.FAMILY}").mkdir()
    page = render(ep)
    rows = [i for i in page.all_ids if i.startswith("f-")]
    assert len(rows) == len(set(rows)), rows
    assert [i for i in rows if i.startswith(f"f-{E.FAMILY}-")] == [
        f"f-{E.FAMILY}-0-{i}" for i in range(3)], rows
    assert f"world-{E.FAMILY}" not in page.ids, page.ids_with("world-")
    assert len(rows) == S.findings, rows

    manifest = E.sample_manifest()
    manifest["worlds"].append(T.world_doc(
        E.FAMILY, role="D", axis="a world wearing the reserved label",
        disposition_declared="benign"))
    T.write_family(ep.dir, manifest)
    with pytest.raises(J.sym("learning.judge", "JudgeRefused"), match="reserved"):
        E.render_episode(ep.dir, module=visualize_episode())


def test_1025_a_response_row_with_an_empty_model_string_is_unpriced(tmp_path):
    """`model: ""` — a call whose model was never recorded — reads "unpriced", not a figure at
    the pricing table's absorbed-row rate: the stage sum excludes it and says so."""
    ep = E.sample_episode(tmp_path)
    E.write_trace(ep.dir, "questioner:c", model="")
    page = render(ep)
    block = page.text_of("tx-questioner_c_trace")
    assert "unpriced" in block, block
    questioner = page.text_of("stage-questioner")
    assert "$0.7500" in questioner, questioner
    assert "partial — 2 of 3 calls priced" in questioner, questioner


def _ledger_of(doc: dict) -> dict[str, tuple[str, str | None]]:
    return {e["finding_id"]: (e["lane"], e["reason"]) for e in doc["dispositions"]}


def test_1025_the_ledger_is_on_the_record_and_read_back_validated(tmp_path):
    """`judge.yaml` carries `dispositions` as `grade_episode` wrote it and `read_grade` hands it
    back unchanged."""
    judge = E.mod("learning.judge")
    enqueue = E.mod("learning.judge.enqueue")
    ep = E.sample_episode(tmp_path)
    grade = judge.read_grade(ep.dir)
    assert grade.dispositions == E.sample_dispositions()
    assert grade.dispositions[0] == enqueue.disposition_entry(
        E.finding_id(E.PASSTHROUGH_WORLD, 0, 0), enqueue.LANE_DEFENDER)

    doc = E.sample_grade()
    del doc["dispositions"]
    E.write_judge(ep.dir, doc)
    assert judge.read_grade(ep.dir).dispositions is None

    doc = E.sample_grade()
    doc["dispositions"] = []
    E.write_judge(ep.dir, doc)
    assert judge.read_grade(ep.dir).dispositions == []

    for bad in ({"finding_id": E.finding_id(E.GRADED_WORLD, 0, 0), "lane": "teleported"},
                {"lane": "defender", "reason": None}):
        doc = E.sample_grade()
        doc["dispositions"].append(bad)
        E.write_judge(ep.dir, doc, check=False)
        with pytest.raises(judge.JudgeRefused, match="ledger entry"):
            judge.read_grade(ep.dir)
    render_text = render(ep).text_of("sec-verdict")
    assert "grade record unreadable" in render_text, render_text


def test_1025_the_page_shows_the_ledger_and_never_re_decides_a_lane(tmp_path):
    """The page's disposition for a finding is the ledger's entry, full stop ."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["enqueued_rows"] = 4
    for i in range(4):
        E.set_lane(doc, E.PASSTHROUGH_WORLD, 0, i, "defender")
        E.set_lane(doc, E.GRADED_WORLD, 0, i, "unqueueable", "a reason the rows never gave")
    E.write_judge(ep.dir, doc)
    page = render(ep)
    for i in range(4):
        passthrough = page.group_of(f"f-{E.PASSTHROUGH_WORLD}-0-{i}").text()
        assert "defender: enqueued" in passthrough, passthrough
        graded = page.group_of(f"f-{E.GRADED_WORLD}-0-{i}").text()
        assert "defender: unqueueable — a reason the rows never gave" in graded, graded
    acct = page.one(cls="vd-acct").text()
    assert "record: 4 enqueued · page found: 4" in acct, acct
    assert "record and page disagree" not in acct, acct
    three = page.text_of("vd-tile-3")
    for part in ("4 defender", "4 unqueueable"):
        assert part in three, (part, three)


def test_1025_a_record_naming_one_world_twice_renders_exactly_what_the_pass_filed(tmp_path):
    """The #1042 review's case: `judge.yaml` names one judged world on TWO rows — the first
    gradable, the second ungradable — and its ledger files that world's findings."""
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    doc["worlds"].append(E.ungradable_row(E.PASSTHROUGH_WORLD, declared="benign",
                                          reason="the second row says ungradable"))
    for i in range(5):
        E.set_lane(doc, E.PASSTHROUGH_WORLD, 0, i, "unqueueable",
                   "world 'no_remote_session' is ungradable: the second row says ungradable")
    doc["enqueued_rows"] = 4
    doc["world_enqueued_rows"] = S.world_author - 1
    E.write_judge(ep.dir, doc)
    page = render(ep)
    for i in range(4):
        group = page.group_of(f"f-{E.PASSTHROUGH_WORLD}-0-{i}").text()
        assert "defender: unqueueable" in group, group
        assert "the second row says ungradable" in group, group
        assert "defender: enqueued" in page.group_of(f"f-{E.GRADED_WORLD}-0-{i}").text()
    three = page.text_of("vd-tile-3")
    for part in ("4 defender", "5 unqueueable"):
        assert part in three, (part, three)
    acct = page.one(cls="vd-acct").text()
    assert "record: 4 enqueued · page found: 4" in acct, acct
    assert "disagree" not in acct, acct


def test_1025_a_record_with_no_ledger_says_so_instead_of_guessing(tmp_path):
    ep = E.sample_episode(tmp_path)
    doc = E.sample_grade()
    del doc["dispositions"]
    E.write_judge(ep.dir, doc)
    (ep.world(E.GRADED_WORLD) / "judge" / "0.yaml").unlink()
    page = render(ep)
    for row_id in (f"f-{E.PASSTHROUGH_WORLD}-0-0", f"f-{E.FAMILY}-0-0"):
        heading = page.group_of(row_id).text()
        assert "record carries no disposition ledger" in heading, heading
    assert not [i for i in page.ids if i.startswith(f"f-{E.GRADED_WORLD}-")], page.ids_with("f-")
    three = page.text_of("vd-tile-3")
    assert three.startswith("0 of 8"), three
