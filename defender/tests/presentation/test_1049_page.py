"""#1049 — the episode page (`presentation/visualize_episode.py`) over the bound readers."""
from __future__ import annotations

from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5

import os
import re
import shutil
import uuid
from pathlib import Path

import pytest
import yaml

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.shared.contracts import _record_1049 as R
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.core import _state1135

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")



def _world(page: E.Page, label: str) -> str:
    return page.text_of(f"world-{label}")


def _leads(page: E.Page, label: str) -> str:
    return page.text_of(f"leads-{label}")


def _ledger_name(label: str) -> str:
    return f"served/{T.fixture_world_id(label)}.jsonl"


#: The two spare worlds the every-arm fixture names through judge rows of their own (no
#: manifest entry), so a symlinked and a dangling `worlds/<w>` each get a section and a leads
#: block. Their arms are STRAY arms, `runs/<uuid4>` no roster entry names (review-3 F33: the
#: roster stays exactly the manifest's worlds, so the page reads a valid roster).
LINKED_WORLD = "spare_link"
DANGLING_WORLD = "spare_dangle"


def _plant_shared_arms(built: E.Episode) -> None:
    """The arms planted in the BUILT tree, before copying: one instance of every arm that
    survives `copytree(symlinks=True)` — a symlink keeps its absolute target (into `built`,
    which is why `str(built)` is asserted absent), plain bytes copy as bytes."""
    E.plant_raw(built.dir / "outcome.yaml", R.UNDECODABLE)                # read arm
    E.plant_raw(built.dir / "samples.yaml", "{\n  [")                    # parse arm
    E.plant_raw(built.dir / "provenance.json", '{"a": 1}')               # shape arm
    E.plant_link(built.dir / "timing.json", built.dir / "family.yaml")    # OSError-shaped, C-02
    E.plant_link(built.world(E.PASSTHROUGH_WORLD) / "report.md", built.dir / "family.yaml")
    (built.dir / _ledger_name(E.PASSTHROUGH_WORLD)).unlink()                 # absent ledger
    E.plant_link(built.dir / _ledger_name(E.CONTROL), built.dir / "family.yaml")  # aliased ledger
    passthrough_summaries = built.world(E.PASSTHROUGH_WORLD) / "gather_summaries"
    passthrough_summaries.rename(built.world(E.PASSTHROUGH_WORLD) / "summaries-real")
    E.plant_link(passthrough_summaries, built.world(E.PASSTHROUGH_WORLD) / "summaries-real")
    E.plant_link(built.world(E.CONTROL) / "gather_summaries" / "l-001.md", built.dir / "family.yaml")
    for label in (LINKED_WORLD, DANGLING_WORLD):
        E.run_dir(built.dir, label, arm_id=str(uuid.uuid4()))


def _plant_per_copy_arms(copy: E.Episode) -> None:
    """The arms that must be planted per copy, after copying: a hard link (copytree flattens
    it) at the graded world's investigation.md, targeting a scratch file inside the copy; a
    symlinked and a dangling worlds/<w> (the link's target is inside THIS copy)."""
    R.plant_hard_link(copy.world(E.GRADED_WORLD) / "investigation.md",
                      copy.dir / "scratch" / "investigation-target.md")
    E.plant_link(copy.world(LINKED_WORLD), copy.world(E.CONTROL))
    E.plant_link(copy.world(DANGLING_WORLD), copy.dir / "worlds" / T.fixture_world_id("nowhere-at-all"))


def _write_grade_over(copy: E.Episode) -> None:
    """`judge.yaml` written from the rows `family.read_world` — the sole producer of a row's
    `ungradable_reason` from the archive — computes over the planted tree, so the record carries
    the reader's sentence for each planted world (the hard-linked investigation; the other
    world's linked `gather_summaries/` — #1234 A3 refuses a listed-but-not-plain input as
    malformed, naming it, where the link at that world's report once read as
    `_missing_required_input`'s "missing its report.md"; the pass no longer requires a served
    ledger, so the absent one is the leads block's note)."""
    family = R.family()
    with J.episode_runs_for(copy.dir).episode_files(copy.dir.name) as episode:
        bound = episode.view()
        manifest = family.read_manifest(bound, expected_episode_id=copy.dir.name)
        rows = [family.read_world(bound, world, episode_dir=copy.dir)[0]
                for world in family.non_control_worlds(manifest)]
    doc = E.sample_grade()
    doc["worlds"] = rows
    doc["worlds"] += [E.ungradable_row(label) for label in (LINKED_WORLD, DANGLING_WORLD)]
    E.write_judge(copy.dir, doc)


def _every_arm(tmp_path: Path) -> tuple[E.Episode, E.Episode, E.Episode]:
    built = E.sample_episode(
        tmp_path, root=T.tenant_episodes(tmp_path / "build"),
        extra_worlds=tuple(T.world_doc(label, role="B", axis=f"{label} fact")
                           for label in (LINKED_WORLD, DANGLING_WORLD)))
    _plant_shared_arms(built)
    # #1187 declared change 10 (R5): a copy keeps the episode's folder name (its manifest's
    # episode id); the two copies differ only in where they sit.
    one = E.copy_episode(built, tmp_path / "root-one" / built.dir.name)
    two = E.copy_episode(built, tmp_path / "root-two" / "nested" / built.dir.name)
    for copy in (one, two):
        _plant_per_copy_arms(copy)
        _write_grade_over(copy)
    return built, one, two


# d-25 — the negative universal: no root in the page, byte-identical from two roots


def test_1049_an_episode_with_every_arm_planted_renders_no_root_and_byte_identically_from_two_roots(tmp_path):
    built, one, two = _every_arm(tmp_path)
    E.render(one)
    E.render(two)
    for copy in (one, two):
        text = copy.page.read_text(encoding="utf-8")
        for absent in (str(copy.dir), os.path.realpath(copy.dir), str(copy.dir.parent),
                       str(built.dir), str(tmp_path), "root-one", "root-two", "nested", "build"):
            assert absent not in text, f"{absent!r} leaked into {copy.dir.name}'s page"
    assert one.page.read_bytes() == two.page.read_bytes(), "the two copies rendered differently"
    # the record the page rendered reasons from carries each planted world's refusal (the control is real)
    rows = {r["world"]: r for r in J.judge_record(one.dir)["worlds"]}
    assert rows[E.GRADED_WORLD].get("malformed") is True, rows[E.GRADED_WORLD]
    assert rows[E.PASSTHROUGH_WORLD].get("malformed") is True, rows[E.PASSTHROUGH_WORLD]
    assert "gather_summaries" in rows[E.PASSTHROUGH_WORLD]["ungradable_reason"], (
        rows[E.PASSTHROUGH_WORLD])
    # R5: a renamed copy is refused, naming the folder's id and the manifest's, and writes no
    # page (the two copies above are the positive control on the same door).
    renamed_id = str(uuid.uuid4())
    renamed = E.copy_episode(built, tmp_path / "root-three" / renamed_id)
    err = H5.raised(E.render_episode, renamed.dir)
    assert err is not None, "a renamed copy rendered (R5)"
    said = H5.message(err)
    assert renamed_id in said, f"the R5 refusal does not name the folder's id: {said!r}"
    assert E.EPISODE_ID in said, f"the R5 refusal does not name the manifest's id: {said!r}"
    assert not renamed.page.exists(), "a page was written for a renamed copy"


# d-26 — the positive control: every refusal is said, in its own slot


def test_1049_every_planted_refusal_is_said_in_its_own_slot(tmp_path):
    _built, one, _two = _every_arm(tmp_path)
    page = E.render(one)
    records = page.text_of("sec-records")
    for slot, name in (("no record", "outcome.yaml is refused"),
                       ("samples record unreadable", "samples.yaml"),
                       ("provenance record unreadable", "provenance.json")):
        assert slot in records, (slot, records)
        assert name in records, (slot, records)
    stages = page.text_of("sec-stages")
    assert 'timing record unreadable' in stages, stages
    assert 'timing.json' in stages, stages
    assert R.ALIAS in stages, stages

    passthrough_report = page.section(f"world-{E.PASSTHROUGH_WORLD}").find_all(cls="w-report")[0].text()
    assert f'worlds/{T.fixture_world_id(E.PASSTHROUGH_WORLD)}/report.md' in passthrough_report, passthrough_report
    assert R.ALIAS in passthrough_report, passthrough_report
    graded_leads = _leads(page, E.GRADED_WORLD)
    assert "investigation record unavailable" in graded_leads, graded_leads
    assert f'worlds/{T.fixture_world_id(E.GRADED_WORLD)}/investigation.md' in graded_leads, graded_leads
    assert R.ALIAS in graded_leads, graded_leads
    assert "served ledger: absent" in _leads(page, E.PASSTHROUGH_WORLD)
    control_leads = _leads(page, E.CONTROL)
    assert 'served ledger unreadable' in control_leads, control_leads
    assert _ledger_name(E.CONTROL) in control_leads, control_leads
    assert 'gather_summaries/l-001.md' in control_leads, control_leads
    assert R.ALIAS in control_leads, control_leads
    passthrough_leads = _leads(page, E.PASSTHROUGH_WORLD)
    assert 'gather_summaries/l-001.md' in passthrough_leads, passthrough_leads
    assert R.ALIAS in passthrough_leads, passthrough_leads

    graded_world = _world(page, E.GRADED_WORLD)
    assert 'ungradable' in graded_world, graded_world
    assert f'worlds/{T.fixture_world_id(E.GRADED_WORLD)}/investigation.md' in graded_world, graded_world
    passthrough_world = _world(page, E.PASSTHROUGH_WORLD)
    assert 'ungradable' in passthrough_world, passthrough_world
    assert 'gather_summaries' in passthrough_world, passthrough_world
    assert R.ALIAS in passthrough_world, passthrough_world

    for label in (LINKED_WORLD, DANGLING_WORLD):
        world = _world(page, label)
        assert f'worlds/{T.fixture_world_id(label)}/report.md' in world, (label, world)
        assert R.ALIAS in world, (label, world)
        assert "not archived" not in world, (label, world)
        # The leads block is refused ONCE, at the directory: a `worlds/<w>` that is not a real
        # directory rosters nothing beneath it, so the one sentence names `worlds/<w>` itself.
        leads = _leads(page, label)
        assert f'worlds/{T.fixture_world_id(label)}' in leads, (label, leads)
        assert leads.count(R.ALIAS) == 1, (label, leads)
        assert "not archived" not in leads, (label, leads)
    linked_leads = _leads(page, LINKED_WORLD)
    assert f"worlds/{T.fixture_world_id(LINKED_WORLD)}" in linked_leads, linked_leads
    assert "gather_summaries/l-001.md" not in linked_leads, "the leads under a symlinked world dir were read through the link"
    assert str(one.dir) not in page.raw
    assert str(tmp_path) not in page.raw

    served = E.sample_episode(tmp_path / "served-link")
    (served.dir / "served").rename(served.dir / "served-real")
    E.plant_link(served.dir / "served", served.dir / "served-real")
    block = _leads(E.render(served), E.GRADED_WORLD)
    assert 'served ledger unreadable' in block, block
    assert _ledger_name(E.GRADED_WORLD) in block, block
    assert R.ALIAS in block, block

    _grade_record_refused_over_its_own_trees(tmp_path)


def _grade_record_refused_over_its_own_trees(tmp_path: Path) -> None:
    """The grade record's arm (F-2): a link at judge.yaml over one tree, then each c-14 shape
    over another — the two-roots tree cannot carry them, its judge.yaml IS the record."""
    linked = E.sample_episode(tmp_path / "judge-link")
    E.plant_link(linked.dir / "judge.yaml", linked.dir / "family.yaml")
    band = _grade_record_unreadable(E.render(linked), linked.dir)
    assert R.ALIAS in band, band
    shaped = E.sample_episode(tmp_path / "judge-shape")
    sound = {"validity": "usable", "worlds": [{"world": E.GRADED_WORLD, "verdict": "malicious"}]}
    for bad in ({**sound, "validity": 5}, {1: "x"}, {**sound, "worlds": [{"verdict": "x"}]},
                {**sound, "not_graded": {"x": 1}}):
        E.plant_raw(shaped.dir / "judge.yaml", yaml.safe_dump(bad))
        band = _grade_record_unreadable(E.render(shaped), shaped.dir)
        assert "is not a family grade record" in band, band


def _grade_record_unreadable(page: E.Page, episode_dir: Path) -> str:
    """The verdict band of a page whose judge.yaml was refused: the slot's word, the record's
    relative name, never the 'no grade record' band — and no spelling of the root (as passed,
    its realpath, or the episodes base it sits in) anywhere in the page."""
    band = page.text_of("sec-verdict")
    assert "grade record unreadable" in band, band
    assert "judge.yaml" in band, band
    assert "no grade record" not in band, band
    for spelling in (str(episode_dir), os.path.realpath(episode_dir), str(episode_dir.parent)):
        assert spelling not in page.raw, (spelling, band)
    return band


# d-27 — _result_event through the JSONL twin


def test_1049_result_event_reads_the_tool_trace_through_the_jsonl_twin(tmp_path):
    ep = E.sample_episode(tmp_path)
    trace = ep.run(E.GRADED_WORLD) / "tool_trace.jsonl"
    assert f"${E.SAMPLE.run_cost[E.GRADED_WORLD]:.4f}" in _world(E.render(ep), E.GRADED_WORLD)
    trace.unlink()
    assert "no cost recorded" in _world(E.render(ep), E.GRADED_WORLD)
    E.plant_link(trace, ep.dir / "family.yaml")
    assert "no result event (refused)" in _world(E.render(ep), E.GRADED_WORLD)
    trace.unlink()
    trace.mkdir()
    assert "no result event (refused)" in _world(E.render(ep), E.GRADED_WORLD)
    trace.rmdir()
    E.write_tool_trace(ep.run(E.GRADED_WORLD), [{"type": "assistant"}])
    world = _world(E.render(ep), E.GRADED_WORLD)
    assert 'no result event' in world, world
    assert '(refused)' not in world, world
    run = ep.run(E.GRADED_WORLD)
    run.rename(ep.dir / "runs" / "run-real")
    E.plant_link(run, ep.dir / "runs" / "run-real")
    assert "run directory absent" in _world(E.render(ep), E.GRADED_WORLD)


# d-36 — the page's flags derive from the readers' states


def test_1049_investigation_present_and_archived_are_read_off_the_readers_states_not_a_stat(tmp_path):
    ep = E.sample_episode(tmp_path)
    (ep.world(E.GRADED_WORLD) / "investigation.md").unlink()
    shutil.rmtree(ep.world(E.PASSTHROUGH_WORLD))
    control = ep.world(E.CONTROL)
    control.rename(ep.dir / "control-real")
    E.plant_link(control, ep.dir / "control-real")
    page = E.render(ep)

    graded = _world(page, E.GRADED_WORLD)
    assert 'investigation.md: not archived' in graded, graded
    assert 'report.md: not archived' not in graded, graded
    graded_leads = _leads(page, E.GRADED_WORLD)
    assert "investigation record unavailable" not in graded_leads, graded_leads
    assert f"summary of l-001 for {E.GRADED_WORLD}" in graded_leads, graded_leads

    passthrough = _world(page, E.PASSTHROUGH_WORLD)
    assert 'report.md: not archived' in passthrough, passthrough
    assert 'investigation.md: not archived' in passthrough, passthrough
    assert "not archived" in _leads(page, E.PASSTHROUGH_WORLD)

    linked = _world(page, E.CONTROL)
    assert f'worlds/{T.fixture_world_id(E.CONTROL)}/report.md' in linked, linked
    assert R.ALIAS in linked, linked
    assert "not archived" not in linked, linked
    linked_leads = _leads(page, E.CONTROL)
    assert f'worlds/{T.fixture_world_id(E.CONTROL)}' in linked_leads, linked_leads  # the directory's own refusal, said once
    assert linked_leads.count(R.ALIAS) == 1, linked_leads
    assert "not archived" not in linked_leads, linked_leads
    assert str(ep.dir) not in page.raw
    assert str(tmp_path) not in page.raw


# D-V5 — the closed list of listing sites


# s-66 — the timing slot tells absent from unreadable from no stages


def test_timing_json_present_empty_versus_empty_steps_versus_absent(tmp_path):
    ep = E.sample_episode(tmp_path)
    absent = E.render(ep).text_of("sec-stages")
    assert 'no timing record' in absent, absent
    assert 'unreadable' not in absent, absent
    E.write_timing(ep.dir, raw="")
    unreadable = E.render(ep).text_of("sec-stages")
    assert 'timing record unreadable' in unreadable, unreadable
    assert 'timing.json' in unreadable, unreadable
    assert 'not a JSON document' in unreadable, unreadable
    assert str(ep.dir) not in unreadable, unreadable
    E.write_timing(ep.dir, [])
    empty = E.render(ep).text_of("sec-stages")
    assert 'no timing record' not in empty, empty
    assert 'unreadable' not in empty, empty
    assert re.search(r"no (completed |recorded )?(stages?|steps?)", empty), empty
    assert empty != absent
