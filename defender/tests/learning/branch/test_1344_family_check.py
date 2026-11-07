"""#1344 r5: the family check after #976's amendment (siblings agree with each other, knowledge stays on
the source, the source is recorded) in the operator and job lanes, and families stamped from a code copy."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from defender.records import _provenance
from defender.tests.learning.branch import test_976_family_anchor as A
from defender.tests.learning.branch.test_976_family_anchor import _outcome, _prepare, _verify
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import location_path

MARKER = ".defender-code-copy.json"
BUILT = "b" * 40


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))


def _lane(lane: str, tag: str) -> tuple[str, ...]:
    """The launcher arguments that put a launch in a lane: an operator's carry none, a job's names its job id."""
    return () if lane == "operator" else ("--job-id", fixture_uuid(f"1344-job-{tag}"))


LANES = ["operator", "job"]


def _copy_with_marker(root: Path, commit: str) -> Path:
    copy = root / "code-copy"
    (copy / "defender").mkdir(parents=True, exist_ok=True)
    (copy / MARKER).write_text(json.dumps({"commit": commit}), encoding="utf-8")
    return copy


def _marker_stamp(root: Path, commit: str = BUILT) -> dict:
    """What the real stamp gives a tree holding the copy's marker, as written to a run's provenance.json."""
    prov = _provenance.capture_tree(_copy_with_marker(root, commit), environ={})
    wire = json.loads(prov.as_json())
    assert wire["origin"] == "code_copy"
    return wire


def _stamped_from_copy(root: Path, commit: str = BUILT, **record: Any) -> dict:
    """A sibling's record in the fixtures' shape (model, knowledge) with commit, dirt and origin from the copy's real stamp."""
    wire = _marker_stamp(root, commit)
    doc = T.provenance_record(commit=commit, **record)
    doc.update({k: wire[k] for k in ("commit", "dirty", "dirty_paths", "dirty_path_count", "unavailable", "origin")})
    return doc


def _plant_stamp(doc: dict):
    def plant(ep, w):
        arm = T.arm_run_dir(ep, w)
        (arm / "provenance.json").write_text(json.dumps(doc), encoding="utf-8")
        return arm
    return plant


class _EditedSiblings(J.FakeSibling):
    """Siblings that ran, then `edits[label]` merged into that sibling's stamp: a real disagreement among arms of one family."""

    def __init__(self, edits: dict[str, dict[str, Any]]) -> None:
        super().__init__()
        self.edits = edits

    def __call__(self, argv: list[str], **kw: Any) -> int:
        code = super().__call__(argv, **kw)
        label = argv[argv.index("--world") + 1] if "--world" in argv else None
        if code != 97 and label in self.edits:
            ep = self.episode_dir
            stamp = ep / "runs" / T.read_roster(ep)[T.world_id(ep, label)] / "provenance.json"
            doc = json.loads(stamp.read_text(encoding="utf-8"))
            stamp.write_text(json.dumps({**doc, **self.edits[label]}), encoding="utf-8")
        return code


# commit and scope are sibling agreement, in both lanes


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("live", ["0ther", "deadbee0", "deadbe"])
def test_o7_a_family_runs_on_code_the_source_did_not_run(tmp_path, lane, live):
    """Source at `deadbee`, the tree since moved: it launches with no flag and the stamp keeps the source's record. (O7, D1, L4)"""
    launch = _prepare(tmp_path, live_tree=T.source_capture(commit=live), siblings_at=live)

    assert launch.run(*_lane(lane, live)) == 0
    assert _outcome(launch.episode_dir)["outcome"] == "accepted"
    assert launch.live_tree.calls == 1
    assert sorted(launch.spawn.worlds) == list(T.WORLDS)
    stamp = launch.family_stamp
    assert (stamp["agreed"]["commit"], stamp["source"]["commit"]) == (live, "deadbee")
    assert stamp["allow_dirty"] is False


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("source", [
    {"dirty": True},
    {"commit": None, "dirty": None, "unavailable": T.GIT_UNAVAILABLE},
], ids=["dirty", "no-commit"])
def test_o7_a_dirty_or_commitless_source_is_recorded_not_judged(tmp_path, lane, source):
    """Source cleanliness and commit are record only and the family stamp keeps all of it. (Family check, L4)"""
    launch = _prepare(tmp_path)
    A._restamp(launch.src, **source)

    stamp = A._accepted(launch, *_lane(lane, "src"))
    expected = T.provenance_record(**source)
    for name in ("commit", "dirty", "scope", "model", "dirty_paths", "dirty_path_count", "unavailable"):
        assert stamp["source"][name] == expected[name], name
    assert (stamp["allow_dirty"], stamp["waived"]) == (False, [])


def test_o7_a_dirty_or_commitless_source_is_no_longer_judged_at_verify(tmp_path):
    """The verify tier asks nothing of the source's dirt or commit. (O7, #976 amended)"""
    location_path(T.runs_base)(tmp_path)

    def clean(ep, w):
        return T.arm_run_dir(ep, w, commit="cafe1")

    for name, source in (("dirty", T.provenance_record(commit="deadbee", dirty=True)),
                         ("silent", T.provenance_record(commit=None, dirty=None, unavailable="no git"))):
        for allow_dirty in (False, True):
            ep = T.episode(tmp_path, episode_id=fixture_uuid(f"1344-{name}-{allow_dirty}"))
            report = _verify(ep, clean, source=source, allow_dirty=allow_dirty)
            assert report["comparable"] is True, (name, allow_dirty, report["reason"])
            stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
            assert stamp["source"]["commit"] == source["commit"]
            assert stamp["source"]["dirty"] == source["dirty"]


def test_o7_siblings_must_still_agree_on_commit_and_stay_on_the_sources_knowledge(tmp_path):
    """Worlds identical in code and knowledge; only knowledge stays anchored to the source. (L4)"""
    location_path(T.runs_base)(tmp_path)
    source = T.provenance_record(commit="deadbee")

    def agreeing(ep, w):
        return T.arm_run_dir(ep, w, commit="cafe1")

    def split(ep, w):
        return T.arm_run_dir(ep, w, commit="cafe1" if w != "b" else "cafe2")

    def other_knowledge(ep, w):
        return T.arm_run_dir(ep, w, commit="cafe1", knowledge={"commit": T.OTHER_KNOWLEDGE_SHA})

    assert _verify(T.episode(tmp_path, episode_id=fixture_uuid("1344-a")), agreeing, source=source)["comparable"] is True
    disagreeing = _verify(T.episode(tmp_path, episode_id=fixture_uuid("1344-b")), split, source=source)
    assert disagreeing["comparable"] is False
    assert "commit" in disagreeing["reason"]
    off_knowledge = _verify(T.episode(tmp_path, episode_id=fixture_uuid("1344-c")), other_knowledge, source=source)
    assert off_knowledge["comparable"] is False
    assert "knowledge" in off_knowledge["reason"]


@pytest.mark.parametrize("source", [
    {},
    {"dirty": True},
    {"commit": None, "dirty": None, "unavailable": T.GIT_UNAVAILABLE},
], ids=["clean", "dirty", "no-commit"])
def test_o7_knowledge_stays_anchored_whatever_the_sources_commit_and_dirt(tmp_path, source):
    """Knowledge anchoring does not depend on the source's commit or cleanliness. (Family check, L4)"""
    location_path(T.runs_base)(tmp_path)
    record = T.provenance_record(**source)

    held = _verify(T.episode(tmp_path, episode_id=fixture_uuid("1344-kh")), T.arm_run_dir, source=record)
    assert held["comparable"] is True, held["reason"]

    def other(ep, w):
        return T.arm_run_dir(ep, w, knowledge={"commit": T.OTHER_KNOWLEDGE_SHA})

    off = _verify(T.episode(tmp_path, episode_id=fixture_uuid("1344-ko")), other, source=record)
    assert off["comparable"] is False
    assert "knowledge" in off["reason"], off["reason"]


# the live tree is judged on its own stamp, before anything is spent


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("live", [
    {"dirty": True},
    {"dirty": None, "unavailable": T.GIT_STATUS_FAILED},
    {"commit": None, "dirty": None, "unavailable": T.GIT_UNAVAILABLE},
], ids=["dirty", "git-status-failed", "no-commit"])
def test_o7_a_bad_live_tree_refuses_before_spend_even_when_it_would_match_the_source(tmp_path, lane, live):
    """A live tree git did not certify clean refuses before the questioner is paid, in both lanes; a clean one launches. (Family check)"""
    launch = _prepare(tmp_path, live_tree=T.source_capture(**live))
    message = A._refused_before_spending(launch, *_lane(lane, "bad"))
    assert "live tree" in message, message
    assert launch.live_tree.calls == 1

    control = _prepare(tmp_path)
    A._accepted(control, *_lane(lane, "good"))


def test_o7_an_operator_waives_a_dirty_live_tree_but_never_a_silent_one(tmp_path):
    """`--allow-dirty` reaches dirt only. (Family check)"""
    waived = _prepare(tmp_path, live_tree=T.source_capture(dirty=True))
    assert A._accepted(waived, "--allow-dirty")["waived"] == ["dirt"]

    silent = _prepare(tmp_path, live_tree=T.source_capture(
        commit=None, dirty=None, unavailable=T.GIT_UNAVAILABLE))
    A._never_waivable(A._refused_before_spending(silent, "--allow-dirty"), "live tree", "names no commit")


# sibling cleanliness and agreement, end to end in both lanes


@pytest.mark.parametrize(("lane", "edit", "why"), [
    ("job", {"commit": "cafe2"}, "siblings disagree on commit"),
    ("job", {"dirty": True}, "not certified clean"),
    ("job", {"dirty": None, "unavailable": T.GIT_STATUS_FAILED}, "not certified clean"),
    ("job", {"knowledge": None}, "knowledge"),
    ("operator", {"dirty": True}, "not certified clean"),
    ("operator", {"dirty": None, "unavailable": T.GIT_STATUS_FAILED}, "not certified clean"),
])
def test_o7_unproven_siblings_withhold_the_family_stamp_in_both_lanes(tmp_path, caplog, lane, edit, why):
    """Sibling disagreement, dirt and unproven knowledge withhold the stamp unless the operator's flag waives them. (Family check, L4)"""
    launch = _prepare(tmp_path, spawn=_EditedSiblings({"b": edit}))
    assert launch.run(*_lane(lane, "sib")) == 0
    assert launch.questioner.calls > 0
    assert why in A._withheld_reason(caplog)
    assert not (launch.episode_dir / "provenance.json").exists()


def test_o7_an_operator_waives_dirty_siblings_and_the_stamp_says_so(tmp_path):
    """Sibling cleanliness is waivable by `--allow-dirty` for operators and the stamp records the waiver. (Family check)"""
    launch = _prepare(tmp_path, spawn=_EditedSiblings({"b": {"dirty": True}}))
    stamp = A._accepted(launch, "--allow-dirty")
    assert (stamp["allow_dirty"], stamp["waived"]) == (True, ["dirt"])


def test_o7_jobs_never_waive_unproven_knowledge(tmp_path):
    """A job whose source knowledge is unproven is refused before spend; the operator flag is the only waiver. (Family check)"""
    job = _prepare(tmp_path)
    A._restamp(job.src, knowledge=T.NO_KNOWLEDGE_KEY)
    message = A._refused_before_spending(job, *_lane("job", "k"))
    assert "knowledge" in message, message

    operator = _prepare(tmp_path)
    A._restamp(operator.src, knowledge=T.NO_KNOWLEDGE_KEY)
    assert A._accepted(operator, "--allow-dirty")["waived"] == ["knowledge"]


# a family whose stamps came from a code copy's marker


def test_o7_siblings_stamped_from_a_code_copy_are_comparable_with_no_parameter(tmp_path):
    """Commit, clean and origin from the marker make siblings comparable with no flag, keep `allow_dirty` False and still refuse unproven knowledge. (Family check, Stamps from the copy)"""
    location_path(T.runs_base)(tmp_path)
    source = T.provenance_record(commit="deadbee")
    built = _stamped_from_copy(tmp_path)

    ep = T.episode(tmp_path, episode_id=fixture_uuid("1344-copy"))
    assert _verify(ep, _plant_stamp(built), source=source)["comparable"] is True
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert (stamp["allow_dirty"], stamp["waived"]) == (False, [])
    assert stamp["agreed"]["commit"] == BUILT
    assert stamp["source"]["commit"] == "deadbee"

    unproven = _stamped_from_copy(tmp_path, knowledge=T.NO_KNOWLEDGE_KEY)
    refused = _verify(T.episode(tmp_path, episode_id=fixture_uuid("1344-copy-u")),
                      _plant_stamp(unproven), source=source)
    assert refused["comparable"] is False
    assert "knowledge" in refused["reason"]


@pytest.mark.parametrize("lane", LANES)
def test_o7_a_stamp_git_could_not_certify_refuses_for_everyone_without_the_flag(tmp_path, lane):
    """Control: the same record without the marker (dirty None, what a failed `git status` gives) is not comparable. (Family check)"""
    location_path(T.runs_base)(tmp_path)
    unknown = {k: v for k, v in _stamped_from_copy(tmp_path).items() if k != "origin"}
    unknown.update(dirty=None, unavailable=T.GIT_STATUS_FAILED)
    report = _verify(T.episode(tmp_path, episode_id=fixture_uuid(f"1344-unknown-{lane}")),
                     _plant_stamp(unknown), source=T.provenance_record())
    assert report["comparable"] is False
    assert "not certified clean" in report["reason"]


def test_o7_a_worker_launched_family_passes_on_its_marker_stamp_alone(tmp_path):
    """A job whose live tree and siblings carry the copy's stamp launches with no flag. (Family check, Stamps from the copy)"""
    record = _stamped_from_copy(tmp_path)
    launch = _prepare(tmp_path, live_tree=T.FakeCapture(record), siblings_at=BUILT)

    stamp = A._accepted(launch, *_lane("job", "copy"))
    assert (stamp["agreed"]["commit"], stamp["allow_dirty"], stamp["waived"]) == (BUILT, False, [])


def _judge_caveats(tmp_path, record: dict) -> str:
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    (ep / "worlds" / T.world_id(ep, "b") / "provenance.json").write_text(json.dumps(record), encoding="utf-8")
    ctx = J.render_at(ep, "b", git_show=J.FakeGitShow(bodies={}))
    return J.mod("learning.judge.render")._render_lessons(ctx.focus.lessons)


def test_o7_a_copy_stamped_family_gets_no_dirt_caveat_from_the_judge(tmp_path):
    """The judge's caveat path treats a marker stamp as clean, with no exception of its own. (Family check)"""
    unknown = {**T.provenance_record(commit=BUILT), "dirty": None, "unavailable": T.GIT_STATUS_FAILED}
    assert "never measured" in _judge_caveats(tmp_path / "unknown", unknown), "control: an unmeasured tree is caveated"

    lessons = _judge_caveats(tmp_path / "copy", _stamped_from_copy(tmp_path))
    assert "### L1" in lessons
    assert "caveat" not in lessons, lessons


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


def test_a_copy_under_an_outer_work_tree_takes_the_marker_commit_not_the_outer_head(tmp_path):
    """The marker is read before git, so an outer repository's HEAD is never the copy's commit. (Stamps from the copy, L-C23)"""
    outer = tmp_path / "outer"
    (outer / "defender").mkdir(parents=True)
    (outer / "defender" / "a.py").write_text("A = 1\n", encoding="utf-8")
    (outer / ".gitignore").write_text("data/\n", encoding="utf-8")
    _git(outer, "init", "-q")
    _git(outer, "add", ".")
    _git(outer, "commit", "-qm", "x")
    head = _git(outer, "rev-parse", "HEAD")
    (outer / "defender" / "a.py").write_text("A = 2\n", encoding="utf-8")
    copy = outer / "data" / "code"
    (copy / "defender").mkdir(parents=True)
    (copy / MARKER).write_text(json.dumps({"commit": BUILT}), encoding="utf-8")

    control = _provenance.capture_tree(outer, environ={})
    assert (control.commit, control.dirty) == (head, True), "control: the outer tree keeps git's answer"
    assert control.origin != "code_copy"

    stamped = _provenance.capture_tree(copy, environ={})
    assert (stamped.commit, stamped.dirty, stamped.origin) == (BUILT, False, "code_copy")
