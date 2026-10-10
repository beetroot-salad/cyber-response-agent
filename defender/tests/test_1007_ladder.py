"""#1007 — the judge record's #1007 fields, and their round trip.

Demand #0's return-value contract and its round trip. Every test drives the real entry point,
`judge.grade_episode`, against an episode built on disk; nothing asserts on a fake's canned
reply alone.

#1224 removed the judge's code half — the withholding ladder (O4/M3), the reachability block it
read off the replay review, and the mechanical `unreachable-difference` finding ("No mechanical
bucket": a world whose change never reached the investigator is the judge model's finding, not
withheld). The tests of those went with it; what survives here is the record's family-level
world fields and the per-world bucket and systems the model answers with.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests import _judge_921 as J
from defender.tests import _world_1007 as W
from defender.tests._state1135 import env_state

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


# ---------------------------------------------------------------------------------------
# The scene: an archived, accepted episode with samples and one graded world.
# ---------------------------------------------------------------------------------------


def graded_episode(tmp_path: Path, monkeypatch, *, worlds=("b",)) -> Path:
    """One episode dir carrying everything the grading pass reads: the v2 manifest, one
    archived world dir per label (the control `a` included), one served ledger per world,
    `samples.yaml`, and pre-flight's `outcome.yaml` saying `accepted`."""
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    docs = [W.base_world()] + [
        W.world_doc(label, facts=[W.fact(f"f-{label}")]) for label in worlds]
    ep = W.episode(tmp_path, doc=W.family_doc(worlds=docs), root=root)
    for label in ("a", *worlds):
        W.archived_world(ep, label)
        W.write_served(ep, label, [W.served_row(world=label)])
    W.write_samples(ep)
    W.write_outcome(ep)
    return ep


def grade(ep: Path, *, judge=None, **kw):
    """`judge.grade_episode` through its own injection seams — never a live provider — over the
    episode at `ep`, by id (#1105 PR 2: `_judge_921.grade_at`)."""
    kw.setdefault("state", env_state())
    return J.grade_at(
        ep, judge=judge if judge is not None else W.FakeJudge(W.reply_document()), **kw)


def rows_of(grade_result) -> dict[str, dict]:
    return {row["world"]: row for row in grade_result.worlds}


# ---------------------------------------------------------------------------------------
# Demand #0 — the return value, and the round trip it must survive
# ---------------------------------------------------------------------------------------


def test_grade_episode_returns_extended_record(tmp_path, monkeypatch):
    """`grade_episode` hands back the family-level record CARRYING the world fields, not a
    record a caller has to re-read `judge.yaml` to see.

    Observably true: the returned `EpisodeGrade` exposes the family-level additions — the family
    draw's own outcome, the world findings it built, the second channel it enqueued them to —
    and the graded world's row carries the model's own `bucket` and `systems` (#1224: those
    replaced the reachability and withholding fields this once named).

    What failure looks like: a pass that writes the fields into `judge.yaml` but not onto its
    return value. Every in-process consumer (the launcher's own stamp, `enqueue`) then reads a
    record that is missing exactly the fields this change exists to add, and the only artifact
    that has them is the file on disk.
    """
    ep = graded_episode(tmp_path, monkeypatch)

    result = grade(ep, judge=W.FakeJudge(W.reply_document(
        findings=[W.world_finding(bucket="an-unlisted-world-bucket")])))

    assert result.family_outcome == "survived", (
        f"the family draw's outcome did not reach the return value: {result.family_outcome!r}")
    assert result.world_enqueued_to, "the return value names no channel world rows went to"
    assert [f["type"] for f in result.world_findings if f["world"] == "b"] == [
        "an-unlisted-world-bucket"], (
        f"the world finding built for b is not on the return value: {result.world_findings}")
    row = rows_of(result)["b"]
    assert (row["bucket"], row["systems"]) == ("lead-set", [W.SYSTEM]), (
        f"the per-world row does not carry the model's own bucket and systems: {sorted(row)}")


def test_judge_yaml_round_trips_every_new_field(tmp_path, monkeypatch):
    """Every field written by `_write_judge_yaml` is read back by `judge.read_grade` — the one
    tolerant reader of `judge.yaml` (#1025 prep 2), which the existing-record path goes through.

    Observably true: grading an episode twice — the second time off the `judge.yaml` the first
    wrote — yields an equal record. The two sites are hand-written enumerations (C32), which is
    exactly why a field added to the writer and not to the reader is lost silently.

    What failure looks like: the second grade returns a record whose new fields are absent or
    defaulted, so a re-read episode grades as if it had measured nothing — and every reader
    downstream of the re-read path sees a different episode from the one that was graded.
    """
    ep = graded_episode(tmp_path, monkeypatch)
    judge = W.FakeJudge(W.reply_document(findings=[W.world_finding()]))

    first = grade(ep, judge=judge)
    second = grade(ep, judge=judge)   # the existing-record path: reads judge.yaml, does not re-draw

    assert (ep / W.JUDGE_NAME).is_file(), "the pass wrote no judge.yaml to round-trip"
    assert first.world_findings, "the first pass built no world finding, so nothing round-trips"
    assert rows_of(second) == rows_of(first), (
        "a per-world field written to judge.yaml did not survive the re-read — "
        f"{rows_of(first)} != {rows_of(second)}")
    for field in ("family_outcome", "world_findings", "world_enqueued_to", "verdict_word"):
        assert getattr(second, field) == getattr(first, field), (
            f"{field!r} is written to judge.yaml and not read back off it")


def test_removing_the_flag_leaves_no_orphan_in_the_committed_spec_corpus(tmp_path):
    """Removing `agreed-without-evidence` settles its THIRD consumer — the committed spec
    corpus the CI ratchet checks — not just the two in code.

    Observably true: after this change no `agreed-without-evidence` string survives in
    `defender/learning/judge/family.py`, in either of the two #921 suites that name it
    (`test_921_family_buckets.py`, `test_921_family_facts.py`), or in
    `spec-flow/specs/spec_graph_921-family-judge.yaml`. The last is the one the design's own
    sweep missed (correction C-B): the committed graph binds the flag as a domain member and
    records an R4 discharge against it, so removing it orphans a coverage row and a mechanical
    discharge in a corpus a ratchet reads.

    Each holder is asserted to EXIST before it is read, which is not bookkeeping and is not
    hypothetical: this test named `tests/e2e/test_921_family_buckets.py`, which is not where
    that suite lives, so one third of its census read no file at all and passed on nothing —
    and the existence check is what found it. The corrected census gained a FOURTH holder
    (`test_921_family_facts.py`) the wrong path had been hiding.

    What failure looks like: the code drops the flag, the spec corpus keeps binding it, and the
    graph checker fails on a repository the change left inconsistent — a red CI whose cause is
    two directories from the diff.
    """
    repo = Path(__file__).resolve().parents[2]
    holders = [
        repo / "defender" / "learning" / "judge" / "family.py",
        repo / "defender" / "tests" / "test_921_family_buckets.py",
        repo / "defender" / "tests" / "test_921_family_facts.py",
        repo / "spec-flow" / "specs" / "spec_graph_921-family-judge.yaml",
    ]
    missing = [p for p in holders if not p.is_file()]
    assert missing == [], (
        f"{[str(p.relative_to(repo)) for p in missing]} do not exist, so the absence below is a "
        "fact about a file nobody read — this is the whole failure mode of a string check: it "
        "is green when the channel it looks through is not there")
    present = [p for p in holders if "agreed-without-evidence" in p.read_text(encoding="utf-8")]

    assert present == [], (
        "these still bind the removed family flag: "
        f"{[str(p.relative_to(repo)) for p in present]} — the last one is the committed spec "
        "corpus, whose orphaned domain member and R4 discharge row the CI ratchet reads")
