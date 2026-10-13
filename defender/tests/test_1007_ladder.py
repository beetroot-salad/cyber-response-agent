"""#1007 — the judge record's #1007 fields, and their round trip.

Demand #0's return-value contract and its round trip. Every test drives the real entry point,
`judge.grade_episode`, against an episode built on disk; nothing asserts on a fake's canned
reply alone.

#1224 removed the judge's code half — the withholding ladder (O4/M3), the reachability block it
read off the replay review, and the mechanical `unreachable-difference` finding. #1234 then
retired the family's own word (`family_outcome`, `verdict_word`) and the record's
`world_findings` list: what a pass did with each finding is the record's ledger
(`dispositions`), and the family call has its own row (`family`). What survives here is the
record's family-level fields and the per-world bucket and systems the model answers with.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests import _world_1007 as W
from defender.tests.judge_contrast_1234 import _spec1234 as S

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def graded_reply() -> dict:
    """World b's reply: the model's own bucket and systems, one investigator finding and one
    design world finding."""
    return S.world_reply("lead-quality", ["idp"], investigator=[S.inv()],
                         world=[S.wf("mislabelled")])


def rows_of(grade_result) -> dict[str, dict]:
    return {row["world"]: row for row in grade_result.worlds}


# ---------------------------------------------------------------------------------------
# Demand #0 — the return value, and the round trip it must survive
# ---------------------------------------------------------------------------------------


def test_grade_episode_returns_extended_record(tmp_path, monkeypatch):
    """`grade_episode` hands back the family-level record CARRYING the world fields, not a
    record a caller has to re-read `judge.yaml` to see.

    Observably true: the returned `EpisodeGrade` exposes the family-level additions — the
    family call's own row, the ledger lane each world finding took, the second channel it
    enqueued them to — and the graded world's row carries the model's own `bucket` and
    `systems` (#1224: those replaced the reachability and withholding fields this once named).

    What failure looks like: a pass that writes the fields into `judge.yaml` but not onto its
    return value. Every in-process consumer then reads a record that is missing exactly the
    fields this change exists to add, and the only artifact that has them is the file on disk.
    """
    built = W.contrast_family(tmp_path, monkeypatch)

    result = S.grade(built, S.judge({"b": graded_reply()}))

    assert (result.family or {}).get("completed_draws") == 1, (
        f"the family call's own row did not reach the return value: {result.family!r}")
    assert result.world_enqueued_to, "the return value names no channel world rows went to"
    assert result.world_enqueued_rows == 1, result.world_enqueued_rows
    lanes = {e["finding_id"]: e["lane"] for e in result.dispositions or []}
    assert lanes.get(built.finding_id("b", 0, 1)) == S.LANES["questioner"], (
        f"the world finding built for b is not on the return value's ledger: {lanes}")
    row = rows_of(result)["b"]
    assert (row["bucket"], row["systems"]) == ("lead-quality", ["idp"]), (
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
    built = W.contrast_family(tmp_path, monkeypatch)
    judge = S.judge({"b": graded_reply()})

    first = S.grade(built, judge)
    second = S.grade(built, judge)   # the existing-record path: every row `queued`, no re-draw

    assert (built.ep / W.JUDGE_NAME).is_file(), "the pass wrote no judge.yaml to round-trip"
    assert first.dispositions, "the first pass routed no finding, so nothing round-trips"
    assert rows_of(second) == rows_of(first), (
        "a per-world field written to judge.yaml did not survive the re-read — "
        f"{rows_of(first)} != {rows_of(second)}")
    for field in ("family", "dispositions", "user", "world_enqueued_rows", "world_enqueued_to",
                  "enqueued_rows", "enqueued_to", "validity"):
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
