"""#1007 — the judge record's #1007 fields, and their round trip."""
from __future__ import annotations


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
    """`grade_episode` hands back the family-level record CARRYING the world fields, not a record a
    caller has to re-read `judge.yaml` to see."""
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
    """Every field written by `_write_judge_yaml` is read back by `judge.read_grade` ."""
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


