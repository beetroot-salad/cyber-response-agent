"""#1487 (design r5, Flow 1 step 2): `screen_findings(channel, rows, job_id)`, the one public door of the channel rules,
refuses a channel's rows whole on any failing row. `channel` is the episode sink's channel object
(`learning.core.state.FINDINGS`, `QUESTIONER_FINDINGS`), as every other function here takes it. No database."""
from __future__ import annotations

import random

import pytest

from defender.tests.support.jobs._findings1487 import defender_row, world_row

JOB = "6b0f2d9c-0d0c-4b1e-8f10-0a1b2c3d4e5f"
OTHER = "0e6f7a8b-1c2d-4e3f-9a0b-1c2d3e4f5a6b"


def _screen():
    from defender.learning.judge.enqueue import JudgeRefused, screen_findings

    return screen_findings, JudgeRefused


def _channels():
    from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS

    return {"defender": (FINDINGS, defender_row), "questioner": (QUESTIONER_FINDINGS, world_row)}


@pytest.mark.parametrize("which", ["defender", "questioner"])
def test_a_channels_rows_that_pass_its_rule_under_the_jobs_prefix_are_screened_clean(which):
    """Positive control for every refusal below, both channels, zero rows included. (Flow 1 step 2)"""
    screen, _ = _screen()
    channel, make = _channels()[which]
    screen(channel, [make(JOB, 0), make(JOB, 1)], JOB)
    screen(channel, [], JOB)


def _bad(which: str):
    channel, make = _channels()[which]
    row = make(JOB, 0)
    rng = random.Random(1487)
    return channel, {
        "row-not-a-dict": ["x", 5, None, [row], 1.5],
        "id-not-under-the-job": [dict(row, finding_id=f"{OTHER}/w/0/0"), dict(row, finding_id=JOB),
                                 dict(row, finding_id=f"{JOB}x/w/0/0"), dict(row, finding_id=""),
                                 dict(row, finding_id=None), dict(row, finding_id=7)],
        "id-too-long": [dict(row, finding_id=f"{JOB}/" + "x" * n) for n in (5000, 100_000)],
        "row-too-large": [dict(row, finding="y" * (6 * 1024 * 1024))],
        "nul": [dict(row, finding="a\x00b"), dict(row, **{"k\x00": 1})],
        "lone-surrogate": [dict(row, finding="\ud800")],
        "fails-the-channel-rule": [{k: v for k, v in row.items() if k != "type"},
                                   {k: v for k, v in row.items() if k != "finding_id"},
                                   dict(row, type=["unhashable"]), dict(row, subject="nobody")],
        "random-values": [{f"k{n}": rng.choice([None, 1, "s", [1], {"a": 1}]) for n in range(3)} for _ in range(4)],
    }


@pytest.mark.parametrize("which", ["defender", "questioner"])
@pytest.mark.parametrize("kind", ["row-not-a-dict", "id-not-under-the-job", "id-too-long", "row-too-large", "nul",
                                  "lone-surrogate", "fails-the-channel-rule", "random-values"])
def test_any_failing_row_refuses_the_whole_channel_even_beside_good_rows(which, kind):
    """Each failing row, alone and after a good row, raises `JudgeRefused`. (O2: row rule, prefix, id bound, size bound,
    non-dict row)"""
    screen, refused = _screen()
    channel, cases = _bad(which)
    good = _channels()[which][1](JOB, 5)
    for row in cases[kind]:
        for rows in ([row], [good, row], [row, good]):
            with pytest.raises(refused):
                screen(channel, rows, JOB)


@pytest.mark.parametrize("rows", ["a string", {"a": 1}, 5, None], ids=["str", "dict", "int", "none"])
def test_rows_that_are_not_a_list_are_refused(rows):
    """A channel that is not a list is a refusal, not a `TypeError`. (Flow 1 step 2: non-list channel)"""
    screen, refused = _screen()
    channel, _ = _channels()["defender"]
    with pytest.raises(refused):
        screen(channel, rows, JOB)
