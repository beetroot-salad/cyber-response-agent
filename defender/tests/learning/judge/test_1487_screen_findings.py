"""#1487 (design r5, Flow 1 step 2): `screen_findings(channel, rows, job_id)`, the one public door of the channel rules,
refuses a channel's rows whole on any failing row. `channel` is the store kind string (`"finding"`,
`"questioner_finding"`: the keys of the findings text; amendment r5.1 item 5). The id and row bounds are the exported
`FINDING_ID_MAX_BYTES` and `FINDING_ROW_MAX_BYTES` (item 2). No database."""
from __future__ import annotations

import random

import pytest

from defender.tests.support.jobs._findings1487 import (
    MULTIBYTE_FILLERS,
    defender_row,
    id_of_utf8_bytes,
    id_over_in_bytes_only,
    row_of_json_bytes,
    world_row,
)

JOB = "6b0f2d9c-0d0c-4b1e-8f10-0a1b2c3d4e5f"
OTHER = "0e6f7a8b-1c2d-4e3f-9a0b-1c2d3e4f5a6b"


def _screen():
    from defender.learning.judge.enqueue import JudgeRefused, screen_findings

    return screen_findings, JudgeRefused


def _channels():
    return {"defender": ("finding", defender_row), "questioner": ("questioner_finding", world_row)}


def _bounds():
    from defender.learning.judge.enqueue import FINDING_ID_MAX_BYTES, FINDING_ROW_MAX_BYTES

    return FINDING_ID_MAX_BYTES, FINDING_ROW_MAX_BYTES


def test_the_bounds_are_the_named_values():
    """Amendment r5.1 item 2: 1024 bytes of id, 1 MiB of row JSON."""
    assert _bounds() == (1024, 1024 * 1024)


@pytest.mark.parametrize("which", ["defender", "questioner"])
def test_a_row_and_an_id_exactly_at_their_bounds_are_screened_clean(which):
    """At-bound positive controls: an id of exactly `FINDING_ID_MAX_BYTES` UTF-8 bytes (ASCII, and multi-byte), a row
    whose JSON is exactly `FINDING_ROW_MAX_BYTES`. (O2 bounds)"""
    screen, _ = _screen()
    channel, make = _channels()[which]
    id_max, row_max = _bounds()
    row = make(JOB, 0)
    for filler in ("x", *MULTIBYTE_FILLERS):
        at_bound = id_of_utf8_bytes(JOB, id_max, filler)
        assert len(at_bound.encode()) == id_max, "premise: exactly at the byte bound"
        assert len(at_bound) <= id_max, "premise: within the bound in characters"
        screen(channel, [dict(row, finding_id=at_bound)], JOB)
    screen(channel, [row_of_json_bytes(row, row_max)], JOB)


@pytest.mark.parametrize("which", ["defender", "questioner"])
def test_a_row_or_an_id_one_over_its_bound_is_refused(which):
    """One byte over each bound is refused; so is an id, of 2-, 3- and 4-byte characters, whose characters are within the
    bound but whose UTF-8 bytes are over it (a count of characters would let it in). The row is one byte over by the compact
    measure (so over by any serialisation). (O2 bounds)"""
    screen, refused = _screen()
    channel, make = _channels()[which]
    id_max, row_max = _bounds()
    row = make(JOB, 0)
    by_bytes_only = [id_over_in_bytes_only(JOB, id_max, filler) for filler in MULTIBYTE_FILLERS]
    for long_id in by_bytes_only:
        assert len(long_id) <= id_max < len(long_id.encode()), "premise: within the bound in characters, over it in bytes"
    over = [dict(row, finding_id=id_of_utf8_bytes(JOB, id_max + 1)),
            *(dict(row, finding_id=long_id) for long_id in by_bytes_only),
            row_of_json_bytes(row, row_max + 1, compact=True)]
    for bad in over:
        with pytest.raises(refused):
            screen(channel, [bad], JOB)


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
    id_max, row_max = _bounds()
    return channel, {
        "row-not-a-dict": ["x", 5, None, [row], 1.5],
        "id-not-under-the-job": [dict(row, finding_id=f"{OTHER}/w/0/0"), dict(row, finding_id=JOB),
                                 dict(row, finding_id=f"{JOB}x/w/0/0"), dict(row, finding_id=""),
                                 dict(row, finding_id=None), dict(row, finding_id=7)],
        "id-too-long": [dict(row, finding_id=id_of_utf8_bytes(JOB, id_max + 1)),
                        dict(row, finding_id=f"{JOB}/" + "x" * 100_000)],
        "row-too-large": [row_of_json_bytes(row, row_max + 1, compact=True)],
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


def _raw_text_of_utf8_bytes(filler: str, size: int) -> str:
    """A findings text object written as raw UTF-8 (not ASCII-escaped): one defender row whose `finding` is `filler`s,
    padded with ASCII so that the whole text is exactly `size` UTF-8 bytes."""
    head, tail = '{"finding": [{"finding": "', '"}], "questioner_finding": []}'
    body = size - len((head + tail).encode())
    width = len(filler.encode())
    text = head + filler * (body // width) + "x" * (body % width) + tail
    assert len(text.encode()) == size, "premise: exactly `size` UTF-8 bytes"
    return text


@pytest.mark.parametrize("filler", MULTIBYTE_FILLERS, ids=["2-byte", "3-byte", "4-byte"])
@pytest.mark.parametrize("bound", ["text-cap", "row-bound"])
def test_o2_the_findings_cap_and_the_row_bound_count_utf8_bytes_not_characters(bound, filler):
    """Multi-byte text over a bound in UTF-8 bytes but within it in characters is refused; text at the 8 MiB cap, and a
    row far within the row bound by any measure, are accepted. (Data model: the cap is UTF-8 bytes; amendment r5.1
    item 2: the row bound is UTF-8 bytes of the row's JSON)"""
    if bound == "text-cap":
        from defender.records.job_lane import FINDINGS_CAP_BYTES, FINDINGS_OVER_CAP, parse_findings_text

        over = _raw_text_of_utf8_bytes(filler, FINDINGS_CAP_BYTES + 1)
        assert len(over) <= FINDINGS_CAP_BYTES, "premise: within the cap in characters"
        assert parse_findings_text(over) == (None, FINDINGS_OVER_CAP)
        obj, why = parse_findings_text(_raw_text_of_utf8_bytes(filler, FINDINGS_CAP_BYTES))
        assert why is None, why
        assert obj is not None and obj["questioner_finding"] == []  # noqa: PT018
        return
    import json

    from defender.records.job_lane import findings_text_bytes

    screen, refused = _screen()
    _, row_max = _bounds()
    row = defender_row(JOB, 0)
    # Over in real UTF-8 bytes (so also over when non-ASCII is measured as escapes), within it in characters.
    over = dict(row, finding=filler * (row_max // len(filler.encode()) + 1))
    raw = json.dumps(over, ensure_ascii=False)
    assert len(raw) <= row_max < findings_text_bytes(raw), "premise: within the bound in characters, over it in bytes"
    assert findings_text_bytes(json.dumps(over)) > row_max, "premise: over it with escapes too"
    with pytest.raises(refused):
        screen("finding", [over], JOB)
    # Far within the bound whether non-ASCII is measured as UTF-8 bytes or as escapes: accepted.
    under = dict(row, finding=filler * (row_max // 24))
    assert max(findings_text_bytes(json.dumps(under)), findings_text_bytes(json.dumps(under, ensure_ascii=False))) \
        < row_max, "premise: within the bound by either measure"
    screen("finding", [under], JOB)
