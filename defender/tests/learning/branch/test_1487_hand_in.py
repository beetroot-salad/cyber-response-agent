"""#1487 (design r5, Flow 1 steps 1-2, P4 container side): at its end the learning job's entry reads the episode's held
findings and carries them in its own end record's `findings` field; it opens no store and never drops a single row.
Driven as `test_1344_job_end.py` drives the entry (`run_entry`). No database."""
from __future__ import annotations

import json

import pytest

from defender.tests.learning.branch.test_1344_job_lane import choose, run_entry, sink_files
from defender.tests.support.jobs._findings1487 import FINDING, MULTIBYTE_FILLERS, QUESTIONER, defender_row, world_row


def _holding(defender=1, questioner=1, *, after=None):
    """The `grade` seam: the judge's real job-lane pass, then rows held in the episode as the judge's sink holds them
    (the fixture family's judge files none); `after(episode_dir)` may then damage the sink."""
    def grade(runs, episode_id, **kw):
        from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
        from defender.learning.judge import grade_episode
        from defender.learning.judge.enqueue import EpisodeFindings

        graded = grade_episode(runs, episode_id, **kw)
        job = str(episode_id)
        with runs.episode_files(episode_id) as episode:
            sink = EpisodeFindings(episode)
            if defender:
                sink.append(FINDINGS, [defender_row(job, n) for n in range(defender)], dedup_key="finding_id")
            if questioner:
                sink.append(QUESTIONER_FINDINGS, [world_row(job, n) for n in range(questioner)], dedup_key="finding_id")
        if after is not None:
            after(episode_id)
        return graded
    return grade


def _findings(ran) -> dict:
    assert ran.end is not None, f"no end record (exit {ran.exit!r})"
    assert ran.end["status"] == "completed", ran.end
    assert isinstance(ran.end.get("findings"), dict), ran.end
    return ran.end["findings"]


def _damage(tmp_path_of, how):
    """After grading, damage the episode's held-findings files (found by content, as `sink_files` does)."""
    def after(episode_id):
        import os
        from pathlib import Path

        ep = next(Path(os.environ["DEFENDER_DATA_ROOT"]).glob(f"*/episodes/{episode_id}"))
        sinks = sink_files(p for p in ep.rglob("*") if p.is_file())
        assert sinks, "premise: the episode holds sink files to damage"
        for path in sinks:
            how(path)
    return after


def test_o1_the_completed_job_carries_every_held_row_by_channel_in_its_end_record(tmp_path):
    """Two defender rows and one questioner row held: `findings.state` `ok`, its text the rows as held, by store kind.
    (O1, Flow 1 step 1)"""
    ran = run_entry(tmp_path, grade=_holding(2, 1))
    found = _findings(ran)
    assert found["state"] == "ok", found
    job = ran.ep.name
    assert json.loads(found["text"]) == {FINDING: [defender_row(job, 0), defender_row(job, 1)],
                                         QUESTIONER: [world_row(job, 0)]}


def test_o1_a_pass_that_held_nothing_carries_ok_findings_with_both_channels_empty(tmp_path):
    """Zero held rows is `ok` with empty channels, not `unreadable`. (O1: zero findings included)"""
    found = _findings(run_entry(tmp_path, grade=_holding(0, 0)))
    assert found["state"] == "ok", found
    assert json.loads(found["text"]) == {FINDING: [], QUESTIONER: []}


def test_p4_one_malformed_held_line_makes_the_whole_findings_malformed_and_drops_no_row(tmp_path):
    """A held line that is not JSON: `malformed`, no `text` (the entry never drops one row and keeps the rest); the
    ending is still `completed`. (P4, Flow 1 step 1)"""
    def spoil(path):
        with path.open("a", encoding="utf-8") as sink:
            sink.write("this is not a finding row\n")

    found = _findings(run_entry(tmp_path, grade=_holding(1, 1, after=_damage(None, spoil))))
    assert found["state"] == "malformed", found
    assert "text" not in found


def test_p4_held_rows_the_job_cannot_read_read_unreadable_and_the_ending_stands(tmp_path):
    """The sink file is unreadable (a directory in its place): `unreadable`, status `completed`. (P4, Flow 1 step 1)"""
    def unreadable(path):
        path.unlink()
        path.mkdir()

    found = _findings(run_entry(tmp_path, grade=_holding(1, 1, after=_damage(None, unreadable))))
    assert found["state"] == "unreadable", found
    assert "text" not in found


def test_p4_held_findings_over_the_cap_read_over_cap_with_no_text(tmp_path):
    """Rows whose text is over `FINDINGS_CAP_BYTES` (8 MiB): `over_cap`, no text, the ending `completed`. (P4, O2)"""
    from defender.records.job_lane import FINDINGS_CAP_BYTES

    def big(job):
        return dict(defender_row(job, 0), finding="z" * (FINDINGS_CAP_BYTES // 4 + 1024))

    def grade(runs, episode_id, **kw):
        from defender.learning.core.state import FINDINGS
        from defender.learning.judge import grade_episode
        from defender.learning.judge.enqueue import EpisodeFindings

        graded = grade_episode(runs, episode_id, **kw)
        with runs.episode_files(episode_id) as episode:
            sink = EpisodeFindings(episode)
            for n in range(5):
                sink.append(FINDINGS, [dict(big(str(episode_id)), finding_id=f"{episode_id}/w-b/0/{n}")],
                            dedup_key="finding_id")
        return graded

    found = _findings(run_entry(tmp_path, grade=grade))
    assert found["state"] == "over_cap", found
    assert "text" not in found


@pytest.mark.parametrize("filler", MULTIBYTE_FILLERS, ids=["2-byte", "3-byte", "4-byte"])
@pytest.mark.parametrize("size", ["within-the-cap-in-utf8", "over-the-cap-in-utf8"])
def test_p4_non_ascii_rows_travel_unescaped_and_count_their_utf8_bytes_toward_the_cap(tmp_path, filler, size):
    """Held rows of 2-, 3- or 4-byte characters travel in the end record's findings text as the raw characters, never
    `\\uXXXX` escapes, and count their UTF-8 bytes toward the 8 MiB cap: about 6 MiB of them (over the cap were they
    escaped) is `ok` with the rows as held; about 9 MiB is `over_cap`. One encoding, UTF-8 bytes (owner, 2026-11-19).
    (P4, Data model: the cap; Flow 1 step 1)"""
    from defender.records.job_lane import FINDINGS_CAP_BYTES, findings_text_bytes

    count = {"within-the-cap-in-utf8": 7, "over-the-cap-in-utf8": 10}[size]
    per_row = 900_000 // len(filler.encode())  # 900 000 UTF-8 bytes of characters a row, within the row bound

    def rows(job):
        return [dict(defender_row(job, n), finding=filler * per_row) for n in range(count)]

    def grade(runs, episode_id, **kw):
        from defender.learning.core.state import FINDINGS
        from defender.learning.judge import grade_episode
        from defender.learning.judge.enqueue import EpisodeFindings

        graded = grade_episode(runs, episode_id, **kw)
        with runs.episode_files(episode_id) as episode:
            EpisodeFindings(episode).append(FINDINGS, rows(str(episode_id)), dedup_key="finding_id")
        return graded

    ran = run_entry(tmp_path, grade=grade)
    held = {FINDING: rows(ran.ep.name), QUESTIONER: []}
    raw, escaped = (findings_text_bytes(json.dumps(held, ensure_ascii=ascii_)) for ascii_ in (False, True))
    found = _findings(ran)
    if size == "over-the-cap-in-utf8":
        assert raw > FINDINGS_CAP_BYTES, "premise: over the cap in UTF-8 bytes"
        assert found["state"] == "over_cap", found.get("state")
        assert "text" not in found
        return
    assert raw < FINDINGS_CAP_BYTES < escaped, "premise: within the cap in UTF-8 bytes, over it in escapes"
    assert found["state"] == "ok", found.get("state")
    text = found["text"]
    assert filler in text, "the findings text does not hold the raw characters"
    assert "\\u" not in text, "the findings text holds \\uXXXX escapes"
    assert findings_text_bytes(text) < FINDINGS_CAP_BYTES
    assert json.loads(text) == held


def test_flow1_an_ending_other_than_completed_carries_no_held_rows(tmp_path):
    """A job with no fork point ends `skipped`; its record carries no findings text. (Flow 1: only `completed`)"""
    ran = run_entry(tmp_path, candidates=choose())
    assert ran.end is not None and ran.end["status"] == "skipped", ran.end  # noqa: PT018
    assert "text" not in (ran.end.get("findings") or {})


@pytest.mark.parametrize("held", [(1, 0), (0, 1)], ids=["only-defender", "only-questioner"])
def test_o1_each_channel_alone_is_carried(tmp_path, held):
    """A channel alone holding rows still travels, the other empty. (O1)"""
    found = _findings(run_entry(tmp_path, grade=_holding(*held)))
    body = json.loads(found["text"])
    assert (len(body[FINDING]), len(body[QUESTIONER])) == held


@pytest.mark.parametrize("how", ["torn-line", "unreadable"])
@pytest.mark.parametrize("channel", ["defender", "questioner"])
def test_p4_damage_to_one_channels_sink_alone_refuses_both_channels(tmp_path, channel, how):
    """Both channels hold rows and only one channel's sink is damaged (a torn last line, or a directory in its place):
    the whole findings read `malformed` or `unreadable`, no text, the ending `completed`. (P4, Flow 1 step 1)"""
    import os
    from pathlib import Path

    marker = {"defender": "/w-b/", "questioner": "/w-c/"}[channel]

    def damage_one(episode_id):
        ep = next(Path(os.environ["DEFENDER_DATA_ROOT"]).glob(f"*/episodes/{episode_id}"))
        sinks = sink_files(p for p in ep.rglob("*") if p.is_file())
        [path] = [p for p in sinks if marker in p.read_text(encoding="utf-8")]
        assert len(sinks) == 2, "premise: both channels hold rows; only one is damaged"
        if how == "torn-line":
            with path.open("a", encoding="utf-8") as sink:
                sink.write('{"finding_id": "torn')
        else:
            path.unlink()
            path.mkdir()

    found = _findings(run_entry(tmp_path, grade=_holding(2, 2, after=damage_one)))
    assert found["state"] == {"torn-line": "malformed", "unreadable": "unreadable"}[how], found
    assert "text" not in found
