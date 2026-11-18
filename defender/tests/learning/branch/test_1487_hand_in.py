"""#1487 sketch (design r1, Flow 1): at its end, the learning job in its container hands its episode's held findings to
its helper in one `findings.publish` request, and opens no store. Driven as `test_1344_job_end.py` drives the entry
(`run_entry`: the real `job_entry.main` over a job-socket stand-in); the helper's own answer is
`tests/jobs/test_1487_store_relay.py`'s. No database."""
from __future__ import annotations

import json

from defender.tests.learning.branch.test_1344_job_lane import run_entry, sink_files
from defender.tests.support.jobs._relay1487 import FINDINGS, QUESTIONER


def _graded_with_one_finding(runs, episode_id, **kw):
    """The judge's real job-lane pass, then one defender finding held in the episode as the judge's sink holds it
    (the fixture family's judge files none)."""
    from defender.learning.core.state import FINDINGS as CHANNEL
    from defender.learning.judge import grade_episode
    from defender.learning.judge.enqueue import EpisodeFindings
    from defender.tests.support.jobs._relay1487 import defender_row

    graded = grade_episode(runs, episode_id, **kw)
    with runs.episode_files(episode_id) as episode:
        EpisodeFindings(episode).append(CHANNEL, [defender_row(str(episode_id))], dedup_key="finding_id")
    return graded


def _held_ids(ep) -> set[str]:
    """The finding ids the episode's sink files hold, read from the files (not through the sink's reader)."""
    ids: set[str] = set()
    for path in sink_files(p for p in ep.rglob("*") if p.is_file()):
        ids |= {json.loads(line)["finding_id"] for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
    return ids


def test_o1_the_completed_learning_job_hands_its_held_findings_to_the_helper_once(tmp_path):
    """A family graded with one finding held: the entry ends `completed` and has sent exactly one
    `findings.publish`, carrying every held row by channel, the ids the episode holds. (O1, Flow 1 steps 1-2)"""
    asked: list[dict] = []

    def publish(fields: dict) -> dict:
        asked.append(fields)
        return {"outcome": "published", "counts": {"finding": len(fields.get("channels", {}).get(FINDINGS, []))}}

    ran = run_entry(tmp_path, grade=_graded_with_one_finding, helper_answers={"findings.publish": publish})

    assert ran.end is not None
    assert ran.end["status"] == "completed", ran.end
    held = _held_ids(ran.ep)
    assert held, "premise: the judge left a finding in the episode"
    assert len(asked) == 1, f"the entry sent {len(asked)} hand-ins"
    channels = asked[0].get("channels", {})
    assert set(channels) <= {FINDINGS, QUESTIONER}, set(channels)
    assert {r["finding_id"] for rows in channels.values() for r in rows} == held


def test_flow1_a_job_that_ends_other_than_completed_sends_no_hand_in(tmp_path):
    """A job with no fork point ends `skipped` and hands nothing in. (Flow 1 step 5)"""
    from defender.tests.learning.branch.test_1344_job_lane import choose

    asked: list[dict] = []
    ran = run_entry(tmp_path, candidates=choose(), helper_answers={"findings.publish": lambda f: asked.append(f) or {}})

    assert ran.end is not None
    assert ran.end["status"] == "skipped", ran.end
    assert asked == []
