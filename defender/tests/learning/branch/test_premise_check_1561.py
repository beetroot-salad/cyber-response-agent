"""#1561: the question-writer's worlds are held to what the source run saw before the branch point.

A world whose fact denies a pre-branch answer (which the investigator's inherited transcript
already shows) is sent back to its seat once to be rebuilt, checked again, and dropped if it
still conflicts. The check runs through its own seam (`premise_check=`), as the questioner does.
"""
from __future__ import annotations

from pathlib import Path

from defender.tests.learning.branch.test_questioner_corpus_samples import author, three_replies
from defender.tests.support.learning.branch import _world_1007 as W

PREBRANCH = [{"call": {"system": "elastic", "verb": "alerts", "params": {"limit": 10}},
              "answer": {"total": 6, "hits": [{"rule": "authorized_keys modification",
                                               "container": "dfd163bc7918"}]}}]


def _conflict(label: str, fact_id: str) -> dict:
    return {"conflicts": [{"label": label, "fact_id": fact_id,
                           "evidence": "the pre-branch alerts answer holds 6 such alerts"}]}


def _revision(fact_id: str = "f1r") -> dict:
    return {"story": "b rebuilt", "axis": "a1", "disposition_declared": "malicious",
            "label_basis": "judgment", "facts": [W.fact(fact_id)]}


def _run(tmp_path: Path, *, questioner_replies: list, check_replies: list):
    paths = W.loop_paths(tmp_path)
    agent = W.FakeAgent(*questioner_replies)
    check = W.FakeAgent(*check_replies)
    recorded: list[list[dict]] = []
    family = author(tmp_path, paths, invoke=agent, premise_check=check, prebranch=PREBRANCH,
                    record_revisions=recorded.append)
    return family, agent, check, recorded


def _labels(family: dict) -> list[str]:
    return [w["label"] for w in family["worlds"]]


def test_no_conflict_leaves_the_family_and_calls_no_revision(tmp_path):
    family, agent, check, recorded = _run(
        tmp_path, questioner_replies=three_replies(), check_replies=[{"conflicts": []}])

    assert _labels(family) == ["a", "b", "c"]
    assert agent.calls == 3
    assert check.calls == 1
    assert check.agent_ids == ["questioner:check"]
    assert recorded == [[]]


def test_the_check_is_shown_the_worlds_facts_and_the_prebranch_answers(tmp_path):
    _family, _agent, check, _recorded = _run(
        tmp_path, questioner_replies=three_replies(), check_replies=[{"conflicts": []}])

    prompt = check.prompts[0]
    assert "dfd163bc7918" in prompt
    assert "authorized_keys modification" in prompt
    assert '"label": "b"' in prompt
    assert '"fact_id": "f1"' in prompt


def test_a_conflicting_world_is_rebuilt_by_its_seat_and_kept_once_it_holds(tmp_path):
    family, agent, check, recorded = _run(
        tmp_path, questioner_replies=[*three_replies(), _revision()],
        check_replies=[_conflict("b", "f1"), {"conflicts": []}])

    b = next(w for w in family["worlds"] if w["label"] == "b")
    assert [f["fact_id"] for f in b["facts"]] == ["f1r"]
    assert b["story"] == "b rebuilt"
    assert b["role"] == "B"
    assert agent.agent_ids[-1] == "questioner:b:revise"
    revise = agent.prompts[-1]
    assert "This is a revision" in revise
    assert "6 such alerts" in revise
    assert check.agent_ids == ["questioner:check", "questioner:check:2"]
    [entry] = recorded[0]
    assert entry["label"] == "b"
    assert entry["revised"]
    assert not entry["dropped"]
    assert [f["fact_id"] for f in entry["original_facts"]] == ["f1"]


def test_a_world_that_still_conflicts_after_its_revision_is_dropped(tmp_path):
    family, _agent, _check, recorded = _run(
        tmp_path, questioner_replies=[*three_replies(), _revision()],
        check_replies=[_conflict("b", "f1"), _conflict("b", "f1r")])

    assert _labels(family) == ["a", "c"]
    [entry] = recorded[0]
    assert entry["revised"]
    assert entry["dropped"]
    assert entry["conflicts_after"]


def test_a_revision_with_no_usable_facts_drops_the_world(tmp_path):
    family, _agent, check, recorded = _run(
        tmp_path, questioner_replies=[*three_replies(), {"story": "only a story"}],
        check_replies=[_conflict("c", "f2")])

    assert _labels(family) == ["a", "b"]
    assert check.calls == 1
    assert recorded[0][0]["dropped"]
    assert not recorded[0][0]["revised"]


def test_an_unreadable_check_reply_changes_nothing(tmp_path):
    family, agent, _check, recorded = _run(
        tmp_path, questioner_replies=three_replies(), check_replies=["not yaml: [unclosed"])

    assert _labels(family) == ["a", "b", "c"]
    assert agent.calls == 3
    assert recorded == [[]]


def test_without_a_check_seam_the_family_is_authored_as_before(tmp_path):
    paths = W.loop_paths(tmp_path)
    agent = W.FakeAgent(*three_replies())

    family = author(tmp_path, paths, invoke=agent)

    assert _labels(family) == ["a", "b", "c"]
    assert agent.calls == 3
