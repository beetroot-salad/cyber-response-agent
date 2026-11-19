"""#1561: the question-writer's worlds are held to what the source run saw before the branch point.

A world whose fact denies a pre-branch answer (which the investigator's inherited transcript
already shows) is sent back to its seat once to be rebuilt, checked again, and dropped if it
still conflicts. The check runs through its own seam (`premise_check=`), as the questioner does.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.learning.branch.test_questioner_corpus_samples import author, three_replies
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.branch import _world_1007 as W
from defender.tests.support.learning.core import _typed_output1579 as TY

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
    assert "a revision: rebuild one sibling world" in revise
    assert "Anything else you return is discarded" not in revise, "the revision is told to drop its facts"
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


#: A revision the in-call check refuses (`facts` present and non-empty, then the world rule): under a
#: fake the call site's re-check refuses it, which is the call's `ReplyUnusable`, and the revision
#: drops its world (#1561). Built lazily: `TY.unusable` resolves a symbol #1579 adds.
_BAD_REVISIONS = {
    "facts absent": lambda: {"story": "only a story"},
    "facts empty": lambda: {**_revision(), "facts": []},
    "fact without entities": lambda: {"story": "b rebuilt", "facts": [
        {"fact_id": "f1r", "statement": "s"}]},
    "extra key": lambda: {**_revision(), "role": "B"},
    "world_id": lambda: {**_revision(), "world_id": T.fixture_world_id("b")},
    "retries exhausted": lambda: TY.unusable("facts must not be empty"),
}


@pytest.mark.parametrize("bad", list(_BAD_REVISIONS))
def test_a_revision_the_call_cannot_use_drops_its_world(tmp_path, bad):
    """P1/P3 at a revision (review r2's `facts: []` counterexample among them): facts are
    non-empty and well-formed in-call; the exhausted revision drops its world, never the family."""
    family, _agent, check, recorded = _run(
        tmp_path, questioner_replies=[*three_replies(), _BAD_REVISIONS[bad]()],
        check_replies=[_conflict("c", "f2")])

    assert _labels(family) == ["a", "b"]
    assert check.calls == 1, "a re-check ran over a world that was never rebuilt"
    assert recorded[0][0]["dropped"]
    assert not recorded[0][0]["revised"]


_UNUSABLE_CHECK_REPLIES = {
    "retries exhausted": lambda: TY.unusable("conflicts must be a list"),
    "conflicts not a list": lambda: {"conflicts": "none"},
    "unknown key beside a real conflict": lambda: {**_conflict("b", "f1"), "bogus": 1},
    "world_id": lambda: {**_conflict("b", "f1"), "world_id": T.fixture_world_id("b")},
    "provider failure": lambda: TY.unprocessable("provider down", cause=TimeoutError("slow")),
    "host bug": lambda: TypeError("a bug in the host's check"),
}


@pytest.mark.parametrize("bad", list(_UNUSABLE_CHECK_REPLIES))
def test_a_check_that_cannot_be_used_names_no_world(tmp_path, bad):
    """P3/P5: a check the call exhausted or the in-call rules refuse, a provider failure and a
    host bug alike leave the family as authored (#1561); the conflict beside the refused part
    is not acted on (no revision call, no second check)."""
    family, agent, check, recorded = _run(
        tmp_path, questioner_replies=three_replies(), check_replies=[_UNUSABLE_CHECK_REPLIES[bad]()])

    assert _labels(family) == ["a", "b", "c"]
    assert agent.calls == 3, "a world was revised on a check the host could not use"
    assert check.calls == 1
    assert recorded == [[]]


def test_a_check_reply_naming_a_real_and_an_unknown_world_drops_the_unknown_and_revises_the_real(tmp_path):
    """P4: `z` is dropped, `b` is revised — the check reply is not refused whole."""
    both = {"conflicts": [*_conflict("z", "f9")["conflicts"], *_conflict("b", "f1")["conflicts"]]}
    family, agent, check, recorded = _run(
        tmp_path, questioner_replies=[*three_replies(), _revision()],
        check_replies=[both, {"conflicts": []}])

    assert [f["fact_id"] for f in next(w for w in family["worlds"] if w["label"] == "b")["facts"]] == ["f1r"]
    assert _labels(family) == ["a", "b", "c"]
    assert agent.agent_ids[-1] == "questioner:b:revise"
    assert agent.calls == 4, "the unknown world got a revision, or the real one did not"
    assert check.calls == 2
    assert [e["label"] for e in recorded[0]] == ["b"]


def test_a_check_naming_only_unknown_worlds_changes_nothing(tmp_path):
    family, agent, check, recorded = _run(
        tmp_path, questioner_replies=three_replies(), check_replies=[_conflict("z", "f9")])

    assert _labels(family) == ["a", "b", "c"]
    assert (agent.calls, check.calls, recorded) == (3, 1, [[]])


def test_without_a_check_seam_the_family_is_authored_as_before(tmp_path):
    paths = W.loop_paths(tmp_path)
    agent = W.FakeAgent(*three_replies())

    family = author(tmp_path, paths, invoke=agent)

    assert _labels(family) == ["a", "b", "c"]
    assert agent.calls == 3


def test_the_evidence_holds_the_prebranch_recorded_answers_and_no_later_call(tmp_path):
    """The launcher's evidence: each pre-branch call with the primed recording's answer for it;
    a call recorded after the branch point is left out."""
    import json

    from defender.learning.branch.ledger import request_key
    from defender.learning.branch.questioner_launch import prebranch_answers

    def row(system, verb, params, answer):
        return {"system": system, "verb": verb, "params": params,
                "payload_text": json.dumps(answer)}

    base = tmp_path / "base.jsonl"
    early = row("elastic", "alerts", {"limit": 10}, {"total": 6})
    late = row("elastic", "alerts", {"limit": 99}, {"total": 7})
    base.write_text("\n".join(json.dumps(r) for r in (early, late)) + "\n", encoding="utf-8")

    from defender._io import read_jsonl_rows

    evidence = prebranch_answers({request_key("elastic", "alerts", {"limit": 10})},
                                 read_jsonl_rows(base))

    assert evidence == [{"call": {"system": "elastic", "verb": "alerts", "params": {"limit": 10}},
                         "answer": {"total": 6}}]
    assert prebranch_answers(set(), read_jsonl_rows(base)) == []


def test_the_revisions_record_is_written_only_when_the_check_named_a_world(tmp_path):
    from defender import _yaml
    from defender.learning.branch.questioner_launch import write_world_revisions
    from defender.records._episode_handle import Episode

    entry = {"label": "b", "conflicts": [{"fact_id": "f1"}], "revised": True, "dropped": False,
             "original_facts": []}
    quiet, named = tmp_path / "quiet", tmp_path / "named"
    for ep, entries in ((quiet, []), (named, [entry])):
        ep.mkdir()
        with Episode.open(ep) as episode:
            write_world_revisions(episode, entries)

    assert not (quiet / "world_revisions.yaml").exists()
    written = _yaml.safe_load((named / "world_revisions.yaml").read_text(encoding="utf-8"))
    assert written == {"worlds": [entry]}


def test_a_revision_whose_facts_the_family_would_refuse_drops_only_its_world(tmp_path):
    """A revised fact without its entities would fail the family's parse later: the world is
    dropped here, and the worlds that never conflicted are kept."""
    bad = {"story": "b rebuilt", "facts": [{"fact_id": "f1r", "statement": "s"}]}
    family, _agent, check, recorded = _run(
        tmp_path, questioner_replies=[*three_replies(), bad],
        check_replies=[_conflict("b", "f1")])

    assert _labels(family) == ["a", "c"]
    assert check.calls == 1
    assert recorded[0][0]["dropped"]


def test_a_check_that_faults_leaves_the_family_as_authored(tmp_path):
    def faulting(*_a, **_k):
        raise TimeoutError("the premise check timed out")

    paths = W.loop_paths(tmp_path)
    agent = W.FakeAgent(*three_replies())
    recorded: list[list[dict]] = []
    family = author(tmp_path, paths, invoke=agent, premise_check=faulting, prebranch=PREBRANCH,
                    record_revisions=recorded.append)

    assert _labels(family) == ["a", "b", "c"]
    assert recorded == [[]]


_REVISION_FAULTS = {
    "timeout": lambda: TimeoutError("the revision timed out"),
    "provider failure": lambda: TY.unprocessable("provider down", cause=TimeoutError("slow")),
    "host bug": lambda: TypeError("a bug in the host's check"),
    "retries exhausted": lambda: TY.unusable("facts must not be empty"),
}


@pytest.mark.parametrize("fault", list(_REVISION_FAULTS))
def test_a_revision_that_faults_drops_only_its_world(tmp_path, fault):
    """#1561 stands for a host exception (`RunUnprocessable`, a `TypeError`) at a revision; P3: an
    exhausted revision (`ReplyUnusable`) drops its world too, caught before the generic handler."""
    replies = iter(three_replies())

    def questioner(prompt, **kwargs):
        if kwargs.get("agent_id", "").endswith(":revise"):
            raise _REVISION_FAULTS[fault]()
        return W.FakeAgent(next(replies))(prompt, **kwargs)

    paths = W.loop_paths(tmp_path)
    check = W.FakeAgent(_conflict("b", "f1"))
    recorded: list[list[dict]] = []
    family = author(tmp_path, paths, invoke=questioner, premise_check=check, prebranch=PREBRANCH,
                    record_revisions=recorded.append)

    assert _labels(family) == ["a", "c"]
    assert recorded[0][0]["dropped"]


def test_a_world_fact_may_not_take_the_oracles_reserved_fork_name():
    import pytest

    from defender.records.formats import FamilyError, parse_facts

    with pytest.raises(FamilyError, match="reserved"):
        parse_facts([{"fact_id": "fork", "statement": "s", "entities": ["web-1"]}], "w")


@pytest.mark.parametrize("bad", list(_UNUSABLE_CHECK_REPLIES))
def test_a_re_check_that_cannot_be_used_drops_the_rebuilt_world_and_records_it(tmp_path, bad):
    """A rebuild the second check never confirmed is not kept, and is not replaced by the world
    the first check found false. P3: an exhausted re-check is a failed one, whatever its cause."""
    family, _agent, _check, recorded = _run(
        tmp_path, questioner_replies=[*three_replies(), _revision()],
        check_replies=[_conflict("b", "f1"), _UNUSABLE_CHECK_REPLIES[bad]()])

    assert _labels(family) == ["a", "c"]
    [entry] = recorded[0]
    assert entry["revised"]
    assert entry["dropped"]


def test_no_prebranch_evidence_skips_the_check(tmp_path):
    paths = W.loop_paths(tmp_path)
    agent = W.FakeAgent(*three_replies())
    check = W.FakeAgent()
    family = author(tmp_path, paths, invoke=agent, premise_check=check, prebranch=[])

    assert _labels(family) == ["a", "b", "c"]
    assert check.calls == 0


def test_the_revision_and_check_prompts_ask_for_the_tool_not_a_yaml_document(tmp_path):
    """O4: neither prompt still tells the model to write one bare YAML document."""
    _family, agent, check, _recorded = _run(
        tmp_path, questioner_replies=[*three_replies(), _revision()],
        check_replies=[_conflict("b", "f1"), {"conflicts": []}])

    assert agent.agent_ids[-1] == "questioner:b:revise"
    for prompt in (agent.prompts[-1], check.prompts[0]):
        assert "one YAML document" not in prompt
        assert "call the tool" in prompt.lower()
