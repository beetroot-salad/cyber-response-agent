"""#1579: a questioner reply that is not valid YAML is asked again, under one breaker per family.

Intent (recorded on #1579): every questioner call of one family authoring (call 1, each seat, the
premise check and re-check, each revision) re-asks a reply whose text does not parse as YAML,
counting it on one breaker shared by the whole family; the third unparsable reply trips it, and an
open breaker refuses every later call without asking the model. A reply refused for another reason
(an alias, a second document, a too-deep nesting) is not retried.
"""
from __future__ import annotations

import pytest
import yaml

from defender.investigation.branch import BranchError
from defender.tests.learning.branch.test_premise_check_1561 import (
    PREBRANCH,
    _conflict,
    _revision,
)
from defender.tests.learning.branch.test_questioner_corpus_samples import author, three_replies
from defender.tests.support.learning.branch import _world_1007 as W

#: The fault from #1579's episode: an unquoted value holding `: `.
UNPARSABLE = "story: in this world it has none: the two-week baseline\naxis: a1\n"


def _assert_unparsable() -> None:
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load(UNPARSABLE)


def _author(tmp_path, agent, check=None):
    return author(tmp_path, W.loop_paths(tmp_path), invoke=agent, premise_check=check,
                  prebranch=PREBRANCH if check is not None else ())


def _labels(family: dict) -> list[str]:
    return [w["label"] for w in family["worlds"]]


def test_an_unparsable_seat_reply_is_asked_again_and_the_family_is_authored(tmp_path):
    _assert_unparsable()
    family_doc, seat_b, seat_c = three_replies()
    agent = W.FakeAgent(family_doc, UNPARSABLE, seat_b, seat_c)

    family = _author(tmp_path, agent)

    assert _labels(family) == ["a", "b", "c"]
    assert family["worlds"][1]["story"] == "b"
    assert agent.agent_ids == ["questioner", "questioner:b", "questioner:b:retry1", "questioner:c"]
    first, again = agent.prompts[1], agent.prompts[2]
    assert again.startswith(first), "the re-ask is not the same ask"
    assert again != first, "the re-ask carries nothing new"
    assert "did not parse" in again[len(first):]


def test_an_unparsable_call_1_reply_is_asked_again(tmp_path):
    family_doc, seat_b, seat_c = three_replies()
    agent = W.FakeAgent(UNPARSABLE, family_doc, seat_b, seat_c)

    family = _author(tmp_path, agent)

    assert _labels(family) == ["a", "b", "c"]
    assert agent.agent_ids[:2] == ["questioner", "questioner:retry1"]


def test_two_unparsable_replies_across_the_family_are_tolerated(tmp_path):
    family_doc, seat_b, seat_c = three_replies()
    agent = W.FakeAgent(UNPARSABLE, family_doc, seat_b, UNPARSABLE, seat_c)

    family = _author(tmp_path, agent)

    assert _labels(family) == ["a", "b", "c"]
    assert agent.calls == 5


def test_the_third_unparsable_reply_of_one_call_refuses_the_family(tmp_path):
    family_doc, seat_b, seat_c = three_replies()
    agent = W.FakeAgent(UNPARSABLE, UNPARSABLE, UNPARSABLE, family_doc, seat_b, seat_c)

    with pytest.raises(BranchError) as err:
        _author(tmp_path, agent)

    assert "call 1" in str(err.value)
    assert isinstance(err.value.__cause__, yaml.YAMLError)
    assert agent.calls == 3


def test_the_breaker_counts_across_calls_not_per_call(tmp_path):
    """One unparsable reply each at call 1, seat B and seat C: the third trips the family's
    breaker, though no single call failed twice."""
    family_doc, seat_b, seat_c = three_replies()
    agent = W.FakeAgent(UNPARSABLE, family_doc, UNPARSABLE, seat_b, UNPARSABLE, seat_c)

    with pytest.raises(BranchError) as err:
        _author(tmp_path, agent)

    assert "seat C" in str(err.value)
    assert agent.agent_ids == ["questioner", "questioner:retry1", "questioner:b", "questioner:b:retry1",
                               "questioner:c"]


def test_an_unparsable_premise_check_reply_is_asked_again(tmp_path):
    agent = W.FakeAgent(*three_replies(), _revision())
    check = W.FakeAgent(UNPARSABLE, _conflict("b", "f1"), {"conflicts": []})

    family = _author(tmp_path, agent, check)

    assert check.agent_ids[:2] == ["questioner:check", "questioner:check:retry1"]
    assert agent.agent_ids[-1] == "questioner:b:revise", "the re-asked check named no world"
    assert _labels(family) == ["a", "b", "c"]


def test_an_unparsable_revision_reply_is_asked_again(tmp_path):
    agent = W.FakeAgent(*three_replies(), UNPARSABLE, _revision())
    check = W.FakeAgent(_conflict("b", "f1"), {"conflicts": []})

    family = _author(tmp_path, agent, check)

    assert agent.agent_ids[-2:] == ["questioner:b:revise", "questioner:b:revise:retry1"]
    assert _labels(family) == ["a", "b", "c"]
    assert family["worlds"][1]["facts"][0]["fact_id"] == "f1r"


def test_an_open_breaker_asks_no_later_call(tmp_path):
    """Two unparsable seat replies, then a third at seat B's revision trips the breaker: B is
    dropped, and seat C's revision is never asked, so C is dropped too (#1561's rule for a
    revision that fails)."""
    family_doc, seat_b, seat_c = three_replies()
    agent = W.FakeAgent(family_doc, UNPARSABLE, seat_b, UNPARSABLE, seat_c, UNPARSABLE,
                        _revision("c1r"))
    both = {"conflicts": [*_conflict("b", "f1")["conflicts"], *_conflict("c", "f2")["conflicts"]]}
    check = W.FakeAgent(both)

    family = _author(tmp_path, agent, check)

    assert "questioner:c:revise" not in agent.agent_ids
    assert agent.agent_ids[-1] == "questioner:b:revise"
    assert _labels(family) == ["a"]
    assert check.calls == 1


def test_the_premise_check_counts_on_the_familys_breaker(tmp_path):
    """Two unparsable seat replies, then the check's first reply does not parse: that is the
    family's third, so the check is not asked again and the worlds stand as authored."""
    family_doc, seat_b, seat_c = three_replies()
    agent = W.FakeAgent(family_doc, UNPARSABLE, seat_b, UNPARSABLE, seat_c)
    check = W.FakeAgent(UNPARSABLE, _conflict("b", "f1"))

    family = _author(tmp_path, agent, check)

    assert check.agent_ids == ["questioner:check"]
    assert _labels(family) == ["a", "b", "c"]


def test_a_second_document_is_refused_without_a_re_ask(tmp_path):
    family_doc, _seat_b, seat_c = three_replies()
    agent = W.FakeAgent(family_doc, "story: x\naxis: a1\n---\nstory: y\n", seat_c)

    with pytest.raises(BranchError) as err:
        _author(tmp_path, agent)

    assert "seat B" in str(err.value)
    assert agent.calls == 2


def test_a_re_asked_check_never_shares_an_id_with_the_re_check(tmp_path):
    """The first check re-asked twice, then the re-check: four calls, four traces."""
    agent = W.FakeAgent(*three_replies(), _revision())
    check = W.FakeAgent(UNPARSABLE, UNPARSABLE, _conflict("b", "f1"), {"conflicts": []})

    family = _author(tmp_path, agent, check)

    assert len(set(check.agent_ids)) == check.calls == 4, check.agent_ids
    assert _labels(family) == ["a", "b", "c"]
