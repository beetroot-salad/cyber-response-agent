"""#1127, second review: a record holding a YAML alias is refused, never read as absent.

Before #1127 the host's own writer (`yaml.safe_dump`) wrote `&id001`/`*id001` whenever a
document shared an object, so an episode archived before it can hold an aliased `review.yaml`.
The tree now refuses any alias at load (`_yaml.AliasRefused`). Two readers of the review record
mapped every `YAMLError` to "nothing recorded", a rule written for a torn or garbage file:

* `staging.merge_review` started empty and REPLACED the record, dropping every other block;
* `episode._recorded_outcome` returned "no outcome", so an episode recorded `incomplete` passed
  the gate that refuses it — failing open.

A refused alias is a refusal, not an absence: both take the branch they already take for a
refused record (a link, undecodable bytes). The controls: a torn record keeps its old meaning.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender._episode_handle import Episode
from defender._episode_paths import LAYOUT
from defender.learning.branch import episode as episode_mod
from defender.learning.branch.staging import StagingRefused, merge_review

#: What the pre-#1127 writer produced for a review whose two worlds shared one block: an
#: `incomplete` outcome, and an alias elsewhere in the document.
ALIASED_REVIEW = (
    "episode:\n  outcome: incomplete\n  reason: a sibling was refused\n"
    "worlds:\n  b: &id001\n    decision: accepted\n  c: *id001\n"
)
#: A record torn mid-write: not a document at all.
TORN_REVIEW = "episode:\n  outcome: [incomplete\n"


def _episode(tmp_path: Path, review: str) -> Episode:
    ep = Episode.create(tmp_path / "ep")
    (ep.dir / LAYOUT.review).write_text(review, encoding="utf-8")
    return ep


def test_merging_into_an_aliased_review_refuses_and_leaves_it_whole(tmp_path):
    ep = _episode(tmp_path, ALIASED_REVIEW)

    with pytest.raises(StagingRefused, match="alias"):
        merge_review(ep, "teardown", {"ok": True})

    assert (ep.dir / LAYOUT.review).read_text(encoding="utf-8") == ALIASED_REVIEW


def test_merging_into_a_torn_review_still_replaces_it(tmp_path):
    """The control: a record that is not a document at all is replaced, as it always was."""
    ep = _episode(tmp_path, TORN_REVIEW)

    merge_review(ep, "teardown", {"ok": True})

    assert "teardown" in (ep.dir / LAYOUT.review).read_text(encoding="utf-8")


def test_an_aliased_review_is_refused_by_the_incomplete_gate_not_read_as_no_outcome(tmp_path):
    ep = _episode(tmp_path, ALIASED_REVIEW)

    with pytest.raises(episode_mod.EpisodeError, match="alias"):
        episode_mod._refuse_incomplete(ep.view())


def test_a_torn_review_still_reads_as_no_outcome(tmp_path):
    """The control: the gate's existing rule for a torn record is unchanged."""
    ep = _episode(tmp_path, TORN_REVIEW)

    assert episode_mod._recorded_outcome(ep.view()) == (None, "")


def test_a_parsed_value_holding_one_immutable_value_twice_is_a_tree():
    """#1127 second review: only a mutable container can be shared or cyclic in a way that
    matters. Python hands back the one empty tuple (and may reuse other immutables) wherever
    one appears, so an identity check on them refused a harmless reply."""
    from defender._yaml import AliasRefused, refuse_shared

    refuse_shared({"a": (), "b": (), "c": frozenset(), "d": frozenset()})
    shared: list = []
    with pytest.raises(AliasRefused):
        refuse_shared({"a": shared, "b": shared})
