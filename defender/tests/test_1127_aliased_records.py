"""#1127, second review: a record holding a YAML alias is refused, never read as absent or as its word.

Before #1127 the host's own writer (`yaml.safe_dump`) wrote `&id001`/`*id001` whenever a
document shared an object, so an episode archived before it can hold an aliased record. The
tree now refuses any alias at load (`_yaml.AliasRefused`). The gate that refuses an episode
whose outcome is not `accepted` must take that refusal as the "no record" state — never read
the word the aliased document carries, which would let an unreadable record pass the gate as
`accepted`, failing open.

(#1224 moved the outcome from the merged `review.yaml` to pre-flight's write-once
`outcome.yaml`, `learning/branch/outcome.py`; the review merge and its replace-a-torn-record
rule went with it.) The control: a torn record keeps its meaning, the same "no record" state.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender._episode_handle import Episode
from defender._episode_paths import LAYOUT
from defender.learning.branch import episode as episode_mod
from defender.learning.branch import outcome as outcome_mod

#: What the pre-#1127 writer produced for a record that shared one block: an `accepted`
#: outcome, and an alias elsewhere in the document.
ALIASED_OUTCOME = (
    "outcome: accepted\nreason: every world calibrated\n"
    "unservable_worlds: []\nnot_replayable: &id001\n- {system: elastic, verb: query}\n"
    "drift: *id001\n"
)
#: A record torn mid-write: not a document at all.
TORN_OUTCOME = "outcome: [accepted\n"


def _episode(tmp_path: Path, outcome: str) -> Episode:
    ep = Episode.create(tmp_path / "ep")
    (ep.dir / LAYOUT.outcome).write_text(outcome, encoding="utf-8")
    return ep


def test_an_aliased_outcome_is_refused_by_the_gate_not_read_as_accepted(tmp_path):
    ep = _episode(tmp_path, ALIASED_OUTCOME)

    with pytest.raises(outcome_mod.OutcomeUnreadable, match="alias"):
        outcome_mod.read_outcome(ep.view())
    with pytest.raises(episode_mod.EpisodeError, match="no outcome record"):
        episode_mod._refuse_incomplete(ep.view())


def test_a_torn_outcome_still_reads_as_no_record(tmp_path):
    """The control: the gate's rule for a torn record is the same "no record" refusal."""
    ep = _episode(tmp_path, TORN_OUTCOME)

    with pytest.raises(episode_mod.EpisodeError, match="no outcome record"):
        episode_mod._recorded_outcome(ep.view())


def test_a_parsed_value_holding_one_immutable_value_twice_is_a_tree():
    """#1127 second review: only a mutable container can be shared or cyclic in a way that
    matters. Python hands back the one empty tuple (and may reuse other immutables) wherever
    one appears, so an identity check on them refused a harmless reply."""
    from defender._yaml import AliasRefused, refuse_shared

    refuse_shared({"a": (), "b": (), "c": frozenset(), "d": frozenset()})
    shared: list = []
    with pytest.raises(AliasRefused):
        refuse_shared({"a": shared, "b": shared})
