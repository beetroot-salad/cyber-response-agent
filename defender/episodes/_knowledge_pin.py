"""The family's knowledge pin (#1108 P4, flow 7, O-PIN): which knowledge commit an episode's
siblings read, and the judge reads lesson bodies at.

The branch launcher decides it once, from the source run's host-held knowledge record (U12),
never from the source's provenance stamp, which sits in the box's rw bind; and creates it once
in the episode folder, where no box writes. Every reader takes the family's commit from here: a
sibling's run start (so a sibling started by hand cannot drift onto a newer `current`) and the
judge. The provenance stamps are compared against it, never read for it.
"""
from __future__ import annotations

import json

from defender._io import Bound, load_json_artifact
from defender.episodes._episode_paths import LAYOUT
from defender.tenancy._exports import OID

#: The pin's one key: the knowledge stamp's own wire spelling (`{"commit": <sha>}`).
_KEY = "commit"


class PinUnreadable(Exception):  # noqa: N818 — named for the refusal, as `KnowledgeRefused` is
    """The episode's knowledge pin is there but is not one a launcher could have written."""


def pin_text(commit: str) -> str:
    """The pin file's text for `commit`."""
    if not OID.fullmatch(commit):
        raise ValueError(f"{commit!r} is not a full knowledge commit id")
    return json.dumps({_KEY: commit}) + "\n"


def read_pin(episode: Bound) -> str | None:
    """The family's knowledge commit, read through the episode's own view; `None` when the
    episode has no pin (one launched before the pin was recorded). A pin that is not a launcher's
    is `PinUnreadable`, never a commit."""
    answer = episode.read(LAYOUT.knowledge_pin)
    if answer.text is None:
        if answer.absent:
            return None
        raise PinUnreadable(f"{LAYOUT.knowledge_pin} cannot be read: {answer.reason}")
    obj, bad = load_json_artifact(answer.text)
    commit = obj.get(_KEY) if bad is None and isinstance(obj, dict) and set(obj) == {_KEY} else None
    if not isinstance(commit, str) or not OID.fullmatch(commit):
        raise PinUnreadable(f"{LAYOUT.knowledge_pin} names no full knowledge commit")
    return commit
