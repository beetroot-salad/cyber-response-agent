"""The learning store's channels (#1278): the names the judge's findings sinks and the corpus curators
share. A channel is the kind of item a queue carries (`name`) and the key its rows are identified by
(`id_key`); where its rows live is the learning store's business (`defender.learning.store`)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Channel:
    """One kind of queued item: its name and the row key its rows are identified by."""

    name: str
    id_key: str


FINDINGS = Channel(name="findings", id_key="finding_id")
QUESTIONER_FINDINGS = Channel(name="questioner_findings", id_key="finding_id")
PITFALLS = Channel(name="pitfalls", id_key="pitfall_id")


def names_systems(value: object) -> bool:
    """Whether a questioner-channel row's `systems` can key a lesson: a non-empty list of
    non-empty names (a lesson is selected for a tenant by system). The one rule for both ends of
    the channel — the judge's enqueue refuses a row that fails it, and the questioner's drain
    only ever meets such a row from before #1224."""
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(s, str) and s.strip() for s in value)
    )
