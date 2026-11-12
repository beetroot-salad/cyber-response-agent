"""The commit-maker's commit: which batch it belongs to and what it changed. Recorded in the learning store."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _BatchKey:
    """Which batch a commit-maker commit belongs to: the branch it was made on, the commit the
    batch started from (the export commit for a drain's batch, `main` for a revert), and the
    start's own random word, so a batch id used again is never mistaken for its earlier use."""

    branch: str
    base: str
    start: str


@dataclass(frozen=True)
class _Made:
    """One commit the commit-maker made (one record row): its batch and lanes; per path it
    changed, the blob at the batch's base and the blob it left (`None`: absent); and, for a
    revert commit, the batch change it undoes (`(batch, path)`). A revert commit changes no
    batch's net change: it is provenance only."""

    commit: str
    batch: _BatchKey
    lanes: tuple[str, ...]
    changes: tuple[tuple[str, str | None, str | None], ...]
    reverts: tuple[_BatchKey, str] | None = None
