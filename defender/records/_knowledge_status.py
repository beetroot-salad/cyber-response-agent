"""How a run came by its tenant knowledge, as every reader of the run's result sees it (#1108
P4, O-WARN, U12, OD22').

Run start writes a host-held record beside the run dir (`RunPaths.knowledge_source`): kind
(fresh, stale or pinned), the commit of the export the run copied, the stale kind and the
publish's own reason. The run page, the ticket write-back and the API read THAT record, never
the provenance stamp's `knowledge_source`, which sits in the box's rw bind (OD17). The stamp is
consulted for one bit only: whether a record should exist at all.

The rule (OD22'), one owner for every reader:
- a readable record is the answer;
- no record and no `knowledge_source` in the stamp: a run from before P4 — `None`, nothing shown;
- a record that does not parse or hold a known shape, or no record while the stamp names a
  source: unreadable — stale, operator kind, no commit. No reader claims fresh.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from defender._io import load_json_artifact, read_guarded

FRESH = "fresh"
STALE = "stale"
PINNED = "pinned"
TRANSIENT = "transient"
OPERATOR = "operator"
KINDS = frozenset({FRESH, STALE, PINNED})
STALE_KINDS = frozenset({TRANSIENT, OPERATOR})

#: The reason an unreadable record is shown with (OD22'): the host knows nothing more.
UNREADABLE_REASON = "knowledge record unreadable"

_COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


@dataclass(frozen=True)
class KnowledgeStatus:
    """The run's knowledge source as its readers act on it. `commit` is `None` only for an
    unreadable record; `stale_kind` is set iff `kind` is stale; `reason` is the host's raw text
    (operator surfaces only — never a customer's ticket)."""

    kind: str
    commit: str | None
    stale_kind: str | None = None
    reason: str | None = None

    @property
    def stale(self) -> bool:
        return self.kind == STALE


UNREADABLE = KnowledgeStatus(kind=STALE, commit=None, stale_kind=OPERATOR,
                             reason=UNREADABLE_REASON)


def _parsed(record_text: str) -> KnowledgeStatus | None:
    """The record's status, or `None` when it is not a record run start could have written."""
    obj, unreadable = load_json_artifact(record_text)
    if unreadable is not None or not isinstance(obj, dict):
        return None
    kind, commit = obj.get("kind"), obj.get("commit")
    stale_kind, reason = obj.get("stale_kind"), obj.get("reason")
    if kind not in KINDS or not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        return None
    if (kind == STALE) != (stale_kind is not None):
        return None
    if stale_kind is not None and stale_kind not in STALE_KINDS:
        return None
    if reason is not None and not isinstance(reason, str):
        return None
    return KnowledgeStatus(kind=kind, commit=commit, stale_kind=stale_kind, reason=reason)


def knowledge_status(record_text: str | None, *, stamp_names_source: bool) -> KnowledgeStatus | None:
    """OD22' over the record's text (`None`: no record) and whether the run's stamp names a
    knowledge source. `None` means no status to show (no run, or a run from before P4)."""
    if record_text is None:
        return UNREADABLE if stamp_names_source else None
    return _parsed(record_text) or UNREADABLE


def _stamp_names_source(stamp: Path) -> bool:
    """Does the provenance stamp at `stamp` carry a `knowledge_source`? Only the key's presence
    is read: its value is the box's to rewrite, so it decides nothing else."""
    text, _refused = read_guarded(stamp)
    if text is None:
        return False
    obj, unreadable = load_json_artifact(text)
    return unreadable is None and isinstance(obj, dict) and obj.get("knowledge_source") is not None


def read_knowledge_status(record: Path, stamp: Path) -> KnowledgeStatus | None:
    """`knowledge_status` over the files: the host record at `record` (an entry that is not a
    readable plain file counts as unreadable) and the stamp at `stamp`."""
    if not record.is_symlink() and not record.exists():
        return knowledge_status(None, stamp_names_source=_stamp_names_source(stamp))
    text, _refused = read_guarded(record)
    if text is None:
        return UNREADABLE
    return knowledge_status(text, stamp_names_source=True)


__all__ = [
    "FRESH", "OPERATOR", "PINNED", "STALE", "TRANSIENT", "UNREADABLE", "UNREADABLE_REASON",
    "KnowledgeStatus", "knowledge_status", "read_knowledge_status",
]
