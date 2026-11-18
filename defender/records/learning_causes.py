"""Why a learning row is set aside (#1537 PR1): the closed cause lists and the one value that carries a cause with its detail.

The one owner of both lists. The learning tables' check constraints are built from the tuples here, and the store and the
tick type their causes with the Literals, so a cause added to one is added to all. It sits in `records`, below both `jobs`
(the tables) and `learning_store`, so each can import it. The migration that created the checks keeps its own
frozen copy: an old revision must not change when a list grows.

Imports nothing, so the tick can load it without the store's database stack."""

from __future__ import annotations

import dataclasses
from typing import Generic, Literal, TypeVar, get_args

#: Why a held, dead or skipped item is set aside: picked by code; the model's and the forge's own words are only the detail
#: (`reason`) beside it.
ItemCause = Literal[
    "attempt_ceiling", "replacement_ceiling", "replacement_committed_nothing", "closed_without_feedback", "cut_from_merge",
    "curator_held", "malformed_row", "abandoned_by_person", "declined_ceiling", "deferral_ceiling", "artifact_missing",
    "superseded", "declined_at_gate", "consumed_no_systems", "unteachable_system", "curator_skipped", "unrecorded"]
#: Why a batch is parked or ended abandoned. `forge_credential_refused` is the one a person may release.
BatchCause = Literal[
    "forge_credential_refused", "forge_refused", "delivery_unavailable", "foreign_commits_remote", "foreign_commits_local",
    "foreign_pr", "holder_lost", "holder_crashed", "stopped", "no_commits", "unrecorded"]

ITEM_CAUSES: tuple[str, ...] = get_args(ItemCause)
BATCH_CAUSES: tuple[str, ...] = get_args(BatchCause)

C = TypeVar("C", ItemCause, BatchCause)


@dataclasses.dataclass(frozen=True)
class Why(Generic[C]):
    """Why a row is set aside: a cause from its table's closed list, which code picks, and the detail text beside it (a
    model's or a forge's own words, shown but never read as the cause). The store writes the two together. `Why[ItemCause]`
    goes on items, `Why[BatchCause]` on batches, so a cause cannot land on the other table's row.

    Product code builds one with `Why.item` or `Why.batch`: their parameter is the table's list itself, so a misspelt cause
    is a type error even where the value is passed to an untyped callee (the tick's store handle), which a bare
    `Why(...)` would take on trust."""

    cause: C
    detail: str

    @staticmethod
    def item(cause: ItemCause, detail: str) -> Why[ItemCause]:
        return Why(cause, detail)

    @staticmethod
    def batch(cause: BatchCause, detail: str) -> Why[BatchCause]:
        return Why(cause, detail)
