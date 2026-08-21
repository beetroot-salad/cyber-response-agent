"""What the estate served, one row per call.

Every response the defender sees in a branched run passes the estate seam, and every one of
them lands here with the DECISION that produced it. That is the batch's central safety
property, and it is the inverse of the one the issue was filed with: under staging a query
reaching a real adapter is the design, so the hazard is a response reaching the defender
WITHOUT passing the applier — silent scenario deletion, a run that looks fine and measures
nothing (#845).

`passthrough` is therefore a decision, not an absence. A served response with no row is the
failure this table exists to make visible.

NO `query_id` COLUMN, deliberately. The seam sits BELOW `QueryCapture`, which is where a
model-supplied `query_id` is resolved — the registry genuinely cannot see one. The run's own
`executed_queries.jsonl` records it against the same `(system, verb, params)`, so the
correlation is a join, and a second copy written from a frame that has to guess would only
drift from the one that knows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._io import append_jsonl, read_jsonl_rows

#: What produced a served payload. A row carrying anything else is a writer that has invented
#: a decision class, which is the same failure as a row nobody wrote.
BASE = "base"
STAGED = "staged"
PATCHED = "patched"
PASSTHROUGH = "passthrough"
SOURCES = frozenset({BASE, STAGED, PATCHED, PASSTHROUGH})


class LedgerError(Exception):
    """A served response that cannot be honestly recorded."""


def request_key(system: str, verb: str, params: Any) -> str:
    """The canonical identity of one question.

    Spelled the way `record_query._request_key` spells it, and for the same reason: a key that
    sorts its params is stable against a dict built in a different order, and two spellings of
    "the same question" would split one memo into two.
    """
    return json.dumps(
        [system, verb, params if isinstance(params, dict) else {}],
        sort_keys=True, default=str,
    )


@dataclass(frozen=True)
class ServedCall:

    system: str
    verb: str
    params: dict
    payload_text: str
    source: str
    world_id: str | None

    @property
    def key(self) -> str:
        return request_key(self.system, self.verb, self.params)

    def row(self) -> dict:
        return {
            "system": self.system, "verb": self.verb, "params": self.params,
            "payload_text": self.payload_text, "source": self.source,
            "world_id": self.world_id,
        }


@dataclass
class Ledger:
    """The append-only record of one world's served calls, and the family's shared base.

    Two tiers in one table, separated by `world_id`: `None` is the family's base payload for a
    key — recorded once, replayed by every sibling — and a world id is that world's own. The
    tiering is what makes a difference between siblings READABLE: everything off a world's
    staged set is literally the same bytes, so a comparison only ever runs over rows that are
    supposed to differ.
    """

    path: Path
    world_id: str | None = None

    def __post_init__(self) -> None:
        self._memo: dict[tuple[str | None, str], str] = {}
        for row in read_jsonl_rows(self.path):
            # `str(...)`, not a cast: a torn or hand-edited row can carry anything, and the
            # tolerant reader's job is to hand back what is there rather than to vouch for it.
            # Keying on the coerced spelling keeps a malformed row addressable instead of
            # crashing the replay that has to notice it.
            key = request_key(str(row.get("system")), str(row.get("verb")), row.get("params"))
            world = row.get("world_id")
            self._memo[(world if world is None else str(world), key)] = str(
                row.get("payload_text", ""))

    def base_payload(self, system: str, verb: str, params: Any) -> str | None:
        """The family's recorded answer for this key, if one world already asked it.

        A hit means NO adapter call: the estate is live, so two siblings querying it minutes
        apart would see different data and the pair's whole invariance would be a fiction.
        Recording once per family is what buys determinism back without snapshot-restore.
        """
        return self._memo.get((None, request_key(system, verb, params)))

    def record(self, call: ServedCall) -> ServedCall:
        if call.source not in SOURCES:
            raise LedgerError(
                f"{call.system}.{call.verb} was served with source {call.source!r}, which is "
                f"not one of {sorted(SOURCES)} — a response with no honest decision behind it "
                "is the silent-scenario-deletion hazard this table exists to catch")
        self._memo[(call.world_id, call.key)] = call.payload_text
        append_jsonl(  # lint-unguarded-tree-write: ok — episode archive under the learning state root, host-side, outside every box mount
            self.path, [call.row()])
        return call
