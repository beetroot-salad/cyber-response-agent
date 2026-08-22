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

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._io import append_jsonl, read_jsonl_rows
from defender.scripts.gather_tools.record_query import _json_safe_params, _request_key

#: What produced a served payload. A row carrying anything else is a writer that has invented
#: a decision class, which is the same failure as a row nobody wrote.
BASE = "base"
STAGED = "staged"
PATCHED = "patched"
PASSTHROUGH = "passthrough"
#: The call reached the seam and was REFUSED — a world whose corpus this query cannot be
#: pointed at. Its own class because the alternative is silence: a refusal that writes no row
#: is "a served response with no row", which is the exact state this table exists to make
#: visible, and a reader counting evidence would see the sibling simply never asking.
REFUSED = "refused"
SOURCES = frozenset({BASE, STAGED, PATCHED, PASSTHROUGH, REFUSED})


class LedgerError(Exception):
    """A served response that cannot be honestly recorded."""


def request_key(system: str, verb: str, params: Any) -> str:
    """The canonical identity of one question.

    `record_query._request_key`'s FUNCTION, not its spelling. A key that sorts its params is
    stable against a dict built in a different order, and two spellings of "the same question"
    would split one memo into two — and a hand-identical copy in a module that does not import
    the original is how the two learn different rules. It is also what makes the correlation
    this table's docstring promises an actual join: `executed_queries.jsonl` keys the same
    `(system, verb, params)` through this call.

    `_json_safe_params` rides with it for the same reason it does there. Without it a
    non-finite float keys as the bare token `Infinity` — which `json.dumps` will happily write
    into the row too, producing a line no JSON reader but Python's own will parse — while
    `record_query` keys the same call as `"inf"`, so the join silently misses.
    """
    return _request_key(
        system, verb, _json_safe_params(params) if isinstance(params, dict) else {})


@dataclass(frozen=True)
class ServedCall:
    """One served call, under BOTH the question asked and the question run.

    They differ exactly when a world stages: `prepare` rewrites the call to point at that
    world's corpus, which is what staging IS. So the two identities answer two different
    questions and neither can do the other's job.

    `key` — the form that RAN. What the family tier memoizes on, and it must stay the prepared
    form: keyed on the asked form instead, a sibling would replay another world's answer, read
    off that world's staged corpus. That is contamination, strictly worse than re-reading.

    `correlation_key` — the form ASKED. What a cross-world comparison pairs on. Without it
    `ΔO` is computed over `keys(A) ∩ keys(B)`, and on a staged system that intersection is
    EMPTY — A recorded `FROM …-w-A` and B recorded `FROM …-w-B`, so no row of A's ever meets a
    row of B's and the difference between them reads as no difference at all. Silent, and
    silent on the event stream, which is where most of a run's evidence lives.
    """

    system: str
    verb: str
    params: dict
    payload_text: str
    source: str
    world_id: str | None
    #: What the model asked, when staging rewrote it. `None` means nothing was rewritten, so
    #: the two identities coincide — the ordinary case for the six unstaged systems.
    asked_params: dict | None = None

    @property
    def key(self) -> str:
        """The memo identity: the call as it RAN."""
        return request_key(self.system, self.verb, self.params)

    @property
    def correlation_key(self) -> str:
        """The comparison identity: the call as it was ASKED."""
        return request_key(
            self.system, self.verb,
            self.params if self.asked_params is None else self.asked_params)

    def row(self) -> dict:
        # `_json_safe_params`, because `append_jsonl` dumps with the stdlib defaults: a param
        # the key already coerced would otherwise reach the file as `Infinity`/`NaN` — tokens
        # no JSON reader outside Python parses — or raise `TypeError` mid-serve on a value
        # `default=str` would have carried.
        row = {
            "system": self.system, "verb": self.verb,
            "params": _json_safe_params(self.params),
            "payload_text": self.payload_text, "source": self.source,
            "world_id": self.world_id,
        }
        if self.asked_params is not None:
            # Written only when it says something. An absent column reads as "nothing was
            # rewritten", which is true of every unstaged call and is the honest default; a
            # column echoing `params` on every row would make the two identities look like one.
            row["asked_params"] = _json_safe_params(self.asked_params)
        return row


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

    def __post_init__(self) -> None:
        self._memo: dict[tuple[str | None, str], str] = {}
        for row in read_jsonl_rows(self.path):
            # `str(...)`, not a cast: a torn or hand-edited row can carry anything, and the
            # tolerant reader's job is to hand back what is there rather than to vouch for it.
            # Keying on the coerced spelling keeps a malformed row addressable instead of
            # crashing the replay that has to notice it.
            text = row.get("payload_text")
            if not isinstance(text, str) or not text:
                # A row with no payload is not an ANSWER, and memoizing it as `""` would make
                # `base_payload` report a hit that `json.loads` then dies on — moving the crash
                # one frame down instead of tolerating the row. Skipped, so the key falls
                # through to the live adapter, which is the honest reading of "nothing recorded".
                continue
            key = request_key(str(row.get("system")), str(row.get("verb")), row.get("params"))
            world = row.get("world_id")
            self._memo[(world if world is None else str(world), key)] = text

    def base_payload(self, system: str, verb: str, params: Any) -> str | None:
        """The family's recorded answer for this key, if one world already asked it.

        A hit means NO adapter call: the estate is live, so two siblings querying it minutes
        apart would see different data and the pair's whole invariance would be a fiction.
        Recording once per family is what buys determinism back without snapshot-restore.

        A MISS RE-READS THE FILE before conceding. The memo is built at construction, so a
        sibling running beside another in a separate process holds a snapshot from before that
        one started writing: both miss, both call the live adapter, and the pair's two bases
        are two different reads — the failure the family tier exists to prevent, arriving by
        the one route it does not watch. This NARROWS that window; it does not close it. Two
        processes can still miss between the re-read and the append, and closing it properly
        needs a lock this seam does not yet have.
        """
        key = request_key(system, verb, params)
        hit = self._memo.get((None, key))
        if hit is not None:
            return hit
        self._refresh()
        return self._memo.get((None, key))

    def _refresh(self) -> None:
        """Re-absorb the file, keeping whatever this process already holds."""
        for row in read_jsonl_rows(self.path):
            text = row.get("payload_text")
            if not isinstance(text, str) or not text:
                continue
            row_key = request_key(str(row.get("system")), str(row.get("verb")), row.get("params"))
            world = row.get("world_id")
            self._memo.setdefault((world if world is None else str(world), row_key), text)

    def record(self, call: ServedCall) -> ServedCall:
        if call.source not in SOURCES:
            raise LedgerError(
                f"{call.system}.{call.verb} was served with source {call.source!r}, which is "
                f"not one of {sorted(SOURCES)} — a response with no honest decision behind it "
                "is the silent-scenario-deletion hazard this table exists to catch")
        # PERSIST FIRST, memoize only on success. Memoizing first meant a failed append left
        # the family's base payload live in memory with no row behind it: every later call for
        # that key took the hit, issued no adapter call, and served a payload the table cannot
        # account for — "a served response with no row", the one state this table exists to
        # make visible. A later sibling rebuilding the memo from the file would find nothing,
        # re-ask the live estate and get different bytes, so the pair's invariance would be
        # gone with nothing in the record to show it.
        append_jsonl(  # lint-unguarded-tree-write: ok — episode archive under the learning state root, host-side, outside every box mount
            self.path, [call.row()])
        self._memo[(call.world_id, call.key)] = call.payload_text
        return call
