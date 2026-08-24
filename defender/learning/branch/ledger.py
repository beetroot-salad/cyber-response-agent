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
import threading
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
#: The call reached the seam, was pointed at this world, and the ESTATE faulted — the adapter
#: body raised, or the applier did. Its own class for the same reason `refused` is one: the
#: query tool turns that exception into a fault row the model reads, so the defender HAS seen a
#: response, and a seam that wrote nothing would leave "a served response with no row" behind
#: the one failure this table exists to make visible. Distinct from `refused` because the two
#: name different faults — a world that cannot be staged is the harness's, an estate that is
#: down is the environment's, and the circuit breaker already tells them apart by exit code.
FAULT = "fault"
SOURCES = frozenset({BASE, STAGED, PATCHED, PASSTHROUGH, REFUSED, FAULT})
#: The subset an APPLIER may name. `base` is the family TIER's label, not a decision — it is
#: written by `_base_payload` alone, against `world_id=None` — and `refused`/`fault` are the
#: seam's own, written when nothing got as far as a decision. Naming the three that are really
#: an applier's is what keeps "the vocabulary is closed" from reading as "any applier may claim
#: any label in it", including the one that means "this is the recording your siblings replay".
APPLIER_DECISIONS = frozenset({STAGED, PATCHED, PASSTHROUGH})


class LedgerError(Exception):
    """A served response that cannot be honestly recorded."""


def _is_json(text: str) -> bool:
    """Is this row's payload something `base_payload`'s caller can actually `loads`?"""
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


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

    `payload_text` — the answer, AS ASKED. The identity a world staged is taken back out before
    the row is written (`WorldApplier.restore`), because the response echoes it: `query`/
    `alerts` return the index they read and `esql` returns the query text, so an unrestored
    payload differs base-vs-sibling in a field NO WORLD TOUCHED, and ΔO over the event stream
    is non-zero on every row regardless of what the world did.

    That the KEYS are keyed on params and the PAYLOAD reads as asked is not a split brain: the
    keys answer "which call is this", and `params` above still holds the form that ran, so what
    actually reached the corpus is one column over and nothing is lost. It is also what makes
    the payload safe to hand back to a model — the memo arm deserializes this text and serves
    it, so a recording carrying a view name would put a corpus the model never wrote into the
    next sibling's context, where re-binding it stages the staged name a second time.
    """

    system: str
    verb: str
    params: dict
    #: The answer with the world's own corpus identity taken back out — see the class
    #: docstring. `params` above is where the form that RAN is kept.
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
        #: THE FAMILY TIER ONLY, keyed by request key. `base_payload` is the sole reader and
        #: only ever asks for a `world_id is None` row, so memoizing a world's own rows kept a
        #: full copy of every payload the run ever served — the table's own comment sizes those
        #: at 52KB each — for the life of the process, with nothing able to read them back.
        self._memo: dict[str, str] = {}
        #: Bytes of `path` already absorbed into `_memo`. `_refresh` compares the file's size
        #: against it and returns without reading when nothing has been appended since — which
        #: is the ordinary case, because this process's own `record` keeps the memo current.
        #: Without it every MISS re-read, re-parsed and re-keyed the whole table, and the table
        #: grows by a full payload per served call: quadratic in bytes over a run, measured at
        #: 5.5s and 858MB of re-reads for 120 calls at 52KB each.
        self._absorbed = 0
        #: `served` runs under `asyncio.to_thread`, and sibling gather leads dispatch in
        #: parallel — so several threads reach `record` at once. `append_jsonl` opens in text
        #: mode and a multi-hundred-KB row is several `write()` calls, which interleave into a
        #: torn line that `read_jsonl_rows` then silently DROPS: the family's base recording
        #: vanishes with nothing in the table to show it. One writer at a time closes that.
        self._lock = threading.Lock()
        self._refresh()

    def base_payload(self, system: str, verb: str, params: Any) -> str | None:
        """The family's recorded answer for this key, if one world already asked it.

        A hit means NO adapter call: the estate is live, so two siblings querying it minutes
        apart would see different data and the pair's whole invariance would be a fiction.
        Recording once per family is what buys determinism back without snapshot-restore.

        A MISS RE-READS THE FILE before conceding. The memo is built at construction, so a
        sibling running beside another in a separate process holds a snapshot from before that
        one started writing: both miss, both call the live adapter, and the pair's two bases
        are two different reads — the failure the family tier exists to prevent, arriving by
        the one route it does not watch. This NARROWS that window; it does not close it: the
        check-then-act spans the adapter call itself, so two siblings — in two processes, or
        on two of this one's worker threads — can still both miss and both read live. Closing
        it needs a per-key lock held ACROSS the adapter call, which this seam does not have.
        """
        key = request_key(system, verb, params)
        hit = self._memo.get(key)
        if hit is not None:
            return hit
        self._refresh()
        return self._memo.get(key)

    def _refresh(self) -> None:
        """Absorb the file, keeping whatever this process already holds.

        THE ONE memo-building loop, and construction runs it too. Built twice, the two copies
        resolved a duplicate key in opposite directions — construction kept the LAST row, this
        kept the FIRST — so two siblings reading one file served different base payloads for
        the same question, which is exactly the invariance the family tier exists to buy. One
        loop, one rule: first row wins, which is the append-only reading of "recorded once".
        """
        size = self.path.stat().st_size if self.path.is_file() else 0
        if size == self._absorbed:
            return
        for row in read_jsonl_rows(self.path):
            # `str(...)`, not a cast: a torn or hand-edited row can carry anything, and the
            # tolerant reader's job is to hand back what is there rather than to vouch for it.
            # Keying on the coerced spelling keeps a malformed row addressable instead of
            # crashing the replay that has to notice it.
            text = row.get("payload_text")
            # A row with no payload is not an ANSWER, and memoizing it as `""` would make
            # `base_payload` report a hit that `json.loads` then dies on — moving the crash one
            # frame down instead of tolerating the row. Nor is a row whose payload is not JSON:
            # a torn line reaches `json.loads` inside the served verb body, where the resulting
            # `JSONDecodeError` is not an `AdapterFault` and the query tool's catch-all files it
            # as exit 2 — an INFRA code, so one torn row counts against the circuit breaker.
            # Skipped either way, so the key falls through to the live adapter, which is the
            # honest reading of "nothing recorded".
            if row.get("world_id") is not None:
                # A world's OWN row, which nothing reads back: `base_payload` asks the family
                # tier and only the family tier. Absorbing it doubled the memo in payload bytes
                # to answer a question no caller has.
                continue
            if not isinstance(text, str) or not text or not _is_json(text):
                continue
            row_key = request_key(str(row.get("system")), str(row.get("verb")), row.get("params"))
            self._memo.setdefault(row_key, text)
        # NEVER BACKWARDS. `size` was read before the loop, and `record` may have appended (and
        # advanced `_absorbed` past it) while we were reading — so assigning it outright let a
        # concurrent writer knock the counter below what is really absorbed, and `record`'s
        # `before == self._absorbed` gate then stopped matching for the rest of the run: every
        # later miss re-read and re-keyed the whole table, which is the cost this counter exists
        # to remove. Measured at one full re-read per miss with a second writer on the path.
        self._absorbed = max(self._absorbed, size)

    def record(self, call: ServedCall) -> ServedCall:
        if call.source not in SOURCES:
            raise LedgerError(
                f"{call.system}.{call.verb} was served with source {call.source!r}, which is "
                f"not one of {sorted(SOURCES)} — a response with no honest decision behind it "
                "is the silent-scenario-deletion hazard this table exists to catch")
        # THE TWO TIERS AGREE, ALWAYS. `base` means "the family's recording, replayed by every
        # sibling", and `world_id is None` is how that is spelled — so a `base` row owned by a
        # world would put one world's answer in the slot its siblings read, and a world row with
        # no owner would be a difference nobody can attribute. That is the silent scenario
        # INJECTION the registry's own `world_id` check guards, arriving through the other door.
        if (call.source == BASE) != (call.world_id is None):
            raise LedgerError(
                f"{call.system}.{call.verb} was recorded as {call.source!r} for world "
                f"{call.world_id!r} — `base` is the FAMILY tier and is spelled `world_id=None`; "
                "the two say the same thing and a row where they disagree is either one world's "
                "answer offered as the shared recording, or a difference with no owner")
        # PERSIST FIRST, memoize only on success. Memoizing first meant a failed append left
        # the family's base payload live in memory with no row behind it: every later call for
        # that key took the hit, issued no adapter call, and served a payload the table cannot
        # account for — "a served response with no row", the one state this table exists to
        # make visible. A later sibling rebuilding the memo from the file would find nothing,
        # re-ask the live estate and get different bytes, so the pair's invariance would be
        # gone with nothing in the record to show it.
        # SERIALISED OUTSIDE THE LOCK. `row()` re-walks the params and `append_jsonl` re-escapes
        # a multi-hundred-KB payload string, and neither needs mutual exclusion — only the write
        # does. Built inside, every parallel sibling gather thread blocked through the dump.
        row = call.row()
        key = call.key
        with self._lock:
            before = self.path.stat().st_size if self.path.is_file() else 0
            append_jsonl(  # lint-unguarded-tree-write: ok — episode archive under the learning state root, host-side, outside every box mount
                self.path, [row])
            # Only when this process was current: if the file grew under us, another writer's
            # rows are unabsorbed and the next miss has to re-read to see them. A writer that
            # lands between our append and this `stat` is counted as absorbed when it is not —
            # the cost is one redundant live read for that key, which is the same cross-process
            # window `base_payload` already documents, not a wrong answer.
            if before == self._absorbed:
                self._absorbed = self.path.stat().st_size
            if call.world_id is None:
                # FIRST ROW WINS, the rule `_refresh` absorbs the file under, and the same rule
                # here because there is only one. Overwriting resolved a duplicate base key in
                # the opposite direction: the window `base_payload` documents as still open lets
                # two siblings both miss and both record, and this process then served the
                # SECOND payload while any process rebuilding the memo from the file served the
                # first. Two answers to one question, with both rows reading honestly — the
                # invariance the family tier exists to buy, gone.
                self._memo.setdefault(key, call.payload_text)
        return call
