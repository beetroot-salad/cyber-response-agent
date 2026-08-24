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
#: The payload came from the SOURCE RUN's capture, primed before any sibling forked. Its own
#: class because `base` no longer means what it meant: #920 defines the base world as "whatever
#: the real adapters returned during the real run", and a row read live by whichever sibling
#: asked first is the estate NOW, not the estate as captured. The two are the same only on a
#: quiet estate, and nothing in a table that could not tell them apart would ever say so.
#:
#: Only the primer writes it, and the primer does not go through `record` — see the refusal
#: there. A row a sibling could stamp `captured` would be a live read wearing capture
#: provenance, which every downstream reader would believe.
CAPTURED = "captured"
SOURCES = frozenset({BASE, STAGED, PATCHED, PASSTHROUGH, REFUSED, FAULT, CAPTURED})
#: The two labels that belong to the FAMILY tier — the rows every sibling replays, spelled
#: `world_id=None`. `captured` is the capture; `base` is now the narrower thing it always
#: honestly was, a live read of a key the capture never recorded, which only happens because a
#: sibling asks questions its source never did. Counting `base` rows across a family therefore
#: measures exactly that residual, which is the one part of the estate a primed base cannot
#: make deterministic.
FAMILY_SOURCES = frozenset({BASE, CAPTURED})
#: The subset an APPLIER may name. `base` is the family TIER's label, not a decision — it is
#: written by `_base_payload` alone, against `world_id=None` — and `refused`/`fault` are the
#: seam's own, written when nothing got as far as a decision. Naming the three that are really
#: an applier's is what keeps "the vocabulary is closed" from reading as "any applier may claim
#: any label in it", including the one that means "this is the recording your siblings replay".
APPLIER_DECISIONS = frozenset({STAGED, PATCHED, PASSTHROUGH})


class LedgerError(Exception):
    """A served response that cannot be honestly recorded."""


#: The directory, under an episode, that holds the family's base and every world's own rows.
SERVED_DIRNAME = "served"
#: The family's capture, inside `SERVED_DIRNAME`. Named here because the primer writes it and
#: every `Ledger` reads it, and a second spelling is how one starts writing where the other is
#: not looking — with the run still green, because a missing base is indistinguishable from a
#: key nobody asked.
BASE_FILENAME = "base.jsonl"


def payload_text(payload: Any) -> str:
    """The canonical bytes for a payload, and the ONE spelling of them.

    `sort_keys` is what makes two dumps of one answer compare equal, so a reader that spells
    this differently does not merely look untidy — it produces a key that never matches. The
    primer is the reason this lives here rather than beside its first caller: the source run's
    captured sidecars were written WITHOUT `sort_keys`, so priming must load and re-dump through
    exactly this, and a near-copy in a third module would make every primed row a permanent
    miss with nothing red to show for it.

    `default=str` keeps a value JSON has no spelling for — a `datetime`, a `Decimal`, a tuple —
    from raising mid-serve, and it is applied on BOTH sides of that round trip, so the capture
    and a live read degrade the same way.
    """
    return json.dumps(payload, sort_keys=True, default=str)


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

    Two tiers, and they are now two FILES rather than two `world_id` values in one. `base_path`
    is the family's capture, primed before any sibling forked and read-only for the whole run;
    `path` is this world's own rows, and it has exactly one writer. The tiering is what makes a
    difference between siblings READABLE: everything off a world's staged set is literally the
    same bytes, so a comparison only ever runs over rows that are supposed to differ.

    ONE WRITER PER FILE is the whole reason for the split, and it buys two things a shared file
    could not. Siblings run in PARALLEL, and `append_jsonl` opens in text mode: a
    multi-hundred-KB row is several `write()` calls, so two PROCESSES appending interleave into
    a torn line that `read_jsonl_rows` then silently drops — the family's recording vanishing
    with nothing in the table to show it. And the check-then-act race this class used to concede
    ("both miss, both read live") cannot happen for a captured key at all, because nothing
    writes the base tier while the run is in progress.

    What the split does NOT close, stated so nobody reads more into it: a key the source run
    never asked has no captured row, so each world reads it live and records its own `base` row.
    Those rows are the residual, and counting them is how big it is.
    """

    path: Path
    base_path: Path

    @classmethod
    def for_world(cls, episode_dir: Path, world_id: str) -> Ledger:
        """This world's ledger under `episode_dir`, over the family's primed base.

        A FACTORY rather than two paths at the call site, because "one writer per file" is the
        property the whole split rests on and it is only true if two worlds can never be handed
        the same path. Deriving it from the world id makes that structural.

        The id is validated AS A FILENAME COMPONENT, which nothing upstream does: the registry
        checks it is a non-empty string, and a stager checks it can name a corpus — and only
        for a world that touches a staged system. Neither refuses `../base`, which would
        resolve onto the family's own capture and let one world's rows be replayed by every
        sibling as the estate.
        """
        if not isinstance(world_id, str) or not world_id:
            raise LedgerError(
                f"a world needs a non-empty string id to name its ledger, got {world_id!r}")
        if world_id != Path(world_id).name or world_id in (".", ".."):
            raise LedgerError(
                f"world id {world_id!r} is not a single filename component — a world's rows are "
                "a file beside the family's base, and an id carrying a separator would write "
                "outside the episode or onto the capture its siblings replay")
        served = Path(episode_dir) / SERVED_DIRNAME
        return cls(path=served / f"{world_id}.jsonl", base_path=served / BASE_FILENAME)

    def __post_init__(self) -> None:
        #: THE FAMILY TIER ONLY, keyed by request key. `base_payload` is the sole reader and
        #: only ever asks for a `world_id is None` row, so memoizing a world's own rows kept a
        #: full copy of every payload the run ever served — the table's own comment sizes those
        #: at 52KB each — for the life of the process, with nothing able to read them back.
        self._memo: dict[str, str] = {}
        #: `served` runs under `asyncio.to_thread`, and this ONE world's gather leads dispatch
        #: in parallel — so several threads reach `record` at once even though only one world
        #: writes this file. Splitting the tiers closed the cross-PROCESS half of the tearing
        #: problem; this is the cross-THREAD half, and it is untouched by the split.
        self._lock = threading.Lock()
        # THE BASE MUST ALREADY EXIST, and that refusal is the ordering guarantee. Priming runs
        # once, before any sibling forks; a `Ledger` built against a missing base is a sibling
        # that started early, and letting it through would mean every key missed the family tier
        # and read the live estate — the run green, the episode worthless, and nothing in the
        # record to say which. #920's fourth trap is this exact shape: "the seam fails open
        # today", and a missed hook answering from the real estate instead of the capture.
        if not self.base_path.is_file():
            raise LedgerError(
                f"no primed base at {self.base_path} — the family's capture is written once, "
                "before any sibling forks, and a world serving without it reads the live estate "
                "for every key while every row it writes still reads correctly")
        # BASE FIRST, then this world's own, both first-row-wins: a captured answer outranks a
        # live one left behind by a crashed earlier attempt at the same episode.
        self._absorb(self.base_path)
        self._absorb(self.path)

    def base_payload(self, system: str, verb: str, params: Any) -> str | None:
        """The family's recorded answer for this key, if there is one.

        A hit means NO adapter call. For a CAPTURED key that is now a guarantee rather than a
        race won: the base tier was primed before any sibling forked and nothing writes it while
        the run is in progress, so every sibling replays the same bytes and there is no
        check-then-act to lose. That is what the file split bought, and it is why this method no
        longer re-reads anything.

        For a key the capture never recorded — one a sibling invented, which it will, because a
        sibling is continuing an investigation — there is no hit and no shared answer to have.
        Each world reads live and records its own `base` row in its own file. Two worlds asking
        the same invented question therefore get two live reads, which may differ; that residual
        is real, it is not closed here, and the count of `base` rows across a family is its size.
        """
        return self._memo.get(request_key(system, verb, params))

    def _absorb(self, path: Path) -> None:
        """Fold one file's FAMILY-tier rows into the memo, first row wins.

        THE ONE memo-building loop, run over the base and then over this world's own file.
        First-row-wins is the append-only reading of "recorded once", and running one loop is
        what stops two copies resolving a duplicate key in opposite directions — which they did,
        one keeping the last row and one the first, so two siblings reading one file served
        different base payloads for the same question.
        """
        for row in read_jsonl_rows(path):
            # `str(...)`, not a cast: a torn or hand-edited row can carry anything, and the
            # tolerant reader's job is to hand back what is there rather than to vouch for it.
            # Keying on the coerced spelling keeps a malformed row addressable instead of
            # crashing the replay that has to notice it.
            text = row.get("payload_text")
            if row.get("world_id") is not None:
                # A world's OWN row, which nothing reads back: this memo answers the family tier
                # and only the family tier. Absorbing it doubled the memo in payload bytes to
                # answer a question no caller has.
                continue
            # A row with no payload is not an ANSWER, and memoizing it as `""` would make
            # `base_payload` report a hit that `json.loads` then dies on — moving the crash one
            # frame down instead of tolerating the row. Nor is a row whose payload is not JSON:
            # a torn line reaches `json.loads` inside the served verb body, where the resulting
            # `JSONDecodeError` is not an `AdapterFault` and the query tool's catch-all files it
            # as exit 2 — an INFRA code, so one torn row counts against the circuit breaker.
            # Skipped either way, so the key falls through to the live adapter, which is the
            # honest reading of "nothing recorded".
            if not isinstance(text, str) or not text or not _is_json(text):
                continue
            row_key = request_key(str(row.get("system")), str(row.get("verb")), row.get("params"))
            self._memo.setdefault(row_key, text)

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
        if (call.source in FAMILY_SOURCES) != (call.world_id is None):
            raise LedgerError(
                f"{call.system}.{call.verb} was recorded as {call.source!r} for world "
                f"{call.world_id!r} — {sorted(FAMILY_SOURCES)} are the FAMILY tier and are "
                "spelled `world_id=None`; the two say the same thing and a row where they "
                "disagree is either one world's answer offered as the shared recording, or a "
                "difference with no owner")
        # CAPTURE PROVENANCE IS NOT A CLAIM A SERVED CALL MAY MAKE. `captured` asserts the
        # payload came from the source run's own capture, and the only thing that can honestly
        # assert that is the primer — which writes the base file directly, before any world
        # exists, and never comes through here. Reachable this way, a live read would wear the
        # one label that tells a reader "this was not read from the estate you are measuring",
        # and every reader downstream would believe it.
        if call.source == CAPTURED:
            raise LedgerError(
                f"{call.system}.{call.verb} was recorded as {CAPTURED!r} through the serving "
                "path — only the primer may claim capture provenance, and it writes the base "
                "file directly. A live read labelled `captured` is unfalsifiable downstream")
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
            append_jsonl(  # lint-unguarded-tree-write: ok — episode archive under the learning state root, host-side, outside every box mount
                self.path, [row])
            if call.world_id is None:
                # FIRST ROW WINS, the rule `_absorb` folds a file under, and the same rule here
                # because there is only one. This world's live read of a key the capture never
                # held is recorded once and replayed by this world for the rest of the run;
                # overwriting would let a second read of the same question answer differently
                # mid-run, with both rows reading honestly.
                self._memo.setdefault(key, call.payload_text)
        return call
