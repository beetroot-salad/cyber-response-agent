"""What the estate served, one row per call."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from defender._model import model
from pathlib import Path
from typing import Any, Self

from defender._io import read_jsonl_rows
from defender.episodes._episode_handle import AppendRecord, Episode
from defender.records import artifact_file
from pydantic import ValidationInfo, field_validator

from defender.knowledge._query_rules import _json_safe_params, _request_key

#: What produced a served payload. Any other value is a writer inventing a decision class.
BASE = "base"
STAGED = "staged"
PASSTHROUGH = "passthrough"
#: The call reached the seam and was refused (e.g. this world's corpus cannot be targeted).
#: Recorded so a refusal does not read as the sibling never asking.
REFUSED = "refused"
#: The call was pointed at this world and the estate faulted (adapter or applier raised). The
#: model sees a fault row, so the table must too. Distinct from `refused`: a world that cannot
#: be staged is the harness's fault, an estate that is down is the environment's.
FAULT = "fault"
#: The payload came from the source run's capture, primed before any sibling forked. Distinct
#: from `base`, which is a live read of the estate now rather than the estate as captured.
#:
#: Only the primer writes it, bypassing `record` (which refuses it): a served call labelled
#: `captured` would be a live read wearing capture provenance.
CAPTURED = "captured"
#: The live oracle served this call (#1224): its submission passed the host checks and the
#: verifier, and it differs from the base answer.
ORACLE = "oracle"
#: The control world's oracle served this call an answer that differs from its base (#1255 D5):
#: a base read live, reconstructed as the world stood at the fork. Not `oracle`: the control
#: world has no facts, so a reconstruction is baseline, never "shown its facts" — the judge reads
#: only `oracle` as an altered call.
RECONSTRUCTED = "reconstructed"
#: The real system errored on the call's base read; the error passed through untouched (O4).
REAL_ERROR = "real-error"
#: `staged` (and `patched`, now unnamed) are the retired staging decisions (#1224): an archived
#: row may carry one, and it is refused as a new row's decision.
SOURCES = frozenset({BASE, PASSTHROUGH, REFUSED, FAULT, CAPTURED, ORACLE, RECONSTRUCTED,
                     REAL_ERROR})
#: The family-tier labels — rows every sibling replays, with `world_id=None`. `base` is a live
#: read of a key the capture never recorded, so counting `base` rows measures the residual a
#: primed base cannot make deterministic.
FAMILY_SOURCES = frozenset({BASE, CAPTURED})


def normalized_source(value: Any) -> str | None:
    """`value` if it is exactly a member of `SOURCES`, else `None`.

    Other modules call this rather than re-deriving membership. No case/whitespace folding:
    `source` is written by code, never typed by a model or operator.
    """
    return value if isinstance(value, str) and value in SOURCES else None


class LedgerError(Exception):
    """A served response that cannot be honestly recorded."""


def payload_text(payload: Any) -> str:
    """A payload's canonical form, for COMPARING answers: `sort_keys` makes two dumps of one
    answer compare equal.

    Never the bytes a world serves (#1255 G8): a world serves an answer in the spelling the
    investigator would get from the system itself — the source's own sidecar for a recorded
    answer, the query tool's spelling (`payload_view.payload_text_of`) for a live read or an
    oracle's submission. A row is found by its request key, which is canonical whatever its
    payload's spelling.

    `default=str` stops a `datetime`, `Decimal` or tuple raising mid-serve.
    """
    return json.dumps(payload, sort_keys=True, default=str)


def _is_json(text: str) -> bool:
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


def request_key(system: str, verb: str, params: Any) -> str:
    """The canonical identity of one question.

    Delegates to `_query_rules._request_key` so this table and `executed_queries.jsonl` key the
    same `(system, verb, params)` identically and can be joined.
    """
    return _request_key(system, verb, params)


def correlation_key_of(row: Any) -> str | None:
    """One recorded row's comparison identity — `ServedCall.correlation_key`, read off disk.

    Derived, not read as a column: `ServedCall.row()` does not write `correlation_key`, so
    reading the column would collapse every row onto one key. A recorded value is still honoured
    first.

    `None` when the row cannot say which call it is (no system or verb); the caller decides
    whether that is a skipped row or a fault.
    """
    if not isinstance(row, Mapping):
        return None
    recorded = row.get("correlation_key")
    if isinstance(recorded, str) and recorded:
        return recorded
    asked = row.get("asked_params")
    params = asked if isinstance(asked, dict) else row.get("params")
    system, verb = row.get("system"), row.get("verb")
    if not isinstance(system, str) or not isinstance(verb, str):
        return None
    return request_key(system, verb, params if isinstance(params, dict) else {})


@model(frozen=True)
class ServedCall:
    """One served call, under both the question asked and the question run."""

    system: str
    verb: str
    params: dict
    #: The answer with the world's own corpus identity taken back out.
    payload_text: str
    source: str
    world_id: str | None
    #: What the model asked, when staging rewrote it. `None` means nothing was rewritten.
    asked_params: dict | None = None
    #: Whether a live read of the un-rewritten base pattern differed from what this world was
    #: served, beyond formatting. `None` means unmeasured, never "no difference". Only a
    #: `staged` row takes a witness.
    differs_from_base: bool | None = None
    #: `sha256` of the base pattern's own canonicalised text — see `differs_from_base`.
    base_pattern_digest: str | None = None
    #: An `oracle` turn's record (#1224): the digest of the base answer it was served
    #: against, the claim it made, the verifier's verdict and how many attempts it took.
    base_digest: str | None = None
    claim: dict | None = None
    verifier_verdict: dict | None = None
    attempts: int | None = None
    #: The call's host-written id (`record_query.next_call_id`, A12): the query tool's, the
    #: same id the run's call join pairs with the call's query-table row (#1255 G6). `None` for a call no query tool allocated
    #: one to (the family primer's rows, a registry driven directly); the row then has no key.
    call_id: str | None = None

    @field_validator("params", "asked_params")
    @classmethod
    def _stored_form(cls, value: dict | None, info: ValidationInfo) -> dict | None:
        """Each params map as the row stores it, cleaned once, here. Params too deep to store
        are `ParamsTooDeep` naming the field, so a call no row could carry is never built, and
        `row()` and both keys cannot fail on depth.

        Cleaned because the appenders dump with stdlib `json.dumps` defaults: otherwise a param
        reaches the file as `Infinity`/`NaN` or raises `TypeError` mid-serve. The keys do not
        move: `request_key` cleans by the same rules, and cleaning twice changes nothing."""
        return None if value is None else _json_safe_params(value, field=info.field_name or "params")

    @property
    def key(self) -> str:
        """The memo identity: the call as it ran."""
        return request_key(self.system, self.verb, self.params)

    @property
    def correlation_key(self) -> str:
        """The comparison identity: the call as it was asked."""
        return request_key(
            self.system, self.verb,
            self.params if self.asked_params is None else self.asked_params)

    def row(self) -> dict:
        row: dict[str, Any] = {
            "system": self.system, "verb": self.verb,
            "params": self.params,
            "payload_text": self.payload_text, "source": self.source,
            "world_id": self.world_id,
        }
        if self.asked_params is not None:
            # Absent means "nothing was rewritten"; echoing `params` on every row would make
            # the two identities look like one.
            row["asked_params"] = self.asked_params
        if self.source == STAGED:
            # Written on every staged row even when `None`: `None` (unmeasured) must be
            # distinguishable from a row that never took a witness. The meaning of the pair
            # is decided by `judge/family._grade_world` alone.
            row["differs_from_base"] = self.differs_from_base
            row["base_pattern_digest"] = self.base_pattern_digest
        for name in ("base_digest", "claim", "verifier_verdict", "attempts", "call_id"):
            value = getattr(self, name)
            if value is not None:
                row[name] = value
        return row


def served_line(row: dict) -> str:
    """One served-call row (`ServedCall.row()`) as its JSONL line: the one spelling of a
    served-file line, for the primer's base and each world's own file.

    @owns served-call line"""
    return json.dumps(row) + "\n"  # lint-jsonl-io: ok — one row, handed whole to the episode's create or append


@model
class Ledger:
    """The append-only record of one world's served calls, and the family's shared base."""

    path: Path
    base_path: Path

    @classmethod
    def for_world(cls, episode: Episode, world_id: str) -> Self:
        """This world's ledger in `episode`, over the family's primed base.

        Deriving the file from the world id makes "two worlds never share a file" structural.

        The episode owner requires the host-minted world UUID before constructing a path;
        a refused identity is reported as `LedgerError`.
        """
        try:
            served = episode.served_world(world_id)
        except ValueError as e:
            raise LedgerError(
                f"world id {world_id!r} cannot name a world's ledger ({e}) — a world's rows are "
                "a file beside the family's base, and an id carrying a separator would write "
                "outside the episode or onto the capture its siblings replay") from None
        ledger = cls(path=served.path, base_path=episode.served_base.path)
        ledger._served = served
        ledger._unrecorded_path = episode.served_unrecorded.path
        return ledger

    def declare(self) -> Ledger:
        """Create this world's ledger empty if it is not there yet, and return the ledger.

        Write-ahead, so an absent ledger means the world never started, never "ran and served
        nothing". A sibling that answered everything from the replayed capture then reads as an
        empty ledger (graded `lead-set`) rather than an incomplete, ungradable archive.

        Called only by the sibling building its registry; `for_world` is also used by readers,
        and creating the file there would mint the artifact being read.

        An empty append: `record` may already be appending from a parallel gather lead.
        """
        self._append("")
        return self

    def _append(self, text: str) -> None:
        """Append to this world's file through the episode's `served_world` record, the one
        write lane. A ledger not built by `for_world` has none and writes nothing."""
        if self._served is None:
            raise LedgerError(
                f"{self.path}: a ledger writes only through its episode — build it with "
                "`Ledger.for_world(episode, world_id)`")
        self._served.append(text)

    def __post_init__(self) -> None:
        #: This world's `served_world` record, the ledger's one write lane; set by `for_world`.
        self._served: AppendRecord | None = None
        #: The primer's skip record beside the base (#1255 D6); set by `for_world`.
        self._unrecorded_path: Path | None = None
        #: Family tier only, keyed by request key: `base_payload` never reads a world's own
        #: rows, so memoizing them would only hold every served payload in memory.
        self._memo: dict[str, str] = {}
        #: `served` runs under `asyncio.to_thread` and one world's gather leads run in
        #: parallel, so several threads reach `record` at once.
        self._lock = threading.Lock()
        # A world's file must never be the family's (e.g. `for_world(episode, "base")`), or its
        # live reads would be served to every sibling as the estate. Checked here so the direct
        # constructor cannot bypass it.
        # Case-folded because the filesystem decides whether two names are one file: on macOS
        # `Base.jsonl` is `base.jsonl`. Refused on case-sensitive hosts too, the safe direction.
        if (self.path.parent, self.path.name.casefold()) == (
                self.base_path.parent, self.base_path.name.casefold()):
            raise LedgerError(
                f"a world's ledger is {self.path}, which is the family's own capture "
                f"({self.base_path}, compared without case) — the base is primed once before "
                "any sibling forks and is read-only for the run, so a world writing there "
                "serves its own live reads to every sibling as the estate")
        # The base must already exist: that is the ordering guarantee. A `Ledger` built without
        # it is a sibling that started before priming, and every key would silently read live.
        # `artifact_file` (lstat), not `is_file()`, so a symlink with the capture's name is not
        # followed and absorbed with `captured` provenance.
        if not artifact_file(self.base_path):
            raise LedgerError(
                f"no primed base at {self.base_path} — the family's capture is written once, "
                "before any sibling forks, and a world serving without it reads the live estate "
                "for every key while every row it writes still reads correctly")
        # Base first, both first-row-wins: a captured answer outranks a live one left by a
        # crashed earlier attempt at this episode.
        self._absorb(self.base_path)
        self._absorb(self.path)

    def base_payload(self, system: str, verb: str, params: Any) -> str | None:
        """The family's recorded answer for this key, if there is one.

        A hit means no adapter call. For a captured key every sibling replays the same bytes.
        A key the capture never recorded gets a live read per world, which may differ.
        """
        return self._memo.get(request_key(system, verb, params))

    def unrecorded_keys(self) -> frozenset[str]:
        """The request keys of the calls the source asked whose answer the base lacks — the call
        failed, or its payload was unreadable — from the primer's skip record
        (`capture.unrecorded_line`, #1255 D6). A world serves such a call through its oracle at
        the fork time, never as a fixed pre-branch answer. An episode primed before the record
        existed (or a ledger not built by `for_world`) has none: the empty set."""
        if self._unrecorded_path is None:
            return frozenset()
        return frozenset(
            request_key(str(row.get("system")), str(row.get("verb")), row.get("params"))
            for row in read_jsonl_rows(self._unrecorded_path)
            if isinstance(row.get("system"), str) and isinstance(row.get("verb"), str))

    def _absorb(self, path: Path) -> None:
        """Fold one file's family-tier rows into the memo, first row wins.

        The single memo-building loop (for both files), so a duplicate key always resolves the
        same way.
        """
        for row in read_jsonl_rows(path):
            # Coerce with `str(...)` below: a torn or hand-edited row can carry anything, and
            # a malformed row should stay addressable rather than crash the replay.
            text = row.get("payload_text")
            if row.get("world_id") is not None or row.get("source") not in FAMILY_SOURCES:
                # Skip a world's own row, and also a `world_id: null` row whose source is not a
                # family label (e.g. a hand-edited `fault` row): memoizing it would serve an
                # error digest to the applier as a successful response. Mirrors `record`'s rule.
                continue
            # Skip a row with no payload or a non-JSON payload: `json.loads` inside the served
            # verb would raise a non-`AdapterFault`, filed as an infra exit that counts against
            # the circuit breaker. The key falls through to the live adapter instead.
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
        # Family-tier sources and `world_id is None` must agree: a `base` row owned by a world
        # would put its answer in the slot siblings replay, and a world row with no owner is
        # an unattributable difference.
        if (call.source in FAMILY_SOURCES) != (call.world_id is None):
            raise LedgerError(
                f"{call.system}.{call.verb} was recorded as {call.source!r} for world "
                f"{call.world_id!r} — {sorted(FAMILY_SOURCES)} are the FAMILY tier and are "
                "spelled `world_id=None`; the two say the same thing and a row where they "
                "disagree is either one world's answer offered as the shared recording, or a "
                "difference with no owner")
        # Only the primer may claim capture provenance, and it writes the base file directly.
        if call.source == CAPTURED:
            raise LedgerError(
                f"{call.system}.{call.verb} was recorded as {CAPTURED!r} through the serving "
                "path — only the primer may claim capture provenance, and it writes the base "
                "file directly. A live read labelled `captured` is unfalsifiable downstream")
        # Persist first, memoize only on success: otherwise a failed append leaves a memo hit
        # with no row behind it, served without an adapter call.
        # Serialise outside the lock; only the write needs mutual exclusion.
        row = call.row()
        key = call.key
        with self._lock:
            self._append(served_line(row))
            if call.world_id is None:
                # First row wins, as in `_absorb`, so a repeated question answers the same way
                # for the rest of the run.
                self._memo.setdefault(key, call.payload_text)
        return call
