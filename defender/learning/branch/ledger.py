"""What the estate served, one row per call.

Every response the defender sees in a branched run passes the estate seam and lands here with
the decision that produced it. Under staging, a query reaching a real adapter is expected; the
hazard is a response reaching the defender without passing the applier — silent scenario
deletion, a run that looks fine and measures nothing.

`passthrough` is therefore a decision, not an absence. A served response with no row is the
failure this table exists to make visible.

There is no `query_id` column: the seam sits below `QueryCapture`, where a model-supplied
`query_id` is resolved. The run's `executed_queries.jsonl` records it against the same
`(system, verb, params)`, so correlation is a join.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from defender._model import model
from pathlib import Path
from typing import Any

from defender._io import append_jsonl, read_jsonl_rows
from defender._episode_paths import EpisodePaths
from defender._run_paths import artifact_file
from defender.scripts.gather_tools.record_query import (
    PARAMS_NESTING_LIMIT,
    _json_safe_params,
    _request_key,
    row_reads_back,
)

#: What produced a served payload. Any other value is a writer inventing a decision class.
BASE = "base"
STAGED = "staged"
PATCHED = "patched"
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
SOURCES = frozenset({BASE, STAGED, PATCHED, PASSTHROUGH, REFUSED, FAULT, CAPTURED})
#: The family-tier labels — rows every sibling replays, with `world_id=None`. `base` is a live
#: read of a key the capture never recorded, so counting `base` rows measures the residual a
#: primed base cannot make deterministic.
FAMILY_SOURCES = frozenset({BASE, CAPTURED})
#: The labels an applier may name. `base` is written only by `_base_payload`; `refused`/`fault`
#: are the seam's own, written when nothing reached a decision.
APPLIER_DECISIONS = frozenset({STAGED, PATCHED, PASSTHROUGH})


def normalized_source(value: Any) -> str | None:
    """`value` if it is exactly a member of `SOURCES`, else `None`.

    Other modules call this rather than re-deriving membership. No case/whitespace folding:
    `source` is written by code, never typed by a model or operator.
    """
    return value if isinstance(value, str) and value in SOURCES else None


class LedgerError(Exception):
    """A served response that cannot be honestly recorded."""


def base_file(episode_dir: Path) -> Path:
    """The family's capture under `episode_dir`: the one path the primer writes and every
    `Ledger` reads.
    """
    return EpisodePaths(Path(episode_dir)).served_base


def payload_text(payload: Any) -> str:
    """The canonical bytes for a payload; the only spelling of them.

    `sort_keys` makes two dumps of one answer compare equal. The source run's captured sidecars
    were written without it, so priming must re-dump through this; any near-copy would make
    every primed row a silent miss.

    `default=str` stops a `datetime`, `Decimal` or tuple raising mid-serve, and applies on both
    the capture and live sides so they degrade the same way.
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

    Delegates to `record_query._request_key` so this table and `executed_queries.jsonl` key the
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
    """One served call, under both the question asked and the question run.

    They differ exactly when a world stages (`prepare` rewrites the call to its corpus).

    `key` is the form that ran, and is what the family tier memoizes on. Keying the memo on the
    asked form would replay another world's staged answer to a sibling.

    `correlation_key` is the form asked, and is what cross-world comparison pairs on. On a
    staged system the ran forms never match across worlds, so pairing on them would report no
    difference at all on the event stream.

    `payload_text` is the answer with the world's staged identity restored out
    (`WorldApplier.restore`), because responses echo it (`query`/`alerts` return the index,
    `esql` the query text); otherwise every event-stream row would differ base-vs-sibling in a
    field no world touched. It is also served back to models from the memo, where a view name
    would leak and get re-staged. `params` still holds what actually ran.
    """

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
        # `_json_safe_params` because `append_jsonl` dumps with stdlib defaults: otherwise a
        # param reaches the file as `Infinity`/`NaN` or raises `TypeError` mid-serve.
        row = {
            "system": self.system, "verb": self.verb,
            "params": _json_safe_params(self.params),
            "payload_text": self.payload_text, "source": self.source,
            "world_id": self.world_id,
        }
        if self.asked_params is not None:
            # Absent means "nothing was rewritten"; echoing `params` on every row would make
            # the two identities look like one.
            row["asked_params"] = _json_safe_params(self.asked_params)
        if self.source == STAGED:
            # Written on every staged row even when `None`: `None` (unmeasured) must be
            # distinguishable from a row that never took a witness. The meaning of the pair
            # is decided by `judge/family._grade_world` alone.
            row["differs_from_base"] = self.differs_from_base
            row["base_pattern_digest"] = self.base_pattern_digest
        return row


@model
class Ledger:
    """The append-only record of one world's served calls, and the family's shared base.

    Two files: `base_path` is the family's capture, primed before any sibling forks and
    read-only for the run; `path` is this world's own rows, with exactly one writer. Rows off a
    world's staged set are therefore byte-identical across siblings.

    One writer per file matters because siblings run in parallel and `append_jsonl` writes a
    large row in several `write()` calls; two processes appending would tear lines that
    `read_jsonl_rows` silently drops. It also removes any check-then-act race for captured keys.

    Not closed: a key the source run never asked has no captured row, so each world reads it
    live and records its own `base` row. Counting those rows sizes that residual.
    """

    path: Path
    base_path: Path

    @classmethod
    def for_world(cls, episode_dir: Path, world_id: str) -> Ledger:
        """This world's ledger under `episode_dir`, over the family's primed base.

        Deriving the path from the world id makes "two worlds never share a file" structural.

        The id is validated as a single filename component (nothing upstream refuses `../base`).
        That check does not stop the bare id `base` from naming the capture; `__post_init__`
        refuses that collision on the resulting paths.
        """
        if not isinstance(world_id, str) or not world_id:
            raise LedgerError(
                f"a world needs a non-empty string id to name its ledger, got {world_id!r}")
        if world_id != Path(world_id).name or world_id in (".", ".."):
            raise LedgerError(
                f"world id {world_id!r} is not a single filename component — a world's rows are "
                "a file beside the family's base, and an id carrying a separator would write "
                "outside the episode or onto the capture its siblings replay")
        base = base_file(episode_dir)
        return cls(path=base.parent / f"{world_id}.jsonl", base_path=base)

    def declare(self) -> Ledger:
        """Create this world's ledger empty if it is not there yet, and return the ledger.

        Write-ahead, so an absent ledger means the world never started, never "ran and served
        nothing". A sibling that answered everything from the replayed capture then reads as an
        empty ledger (graded `lead-set`) rather than an incomplete, ungradable archive.

        Called only by the sibling building its registry; `for_world` is also used by readers,
        and creating the file there would mint the artifact being read.

        Opens in append mode: `record` may already be appending from a parallel gather lead.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)  # lint-unguarded-tree-write: ok — episode archive under the learning state root, host-side, outside every box mount, exactly as `record`'s own append below  # noqa: E501
        with self.path.open("a", encoding="utf-8"):  # lint-unguarded-tree-write: ok — same tree and same rationale as `record`; opened in append so a concurrent writer's rows survive  # noqa: E501
            pass
        return self

    def __post_init__(self) -> None:
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
        # A row this table's reader skips would be an answer served with no record behind it.
        # `LedgerError`, not `RuntimeError`: `_served` re-raises the table's own refusal, where
        # any other exception would be re-filed as a FAULT row carrying the same params.
        if not row_reads_back(row):
            raise LedgerError(
                f"{call.system}.{call.verb} was not recorded: its row could not be read back "
                f"(params nested past {PARAMS_NESTING_LIMIT})")
        key = call.key
        with self._lock:
            append_jsonl(  # lint-unguarded-tree-write: ok — episode archive under the learning state root, host-side, outside every box mount
                self.path, [row])
            if call.world_id is None:
                # First row wins, as in `_absorb`, so a repeated question answers the same way
                # for the rest of the run.
                self._memo.setdefault(key, call.payload_text)
        return call
