"""The fork snapshot: what a run held when one of MAIN's responses arrived (#1255 P2, P3).

When a MAIN model response that called tools arrives, before any of its calls run, the host
records (`SnapshotWriter.record`):

  * every per-run counter the model can feel — the budget counters, permanent system-down
    causes and the circuit breaker
    (`RunState.fork_counters`), the challenge gate's rounds and raised asks, main's request
    count (this response included, the snapshot's key), and the caps the run runs under (its
    limits and its request ceiling, rev 5 C3);
  * each append-only model-readable file by length and digest (the queries table, the lessons
    and denials logs);
  * the rewritable document (`investigation.md`, which `fix_row` edits in place) by content;
  * each write-once file by digest (lead claims, raw payloads, gather summaries, review records).

It is kept in the run's session store (`session_store.write_fork_snapshot`), beside the runs base
and outside every box mount (P3), keyed by the session that drove the response and the
framework's request count. Gather and review run inside MAIN's awaited tool calls and nothing
writes in the background, so the moment a response arrives is a clean cut.

An arm restores the snapshot of its branch point (`ForkSnapshot.verify` before the fork,
`restore_files` after it): each append-only file is copied cut to its recorded length, the
document is written from its recorded content, each write-once file is copied whole, and every
copy must be the bytes that were recorded — a restore that does not match refuses the arm. The
counters, the gate's state and the caps are handed to the driver, which runs the arm under them.
This replaces the per-file cut rules (fence counting, lead selection) a sibling was seeded by.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import UTC, datetime
from collections.abc import Callable, Iterator
from functools import partial
from typing import Any

from defender._clock import parse_iso_utc
from defender._io import parse_jsonl_row
from defender.run_repository import RecordHandle, Run

from pydantic_ai.messages import ModelResponse

from .. import session_store
from ..run_state import RunState
from ..system_status import down_from_snapshot
from ._frontier import lead_records, source_session
from ._spec import BranchError, BranchSpec

_logger = logging.getLogger(__name__)

#: The snapshot body's shape version; a body of any other version is not one this reader knows.
SNAPSHOT_VERSION = 2


def _queries(run: Run) -> RecordHandle:
    return run.tables.queries


def _lessons_loaded(run: Run) -> RecordHandle:
    return run.observability.lessons_loaded


def _policy_denials(run: Run) -> RecordHandle:
    return run.tables.policy_denials


#: The append-only model-readable files, by the name the snapshot records them under, and the
#: run's own record for each.
_APPEND_ONLY: dict[str, Callable[[Run], RecordHandle]] = {
    "executed_queries": _queries,
    "lessons_loaded": _lessons_loaded,
    "policy_denials": _policy_denials,
}


def _lead_claim(run: Run, lead: str) -> RecordHandle:
    return run.tables.leads(lead)


def _payload(run: Run, lead: str, seq: int) -> RecordHandle:
    return run.tables.payloads(lead, seq)


def _gather_summary(run: Run, lead: str) -> RecordHandle:
    return run.documents.gather_summaries(lead)


def _review_record(run: Run, turn: int) -> RecordHandle:
    return run.observability.review_record(turn)


#: The write-once model-readable files, by kind: the run's record for one, from its arguments.
_WRITE_ONCE: dict[str, Callable[..., RecordHandle]] = {
    "lead_claim": _lead_claim,
    "payload": _payload,
    "gather_summary": _gather_summary,
    "review_record": _review_record,
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bytes_of(record: RecordHandle) -> bytes | None:
    """A record's bytes; `None` when it is absent. A refused read (a link, a non-file) raises
    `OSError`: what the run holds there is not a record it wrote."""
    found = record.read_bytes()  # lint-whole-read: ok — a RecordHandle, whose core enforces READ_LIMIT
    if found.absent:
        return None
    if found.data is None:
        raise OSError(found.reason)
    return found.data


def _write_once_files(run: Run) -> Iterator[tuple[str, tuple[Any, ...]]]:
    """Every write-once record the run holds, as `(kind, args)`: the per-lead records
    (`lead_records`) and the review records, which the close writes one per round from 1."""
    yield from lead_records(run)
    turn = 1
    while _bytes_of(_review_record(run, turn)) is not None:
        yield "review_record", (turn,)
        turn += 1


# ------------------------------------------------------------------------------------------
# Recording.
# ------------------------------------------------------------------------------------------


class SnapshotWriter:
    """Records MAIN's fork snapshots for one run, into its session store.

    `limits` and `request_ceiling` are the caps this run runs under (C3: an arm runs under its
    source's, so they are recorded with every snapshot). Write-once files are hashed once: a
    later snapshot reuses the digest, and a file changed after it was recorded makes a restore
    from the source refuse rather than copy the change."""

    def __init__(self, store: Any, session_id: str, *, run: Run, state: RunState,  # noqa: PLR0913 — the run's identity plus the caps it records
                 limits: dict, base_request_limit: int, extra_turns: int) -> None:
        self._store = store
        self._session_id = session_id
        self._run = run
        self._state = state
        self._caps = {"limits": dict(limits), "base_request_limit": base_request_limit,
                      "extra_turns": extra_turns}
        self._digests: dict[tuple[str, tuple[Any, ...]], str | None] = {}

    def record(self, request: int, review: Any) -> None:
        """Record the snapshot of MAIN's `request`-th response (`review`: the run's
        `challenge_gate.ReviewState`).

        A snapshot that cannot be taken is logged and the run goes on: it only means this
        response cannot be branched from (an arm asked for it is refused for the missing
        snapshot), and a natural run's investigation is not the place that fault belongs."""
        try:
            body, blobs = self._capture(request, review)
            self._store.write_fork_snapshot(self._session_id, request, body, blobs)
        except (OSError, ValueError, sqlite3.Error) as error:
            _logger.error(f"fork snapshot at request {request} not recorded ({error!r}); this "
                          "response cannot be branched from")

    def _capture(self, request: int, review: Any) -> tuple[str, dict[str, str]]:
        run = self._run
        append_only = {}
        for name, record in _APPEND_ONLY.items():
            data = _bytes_of(record(run)) or b""
            append_only[name] = {"length": len(data), "sha256": _sha(data)}
        write_once = []
        for kind, args in _write_once_files(run):
            key = (kind, args)
            if key not in self._digests:
                try:
                    held = _bytes_of(_WRITE_ONCE[kind](run, *args))
                except OSError:
                    # A recognised record the run holds that refuses to be read (a link, a
                    # directory) is recorded with no digest, never left out: left out, an arm
                    # would be restored as if the run never held it. No bytes match it, so
                    # every arm from here is refused (`ForkSnapshot.verify`).
                    self._digests[key] = None
                else:
                    if held is None:
                        continue
                    self._digests[key] = _sha(held)
            write_once.append({"kind": kind, "args": list(args), "sha256": self._digests[key]})
        document = run.documents.investigation.read()
        blobs = {} if document is None else {_sha(document.encode("utf-8")): document}
        body = {
            "version": SNAPSHOT_VERSION,
            "request": request,
            "counters": self._state.fork_counters(),
            "review": {"turns": review.turns, "raised_asks": dict(review.raised_asks),
                       "closed": review.closed, "disposition": review.disposition},
            "caps": self._caps,
            "append_only": append_only,
            "write_once": write_once,
            "document": next(iter(blobs), None),
        }
        return json.dumps(body, sort_keys=True), blobs


# ------------------------------------------------------------------------------------------
# Reading and restoring.
# ------------------------------------------------------------------------------------------


class ForkSnapshot:
    """One recorded snapshot, read back for a branch point (see the module docstring)."""

    def __init__(self, body: dict, document: str | None) -> None:
        self.body = body
        #: The document as it stood (`None`: the run had written none yet).
        self.document = document

    @property
    def request(self) -> int:
        """MAIN's request count at the branch point, this response included: the arm's
        starting usage."""
        return int(self.body["request"])

    @property
    def counters(self) -> dict:
        return dict(self.body["counters"])

    @property
    def fork_time(self) -> datetime:
        """The run clock's reading when the response arrived, whole seconds, aware UTC: the
        arm's cut-off (`as_of`) and the fork time the oracle is handed (rev 5 C4)."""
        raw = self.body["counters"]["clock"]["reading"]
        reading = parse_iso_utc(raw)
        if reading is None:
            raise BranchError(f"the fork snapshot's run-clock reading {raw!r} is not an ISO-8601 "
                              "timestamp, so the branch point has no moment")
        return reading.astimezone(UTC).replace(microsecond=0)

    @property
    def review(self) -> dict:
        return dict(self.body["review"])

    @property
    def limits(self) -> dict:
        return dict(self.body["caps"]["limits"])

    @property
    def base_request_limit(self) -> int:
        return int(self.body["caps"]["base_request_limit"])

    @property
    def extra_turns(self) -> int:
        return int(self.body["caps"]["extra_turns"])

    def verify(self, source_run: Run) -> None:
        """Refuse (`BranchError`) unless the source still holds what was recorded: each
        append-only file at least as long as recorded and opening on the recorded bytes, each
        write-once file the recorded bytes. Reads only; asked before the fork."""
        self._append_only_prefixes(source_run)
        for entry in self.body["write_once"]:
            self._write_once_bytes(source_run, entry)

    def captured_rows(self, source_run: Run) -> list[dict]:
        """The queries table's rows as they stood at the branch point."""
        prefix = self._append_only_prefixes(source_run)["executed_queries"]
        return _rows_of(prefix)

    def restore_files(self, source_run: Run, run: Run, state: RunState) -> None:
        """Write the arm's model-readable files as they stood at the branch point, into a run
        folder that holds none of them (`run.documents.investigation.seed` refuses one that
        does), and record the restored query rows into the arm's run state.

        Each copy is read back and compared with what was recorded, so a restore that does not
        match refuses the arm."""
        prefixes = self._append_only_prefixes(source_run)
        if self.document is not None:
            run.documents.investigation.seed(self.document)
        # The table is copied as the source held it, byte for byte: a torn or foreign line is
        # part of what the arm inherits, and re-recording rows could not reproduce it. The
        # state inherits only the lines that parse as rows (a damaged table fails open).
        table = prefixes["executed_queries"]
        rows = _rows_of(table)
        if table:
            run.tables.queries.seed(table)
        lessons = prefixes["lessons_loaded"]
        if lessons:
            run.observability.lessons_loaded.append(_rows_of(lessons))
        denials = prefixes["policy_denials"]
        if denials:
            run.tables.policy_denials.start_stream(denials.decode("utf-8"))
        for name, record in _APPEND_ONLY.items():
            if (_bytes_of(record(run)) or b"") != prefixes[name]:
                raise BranchError(
                    f"the arm's {name} does not hold the {len(prefixes[name])} byte(s) the "
                    "source held at the branch point after it was restored — a row that does "
                    "not survive being re-recorded is not one the arm can be handed")
        for entry in self.body["write_once"]:
            data = self._write_once_bytes(source_run, entry)
            try:
                _WRITE_ONCE[entry["kind"]](run, *entry["args"]).write(data)
            except OSError as error:
                raise BranchError(
                    f"the source's {entry['kind']} {entry['args']} could not be restored into "
                    f"the arm: {error}") from error
        state.inherit_rows(rows)

    def _append_only_prefixes(self, source_run: Run) -> dict[str, bytes]:
        out = {}
        for name, record in _APPEND_ONLY.items():
            recorded = self.body["append_only"][name]
            data = self._read(partial(record, source_run), name) or b""
            length = int(recorded["length"])
            prefix = data[:length]
            if len(data) < length or _sha(prefix) != recorded["sha256"]:
                raise BranchError(
                    f"the source's {name} no longer opens on the {length} byte(s) it held at the "
                    f"branch point (it holds {len(data)}) — the arm cannot be restored to what "
                    "the source held there")
            out[name] = prefix
        return out

    def _write_once_bytes(self, source_run: Run, entry: dict) -> bytes:
        kind, args = entry["kind"], entry["args"]
        what = f"{kind} {'/'.join(str(a) for a in args)}"
        data = self._read(partial(_WRITE_ONCE[kind], source_run, *args), what)
        if data is None or _sha(data) != entry["sha256"]:
            raise BranchError(
                f"the source's {what} is not the one it held at the branch point "
                f"({'gone' if data is None else 'changed'}) — the arm cannot be restored to "
                "what the source held there")
        return data

    @staticmethod
    def _read(record: Callable[[], RecordHandle], what: str) -> bytes | None:
        """The bytes of the record `record()` names; a record the layout refuses to name or
        the reader refuses to follow (a planted link) is a `BranchError` naming it."""
        try:
            handle = record()
            named = f"{what} (`{handle.path.name}`)"
        except OSError as error:
            raise BranchError(f"the source's {what} could not be named: {error}") from error
        try:
            return _bytes_of(handle)
        except OSError as error:
            raise BranchError(f"the source's {named} could not be read: {error}") from error


def _rows_of(data: bytes) -> list[dict]:
    """The JSONL rows of a table's bytes, in order; a line that is no row is left out."""
    rows = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        row = parse_jsonl_row(line)
        if row is not None:
            rows.append(row)
    return rows


def request_count(prefix: list) -> int:
    """MAIN's request count once the last response of `prefix` (a session's path through a
    response) arrived: one request per response on the path — the snapshot's key."""
    return sum(isinstance(m, ModelResponse) for m in prefix)


def snapshot_at(store: Any, spec: BranchSpec, *, source_run: Run) -> ForkSnapshot | None:
    """The fork snapshot the source recorded for `spec`'s branch point, or `None` when it
    recorded none (or the branch point is not on its MAIN path). Reads only; `validate` is
    what judges the branch point."""
    session = source_session(store, spec, source_run=source_run)
    path = session_store.path_row_ids(store, session)
    if spec.branch_message_id not in path:
        return None
    prefix = session_store.hydrate(store, session, role="analysis")
    return load(store, session, request_count(prefix[: path.index(spec.branch_message_id) + 1]))


def load(store: Any, session_id: str, request: int) -> ForkSnapshot | None:
    """The snapshot `session_id` recorded at its `request`-th response, or `None` when it
    recorded none (a run recorded before #1235's fork snapshots existed, N4). A body this
    reader cannot read is a `BranchError`, never `None`."""
    raw = store.fork_snapshot(session_id, request)
    if raw is None:
        return None
    try:
        body = json.loads(raw)
        if not isinstance(body, dict) or body.get("version") != SNAPSHOT_VERSION:
            raise ValueError(f"version {body.get('version') if isinstance(body, dict) else body!r}")
        down_from_snapshot(body["counters"]["system_down"])
        digest = body["document"]
    except (ValueError, KeyError, TypeError) as error:
        raise BranchError(
            f"the fork snapshot at request {request} cannot be read: {error!r}") from error
    document = None
    if digest is not None:
        document = store.fork_snapshot_blob(digest)
        if document is None or _sha(document.encode("utf-8")) != digest:
            raise BranchError(
                f"the fork snapshot at request {request} names a document the store does not "
                "hold as recorded")
    return ForkSnapshot(body, document)
