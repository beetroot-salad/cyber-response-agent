"""The fork snapshot: what a run held when one of MAIN's responses arrived (#1255 P2, P3).

When a MAIN model response that called tools arrives, before any of its calls run, the host
records (`SnapshotWriter.record`):

  * every per-run counter the model can feel — the budget counters and the circuit breaker
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
import re
import sqlite3
from collections.abc import Callable, Iterator
from typing import Any

from defender._io import parse_jsonl_row
from defender.run_repository import (
    LEAD_CLAIM_SUFFIX,
    REVIEW_RECORD_PREFIX,
    RUN_LAYOUT,
    RecordHandle,
    Run,
    RunPaths,
    artifact_dir,
)

from ..run_state import RunState
from ._spec import BranchError

_logger = logging.getLogger(__name__)

#: The snapshot body's shape version; a body of any other version is not one this reader knows.
SNAPSHOT_VERSION = 1

#: The append-only model-readable files, by the name the snapshot records them under, and the
#: run's own record for each.
_APPEND_ONLY: dict[str, Callable[[Run], RecordHandle]] = {
    "executed_queries": lambda run: run.tables.queries,
    "lessons_loaded": lambda run: run.observability.lessons_loaded,
    "policy_denials": lambda run: run.tables.policy_denials,
}

#: The write-once model-readable files, by kind: the run's record for one, from its arguments.
_WRITE_ONCE: dict[str, Callable[..., RecordHandle]] = {
    "lead_claim": lambda run, lead: run.tables.leads(lead),
    "payload": lambda run, lead, seq: run.tables.payloads(lead, seq),
    "gather_summary": lambda run, lead: run.documents.gather_summaries(lead),
    "review_record": lambda run, turn: run.observability.review_record(turn),
}

_REVIEW_RECORD = re.compile(rf"\A{re.escape(REVIEW_RECORD_PREFIX)}([1-9][0-9]*)\.json\Z")


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
    """Every write-once record the run holds, as `(kind, args)`, by its canonical name only: an
    entry the layout would not name (a planted link, a stray file) is not a record."""
    paths = RunPaths(run.run_dir)
    yield from _gather_raw_files(paths)
    if artifact_dir(paths.gather_summaries):
        for entry in sorted(paths.gather_summaries.iterdir()):
            lead = entry.name.removesuffix(".md")
            if _canonical("gather_summary", (lead,), entry.name):
                yield "gather_summary", (lead,)
    if artifact_dir(run.run_dir):
        for entry in sorted(run.run_dir.iterdir()):
            found = _REVIEW_RECORD.match(entry.name)
            if found is not None:
                yield "review_record", (int(found.group(1)),)


def _gather_raw_files(paths: RunPaths) -> Iterator[tuple[str, tuple[Any, ...]]]:
    """The lead claims and raw payloads under `gather_raw/`, as `_write_once_files` names them."""
    if not artifact_dir(paths.gather_raw):
        return
    for entry in sorted(paths.gather_raw.iterdir()):
        if not artifact_dir(entry):
            lead = entry.name.removesuffix(LEAD_CLAIM_SUFFIX)
            if _canonical("lead_claim", (lead,), entry.name):
                yield "lead_claim", (lead,)
            continue
        for payload in sorted(entry.iterdir()):
            seq = payload.stem
            if seq.isascii() and seq.isdecimal() and _canonical(
                    "payload", (entry.name, int(seq)), payload.name):
                yield "payload", (entry.name, int(seq))


#: The layout's name for each write-once kind, from the record's arguments.
_LAYOUT_NAME: dict[str, Callable[..., str]] = {
    "lead_claim": lambda lead: RUN_LAYOUT.lead_claim(lead).name,
    "payload": lambda lead, seq: RUN_LAYOUT.payload(lead, seq).name,
    "gather_summary": lambda lead: RUN_LAYOUT.gather_summary(lead).name,
}


def _canonical(kind: str, args: tuple[Any, ...], actual: str) -> bool:
    """Whether `actual` is exactly the name the layout gives that record (`False` when the
    layout refuses its components)."""
    try:
        return _LAYOUT_NAME[kind](*args) == actual
    except ValueError:
        return False


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
        self._digests: dict[tuple[str, tuple[Any, ...]], str] = {}

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
                data = _bytes_of(_WRITE_ONCE[kind](run, *args))
                if data is None:
                    continue
                self._digests[key] = _sha(data)
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
        rows = _rows_of(prefixes["executed_queries"])
        if prefixes["executed_queries"]:
            run.tables.queries.seed(rows)
        lessons = prefixes["lessons_loaded"]
        if lessons:
            run.observability.lessons_loaded.append(_rows_of(lessons))
        denials = prefixes["policy_denials"]
        if denials:
            run.tables.policy_denials.start_stream(denials.decode("utf-8"))
        for name, record in _APPEND_ONLY.items():
            if (_bytes_of(record(run)) or b"") != prefixes[name]:
                raise BranchError(
                    f"the arm's {record(run).path.name} does not hold the {len(prefixes[name])} byte(s) the "
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
            handle = record(source_run)
            data = self._read(handle, handle.path.name) or b""
            length = int(recorded["length"])
            prefix = data[:length]
            if len(data) < length or _sha(prefix) != recorded["sha256"]:
                raise BranchError(
                    f"the source's {handle.path.name} no longer opens on the {length} byte(s) "
                    "it held at "
                    f"the branch point (it holds {len(data)}) — the arm cannot be restored to "
                    "what the source held there")
            out[name] = prefix
        return out

    def _write_once_bytes(self, source_run: Run, entry: dict) -> bytes:
        handle = _WRITE_ONCE[entry["kind"]](source_run, *entry["args"])
        what = f"{entry['kind']} {handle.path.relative_to(source_run.run_dir)}"
        data = self._read(handle, what)
        if data is None or _sha(data) != entry["sha256"]:
            raise BranchError(
                f"the source's {what} is not the one it held at the branch point "
                f"({'gone' if data is None else 'changed'}) — the arm cannot be restored to "
                "what the source held there")
        return data

    @staticmethod
    def _read(record: RecordHandle, what: str) -> bytes | None:
        try:
            return _bytes_of(record)
        except OSError as error:
            raise BranchError(f"the source's {what} could not be read: {error}") from error


def _rows_of(data: bytes) -> list[dict]:
    """The JSONL rows of a table's bytes, in order (a line that is no row is left out; the
    read-back comparison then refuses the restore)."""
    rows = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        row = parse_jsonl_row(line)
        if row is not None:
            rows.append(row)
    return rows


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
        digest = body["document"]
    except (ValueError, KeyError) as error:
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
