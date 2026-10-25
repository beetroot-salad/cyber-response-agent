"""The file-backed `Run` handle: five sub-collections, a `RunRecord` value object, and a
per-kind `RecordHandle` every record accessor answers."""
from __future__ import annotations

from defender.records._locations import (RunsBase, _unwrap_runs_base, _unwrap_session_trust_root)

import contextlib
import dataclasses
import json
from collections.abc import Callable, Iterator
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from defender.records import _alert_input
from defender.records import _artifact_schema
from defender.episodes import _episode_paths
from defender.records import _provenance
from defender.records import _report
from defender import _io as _real_io
from defender.run_repository import _layout
from defender.run_repository._id import RunId
from defender.run_repository._layout import RUN_LAYOUT, RunPaths, SessionPaths

#: The five groups, addressed group-then-kind.
GROUPS = ("tables", "facts", "documents", "observability", "session")

#: Must mirror `defender/tests/support/shared/contracts/_spec1077.py::GROUP_MEMBERS`, the spec for this table, plus
#: #1255's two host-only sidecars: `call_join` (the query writer's, G4/G6) and
#: `ticket_comments` (the ticket writer's record of its accepted comments, P5).
GROUP_MEMBERS: dict[str, tuple[str, ...]] = {
    "tables": ("queries", "policy_denials", "leads", "payloads", "ticket_reads", "call_join"),
    "facts": ("alert", "alert_record", "provenance", "run_end", "scrub_verdict"),
    "documents": ("investigation", "report", "gather_summaries", "lead_author"),
    "observability": (
        "wire_log", "review_trace", "tool_trace", "review_record",
        "lessons_loaded", "ticket_write", "runtime_html", "box_sentinel", "session_pointer",
        "ticket_comments"),
    "session": ("session_db",),
}
MEMBER_ACCESSOR: dict[str, str] = {
    "queries": "executed_queries", "policy_denials": "policy_denials", "leads": "lead_claim",
    "payloads": "payload", "ticket_reads": "ticket_read",
    "alert": "alert", "alert_record": "alert_record", "provenance": "provenance", "run_end": "run_end_sidecar",
    "scrub_verdict": "scrub_verdict",
    "investigation": "investigation", "report": "report",
    "gather_summaries": "gather_summary", "lead_author": "lead_author",
    "wire_log": "wire_log", "review_trace": "review_trace",
    "tool_trace": "tool_trace",
    "review_record": "review_record", "lessons_loaded": "lessons_loaded",
    "ticket_write": "ticket_write", "runtime_html": "runtime_html",
    "box_sentinel": "box_sentinel", "session_pointer": "session_pointer",
    "session_db": "session_db", "call_join": "call_join",
    "ticket_comments": "ticket_comments",
}
#: The one write verb per member — per record, not per group, since the group only says how a
#: record is read. `append` (JSONL), `write` (whole document or write-once fact), `open`
#: (session store), or none. (No `update` member remains: the two `flock`ed JSON states, the
#: budget and the breaker, became the run process's memory in #1235.)
MEMBER_VERB: dict[str, str | None] = {
    "queries": "append", "policy_denials": "append", "leads": "write", "payloads": "write",
    "ticket_reads": "write",
    "alert": "write", "alert_record": "write", "provenance": "write", "run_end": "write", "scrub_verdict": "write",
    "investigation": "write", "report": "write", "gather_summaries": "write",
    "lead_author": None,
    "wire_log": "append", "review_trace": "append",
    "tool_trace": "append", "review_record": "write", "lessons_loaded": "append",
    "ticket_write": "write",
    "runtime_html": "write", "box_sentinel": "write", "session_pointer": "write",
    "session_db": "open", "call_join": "append", "ticket_comments": "append",
}
# The capability table is authoritative; MEMBER_VERB retains the primary-verb API.
MEMBER_CAPABILITIES = {name: frozenset((verb,)) if verb else frozenset()
                       for name, verb in MEMBER_VERB.items()}
for _member, _added in {
    "queries": ("seed",), "alert_record": ("replace",),
    "payloads": ("ensure_parent",), "gather_summaries": ("ensure_parent",),
    "investigation": ("seed",), "ticket_write": ("delete",),
    "wire_log": ("append_text", "start_stream"),
    "policy_denials": ("append_text", "start_stream"), "review_trace": ("append_text",),
}.items():
    MEMBER_CAPABILITIES[_member] |= frozenset(_added)
for _member in ("wire_log", "policy_denials", "review_trace"):
    MEMBER_CAPABILITIES[_member] -= frozenset({"append"})

UPWARD_ACCESSORS = (
    "run_end_sidecar", "scrub_verdict", "ticket_write", "session_pointer", "sessions_dir",
    "session_db", "call_join", "ticket_comments")
#: The sidecars sit directly in the runs base, so they are anchored there. (The session db's
#: `open_store` anchors its own directory.)
_SIDECAR_MEMBERS = ("run_end", "scrub_verdict", "ticket_write", "session_pointer", "call_join",
                    "ticket_comments")
#: Written once through the exclusive lane (a second lead claim must collide). The scrub
#: verdict is a fact too but is rewritten, so it uses `replace` like every other `write`.
_WRITE_ONCE_MEMBERS = frozenset({"alert", "alert_record", "provenance", "leads"})
#: The two model-authored documents, held to their content schema at every write.
_SCHEMA_GATED_MEMBERS = {"investigation": RUN_LAYOUT.investigation.name,
                         "report": RUN_LAYOUT.report.name}

#: Members whose owner accessor takes a caller-supplied component: `run.<group>.<name>` answers
#: a callable taking the same positional args and returning the `RecordHandle`.
_COMPOSING_MEMBERS = frozenset({
    "leads", "payloads", "ticket_reads", "gather_summaries", "review_trace",
    "review_record", "session_db",
})


def _jsonl_text(rows: list[dict]) -> str:
    """Encode table rows with the same JSON defaults and insertion order for every writer."""
    return "".join(json.dumps(row) + "\n" for row in rows)  # lint-jsonl-io: ok — serialized rows go whole to the rooted write seam


class RecordHandle:
    """A thin per-kind wrapper: `.path` plus read and the record's own verb, delegating to the
    existing seams."""

    if TYPE_CHECKING:
        write: Callable[[str | bytes], None]
    _lineage_id: Any
    _sessions_runs_base: RunsBase | None

    def __init__(
        self, resolve: Callable[[], Path], *, io: Any, root: Callable[[], Path], group: str,
        member: str, on_partial_failure: Any = None,
        session_args: tuple[Any, RunsBase | None] | None = None,
        prepare_write: Callable[[], None] | None = None,
    ) -> None:
        self._resolve = resolve
        self._io = io
        # A thunk, so a `Run.at` handle only raises for a missing runs base when a write needs it.
        self._root = root
        self._group = group
        self._member = member
        self._on_partial_failure = on_partial_failure
        self._prepare_write = prepare_write
        if member == "session_db":
            from defender.runtime import session_store

            self.open_store = session_store.open_store
            self._lineage_id, self._sessions_runs_base = session_args or (None, None)
        operations = {
            "write": self._do_write, "append": self._do_append, "open": self._do_open,
            "replace": self._do_replace,
            "seed": self._do_seed_queries if member == "queries" else self._do_seed,
            "delete": self._do_delete,
            "append_text": self._do_append_text, "start_stream": self._do_start_stream,
            "ensure_parent": self._do_ensure_parent,
        }
        for capability in MEMBER_CAPABILITIES[member]:
            setattr(self, capability, operations[capability])

    @property
    def path(self) -> Path:
        return self._resolve()

    def _address(self) -> tuple[Path, PurePosixPath]:
        """The record's trust root and its name relative to it. The owner builds the path
        first, so its refusals (a malformed component, `_confine`) fire before any I/O."""
        p = self.path
        root = self._root()
        return root, PurePosixPath(p.relative_to(root).as_posix())

    def read(self) -> str | None:
        root, name = self._address()
        text, _reason = self._io.rooted_read(root, name)
        return text

    def _read_bound(self, operation: str, **kwargs: Any) -> Any:
        try:
            root, name = self._address()
            with self._io.bind(root) as bound:
                return getattr(bound, operation)(name, **kwargs)
        except OSError as error:
            kind = _real_io._refused_by(error)
            result = _real_io.RecordRead("", False, str(error), None, kind)
            if operation == "read_bytes":
                return _real_io.BytesRead("", False, str(error), None, kind)
            return ([], 0, result) if operation == "read_jsonl" else result

    def read_result(self, *, errors: str = "strict") -> _real_io.RecordRead:
        if errors not in ("strict", "replace"):
            raise ValueError("errors must be strict or replace")
        return self._read_bound("read", errors=errors)

    def read_bytes(self) -> _real_io.BytesRead:
        return self._read_bound("read_bytes")

    def read_rows(self) -> tuple[list[dict], int, _real_io.RecordRead]:
        return self._read_bound("read_jsonl")

    def _mutate(self, text: str | bytes, mode: str) -> None:
        root, name = self._address()
        self._mkdir(root, name)
        self._io.rooted_write(root, name, text, mode=mode)

    def _do_ensure_parent(self) -> None:
        root, name = self._address()
        self._mkdir(root, name)

    def _do_replace(self, text: str | bytes) -> None:
        self._mutate(text, "replace")

    def _do_append_text(self, text: str) -> None:
        self._mutate(text, "append")

    def _do_start_stream(self, text: str) -> None:
        self._mutate(text, "replace")

    def _do_seed_queries(self, rows: list[dict] | bytes) -> None:
        """Replace the selected snapshot; sibling freshness belongs to the caller. `bytes` is a
        table recorded elsewhere, written as it is (a branch arm's restore copies its source's
        table cut to the snapshot's length, damaged lines and all, #1255 P2); rows are encoded
        as every table writer encodes them."""
        self._mutate(rows if isinstance(rows, bytes) else _jsonl_text(rows), "replace")

    def _do_seed(self, text: str) -> None:
        from defender.runtime.branch._seed import refuse_seeded_run_dir

        root, _name = self._address()
        refuse_seeded_run_dir(root)
        reason = _artifact_schema.validate_artifact(RUN_LAYOUT.investigation.name, text, text)
        if reason is not None:
            raise ValueError(f"run.documents.investigation: {reason}")
        self._mutate(text, "replace")

    def _do_delete(self) -> None:
        root, name = self._address()
        self._io.rooted_unlink(root, name)

    def _mkdir(self, root: Path, name: PurePosixPath) -> None:
        self._io.rooted_mkdir(root, name.parent)

    def _do_write(self, text: str | bytes) -> None:
        if self._prepare_write is not None:
            try:
                self._prepare_write()
            except OSError as error:
                # Keep an existing owner-address refusal's class, errno and alias marker.
                # Preparation still identifies this as a holding-folder fault to claimers.
                try:
                    self._address()
                except OSError as address_error:
                    address_error.record_parent_refused = True  # type: ignore[attr-defined]  # OSError carries the same dynamic refusal metadata as write_guarded_alias
                    raise address_error from error
                error.record_parent_refused = True  # type: ignore[attr-defined]  # dynamic refusal metadata, as in _io._mark_alias
                raise
        root, name = self._address()
        schema_name = _SCHEMA_GATED_MEMBERS.get(self._member)
        if schema_name is not None:
            current = self.read() if self._member == "investigation" else None
            proposed = text.decode("utf-8") if isinstance(text, bytes) else text
            reason = _artifact_schema.validate_artifact(schema_name, proposed, current)
            if reason is not None:
                raise ValueError(f"run.{self._group}.{self._member}: {reason}")
        if self._prepare_write is None:
            self._mkdir(root, name)
        if self._member in _WRITE_ONCE_MEMBERS:
            # Stays a `FileExistsError` (an `OSError`) so callers' OSError arms still catch it.
            try:
                self._io.rooted_write(root, name, text, mode="create")
            except FileExistsError as taken:
                raise FileExistsError(
                    taken.errno, f"{root / name} already exists — run.{self._group}.{self._member} is "
                    "write-once") from taken
            return
        self._io.rooted_write(root, name, text, mode="replace")

    def _do_append(self, rows: list[dict]) -> None:
        if not rows:
            return
        root, name = self._address()
        # Outside the `try`: a refused holding folder raises even for observability.
        self._mkdir(root, name)
        # One guarded append for the batch; a plain `open("a")` would follow a planted link.
        text = _jsonl_text(rows)
        try:
            self._io.rooted_write(root, name, text, mode="append")
        except OSError:
            if self._group != "observability" or self._on_partial_failure is None:
                raise
            self._on_partial_failure(f"{self._member}: append failed")

    def _do_open(self):
        # Resolve first so the owner's refusals apply to `.open()` as to `.path`.
        _ = self.path
        assert self._sessions_runs_base is not None  # resolved above: a bare Run.at refused
        return self.open_store(case_id=self._lineage_id,
                               sessions=SessionPaths(self._sessions_runs_base))


class _RecordHandleGroup:
    """`run.<group>` — the group's own members, each a `RecordHandle`."""

    def __init__(self, run: Run, group: str) -> None:
        self._run = run
        self._group = group

    @property
    def members(self) -> tuple[str, ...]:
        return GROUP_MEMBERS[self._group]

    def __getattr__(self, name: str) -> Any:
        if name not in GROUP_MEMBERS.get(self._group, ()):
            raise AttributeError(name)
        return self._run._member_accessor(self._group, name)


@dataclasses.dataclass(frozen=True)
class RunRecord:
    """The run's descriptive fields, read-only, through the existing readers."""

    tenant_id: str | None
    world_id: str | None
    commit: str | None
    dirty: bool | None
    model: str | None
    run_id: str
    alert_ref: str | None
    parent_run_id: str | None
    fork_turn: int | None
    exit_class: str | None
    disposition: str | None
    review_outcome: str | None
    faults: tuple[str, ...] = ()


#: A handle's address: set once in `Run.__init__`, never reassigned or deleted (#1105 O5.13,
#: the frozen-dataclass convention). The groups and `partial_failures` stay its own state.
_ADDRESS = frozenset({"run_dir", "runs_base", "tenant_id"})


class Run:
    """The file-backed run handle, addressed by `(tenant_id, run_id)`."""

    #: The five sub-collections, bound per instance in `__init__`.
    tables: _RecordHandleGroup
    facts: _RecordHandleGroup
    documents: _RecordHandleGroup
    observability: _RecordHandleGroup
    session: _RecordHandleGroup
    #: The address (frozen, `_ADDRESS`): the run folder and the runs base holding it (`None`
    #: on a `Run.at` handle), and the tenant half — present on an `under` handle, absent on
    #: `at`.
    run_dir: Path
    runs_base: RunsBase | None
    tenant_id: str

    def __init__(
        self, run_dir: Path, *, runs_base: RunsBase | None, io: Any = _real_io,
        tenant_id: str | None = None,
    ) -> None:
        # The address is frozen once built (#1105 O5.13): `__setattr__` refuses these names.
        object.__setattr__(self, "run_dir", Path(run_dir))
        object.__setattr__(self, "runs_base", runs_base)
        # The address's tenant, not the stamp's (that is `run.record.tenant_id`). A `Run.at`
        # handle has no address and no such attribute.
        if tenant_id is not None:
            object.__setattr__(self, "tenant_id", tenant_id)
        self._io = io
        self.partial_failures: tuple[str, ...] = ()
        for group in GROUPS:
            setattr(self, group, _RecordHandleGroup(self, group))

    def __setattr__(self, name: str, value: object) -> None:
        if name in _ADDRESS:
            raise AttributeError(f"a Run's address is frozen; cannot assign {name!r}")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if name in _ADDRESS:
            raise AttributeError(f"a Run's address is frozen; cannot delete {name!r}")
        object.__delattr__(self, name)

    @property
    def subcollections(self) -> tuple[str, ...]:
        return GROUPS

    def knowledge_status(self) -> Any:
        """How this run came by its tenant knowledge, and which commit it read (#1108 P4, U12):
        `records._knowledge_status`'s rule over the host-held record beside the run folder,
        where no box writes — the one source of a run's knowledge commit for anything that
        acts on it. `None` for a run from before records were written."""
        from defender.records._knowledge_status import read_knowledge_status

        paths = RunPaths(self.run_dir)
        return read_knowledge_status(paths.knowledge_source(), paths.provenance)

    @property
    def id(self) -> RunId:
        """The address's run half, as a `RunId` (the run folder's own name, which the
        constructors admitted). Not `run_id`: that is one of the twelve descriptive fields,
        which live on `RunRecord` (fork D-F2) — `run.record.run_id` is what the stamp says."""
        return RunId.parse(self.run_dir.name)

    def runs_base_export(self) -> str:
        """The value `DEFENDER_RUNS_BASE` carries for this run's children (its container), as
        the layout owner hands it out (`RunPaths.runs_base_export`, #1105 PR 2)."""
        return RunPaths(self.run_dir).runs_base_export()

    def make_run_dir(self) -> None:
        """Make the run folder and its `gather_raw/` (run setup), judged component by component
        from the container — the trust root this handle holds — so a link at the run id or at
        `gather_raw` is refused and nothing above the container is judged. The container is
        never handed out for it (#1105 PR 2, J15)."""
        self._io.guarded_mkdir(RunPaths(self.run_dir).gather_raw,
                               base=_unwrap_runs_base(self._runs_base_for("make_run_dir", "gather_raw")))

    @contextlib.contextmanager
    def reader(self) -> Iterator[_real_io.Bound]:
        """A no-follow reader over this run's folder (#1105 D-read), for a caller that reads the
        run's records as one bound tree (the episode page's per-arm reads): the container is
        held no-follow — a link there is refused — and every read walks no-follow below it,
        so the caller formats no path. Held for the `with` block only. A handle built from a
        bare directory (`Run.at`) holds no container and refuses (`ValueError`)."""
        held = self._io.hold(_unwrap_runs_base(self._runs_base_for("reader", "run folder")), follow=False)
        try:
            yield held.view().under(self.run_dir.name)
        finally:
            held.close()

    def _record_partial_failure(self, note: str) -> None:
        self.partial_failures = (*self.partial_failures, note)

    def _runs_base_for(self, group: str, name: str) -> RunsBase:
        if self.runs_base is None:
            raise ValueError(
                f"run.{group}.{name} needs the runs base, which this handle does not hold — "
                "it was built from a bare directory (Run.at)")
        return self.runs_base

    def _member_accessor(self, group: str, name: str) -> Any:
        attr = MEMBER_ACCESSOR[name]
        composing = name in _COMPOSING_MEMBERS
        upward = attr in UPWARD_ACCESSORS

        def build(*args: Any) -> RecordHandle:
            def resolve() -> Path:
                target = getattr(RunPaths(self.run_dir), attr)
                if upward:
                    return target(self._runs_base_for(group, name), *args)
                # Whether the owner's accessor is CALLED is a fact of the member table, never
                # of how many arguments arrived: a composing accessor with every component
                # defaulted (`review_record()` → turn 1) is still a call.
                return target(*args) if composing else target

            def trust_root() -> Path:
                if name in _SIDECAR_MEMBERS:
                    return _unwrap_runs_base(self._runs_base_for(group, name))
                if name == "session_db":
                    return _unwrap_session_trust_root(SessionPaths(self._runs_base_for(group, name)).trust_root)
                return self.run_dir

            def prepare_write() -> None:
                # Claims historically prepare their folder before judging the leaf. Validate
                # the component first, so an addressing bug still performs no I/O.
                RUN_LAYOUT.lead_claim(*args)
                self._io.rooted_mkdir(self.run_dir, RUN_LAYOUT.gather_raw)

            session_args = (args[0], self.runs_base) if name == "session_db" and args else None
            return RecordHandle(
                resolve, io=self._io, root=trust_root, group=group, member=name,
                on_partial_failure=self._record_partial_failure, session_args=session_args,
                prepare_write=prepare_write if name == "leads" else None)

        return build if composing else build()

    # -- constructors --------------------------------------------------------------------------

    @classmethod
    def under(
        cls, runs_base: RunsBase, run_id: str | RunId, *, io: Any = _real_io,
        tenant_id: str | None = None,
    ) -> Run:
        """The no-I/O builder the repository's opens and creates share — not a public front
        door. The id is a `RunId`, or text `RunId.parse` admits (`RunRefused` otherwise): the
        repository has one admission rule, so no handle is built for a run whose sidecar files
        could not be named."""
        name = str(run_id if isinstance(run_id, RunId) else RunId.parse(run_id))
        folder = _unwrap_runs_base(runs_base)
        return cls(folder / name, runs_base=runs_base, io=io, tenant_id=tenant_id)

    @classmethod
    def at(cls, directory: Path) -> Run:
        """The eval/fixture/tooling escape hatch — directory walkers, test fixtures, and the
        archive/branch machinery. Accepts any existing directory without inspecting it; not the
        live investigation path (that is the tenant's repository)."""
        directory = Path(directory)
        if not directory.is_dir():
            raise ValueError(f"{directory} is not an existing directory")
        return cls(directory, runs_base=None)

    # -- the record -----------------------------------------------------------------------------

    @property
    def record(self) -> RunRecord:
        owner = RunPaths(self.run_dir)
        faults: list[str] = []
        # Reads go through `io`, which refuses planted aliases (e.g. a symlinked `alert.json`
        # would make `alert_ref` hash bytes outside the run).
        prov = self._provenance(faults)
        exit_class = self._exit_class(owner, faults) if self.runs_base is not None else None
        disposition, review_outcome = self._report_fields()
        alert_ref = self._alert_ref()
        return RunRecord(
            tenant_id=prov.tenant_id if prov is not None else None,
            world_id=prov.world_id if prov is not None else None,
            commit=prov.commit if prov is not None else None,
            dirty=prov.dirty if prov is not None else None,
            model=prov.model if prov is not None else None,
            run_id=self.run_dir.name,
            alert_ref=alert_ref,
            # Lineage comes from the stamp, never a `family.yaml` guessed from the runs base.
            parent_run_id=prov.parent_run_id if prov is not None else None,
            fork_turn=prov.fork_turn if prov is not None else None,
            exit_class=exit_class,
            disposition=disposition,
            review_outcome=review_outcome,
            faults=tuple(faults),
        )

    def _alert_ref(self) -> str | None:
        """The run's curation key, from its record's digest — `None` for a folder with no
        record. A stored alert whose bytes no longer match the record is refused
        (`AlertReplaced`, naming the run): the key must never follow replaced bytes."""
        record_text, _reason = self._io.rooted_read(self.run_dir, RUN_LAYOUT.alert_record)
        record = None if record_text is None else _alert_input.parse_alert_record(record_text)
        if record is None:
            return None
        alert_bytes, _reason = self._io.rooted_read(
            self.run_dir, RUN_LAYOUT.alert, binary=True)
        if alert_bytes is not None and _alert_input.digest_of(alert_bytes) != record.digest:
            raise _alert_input.AlertReplaced(
                f"the alert stored for run {self.run_dir.name} does not match the digest its "
                "record carries — the run's input was replaced or damaged, and nothing is "
                "read from it")
        return case_ref_of_digest(record.digest)

    def _provenance(self, faults: list[str]) -> _provenance.RunProvenance | None:
        raw, _reason = self._io.rooted_read(self.run_dir, RUN_LAYOUT.provenance)
        if raw is None:
            return None
        try:
            parsed = json.loads(raw)
        except ValueError:
            faults.append("provenance: unparseable")
            return None
        if not isinstance(parsed, dict):
            faults.append("provenance: wrong shape")
            return None
        prov = _provenance.RunProvenance.from_obj(parsed)
        if prov is None:
            faults.append("provenance: wrong shape")
        for field in ("tenant_id", "world_id"):
            v = parsed.get(field)
            if v is not None and not isinstance(v, str):
                faults.append(f"provenance: {field} is wrong-shaped")
        return prov

    def _exit_class(self, owner: RunPaths, faults: list[str]) -> str | None:
        from defender.runtime import run_end as run_end_mod

        assert self.runs_base is not None
        sidecar_text, _reason = self._io.rooted_read(
            _unwrap_runs_base(self.runs_base), owner.run_end_sidecar(self.runs_base).name)
        if sidecar_text is None:
            return None
        try:
            doc = json.loads(sidecar_text)
        except ValueError:
            faults.append("run_end: unparseable")
            return None
        rec = run_end_mod.parse_record(doc)
        if rec is None:
            faults.append("run_end: wrong shape")
            return None
        return rec.truncated_by

    def _report_fields(self) -> tuple[str | None, str | None]:
        report_text, _reason = self._io.rooted_read(self.run_dir, RUN_LAYOUT.report)
        if report_text is None:
            return None, None
        read = _report.parse_report_text(report_text)
        fm = read.frontmatter
        outcome = fm.get("outcome") if isinstance(fm, dict) else None
        return read.disposition, (outcome if isinstance(outcome, str) else None)

def case_ref_of_digest(digest: str) -> str:
    """The curation key a run is known by: `case-<the alert's sha256 digest>[:16]`, the digest
    its record carries."""
    return f"case-{digest[:16]}"


def case_ref(alert_bytes: bytes) -> str:
    """`case_ref_of_digest` for alert bytes in hand."""
    return case_ref_of_digest(_alert_input.digest_of(alert_bytes))


# ---------------------------------------------------------------------------------------
# ArchivedWorld — the archive projection's read-only handle; not a `Run`.
# ---------------------------------------------------------------------------------------

#: The copied set, each name from its owner: run-dir names from `_layout`, the archive's
#: re-homed sidecar names from `_episode_paths`.
_ARCHIVED_WORLD_NAMES: dict[str, str] = {
    "report": _layout.REPORT, "investigation": _layout.INVESTIGATION,
    "provenance": _layout.PROVENANCE,
    "scrub_verdict": _episode_paths.ARCHIVED_SCRUB_VERDICT_NAME,
    "run_end": _episode_paths.ARCHIVED_RUN_END_NAME,
    "lessons_loaded": _layout.LESSONS_LOADED, "alert": _layout.ALERT,
    "gather_summaries": _layout.GATHER_SUMMARIES_DIRNAME,
    "executed_queries": _layout.EXECUTED_QUERIES,
    "gather_raw": _layout.RAW_MARKER,
}


class _ArchivedRecordHandle:
    def __init__(self, world_dir: Path, name: str, *, io: Any) -> None:
        self._world_dir = world_dir
        self._name = name
        self._io = io

    @property
    def path(self) -> Path:
        return self._world_dir / self._name

    def read(self) -> str | None:
        text, _reason = self._io.rooted_read(self._world_dir, self._name)
        return text


class ArchivedWorld:
    """A read-only projection of an archived `worlds/<world UUID>/` directory — exactly the copied
    set. Not a `Run`: no `.record`, not addressed by `(tenant_id, run_id)`."""

    def __init__(self, world_dir: Path, *, io: Any = _real_io) -> None:
        self.world_dir = Path(world_dir)
        self._io = io

    @classmethod
    def at(cls, world_dir: Path) -> ArchivedWorld:
        return cls(world_dir)

    @property
    def members(self) -> tuple[str, ...]:
        return tuple(_ARCHIVED_WORLD_NAMES)

    def __getattr__(self, name: str) -> Any:
        if name not in _ARCHIVED_WORLD_NAMES:
            raise AttributeError(name)
        return _ArchivedRecordHandle(self.world_dir, _ARCHIVED_WORLD_NAMES[name], io=self._io)
