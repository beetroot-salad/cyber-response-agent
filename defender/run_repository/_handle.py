"""The file-backed `Run` handle: five sub-collections, a `RunRecord` value object, and a
per-kind `RecordHandle` every record accessor answers.

`Run.for_tenant(tenant_id, run_id, *, runs_base, io=)` is the constructor run setup uses; it
refuses a runs folder with no tenant record. `Run.at(directory)` is the eval/fixture/tooling
escape hatch with no runs base. `Run.under` builds the handle with no I/O: `for_tenant` uses it
after judging the record, and so does the repository's `open_run`, which judged the record
through its own held runs folder. Outside the package every constructor is gated by
`scripts/lint/lint_run_layout_imports.py`; application code gets a `Run` from `open_run`.

Every accessor answers a `RecordHandle` (`.path`, `.read`, and the record's own write verb),
never parsed contents. Asking for `.path` creates nothing; writes create the holding directory
through the same injected `io=` seam as every read.

Every read and write goes through the rooted seam (`_io.rooted_read`, `rooted_mkdir`,
`rooted_write`, `rooted_locked_for_rewrite`): the record's trust root, whose spelling is
followed, and its name relative to that root, which never is (#1111). The trust root is the run
dir; the runs base for the four sidecars; `SessionPaths(runs_base).trust_root` for the session
db. The session db itself is opened through `session_store.open_store`. The two model-authored documents are validated against
`_artifact_schema` at every write, so no writer bypasses the schema.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from defender import _artifact_schema, _episode_paths, _provenance, _report
from defender import _io as _real_io
from defender import _tenant
from defender._run_id import refuse_bad_run_id
from defender.run_repository import _layout
from defender.run_repository._layout import RUN_LAYOUT, RunPaths, SessionPaths

#: The five groups, addressed group-then-kind.
GROUPS = ("tables", "facts", "documents", "observability", "session")

#: Must mirror `defender/tests/_spec1077.py::GROUP_MEMBERS`, the spec for this table.
GROUP_MEMBERS: dict[str, tuple[str, ...]] = {
    "tables": ("queries", "policy_denials", "leads", "payloads", "ticket_reads"),
    "facts": ("alert", "provenance", "run_end", "scrub_verdict", "accounting"),
    "documents": ("investigation", "report", "gather_summaries", "lead_author", "source_refs"),
    "observability": (
        "wire_log", "review_trace", "forward_check_trace", "tool_trace", "review_record",
        "budget", "circuit_breaker", "lessons_loaded", "ticket_write", "runtime_html",
        "box_sentinel", "session_pointer"),
    "session": ("session_db",),
}
MEMBER_ACCESSOR: dict[str, str] = {
    "queries": "executed_queries", "policy_denials": "policy_denials", "leads": "lead_claim",
    "payloads": "payload", "ticket_reads": "ticket_read",
    "alert": "alert", "provenance": "provenance", "run_end": "run_end_sidecar",
    "scrub_verdict": "scrub_verdict", "accounting": "accounting_failures",
    "investigation": "investigation", "report": "report",
    "gather_summaries": "gather_summary", "lead_author": "lead_author",
    "source_refs": "source_refs",
    "wire_log": "wire_log", "review_trace": "review_trace",
    "forward_check_trace": "forward_check_trace", "tool_trace": "tool_trace",
    "review_record": "review_record", "budget": "budget",
    "circuit_breaker": "circuit_breaker", "lessons_loaded": "lessons_loaded",
    "ticket_write": "ticket_write", "runtime_html": "runtime_html",
    "box_sentinel": "box_sentinel", "session_pointer": "session_pointer",
    "session_db": "session_db",
}
#: The one write verb per member — per record, not per group, since the group only says how a
#: record is read. `append` (JSONL), `write` (whole document or write-once fact), `update` (the
#: `flock`ed JSON states), `open` (session store), or none.
MEMBER_VERB: dict[str, str | None] = {
    "queries": "append", "policy_denials": "append", "leads": "write", "payloads": "write",
    "ticket_reads": "write",
    "alert": "write", "provenance": "write", "run_end": "write", "scrub_verdict": "write",
    "accounting": "write",
    "investigation": "write", "report": "write", "gather_summaries": "write",
    "lead_author": None, "source_refs": "write",
    "wire_log": "append", "review_trace": "append", "forward_check_trace": "append",
    "tool_trace": "append", "review_record": "write", "budget": "update",
    "circuit_breaker": "update", "lessons_loaded": "append", "ticket_write": "write",
    "runtime_html": "write", "box_sentinel": "write", "session_pointer": "write",
    "session_db": "open",
}
UPWARD_ACCESSORS = (
    "run_end_sidecar", "scrub_verdict", "accounting_failures", "ticket_write", "sessions_dir",
    "session_db")
#: The four sidecars sit directly in the runs base, so they are anchored there. (The session
#: db's `open_store` anchors its own directory.)
_SIDECAR_MEMBERS = ("run_end", "scrub_verdict", "accounting", "ticket_write")
#: Written once through the exclusive lane (a second lead claim must collide). The scrub
#: verdict and accounting counter are facts too but are rewritten, so they use `replace` like
#: every other `write`.
_WRITE_ONCE_MEMBERS = frozenset({"alert", "provenance", "run_end", "leads"})
#: The two model-authored documents, held to their content schema at every write.
_SCHEMA_GATED_MEMBERS = {"investigation": RUN_LAYOUT.investigation.name,
                         "report": RUN_LAYOUT.report.name}

#: Members whose owner accessor takes a caller-supplied component: `run.<group>.<name>` answers
#: a callable taking the same positional args and returning the `RecordHandle`.
_COMPOSING_MEMBERS = frozenset({
    "leads", "payloads", "ticket_reads", "gather_summaries", "review_trace",
    "review_record", "forward_check_trace", "session_db",
})


class RecordHandle:
    """A thin per-kind wrapper: `.path` plus read and the record's own verb, delegating to the
    existing seams."""

    def __init__(
        self, resolve: Callable[[], Path], *, io: Any, root: Callable[[], Path], group: str,
        member: str, on_partial_failure: Any = None,
        session_args: tuple[Any, ...] | None = None,
    ) -> None:
        self._resolve = resolve
        self._io = io
        # A thunk, so a `Run.at` handle only raises for a missing runs base when a write needs it.
        self._root = root
        self._group = group
        self._member = member
        self._verb = MEMBER_VERB[member]
        self._on_partial_failure = on_partial_failure
        if member == "wire_log":
            from defender.runtime import observe

            self.logger_factory = observe.RequestLogger
        if member == "session_db":
            from defender.runtime import session_store

            self.open_store = session_store.open_store
            self._lineage_id, self._sessions_runs_base = session_args or (None, None)
        # Only the record's own verb is a public attribute; tests check the others are absent.
        if self._verb == "write":
            self.write = self._do_write
        elif self._verb == "append":
            self.append = self._do_append
        elif self._verb == "update":
            self.update = self._do_update
        elif self._verb == "open":
            self.open = self._do_open

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

    def _mkdir(self, root: Path, name: PurePosixPath) -> None:
        self._io.rooted_mkdir(root, name.parent)

    def _do_write(self, text: str | bytes) -> None:
        root, name = self._address()
        schema_name = _SCHEMA_GATED_MEMBERS.get(self._member)
        if schema_name is not None:
            current, _reason = self._io.rooted_read(root, name)
            proposed = text.decode("utf-8") if isinstance(text, bytes) else text
            reason = _artifact_schema.validate_artifact(schema_name, proposed, current)
            if reason is not None:
                raise ValueError(f"run.{self._group}.{self._member}: {reason}")
        self._mkdir(root, name)
        if self._member in _WRITE_ONCE_MEMBERS:
            # Stays a `FileExistsError` (an `OSError`) so callers' OSError arms still catch it.
            try:
                self._io.rooted_write(root, name, text, mode="create")
            except FileExistsError as taken:
                raise FileExistsError(
                    f"{root / name} already exists — run.{self._group}.{self._member} is "
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
        text = "".join(json.dumps(row) + "\n" for row in rows)  # lint-jsonl-io: ok — the rows are handed whole to the guarded append seam, not to a line loop over an open handle  # noqa: E501
        try:
            self._io.rooted_write(root, name, text, mode="append")
        except OSError:
            if self._group != "observability" or self._on_partial_failure is None:
                raise
            self._on_partial_failure(f"{self._member}: append failed")

    def _do_update(self, patch: dict) -> None:
        root, name = self._address()
        self._mkdir(root, name)
        with self._io.rooted_locked_for_rewrite(root, name) as f:
            f.seek(0)
            raw = f.read()
            try:
                current = json.loads(raw) if raw.strip() else {}
            except ValueError:
                current = {}
            if not isinstance(current, dict):
                current = {}
            current.update(patch)
            f.seek(0)
            f.truncate()
            f.write(json.dumps(current))

    def _do_open(self):
        # Resolve first so the owner's refusals apply to `.open()` as to `.path`.
        _ = self.path
        return self.open_store(case_id=self._lineage_id, runs_base=self._sessions_runs_base)


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
    #: on a `Run.at` handle), and the tenant half — present on a `for_tenant`/`under` handle,
    #: absent on `at`.
    run_dir: Path
    runs_base: Path | None
    tenant_id: str

    def __init__(
        self, run_dir: Path, *, runs_base: Path | None, io: Any = _real_io,
        tenant_id: str | None = None,
    ) -> None:
        # The address is frozen once built (#1105 O5.13): `__setattr__` refuses these names.
        object.__setattr__(self, "run_dir", Path(run_dir))
        object.__setattr__(self, "runs_base", Path(runs_base) if runs_base is not None else None)
        # The address's tenant, not the stamp's (that is `run.record.tenant_id`; `for_tenant`
        # ensures they agree). A `Run.at` handle has no address and no such attribute.
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

    def _record_partial_failure(self, note: str) -> None:
        self.partial_failures = (*self.partial_failures, note)

    def _runs_base_for(self, group: str, name: str) -> Path:
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
                    return self._runs_base_for(group, name)
                if name == "session_db":
                    return SessionPaths(self._runs_base_for(group, name)).trust_root
                return self.run_dir

            session_args = (args[0], self.runs_base) if name == "session_db" and args else None
            return RecordHandle(
                resolve, io=self._io, root=trust_root, group=group, member=name,
                on_partial_failure=self._record_partial_failure, session_args=session_args)

        return build if composing else build()

    # -- constructors --------------------------------------------------------------------------

    @classmethod
    def for_tenant(
        cls, tenant_id: str, run_id: str, *, runs_base: Path, io: Any = _real_io,
    ) -> Run:
        """The constructor run setup uses, once the tenant record exists. Refuses when
        `runs_base` holds no tenant record (`TenantRefused`, #1105 NH-3), and when `tenant_id`
        disagrees with the record stored there, rather than silently trusting either."""
        runs_base = Path(runs_base)
        path = _tenant.record_path(runs_base)
        if not io.entry_present(path):
            raise _tenant.TenantRefused(
                f"{path} is absent — a run is built only under a runs folder whose tenant "
                "record names its tenant")
        record = _tenant.read_tenant(runs_base, io=io)
        if record.tenant_id != tenant_id:
            raise _tenant.TenantRecordMismatch(
                f"tenant_id {tenant_id!r} disagrees with the tenant record at "
                f"{runs_base} ({record.tenant_id!r}) — for_tenant is an enforcement "
                "point, not a migration"
            )
        return cls.under(runs_base, run_id, io=io, tenant_id=tenant_id)

    @classmethod
    def under(
        cls, runs_base: Path, run_id: str, *, io: Any = _real_io, tenant_id: str | None = None,
    ) -> Run:
        """The no-I/O builder `for_tenant` and `open_run` share — not a public front door."""
        refuse_bad_run_id(run_id)
        runs_base = Path(runs_base)
        return cls(runs_base / run_id, runs_base=runs_base, io=io, tenant_id=tenant_id)

    @classmethod
    def at(cls, directory: Path) -> Run:
        """The eval/fixture/tooling escape hatch — directory walkers, test fixtures, and the
        archive/branch machinery. Accepts any existing directory without inspecting it; not the
        live investigation path (use `for_tenant`)."""
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
        alert_bytes, _reason = self._io.rooted_read(
            self.run_dir, RUN_LAYOUT.alert, binary=True)
        return RunRecord(
            tenant_id=prov.tenant_id if prov is not None else None,
            world_id=prov.world_id if prov is not None else None,
            commit=prov.commit if prov is not None else None,
            dirty=prov.dirty if prov is not None else None,
            model=prov.model if prov is not None else None,
            run_id=self.run_dir.name,
            alert_ref=case_ref(alert_bytes) if alert_bytes is not None else None,
            # Lineage comes from the stamp, never a `family.yaml` guessed from the runs base.
            parent_run_id=prov.parent_run_id if prov is not None else None,
            fork_turn=prov.fork_turn if prov is not None else None,
            exit_class=exit_class,
            disposition=disposition,
            review_outcome=review_outcome,
            faults=tuple(faults),
        )

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
            self.runs_base, owner.run_end_sidecar(self.runs_base).name)
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

def case_ref(alert_bytes: bytes) -> str:
    """The curation key a run is known by: `case-<sha256 of the alert's bytes>[:16]`."""
    return f"case-{hashlib.sha256(alert_bytes).hexdigest()[:16]}"


# ---------------------------------------------------------------------------------------
# ArchivedWorld — the archive projection's read-only handle; not a `Run`.
# ---------------------------------------------------------------------------------------

#: The copied set, each name from its owner: run-dir names from `_layout`, the archive's
#: re-homed sidecar names and run-dir pointer from `_episode_paths`.
_ARCHIVED_WORLD_NAMES: dict[str, str] = {
    "report": _layout.REPORT, "investigation": _layout.INVESTIGATION,
    "provenance": _layout.PROVENANCE,
    "scrub_verdict": _episode_paths.ARCHIVED_SCRUB_VERDICT_NAME,
    "run_end": _episode_paths.ARCHIVED_RUN_END_NAME,
    "lessons_loaded": _layout.LESSONS_LOADED, "alert": _layout.ALERT,
    "gather_summaries": _layout.GATHER_SUMMARIES_DIRNAME,
    "executed_queries": _layout.EXECUTED_QUERIES,
    "gather_raw": _layout.RAW_MARKER, "run_dir_pointer": _episode_paths.RUN_DIR_POINTER_NAME,
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
    """A read-only projection of an archived `worlds/<label>/` directory — exactly the copied
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
