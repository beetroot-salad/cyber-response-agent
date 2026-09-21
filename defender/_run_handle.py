"""D5 — the file-backed `Run` handle: five sub-collections, a `RunRecord` value object, and a
per-kind `RecordHandle` every record accessor answers.

`Run.for_tenant(tenant_id, run_id, *, runs_base, io=)` is the PRIMARY constructor application
code uses. `Run.at(directory)` is the eval/fixture/tooling escape hatch — total over any
existing directory, no runs base in hand. `Run.under(runs_base, run_id)` is the internal helper
`for_tenant` is built on; nothing outside this module should reach it.

Every record accessor answers a `RecordHandle` (`.path`, `.read`, and the group's own write
verb) rather than a bare `pathlib.Path` (decision 1c) — never parsed contents, never validation
beyond what today's seam for that record already does. Asking for `.path` creates nothing on
disk (decision 9); only a write/append/update call creates the holding directory, through the
SAME `io=` seam every accessor routes through, so a fake injected at construction sees every
operation — the reads `run.record` makes included.

THE VERBS ARE TODAY'S SEAMS, NOT A SECOND SET. Every write lands through `_io.write_guarded`
(`create` for the write-once facts, `replace` for a document, `append` for a table or a trace)
or `_io.locked_for_rewrite` (the two locked states), anchored by `guarded_mkdir` on the trust
root the record actually sits under — the run dir for everything inside it, the runs base for
the three sidecars, its parent for the session db (claim C15). The two model-authored
documents are held to `_artifact_schema` at the write, because that schema is what "a
committed investigation parses" rests on and a writer outside the gate is the #961/#964
class. Nothing here reaches the pre-#771 `append_jsonl`.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender import _artifact_schema
from defender import _io as _real_io
from defender import _provenance, _report, _tenant
from defender._run_id import refuse_bad_run_id
from defender._run_paths import RunPaths

#: Decision 1a — the five group cells, group-then-kind addressed.
GROUPS = ("tables", "facts", "documents", "observability", "session")

#: D5's group table — mirrors `defender/tests/_spec1077.py::GROUP_MEMBERS` exactly; that file
#: is the spec, this is the shipped shape it describes.
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
GROUP_OF: dict[str, str] = {n: g for g, ns in GROUP_MEMBERS.items() for n in ns}
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
GROUP_WRITE_VERB: dict[str, str] = {
    "tables": "append", "facts": "write", "documents": "write",
    "observability": "append", "session": "append"}
LOCKED_STATE_MEMBERS = ("budget", "circuit_breaker")
UPWARD_ACCESSORS = (
    "run_end_sidecar", "scrub_verdict", "accounting_failures", "sessions_dir", "session_db")
#: The three sidecars sit DIRECTLY in the runs base; the session db under `<runs_base>/../
#: sessions` — so their holding directories are anchored there, not on the run dir (claim
#: C15: `session_store` anchors its own mkdir at `runs_base.parent`).
_SIDECAR_MEMBERS = ("run_end", "scrub_verdict", "accounting")
#: The two model-authored documents, held to their content schema at every write.
_SCHEMA_GATED_MEMBERS = {"investigation": _artifact_schema.INVESTIGATION_NAME,
                         "report": _artifact_schema.REPORT_NAME}

RUN_RECORD_FIELDS = (
    "tenant_id", "world_id", "commit", "dirty", "model", "run_id", "alert_ref",
    "parent_run_id", "fork_turn", "exit_class", "disposition", "review_outcome")


#: Sub-collection members whose owner accessor takes a caller-supplied component — `run.
#: <group>.<name>` answers a CALLABLE for these, taking the same positional args the owner
#: accessor does, and returning the `RecordHandle`; every other member answers the
#: `RecordHandle` directly.
_COMPOSING_MEMBERS = frozenset({
    "leads", "payloads", "ticket_reads", "gather_summaries", "review_trace",
    "review_record", "forward_check_trace", "session_db",
})


class RecordHandle:
    """A thin per-kind wrapper: `.path` (the owner's own resolved `pathlib.Path`) plus
    read/write/append/update delegating to today's seams — never a bare `Path`, never parsed
    contents beyond what the seam it wraps already returns."""

    def __init__(
        self, resolve: Callable[[], Path], *, io: Any, root: Callable[[], Path], group: str,
        member: str, on_partial_failure: Any = None,
        session_args: tuple[Any, ...] | None = None,
    ) -> None:
        self._resolve = resolve
        self._io = io
        # The trust root the holding directory is created under — a thunk, like `resolve`, so
        # asking for a handle over a bare directory (`Run.at`) does not raise until a write
        # actually needs the runs base (decision 10: a missing precondition, at use).
        self._root = root
        self._group = group
        self._member = member
        self._verb = GROUP_WRITE_VERB[group]
        self._locked = member in LOCKED_STATE_MEMBERS
        self._on_partial_failure = on_partial_failure
        if member == "wire_log":
            from defender.runtime import observe

            self.logger_factory = observe.RequestLogger
        if member == "session_db":
            from defender.runtime import session_store

            self.open_store = session_store.open_store
            self._lineage_id, self._sessions_runs_base = session_args or (None, None)
        # ONLY the group's own write verb is exposed as a PUBLIC attribute — `hasattr(rec,
        # "append")`/`"write"`/`"update"` is how the suite asserts a member does NOT carry a
        # verb it should not (a `facts`/`documents` record exposes no `append`; the ordinary
        # `observability` members expose no `update`; the two locked states expose no `write`).
        if self._locked:
            self.update = self._do_update
            # The group's own verb is still present, uniformly, on every member (decision 11)
            # — for the two locked states it is an alias of `update`'s read-modify-write.
            setattr(self, self._verb, self._do_update)
        elif self._verb == "write":
            self.write = self._do_write
        elif self._verb == "append":
            self.append = self._do_append

    @property
    def path(self) -> Path:
        return self._resolve()

    def read(self) -> str | None:
        text, _reason = self._io.read_guarded(self.path)
        return text

    def _mkdir(self, p: Path) -> None:
        self._io.guarded_mkdir(p.parent, base=self._root())

    def _do_write(self, text: str) -> None:
        p = self.path
        schema_name = _SCHEMA_GATED_MEMBERS.get(self._member)
        if schema_name is not None:
            current, _reason = self._io.read_guarded(p)
            reason = _artifact_schema.validate_artifact(schema_name, text, current)
            if reason is not None:
                raise ValueError(f"run.{self._group}.{self._member}: {reason}")
        self._mkdir(p)
        if self._group == "facts":
            # Write-once, outside the model's reach: the exclusive lane refuses an occupied
            # name instead of replacing it, so a fact is never rewritten by any writer.
            try:
                self._io.write_guarded(p, text, mode="create")
            except FileExistsError as taken:
                raise ValueError(
                    f"{p} already exists — run.facts.{self._member} is write-once, outside "
                    "the model's reach") from taken
            return
        self._io.write_guarded(p, text, mode="replace")

    def _do_append(self, rows: list[dict]) -> None:
        if not rows:
            return
        p = self.path
        self._mkdir(p)
        # One guarded append for the batch (the same seam `record_query.append_query_row` and
        # `challenge_gate._write_trace_row` reach), never the pre-#771 `append_jsonl`, whose
        # `open("a")` follows a link the model planted at the table's name.
        text = "".join(json.dumps(row) + "\n" for row in rows)  # lint-jsonl-io: ok — the rows are handed whole to the guarded append seam, not to a line loop over an open handle  # noqa: E501
        try:
            self._io.write_guarded(p, text, mode="append")
        except OSError:
            if self._group != "observability" or self._on_partial_failure is None:
                raise
            self._on_partial_failure(f"{self._member}: append failed")

    def _do_update(self, patch: dict) -> None:
        p = self.path
        self._mkdir(p)
        with self._io.locked_for_rewrite(p) as f:
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

    def open(self):
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
    """D4's twelve descriptive fields, read-only, through the readers that already exist."""

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


class Run:
    """The file-backed run handle, addressed by `(tenant_id, run_id)`."""

    def __init__(
        self, run_dir: Path, *, runs_base: Path | None, io: Any = _real_io,
        tenant_id: str | None = None,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.runs_base = Path(runs_base) if runs_base is not None else None
        # NOT a public attribute (decision 1b/fork D-F2): the twelve descriptive fields,
        # tenant_id included, live only on `run.record`, never as a property of `Run` itself.
        self._for_tenant_id = tenant_id
        self._io = io
        self.partial_failures: tuple[str, ...] = ()
        for group in GROUPS:
            setattr(self, group, _RecordHandleGroup(self, group))

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
                    return self._runs_base_for(group, name).parent
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
        """The constructor real APPLICATION code uses — the host process that creates and
        operates on one specific run. Refuses when `tenant_id` disagrees with the tenant
        record actually stored at `runs_base` (decision 22): neither argument is trusted over
        the other, because trusting either makes a mismatch silent."""
        runs_base = Path(runs_base)
        if io.entry_present(_tenant.record_path(runs_base)):
            record = _tenant.read_tenant(runs_base, io=io)
            if record.tenant_id != tenant_id:
                raise ValueError(
                    f"tenant_id {tenant_id!r} disagrees with the tenant record at "
                    f"{runs_base} ({record.tenant_id!r}) — for_tenant is an enforcement "
                    "point, not a migration"
                )
        return cls.under(runs_base, run_id, io=io, tenant_id=tenant_id)

    @classmethod
    def under(
        cls, runs_base: Path, run_id: str, *, io: Any = _real_io, tenant_id: str | None = None,
    ) -> Run:
        """The internal helper `for_tenant` is built on — not a public front door."""
        refuse_bad_run_id(run_id)
        runs_base = Path(runs_base)
        return cls(runs_base / run_id, runs_base=runs_base, io=io, tenant_id=tenant_id)

    @classmethod
    def at(cls, directory: Path) -> Run:
        """The eval/fixture/tooling escape hatch — bulk directory-walkers mining
        training/held-out data, checked-in test fixtures, and the archive/branch machinery
        reading an already-materialized world copy. Total over any EXISTING directory (never
        inspects contents; an empty directory is accepted with all identity fields `None`),
        refuses only when the path is not an existing directory. NOT the live investigation
        path — real application code constructs through `for_tenant`."""
        directory = Path(directory)
        if not directory.is_dir():
            raise ValueError(f"{directory} is not an existing directory")
        return cls(directory, runs_base=None)

    # -- the record -----------------------------------------------------------------------------

    @property
    def record(self) -> RunRecord:
        owner = RunPaths(self.run_dir)
        faults: list[str] = []
        # Every read below goes through the injected `io` and refuses an alias the box planted
        # at the record's name — a symlinked `alert.json` would otherwise make `alert_ref` (the
        # curation key) the hash of bytes outside the run.
        prov = self._provenance(owner, faults)
        exit_class = self._exit_class(owner, faults) if self.runs_base is not None else None
        disposition, review_outcome = self._report_fields(owner)
        parent_run_id, fork_turn = self._family_fields()
        alert_bytes, _reason = self._io.read_bytes_guarded(owner.alert)
        return RunRecord(
            tenant_id=prov.tenant_id if prov is not None else None,
            world_id=prov.world_id if prov is not None else None,
            commit=prov.commit if prov is not None else None,
            dirty=prov.dirty if prov is not None else None,
            model=prov.model if prov is not None else None,
            run_id=self.run_dir.name,
            alert_ref=(f"case-{hashlib.sha256(alert_bytes).hexdigest()[:16]}"
                       if alert_bytes is not None else None),
            parent_run_id=parent_run_id,
            fork_turn=fork_turn,
            exit_class=exit_class,
            disposition=disposition,
            review_outcome=review_outcome,
            faults=tuple(faults),
        )

    def _provenance(
        self, owner: RunPaths, faults: list[str],
    ) -> _provenance.RunProvenance | None:
        raw, _reason = self._io.read_guarded(owner.provenance)
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
        sidecar_text, _reason = self._io.read_guarded(owner.run_end_sidecar(self.runs_base))
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

    def _report_fields(self, owner: RunPaths) -> tuple[str | None, str | None]:
        report_text, _reason = self._io.read_guarded(owner.report)
        if report_text is None:
            return None, None
        read = _report.parse_report_text(report_text)
        fm = read.frontmatter
        outcome = fm.get("outcome") if isinstance(fm, dict) else None
        return read.disposition, (outcome if isinstance(outcome, str) else None)

    def _family_fields(self) -> tuple[str | None, int | None]:
        if self.runs_base is None:
            return None, None
        family_path = self.runs_base.parent / "family.yaml"
        if not family_path.is_file():
            return None, None
        from defender.runtime.branch import _family

        try:
            fam = _family.load_family(family_path)
        except _family.FamilyError:
            return None, None
        return fam.source_run_id, fam.branch_message_id


# ---------------------------------------------------------------------------------------
# ArchivedWorld — the archive projection's read-only handle (D5/N5); not a `Run`.
# ---------------------------------------------------------------------------------------

_ARCHIVED_WORLD_NAMES: dict[str, str] = {
    "report": "report.md", "investigation": "investigation.md", "provenance": "provenance.json",
    "scrub_verdict": "scrub_verdict.json", "run_end": "run_end.json",
    "lessons_loaded": "lessons_loaded.jsonl", "alert": "alert.json",
    "gather_summaries": "gather_summaries", "executed_queries": "executed_queries.jsonl",
    "gather_raw": "gather_raw", "run_dir_pointer": "run_dir",
}


class _ArchivedRecordHandle:
    def __init__(self, path: Path, *, io: Any) -> None:
        self._path = path
        self._io = io

    @property
    def path(self) -> Path:
        return self._path

    def read(self) -> str | None:
        text, _reason = self._io.read_guarded(self._path)
        return text


class ArchivedWorld:
    """A read-only projection of an archived `worlds/<label>/` directory — exactly the copied
    set (page §5, D5/N5). Not a `Run`: it has no `.record` and is not addressed by
    `(tenant_id, run_id)`."""

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
        return _ArchivedRecordHandle(self.world_dir / _ARCHIVED_WORLD_NAMES[name], io=self._io)
