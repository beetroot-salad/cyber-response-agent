"""D5 — the file-backed `Run` handle: five sub-collections, a `RunRecord` value object, and a
per-kind `RecordHandle` every record accessor answers.

`Run.for_tenant(tenant_id, run_id, *, runs_base, io=)` is the PRIMARY constructor application
code uses. `Run.at(directory)` is the eval/fixture/tooling escape hatch — total over any
existing directory, no runs base in hand. `Run.under(runs_base, run_id)` is the internal helper
`for_tenant` is built on; nothing outside this module should reach it.

Every record accessor answers a `RecordHandle` (`.path`, `.read`, and the group's own write
verb) rather than a bare `pathlib.Path` (decision 1c) — never parsed contents, never validation
beyond what today's seam already does. Asking for `.path` creates nothing on disk (decision
9); only a write/append/update call creates the holding directory, through the SAME `io=`
seam every accessor routes through, so a fake injected at construction sees every operation.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

from defender import _io as _real_io
from defender import _provenance, _report, _tenant
from defender._run_id import (
    CASE_STABLE_REQUIRED,
    RUN_ID_ALLOWED,
    is_case_stable_id,
    is_valid_run_id,
)
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
        self, resolve: Any, *, io: Any, root: Path, group: str, member: str,
        on_partial_failure: Any = None, session_args: tuple[Any, ...] | None = None,
    ) -> None:
        self._resolve = resolve
        self._io = io
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
        self._io.guarded_mkdir(p.parent, base=self._root)

    def _do_write(self, text: str) -> None:
        p = self.path
        if self._group == "facts" and p.is_file():
            raise ValueError(
                f"{p} already exists — run.facts.{self._member} is write-once, outside the "
                "model's reach")
        self._mkdir(p)
        self._io.write_guarded(p, text)

    def _do_append(self, rows: list[dict]) -> None:
        p = self.path
        self._mkdir(p)
        try:
            self._io.append_jsonl(p, rows)
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
        self, run_dir: Path, *, runs_base: Path | None, io: Any = None,
        tenant_id: str | None = None,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.runs_base = Path(runs_base) if runs_base is not None else None
        # NOT a public attribute (decision 1b/fork D-F2): the twelve descriptive fields,
        # tenant_id included, live only on `run.record`, never as a property of `Run` itself.
        self._for_tenant_id = tenant_id
        self._io = io if io is not None else _real_io
        self.partial_failures: tuple[str, ...] = ()
        for group in GROUPS:
            setattr(self, group, _RecordHandleGroup(self, group))

    @property
    def subcollections(self) -> tuple[str, ...]:
        return GROUPS

    def _record_partial_failure(self, note: str) -> None:
        self.partial_failures = (*self.partial_failures, note)

    def _member_accessor(self, group: str, name: str) -> Any:
        attr = MEMBER_ACCESSOR[name]

        def build(*args: Any) -> RecordHandle:
            def resolve() -> Path:
                target = getattr(RunPaths(self.run_dir), attr)
                if attr in UPWARD_ACCESSORS:
                    if self.runs_base is None:
                        raise ValueError(
                            f"run.{group}.{name} needs the runs base, which this handle does "
                            "not hold — it was built from a bare directory (Run.at)")
                    return target(self.runs_base, *args)
                return target(*args) if args else target

            session_args = (args[0], self.runs_base) if name == "session_db" and args else None
            return RecordHandle(
                resolve, io=self._io, root=self.run_dir, group=group, member=name,
                on_partial_failure=self._record_partial_failure, session_args=session_args)

        if name in _COMPOSING_MEMBERS:
            return build
        return build()

    # -- constructors --------------------------------------------------------------------------

    @classmethod
    def for_tenant(cls, tenant_id: str, run_id: str, *, runs_base: Path, io: Any = None) -> Run:
        """The constructor real APPLICATION code uses — the host process that creates and
        operates on one specific run. Refuses when `tenant_id` disagrees with the tenant
        record actually stored at `runs_base` (decision 22): neither argument is trusted over
        the other, because trusting either makes a mismatch silent."""
        real_io = io if io is not None else _real_io
        runs_base = Path(runs_base)
        record_path = _tenant.record_path(runs_base)
        if record_path.is_file():
            record = _tenant.read_tenant(runs_base, io=real_io)
            if record.tenant_id != tenant_id:
                raise ValueError(
                    f"tenant_id {tenant_id!r} disagrees with the tenant record at "
                    f"{runs_base} ({record.tenant_id!r}) — for_tenant is an enforcement "
                    "point, not a migration"
                )
        return cls.under(runs_base, run_id, io=io, tenant_id=tenant_id)

    @classmethod
    def under(
        cls, runs_base: Path, run_id: str, *, io: Any = None, tenant_id: str | None = None,
    ) -> Run:
        """The internal helper `for_tenant` is built on — not a public front door."""
        _refuse_bad_run_id(run_id)
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

        prov_obj: dict[str, Any] | None = None
        raw, _reason = self._io.read_guarded(owner.provenance)
        if raw is not None:
            try:
                parsed = json.loads(raw)
            except ValueError:
                faults.append("provenance: unparseable")
                parsed = None
            if isinstance(parsed, dict):
                prov_obj = parsed
            elif parsed is not None:
                faults.append("provenance: wrong shape")

        prov = _provenance.RunProvenance.from_obj(prov_obj) if prov_obj is not None else None
        if prov_obj is not None and prov is None:
            faults.append("provenance: wrong shape")
        if prov_obj is not None:
            for field in ("tenant_id", "world_id"):
                v = prov_obj.get(field)
                if v is not None and not isinstance(v, str):
                    faults.append(f"provenance: {field} is wrong-shaped")

        alert_ref = None
        if owner.alert.is_file():
            alert_ref = f"case-{hashlib.sha256(owner.alert.read_bytes()).hexdigest()[:16]}"

        exit_class = None
        if self.runs_base is not None:
            from defender.runtime import run_end as run_end_mod

            sidecar = owner.run_end_sidecar(self.runs_base)
            if sidecar.is_file():
                try:
                    doc = json.loads(sidecar.read_text(encoding="utf-8"))
                except ValueError:
                    doc = None
                    faults.append("run_end: unparseable")
                if doc is not None:
                    rec = run_end_mod.parse_record(doc)
                    if rec is None:
                        faults.append("run_end: wrong shape")
                    else:
                        exit_class = rec.truncated_by

        disposition = None
        review_outcome = None
        if owner.report.is_file():
            read = _report.read_report(owner.report)
            disposition = read.disposition
            fm = read.frontmatter
            if isinstance(fm, dict):
                outcome = fm.get("outcome")
                review_outcome = outcome if isinstance(outcome, str) else None

        parent_run_id = None
        fork_turn = None
        if self.runs_base is not None:
            family_path = self.runs_base.parent / "family.yaml"
            if family_path.is_file():
                from defender.runtime.branch import _family

                try:
                    fam = _family.load_family(family_path)
                except _family.FamilyError:
                    fam = None
                if fam is not None:
                    parent_run_id = fam.source_run_id
                    fork_turn = fam.branch_message_id

        return RunRecord(
            tenant_id=prov.tenant_id if prov is not None else None,
            world_id=prov.world_id if prov is not None else None,
            commit=prov.commit if prov is not None else None,
            dirty=prov.dirty if prov is not None else None,
            model=prov.model if prov is not None else None,
            run_id=self.run_dir.name,
            alert_ref=alert_ref,
            parent_run_id=parent_run_id,
            fork_turn=fork_turn,
            exit_class=exit_class,
            disposition=disposition,
            review_outcome=review_outcome,
            faults=tuple(faults),
        )


def _refuse_bad_run_id(run_id: str) -> None:
    if not is_valid_run_id(run_id):
        raise ValueError(f"{run_id!r} is not a valid run id (allowed: {RUN_ID_ALLOWED})")
    if not is_case_stable_id(run_id):
        raise ValueError(
            f"{run_id!r} is not case-stable ({CASE_STABLE_REQUIRED}) — use "
            f"{run_id.casefold()!r}")


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

    def __init__(self, world_dir: Path, *, io: Any = None) -> None:
        self.world_dir = Path(world_dir)
        self._io = io if io is not None else _real_io

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
