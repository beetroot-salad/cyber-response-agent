#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import datetime as _dt
import functools
import logging
import signal
import sys
import threading
import dataclasses as _dataclasses
from collections.abc import Collection, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

DEFENDER_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEFENDER_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender import _clock, _io
from defender.records import formats, run_end
from defender import tenancy  # noqa: E402
from defender._io import read_bytes_capped  # noqa: E402
from defender.records import (  # noqa: E402
    RUN_LAYOUT, Run, RunAddress, RunId, RunPaths, RunRefused, artifact_dir, artifact_file, case_ref_of_digest, sidecar_names,
)
from defender.presentation import VisualizeFailed  # noqa: E402
from defender.records.formats import DataRoot, TenantId, TenantRefused

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from defender.records.formats import AlertMapping
    from defender.records.job_lane import Launched
    from defender.records.formats import ResumeWorld
    from defender.systems.run_tenant import RunTenant
    from defender.tenancy.run_knowledge import KnowledgeSource, PublishReport, RunCopy

_GENERIC_ALERT_STEMS = {"alert"}


def _alert_label(alert: Path) -> str:
    return alert.parent.name if alert.stem in _GENERIC_ALERT_STEMS else alert.stem


def materialize_run(  # noqa: PLR0913 — the run's case, its tenant, and the knowledge it reads
    alert: Path, *, tenant: tenancy.Tenant, run: Run | None = None, model: str | None = None,
    world: ResumeWorld | None = None,
    mapping: AlertMapping | None = None, knowledge: KnowledgeSource | None = None,
    launch: Launched | None = None,
    started_at: _dt.datetime | None = None,
) -> Run:
    """Build the run directory of a fresh run and return the tenant-bound handle the run's later
    records are saved through. No caller names the run's id (#1279 A3): `run` is the handle the
    runs repository handed out — `RunsRepository.create()` mints one, and an arm's is its
    episode's `EpisodeRuns.create(<the roster's arm id>)` — so run.py can name the run's knowledge
    copy by it before setup (#1279 rev 6). Without `run`, setup makes a fresh ordinary run of the
    tenant; an arm (`world`) always comes as its handle. A run dir or sidecar already at that id
    is refused; there is no resume (O8).

    `mapping` is the tenant's alert mapping, read from the database by run start (#1345 O3): the
    four facts are derived through it, once. A fresh run must be handed it; a sibling (`world`)
    carries its source's record and needs none. `knowledge` is the source of the knowledge it
    reads, whose commit the stamp records (O-B: the export copied, never a clone's HEAD); it
    defaults to a stamp that says nothing of knowledge.

    `launch` is a job's checked launch record (#1342 O6, M5): `alert` is then its alert file, the
    bytes admitted are compared to the record's digest (one read, as a sibling's are to its
    record), and the stamp's label is the record's (the alert's title), not the file's name.

    `started_at` is the start the stamp records when the run clock does not start now (`--as-of`,
    #1347 O5); `None` is the wall time."""
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    if world is not None and run is None:
        raise TypeError("materialize_run(world=…) needs the arm's handle (`run=`): an arm is made "
                        "only from its episode's roster")
    if world is None and mapping is None:
        raise TypeError("materialize_run needs the tenant's alert mapping (`mapping=`) for a fresh run")
    started = _started_at() if started_at is None else _clock.z_seconds(started_at)
    front_door = _admit_input(alert, mapping=mapping, world=world,
                              digest=None if launch is None else launch.record.digest)
    world_id: str | None = None
    if run is None:
        try:
            run = tenant.runs_repository().create()
        except RunRefused as refused:
            sys.exit(str(refused))
    run_dir = run.run_dir

    # A sidecar beside the dir is a trace of an earlier run at this id; nothing clears it.
    for name in sidecar_names(RunId.parse(run_dir.name)):
        if _io.entry_present(run_dir.parent / name):
            sys.exit(f"run id already used: {run_dir.parent / name} exists beside {run_dir} — a run "
                     "id names one investigation")
    # Judged component by component, and exclusive at the run dir itself: anything already at
    # the run id (a directory, a file, a link) is refused as found.
    try:
        run.make_run_dir()
    except FileExistsError:
        sys.exit(f"run dir already exists: {run_dir} — a run id names one investigation and a "
                 "run dir is never resumed")
    _write_input(run, front_door)
    # Every executed run is stamped here, by its own process (branched siblings each reach
    # this, and `verify_family` compares their stamps), before the box exists: the run dir is
    # the box's rw bind, so a later stamp could have been moved by the run. There is no seam to
    # hand a stamp in.
    _stamp(
        run, knowledge=knowledge, model=model, tenant_id=run.tenant_id,
        world_id=world_id,
        started_at=started,
        alert_label=_alert_label(alert) if launch is None else launch.record.label,
    )
    return run


def _started_at() -> str:
    """When run setup started this run, as ISO-8601 UTC text to the second (#1187 O7)."""
    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@_dataclasses.dataclass(frozen=True)
class _FrontDoor:
    """What run start settled about the alert before any folder existed: its admitted bytes, and
    the record text that goes beside them."""

    raw: bytes
    record: str


def _admit_input(alert: Path, *, mapping: AlertMapping | None, world: ResumeWorld | None,
                 digest: str | None = None) -> _FrontDoor:
    """Admit the operator's alert (A8) and settle its facts through the tenant's alert `mapping`,
    read once (A1) — or exit with the fixed reason, before a run folder exists. A sibling's input
    is its episode's copy of the source run's alert, carried with the record launch copied
    beside it; neither is derived again. A job's alert (`digest`, its launch record's) must be
    the bytes its worker recorded."""
    try:
        raw = formats.read_operator_alert(alert)
        admitted = formats.admit(raw)
    except formats.AlertRefused as refused:
        sys.exit(f"[run.py] {refused}")
    except OSError as e:
        sys.exit(f"[run.py] the alert {alert} could not be read: {e}")
    if digest is not None and admitted.digest != digest:
        sys.exit(f"[run.py] the alert {alert} is not the one its launch record names: its digest "
                 "differs from the record's")
    if world is not None:
        from defender.records.formats import EpisodePaths

        record_path = EpisodePaths(world.episode_dir).source_record
        text, reason = _io.read_guarded(record_path)
        parsed = None if text is None else formats.parse_alert_record(text)
        if text is None or parsed is None or parsed.digest != admitted.digest:
            sys.exit(f"[run.py] episode {world.episode_dir.name}: its copy of the source alert does not "
                     f"match the record beside it "
                     f"({reason or 'the record is missing, malformed or for another alert'})")
        return _FrontDoor(raw=raw, record=text)
    assert mapping is not None  # materialize_run: a fresh run is handed it
    facts = formats.derive_facts(admitted.document, mapping)
    return _FrontDoor(raw=raw, record=formats.record_text(admitted.digest, facts))


def _write_input(run: Run, door: _FrontDoor) -> None:
    """The alert and its record, written once into the run's read-only input directory through
    the guarded exclusive lane. The run dir was just created exclusively (O8), so neither file
    can be there yet."""
    paths = RunPaths(run.run_dir)
    _unseal(paths.alert_input_dir)
    try:
        run.facts.alert.write(door.raw)
        _io.rooted_write(run.run_dir, RUN_LAYOUT.alert_record, door.record, mode="create")
    except OSError as e:
        sys.exit(f"cannot write the run's input at {paths.alert_input_dir}: {e!r} — no run "
                 f"starts without its alert and {paths.alert_record.name}")
    finally:
        _seal(paths.alert_input_dir)


def _unseal(input_dir: Path) -> None:
    """Make the input directory (and what it holds) writable for the owner, for the one write
    run start makes into it. Best effort: the box's read-only bind is the real protection."""
    with contextlib.suppress(OSError):
        if artifact_dir(input_dir):
            input_dir.chmod(0o755)


def _seal(input_dir: Path) -> None:
    """Take the owner's write permission off the input directory and its files, so a host
    process running as the same user cannot rewrite them by accident. Best effort, like
    `_unseal`: the box's read-only bind is what holds against the run."""
    with contextlib.suppress(OSError):
        if not artifact_dir(input_dir):
            return
        for child in input_dir.iterdir():
            if artifact_file(child):
                child.chmod(0o444)
        input_dir.chmod(0o555)


def _stamp(  # noqa: PLR0913 — one keyword per stamped fact
    run: Run, *, knowledge: KnowledgeSource | None, model: str | None = None,
    tenant_id: str | None = None, world_id: str | None = None,
    started_at: str | None = None, alert_label: str | None = None,
) -> None:
    """Write the run's stamp, never taking the run down doing it (ENOSPC, read-only remount,
    a planted alias). Unlike a missing alert, a missing stamp only means the run's code cannot
    be proven later, so it is logged loudly and the run continues. An interrupted setup is
    resumable, so a retry re-stamps. `knowledge` is where the run's tenant knowledge came from:
    its export's commit rides beside the product's (#1204; #1108 P4 O-B: the export copied,
    never a clone's checked-out commit), with the informational `knowledge_source` (OD17)."""
    path = run.facts.provenance.path
    try:
        record = formats.capture_tree(REPO_ROOT)
        if knowledge is not None:
            record = _dataclasses.replace(
                record, knowledge=formats.KnowledgeRevision.at(knowledge.commit))
        # Set in the single pre-box write; a later write would land in the box's rw bind.
        if model is not None:
            record = _dataclasses.replace(record, model=model)
        # Both run types expose the same stamp shape; lineage stays in host episode records.
        record = _dataclasses.replace(
            record, tenant_id=tenant_id, world_id=world_id,
            started_at=started_at, alert_label=alert_label)
        run.facts.provenance.write(record.as_json(
            knowledge_source=None if knowledge is None else knowledge.stamp_view()))
    except OSError as e:
        _logger.error(f"could not stamp {path}: {e!r} — the run continues UNSTAMPED, so "
                      "nothing downstream can prove which code it ran")


def visualize(run: Run, *, tenant: tenancy.Tenant, update_ticket: bool = False, mirror: bool = True) -> None:
    """The post-run page step as `run.py` takes it: load the renderer, then hand it the run
    (`visualize_run.publish_page` renders, saves the record through `run`, and makes the dev-only
    copy). Runs in the process holding the handle, after the sandbox has exited and the tree has
    been scrubbed, so the model never had a chance to rewrite its own report.

    `mirror=False` is a job container's page (#1170 A10): the record is saved in the run's own
    folder and nothing else is written; the shared publish folder is never the job's to reach, and
    the job's host helper copies the record there once the container has exited."""
    try:
        from defender.presentation import visualize_run as vr
    except Exception as e:
        raise VisualizeFailed("the renderer could not be loaded") from e
    if mirror:
        vr.publish_page(run, tenant=tenant, update_ticket=update_ticket)
    else:
        vr.save_page(run, update_ticket=update_ticket)


def cross_check_tables(run_dir: Path) -> None:
    if not RunPaths(run_dir).investigation.is_file():
        return
    try:
        from defender.learning import lead_repository

        xcheck = lead_repository.narration_crosscheck_from_run(run_dir)
    except Exception as e:  # noqa: BLE001 — diagnostics must never break the run
        _logger.warning(f"narration cross-check skipped: {e!r}")
        return
    if not xcheck["ok"]:
        _logger.warning(
            "narration cross-check FAILED — the live tables "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "disagree with investigation.md's :L rows:",
        )
        if xcheck["missing_from_narration"]:
            _logger.warning(f"table lead_ids with no :L row: {xcheck['missing_from_narration']}")
        if xcheck["queries_without_lead"]:
            _logger.warning(f"query FKs with no lead sidecar (orphans): {xcheck['queries_without_lead']}")
    if xcheck["leads_without_queries"]:
        _logger.info(f"note: leads with no queries (monitor): {xcheck['leads_without_queries']}")


HELD_OUT_FIXTURES = REPO_ROOT / "evaluations" / "fixtures" / "held_out"


def is_held_out_fixture(alert: Path, fixtures_dir: Path = HELD_OUT_FIXTURES) -> bool:
    try:
        alert.resolve().relative_to(fixtures_dir.resolve())
    except ValueError:
        return False
    return True


def held_out_alert_digests(fixtures_dir: Path = HELD_OUT_FIXTURES) -> set[str]:
    out: set[str] = set()
    if not fixtures_dir.is_dir():
        return out
    for child in sorted(fixtures_dir.iterdir()):
        try:
            out.add(formats.digest_of(read_bytes_capped(child / "alert.json")))  # lint-run-records: ok — a held-out fixture folder's own file, not a run's record
        except OSError:
            continue
    return out


def learning_refusal_gate(
    run_dir: Path,
    alert: Path | None = None,
    *,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
    truncated_by: str | None = None,
    unsandboxed_ok: bool = False,
) -> str | None:
    """The refusal predicate every learning enqueue consults: the reason a run must not feed
    a corpus, or `None`.

    Held-out fixtures are checked by the run's RECORDED digest (the alert it admitted at run
    start, whatever has become of the operator's input file since: catches copies outside
    `fixtures_dir`) and, when the operator's input path is given, by path containment (catches
    files the digest walk, which reads only `<slug>/alert.json`, never sees)."""
    if truncated_by is not None:
        return f"run was truncated (truncated_by={truncated_by!r}) — a truncated " \
            "investigation must not train the corpus"
    record = formats.read_record(RunPaths(run_dir).alert_record)
    if record is None:
        return f"{run_dir} carries no readable record of its alert — a folder without one is " \
            "not a run, and nothing is learned from it"
    held_out_input = alert is not None and is_held_out_fixture(alert, fixtures_dir)
    if held_out_input or record.digest in held_out_alert_digests(fixtures_dir):
        return f"{run_dir.name} investigated a held-out eval fixture (or a copy of one) — its " \
            "findings must never feed a corpus it is scored against"
    from defender import box

    if not unsandboxed_ok and box.tree_unsandboxed(run_dir):
        return f"{run_dir.name} ran without a sandbox, so its input directory was never bound " \
            "read-only — nothing is learned from it"
    if not box.tree_verified(run_dir):
        # No completed scan verdict: the crash path most likely to hold what a box planted.
        return f"{run_dir} carries no completed reap-scan verdict — an unverified tree " \
            "must not feed the corpus"
    return None




def enqueue_curation(
    run: Run,
    alert: Path | None = None,
    *,
    tenant: tenancy.Tenant,
    truncated_by: str | None = None,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
) -> bool:
    """Enqueue catalog curation for a run, through `learning_refusal_gate` — this hands
    attacker-influenced content (goal text, bound params, rendered queries) to the curator. The
    request is keyed on the run's recorded digest; `alert`, the operator's input path, is only
    the held-out gate's path arm.

    `tenant` is the run's accepted tenant, the value of run start's host acceptance (r10 O-A5): the
    request is written under it with no second read of the tenant. A tenant whose id is not the
    run's is refused here, on the same NOT-enqueuing channel (r10.1 C7, fail closed)."""
    run_dir = run.run_dir
    if str(tenant.id) != str(run.tenant_id):
        _logger.error(f"NOT enqueuing for curation: the request names tenant {tenant.id}, but the run "
                      f"is tenant {run.tenant_id}'s")
        return False
    reason = learning_refusal_gate(
        run_dir, alert, fixtures_dir=fixtures_dir, truncated_by=truncated_by
    )
    if reason is not None:
        _logger.info(f"NOT enqueuing for curation: {reason}")
        return False
    import os

    from defender.learning.store import blocking

    address = RunAddress(tenant_id=TenantId(run.tenant_id), run_id=run.id)
    # Reading the alert is guarded: a moved alert must not fail the run. So is the learning store
    # (#1278): one it cannot reach, or that refuses the request (the tenant is not active, the
    # request holds what it can never hold), costs this request, never the investigation.
    try:
        record = formats.read_record(RunPaths(run_dir).alert_record)
        if record is None:
            raise OSError("the run's record vanished")
        case_id = case_ref_of_digest(record.digest)
    except (OSError, ValueError) as e:
        _logger.error(f"NOT enqueuing for curation: could not read the run's record: {e}")
        return False
    variable = tenancy.database_address_variable()
    dsn = os.environ.get(variable, "")
    if not dsn:
        _logger.error(f"NOT enqueuing for curation: {variable} is not set, so the learning store "
                      "cannot be reached")
        return False
    try:
        with blocking(dsn) as store:
            store.enqueue_request(
                str(address.tenant_id), str(address.run_id), case_id,
                {"case_id": case_id, "tenant_id": str(address.tenant_id), "run_id": str(address.run_id)})
    except Exception as failed:  # noqa: BLE001 — a request that cannot be filed costs only itself
        _logger.error(f"NOT enqueuing for curation: the learning store did not take the request: {failed!r}")
        return False
    return True


def enqueue_feedback_issue(run: Run, alert: Path | None = None, **kw: Any) -> bool:
    """Queue an open-issue request for a run whose outcome the tenant's feedback setting lists
    (#1414 F1); False when none is queued. Never raises: it runs at run end beside curation and
    the run page, and a failure of any kind (an unreadable record, a broken gate) costs the run
    only its feedback issue, logged."""
    try:
        return _enqueue_feedback_issue(run, alert, **kw)
    except Exception as failed:  # noqa: BLE001 — a post-step must never break the run
        _logger.error(f"NOT enqueuing a feedback issue: it failed unexpectedly: {failed!r}")
        return False


def _enqueue_feedback_issue(
    run: Run,
    alert: Path | None = None,
    *,
    tenant: RunTenant,
    truncated_by: str | None = None,
    closed_before_cut: bool = False,
    run_state: Any = None,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
) -> bool:
    """`enqueue_feedback_issue`'s work. The learning gate's refusals apply except two arms: its
    truncation arm (the escalated outcomes are truncations) and its unsandboxed arm
    (`unsandboxed_ok`: a contract test asks for a request from a run with no box, an open human
    decision on PR #1463). A run that ended silently opens nothing."""
    from defender.investigation import ticket_writer
    from defender.tenancy import feedback_setting

    accepted = tenant.tenant
    owner = getattr(run, "tenant_id", None)  # a `Run.at` handle carries no address, so no tenant
    if owner is None or str(accepted.id) != str(owner):
        whose = "addressed to no tenant" if owner is None else f"tenant {owner}'s"
        _logger.error(f"NOT enqueuing a feedback issue: the request names tenant {accepted.id}, but the run is {whose}")
        return False
    truncated_by = run_end.normalized_truncated_by(truncated_by)
    if not ticket_writer.comments_on(truncated_by, closed_before_cut):
        _logger.info(f"NOT enqueuing a feedback issue: the run ended silently ({truncated_by})")
        return False
    reason = learning_refusal_gate(run.run_dir, alert, fixtures_dir=fixtures_dir, truncated_by=None,
                                   unsandboxed_ok=True)
    if reason is not None:
        _logger.info(f"NOT enqueuing a feedback issue: {reason}")
        return False
    try:
        listed = feedback_setting.load_feedback_outcomes(tenant.settings)
    except feedback_setting.FeedbackSettingError as bad:
        _logger.error(f"NOT enqueuing a feedback issue: {bad}")
        return False
    if not listed:
        return False
    outcome = ticket_writer.run_outcome(run, truncated_by=truncated_by,
                                        closed_before_cut=closed_before_cut)
    if outcome not in listed:
        return False
    return _file_feedback_request(run, outcome, run_state)


def _file_feedback_request(run: Run, outcome: str, run_state: Any) -> bool:
    """File the run's open-issue request in the learning store (#1278 A4 F1), as `enqueue_curation` files its
    request. Reading the run's record is guarded, and so is the store: one it cannot reach, or that refuses the
    request (the tenant is not active, the request holds what it can never hold), costs this request, never the
    investigation or its curation."""
    import os

    from defender.investigation.record_query import captured_lookups
    from defender.learning import store as learning_store

    try:
        record = formats.read_record(RunPaths(run.run_dir).alert_record)
        if record is None:
            raise OSError("the run's record vanished")
        case_id = case_ref_of_digest(record.digest)
        lookups = captured_lookups(run_state) if run_state is not None else []
    except (OSError, ValueError, TenantRefused) as failed:
        _logger.error(f"NOT enqueuing a feedback issue: could not read the run's record: {failed}")
        return False
    variable = tenancy.database_address_variable()
    dsn = os.environ.get(variable, "")
    if not dsn:
        _logger.error(f"NOT enqueuing a feedback issue: {variable} is not set, so the learning store cannot be "
                      "reached")
        return False
    try:
        with learning_store.blocking(dsn) as store:
            filed = store.enqueue_feedback_issue(str(run.tenant_id), str(run.id), case_id, outcome=outcome,
                                                 lookups=lookups)
    except Exception as failed:  # noqa: BLE001 — a request that cannot be filed costs only itself
        _logger.error(f"NOT enqueuing a feedback issue: the learning store did not take the request: {failed!r}")
        return False
    if not filed:
        _logger.info(f"NOT enqueuing a feedback issue: run {run.id} is already filed")
    return bool(filed)


# -- run setup's host half (#1342 M3, #1170 A6) -----------------------------------------------------
#
# What a run does on the trusted side before its investigation: the tenant's alert mapping, the
# launch-time publish and its outcome, the run's own copy of its knowledge, the tenant resolved over
# that copy and its read grant, the knowledge record beside the run folder. Shared by the operator
# command (`run.py <alert>`, which runs both halves in one process) and the per-job host helper
# (`defender.job_host`, which runs this half for a job and hands the job container the rest). Every
# refusal is a `SystemExit` naming its cause, as run setup's are.

def read_alert_mapping(records: Any, tenant_id: Any) -> AlertMapping:
    """The tenant's alert mapping from its records, or a `[run.py]` refusal: none saved (the wording
    `records` owns, naming how to set one) or the records could not be reached (#1345 O4)."""
    try:
        mapping = records.alert_mapping(tenant_id)
    except TenantRefused as refused:
        sys.exit(f"[run.py] this run's tenant cannot be used: {refused}")
    if mapping is None:
        sys.exit(f"[run.py] this run's tenant cannot be used: {formats.ALERT_MAPPING_MISSING}")
    return mapping


class PublishLaunch(Protocol):
    """The launch-time publish run start calls (`publish_launch.launch_publish`, or an in-process
    caller's stand-in): typed, so the tenant id reaches the records it writes as a `TenantId`."""

    def __call__(self, tenant_id: TenantId, *, data_root: Path) -> object: ...


def default_publish(records: tenancy.TenantDirectory) -> PublishLaunch:
    """The real launch-time publish: a separate child process (O-BUDGET, P-3), whose outcomes
    only the launcher sees are recorded through this run's tenant records."""
    from defender.investigation.publish_launch import launch_publish as real

    return functools.partial(real, directory=records)


@contextlib.contextmanager
def stopped_by_sigterm() -> Iterator[None]:
    """While the launch-time publish runs, a SIGTERM (teardown stopping this run) unwinds this
    process as `SystemExit(128 + SIGTERM)`, so the run never goes on past its publish. The real
    launcher holds the signal back while its child runs: it stops the child by its one rule (a
    child that took the tenant lock is waited for, never signalled), kills its process group (its own session, which
    no signal to this process reaches) and only then delivers the signal here (#1379 r3). The
    handler found is put back after. Only in the main thread, the one a handler runs in."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def stop(signum: int, _frame: object) -> None:
        raise SystemExit(128 + signum)

    previous = signal.signal(signal.SIGTERM, stop)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)


def publish_report(
    publish: PublishLaunch | None, tenant: tenancy.Tenant, data_root: DataRoot,
    records: tenancy.TenantDirectory,
) -> PublishReport:
    """The launch-time publish's outcome (#1108 P4, U7): the child is handed identifiers only
    — the tenant id and the data root (O8: no login material passes through the run process)
    — and its one report line is read back. The real launcher never raises and records every
    outcome itself in the tenant records; a seam that raises is U11's `stale:operator`, never
    fresh, recorded by the same recorder the launcher uses."""
    from defender.tenancy import run_knowledge

    try:
        launch = publish if publish is not None else default_publish(records)
        with stopped_by_sigterm():
            line = launch(tenant.id, data_root=tenancy.data_root_for_child(data_root))
    except Exception as failed:  # noqa: BLE001 — U11: a failed child is stale:operator, recorded
        from defender.tenancy import record_report

        line = run_knowledge.failed_line(f"{type(failed).__name__}: {failed}")
        record_report(records, tenant.id, line, by="launch-time publish")
    return run_knowledge.read_publish_report(line)


def resolve_knowledge(
    tenant: tenancy.Tenant, *, pin: str | None, publish: PublishLaunch | None,
    data_root: DataRoot, records: tenancy.TenantDirectory,
) -> KnowledgeSource:
    """Which export this run reads and why: the pinned one (no publish), else `current` after
    the launch-time publish — or the refusal before the box (O-A, O9)."""
    from defender.tenancy import run_knowledge

    report = None if pin is not None else publish_report(publish, tenant, data_root, records)
    try:
        source = run_knowledge.resolve_source(tenant, report=report, pinned=pin)
    except run_knowledge.KnowledgeRefused as refused:
        sys.exit(f"[run.py] {refused}")
    if source.kind == run_knowledge.STALE:
        _logger.warning(f"knowledge is stale ({source.stale_kind}): the run reads the last "
                        f"published snapshot {source.commit[:12]}; the publish said: "
                        f"{source.reason}")
    return source


def copy_knowledge(tenant: tenancy.Tenant, source: KnowledgeSource, run_id: str) -> RunCopy:
    """The run's own copy of its export (U9), made and owned by the calling process, or the
    refusal before the box."""
    from defender.tenancy import run_knowledge

    try:
        copy = run_knowledge.copy_for_run(tenant, source, run_id)
    except (run_knowledge.KnowledgeRefused, OSError) as refused:
        sys.exit(f"[run.py] the run's knowledge could not be copied: {refused}")
    try:
        tenancy.check_run_settings(copy.settings)
    except TenantRefused as refused:
        copy.remove()
        sys.exit(f"[run.py] this run's tenant cannot be used: {refused}")
    return copy


def run_tenant_or_exit(
    tenant: tenancy.Tenant, *, defender_dir: Path | None = None, dispatches_lead_zero: bool,
    copy: RunCopy | None = None,
) -> RunTenant:
    """The accepted tenant ready to run — its grants and lead-zero dispatch from run start's
    readiness function, over the run's own copy of its knowledge (#1108 P4, O-B: settings,
    catalog and lessons from one export) — or the refusal, before the run dir, the box and any
    model call, so tenant misconfiguration fails early. Refusals name the file to edit.

    `dispatches_lead_zero` is False for an `--episode` sibling, which dispatches no turn-0
    lead. Without `copy` (a direct caller), the record is resolved over the tenant's own
    folder. `defender_dir` is not read: the code tree holds no tenant knowledge (O1)."""
    from defender.systems import run_tenant as run_tenant_mod

    del defender_dir
    roots = ({} if copy is None else
             {"agent_root": copy.agent, "settings_root": copy.settings,
              "stage_token": copy.token})
    try:
        return run_tenant_mod.run_tenant_for(
            tenant, dispatches_lead_zero=dispatches_lead_zero, **roots)
    except run_tenant_mod.TenantRefused as refusal:
        sys.exit(f"[run.py] this run's tenant {tenant.id!r} cannot be used: {refusal}")


def proxied_reads(tenant: RunTenant, *, down: Collection[str] = ()) -> tuple[str, ...]:
    """The systems a run's read pass names (#1163, #1449): the tenant's granted systems that are
    declared `http-proxy` in the knowledge the run reads, less `down`. The operator's run subtracts
    the systems its start judged down; a job's helper subtracts none, since that judgement runs
    adapter code (#1170 O5)."""
    from defender.kit.access import AccessDeclaration
    from defender.systems import system_status

    proxied = {name for name, found in tenant.access.items()
               if isinstance(found, AccessDeclaration) and name not in down}
    return tuple(sorted(system_status.granted_systems(tenant.grants) & proxied))


def write_knowledge_record(run_dir: Path, source: KnowledgeSource) -> None:
    """The host-held knowledge-source record beside the run dir (U12): what every reader of
    the run's knowledge status reads. A run that cannot write it does not start: a missing
    record would read as unreadable everywhere (OD22')."""
    from defender.tenancy import run_knowledge

    path = RunPaths(run_dir).knowledge_source()
    try:
        run_knowledge.write_host_record(path, source)
    except OSError as e:
        sys.exit(f"[run.py] could not write the run's knowledge record {path}: {e}")
