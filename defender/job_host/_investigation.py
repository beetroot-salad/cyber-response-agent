"""The investigation kind (#1170 A3, A6, O5): the host half of run setup, its pass and its shell box.

The host half, in order, before the container (the run half is the container's `run.py --job`): the tenant's lock and
admission (`host_tenant`: an investigation waits for a busy lock, A3), the launch check (the worker's launch record),
the alert mapping, the launch-time publish, the run copy (owned by this helper, C20) and its settings check, the tenant
resolved over the copy and the tenant's current records (#1366: read once, before the alert mapping; a tenant not
imported is refused), the grant (the granted systems declared `http-proxy` in the export just copied, narrowed to the
systems the tenant has enabled records of; systems the run later judges down are not subtracted, O5), the first pass (only for a non-empty grant: a pass that cannot be signed
refuses the job, O11), then the run folder made (`materialize_run`: the alert admitted against the launch record's
digest, input and stamp) and the knowledge-source and record-versions records beside it. The records read are handed
to the container in the launch facts. Every refusal is `SetupRefused`, its cause on the
helper's stderr, and the job-end record says `setup: refused` (A3).

This half is the operator command's too (A6): each step is `run_common`'s, the one `run.py <alert>` calls in its own
process; the helper adds only the lock, the launch check, the pass mint and its own ownership of what it made."""
from __future__ import annotations

import contextlib
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.credential_proxy import PASS_LIFETIME_SEC
from defender.job_socket import Refused

from ._common import answer_pass, first_pass, grant, mirror_run_page, settle_knowledge, start_run_box
from ._session import DOCKER_DID_NOT_RUN, KindSpec, Prepared, Registry, Session, SetupRefused, setup_step

_logger = logging.getLogger(__name__)

KIND = "investigation"


@dataclass
class _State:
    """What the investigation's host half made: the run, its copy, the tenant accepted, and the box token its worker
    minted (the run box is stamped with it, #1342 r5 C1)."""

    run: Any
    copy: Any
    tenant: Any
    box_token: str


def _materialize(session: Session, accepted: Any, run: Any, launch: Any, mapping: Any, source: Any) -> Any:
    """The run folder, made by the helper (A6): its input and stamp, then the host-held knowledge record beside it."""
    from defender import run_common
    from defender.investigation.driver import resolve_main_model
    from defender.records.formats import TenantRefused

    try:
        made = run_common.materialize_run(launch.alert, run=run, tenant=accepted, model=resolve_main_model(None),
                                          mapping=mapping, knowledge=source, launch=launch)
    except TenantRefused as refused:
        raise SetupRefused(str(refused)) from None
    except SystemExit as refused:
        raise SetupRefused(str(refused.code)) from None
    try:
        run_common.write_knowledge_record(Path(made.run_dir), source)
    except SystemExit as refused:
        raise SetupRefused(str(refused.code)) from None
    return made


def prepare(session: Session, hold: contextlib.ExitStack) -> Prepared:  # noqa: C901, PLR0915 — the host half, in order
    from defender import run_common
    from defender.records import job_lane
    from defender.records.formats import TenantRefused
    from defender.systems.run_tenant import host_tenant

    inv = str(session.job_id)
    data_root = session.root
    try:
        admitted = host_tenant(data_root, session.tenant_id, defender_dir=session.defender_dir, clone_tree=False)
    except TenantRefused as refused:
        raise SetupRefused(f"this job's tenant cannot be used: {refused}") from None
    hold.enter_context(admitted)
    accepted, records = admitted.tenant, admitted.directory
    session.tenant_accepted(accepted)
    try:
        with job_lane.JobLane.open(data_root, session.tenant_id) as lane:
            launch = lane.check_launch(inv)
    except job_lane.JobLaneRefused as refused:
        raise SetupRefused(f"the launch check refused the job: {refused}") from None
    # The tenant's current records, read once here (#1366 O6): a tenant not imported is refused before its alert
    # mapping is read (R8). The container reads no database; it is handed these in the launch facts.
    current = setup_step(run_common.read_records, records, accepted.id)
    mapping = setup_step(run_common.read_alert_mapping, records, accepted.id)
    source = settle_knowledge(session, accepted, records)
    try:
        run = accepted.runs_repository().launched(launch)
    except TenantRefused as refused:
        raise SetupRefused(str(refused)) from None
    cleanup = contextlib.ExitStack()
    try:
        copy = setup_step(run_common.copy_knowledge, accepted, source, inv)
        cleanup.callback(copy.remove)
        try:
            run_tenant = setup_step(run_common.run_tenant_or_exit, accepted, dispatches_lead_zero=True,
                                 records=current, copy=copy)
        except TenantRefused as refused:
            raise SetupRefused(f"this job's tenant cannot be used: {refused}") from None
        # The tenant's systems over the catalog (read cold: no adapter code runs here, N7), its grants narrowed to the
        # systems it has enabled records of (#1366 R12), so the pass names none it has not; the container warns.
        roster = setup_step(run_common.run_roster, session.defender_dir)
        verdict = setup_step(run_common.tenant_verdict, run_tenant, roster, warn=False)
        reads = grant(verdict.tenant)
        passes = first_pass(session, accepted, records, reads)
        made = _materialize(session, accepted, run, launch, mapping, source)
        setup_step(run_common.write_versions_record, Path(made.run_dir), current)
    except BaseException:
        cleanup.close()
        raise
    session.minted.add(inv)
    command = session.command or [
        "python3", str(session.defender_dir / "run.py"), "--job", inv, "--tenant", session.tenant_id]
    facts = {
        "kind": KIND, "tenant": session.tenant_id, "job": inv, "tenant_state": "active",
        "export_commit": source.commit, "knowledge": source.host_record(), "run_dir": str(made.run_dir),
        "run_copy": str(copy.root), "proxy_url": passes.proxy_url if passes is not None else None,
        "grant": [[s, "r"] for s in reads], "pass_lifetime": PASS_LIFETIME_SEC,
        # The records read above (#1366 O6), which the container builds its tenant from (it reads no database).
        "records": current.as_wire(),
        # The start token the worker minted for the run box (#1342 r5 C1); the helper stamps it on the box itself.
        "box_token": launch.record.box_token,
    }
    return Prepared(launch=facts, command=list(command), passes=passes, cleanup=cleanup,
                    state=_State(made, copy, accepted, launch.record.box_token), exited=_exited)


def end(session: Session, cause: str) -> None:
    """The job-end record for an ending decided before the container (A3), in the job lane's vocabulary."""
    from defender.records import job_facts, job_lane

    setup, box = {
        "refused": (job_facts.SETUP_REFUSED, job_facts.BOX_NOT_STARTED),
        "start-failed": (job_facts.SETUP_DONE, job_facts.BOX_START_FAILED),
    }.get(cause, (job_facts.SETUP_CRASHED, job_facts.BOX_NOT_STARTED))
    record = job_lane.JobEnd(setup=setup, box=box, report_committed=False, scrub_verified=False, cut_short=None)
    try:
        with job_lane.JobLane.open(session.root, session.tenant_id) as lane:
            lane.write_job_end(session.job_id, record)
    except FileExistsError:
        _logger.error("job %s: a job-end record is already there; it is kept, and this one (%s) is not written",
                      session.job_id, record.text())
    except (OSError, job_lane.JobLaneRefused) as e:
        _logger.error("job %s: the job-end record could not be written: %s", session.job_id, e)


def _exited(session: Session, rc: int) -> None:
    """After the container: a `docker run` that never ran the job (and so wrote no end record) ends the row as a start
    failure (A3, O11); the job's page, left in its run folder, is copied to the tenant's publish area (A10)."""
    from defender.records import job_lane

    state = session.prepared.state if session.prepared is not None else None
    if rc in DOCKER_DID_NOT_RUN:
        try:
            with job_lane.JobLane.open(session.root, session.tenant_id) as lane:
                written = lane.read_job_end(session.job_id) is not None
        except (OSError, job_lane.JobLaneRefused):
            written = False
        if not written:
            sys.stderr.write(f"[job_host] job {session.job_id}: the job container did not start (docker exit "
                             f"{rc}); the job ran nowhere\n")
            end(session, "start-failed")
            return
    if isinstance(state, _State):
        mirror_run_page(state.run, state.tenant)


def _run_box(session: Session, ident: str) -> Any:
    """The investigation's run box (`start_run_box`), shaped from the claim alone: the run folder `<T>/runs/<inv>`,
    the run copy's stage, the run clock, the code tree."""
    state = session.prepared.state if session.prepared is not None else None
    if not isinstance(state, _State) or ident != session.job_id:
        raise Refused(f"no run box is served for {ident!r}", "unknown-id")
    return start_run_box(session, Path(state.run.run_dir), state.copy, start_token=state.box_token)


def register_investigation(registry: Registry) -> None:
    registry.kind(KIND, KindSpec(prepare=prepare, end=end))
    registry.add("pass", kinds=(KIND,), handler=answer_pass, required=("id",))
    registry.box_kind("shell", kinds=(KIND,), start=_run_box)
