"""The investigation kind (#1170 A3, A6, O5): the host half of run setup, its pass and its shell box.

The host half, in order, before the container (the run half is the container's `run.py --job`): the tenant's lock and
admission (`host_tenant`: an investigation waits for a busy lock, A3), the launch check (the worker's launch record),
the alert mapping, the launch-time publish, the run copy (owned by this helper, C20) and its settings check, the tenant
resolved over the copy, the grant (the granted systems declared `http-proxy` in the export just copied; systems the
run later judges down are not subtracted, O5), the first pass (only for a non-empty grant: a pass that cannot be signed
refuses the job, O11), then the run folder made (`materialize_run`: the alert admitted against the launch record's
digest, input and stamp) and the knowledge-source record beside it. Every refusal is `SetupRefused`, its cause on the
helper's stderr, and the job-end record says `setup: refused` (A3).

This half is the operator command's too (A6): each step is `run_common`'s, the one `run.py <alert>` calls in its own
process; the helper adds only the lock, the launch check, the pass mint and its own ownership of what it made."""
from __future__ import annotations

import contextlib
import functools
import logging
import signal
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender.job_socket import Refused

from ._common import answer_pass
from ._paths import confined
from ._session import PASS_LIFETIME, KindSpec, PassMint, Prepared, Registry, Session, SetupRefused, StartFailed

if TYPE_CHECKING:
    from defender.records import Run

_logger = logging.getLogger(__name__)

KIND = "investigation"
#: The exit statuses of a `docker run` that never ran the job: docker's own failure (an image missing, a runtime
#: refused, 125), a command it could not invoke (126) or find (127).
_DOCKER_DID_NOT_RUN = frozenset({125, 126, 127})


@dataclass
class _State:
    """What the investigation's host half made: the run, its copy, the tenant accepted, and the box token its worker
    minted (the run box is stamped with it, #1342 r5 C1)."""

    run: Any
    copy: Any
    tenant: Any
    box_token: str


def _publish_line(session: Session, accepted: Any, data_root: Any, records: Any) -> str:
    """The launch-time publish's one report line (#1108 P4, U7), run under this helper's lock (C19). A seam that
    raises is U11's `stale:operator`, recorded as the run's own launcher records it."""
    from defender import tenancy
    from defender.tenancy import run_knowledge

    try:
        if session.publish is not None:
            launch = session.publish
        else:
            from defender.investigation.publish_launch import launch_publish

            launch = functools.partial(launch_publish, directory=records)
        return str(launch(accepted.id, data_root=tenancy.data_root_for_child(data_root)))
    except Exception as failed:  # noqa: BLE001 — U11: a failed publish is stale:operator, recorded
        from defender.tenancy import record_report

        line = run_knowledge.failed_line(f"{type(failed).__name__}: {failed}")
        record_report(records, accepted.id, line, by="launch-time publish")
        return line


def _grant(run_tenant: Any) -> tuple[str, ...]:
    """The pass's reads: the granted systems declared `http-proxy`, none subtracted as down (O5)."""
    from defender import run_common

    return run_common.proxied_reads(run_tenant)


def _first_pass(session: Session, accepted: Any, records: Any, reads: tuple[str, ...]) -> PassMint | None:
    """The pass mint over the grant, its first pass signed now (O5, O11); None for an empty grant (nothing to sign,
    so a sealed signer is never asked)."""
    from defender.credential_proxy import signing_access
    from defender.kit.faults import ConfigFault

    if not reads:
        return None
    try:
        signer, address = signing_access(accepted.id, directory=records, signer=session.signer)
    except ConfigFault as refused:
        raise SetupRefused(f"the job's first pass cannot be signed: {refused.detail}") from None
    mint = PassMint(signer, address, str(accepted.id), reads)
    try:
        mint.mint(str(session.job_id))
    except Exception as failed:  # noqa: BLE001 — a first pass that cannot be signed refuses the job (O11)
        raise SetupRefused(f"the job's first pass could not be signed: {type(failed).__name__}: {failed}") from None
    return mint


def _shared(step: Any, *args: Any, **kwargs: Any) -> Any:
    """One step of run setup's shared host half (`run_common`, the operator command's too, A6): its `SystemExit`
    refusal is this job's `setup: refused`, its message the cause."""
    try:
        return step(*args, **kwargs)
    except SystemExit as refused:
        raise SetupRefused(str(refused.code)) from None


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
    from defender.run_common import knowledge_source
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
    try:
        with job_lane.JobLane.open(data_root, session.tenant_id) as lane:
            launch = lane.check_launch(inv)
    except job_lane.JobLaneRefused as refused:
        raise SetupRefused(f"the launch check refused the job: {refused}") from None
    mapping = _shared(run_common.read_alert_mapping, records, accepted.id)
    try:
        source = knowledge_source(accepted, pin=None, publish=session.publish, data_root=data_root, records=records)
    except SystemExit as refused:
        if refused.code == 128 + signal.SIGTERM:  # told to stop while the publish ran: no container (A1)
            session.signalled.set()
            raise StartFailed("the helper was told to stop before its container started; none was started") from None
        raise SetupRefused(str(refused.code)) from None
    try:
        run = accepted.runs_repository().launched(launch)
    except TenantRefused as refused:
        raise SetupRefused(str(refused)) from None
    cleanup = contextlib.ExitStack()
    try:
        copy = _shared(run_common.copy_knowledge, accepted, source, inv)
        cleanup.callback(copy.remove)
        try:
            run_tenant = _shared(run_common.resolve_run_tenant, accepted, dispatches_lead_zero=True, copy=copy)
        except TenantRefused as refused:
            raise SetupRefused(f"this job's tenant cannot be used: {refused}") from None
        reads = _grant(run_tenant)
        passes = _first_pass(session, accepted, records, reads)
        made = _materialize(session, accepted, run, launch, mapping, source)
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
        "grant": [[s, "r"] for s in reads], "pass_lifetime": PASS_LIFETIME,
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
    if rc in _DOCKER_DID_NOT_RUN:
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
        _copy_page(state.run, state.tenant)


def _copy_page(run: Run, tenant: Any) -> None:
    """The run page the container saved in its run folder, copied to the shared publish folder (A10)."""
    from defender.presentation.visualize_run import mirror_page

    try:
        page = run.observability.runtime_html.read()
    except Exception:  # noqa: BLE001 — no page is no copy; the run's own records say why
        _logger.warning("the run page of %s could not be read", run.run_dir, exc_info=True)
        return
    if page:
        mirror_page(page, run.run_dir.name, tenant)


def _run_box(session: Session, ident: str) -> Any:
    """The investigation's run box (#1343 B10, its attached start held here), shaped from the claim alone: the run
    folder `<T>/runs/<inv>`, the run copy's stage, the run clock, the code tree; each path judged with no link
    followed out of the tenant's folder first (H10)."""
    from defender import box

    state = session.prepared.state if session.prepared is not None else None
    if not isinstance(state, _State) or ident != session.job_id:
        raise Refused(f"no run box is served for {ident!r}", "unknown-id")
    run_dir = Path(state.run.run_dir)
    root = session.tenant_root
    confined(root, run_dir)
    confined(root, Path(state.copy.agent))
    confined(root, box.clock_dir(run_dir).parent, must_exist=False)
    return box.start_box(run_dir, session.defender_dir, docker=session.docker, tenant_agent=state.copy.agent,
                         staged_token=state.copy.token, tenant_id=session.tenant_id, require_sandbox=True,
                         start_token=state.box_token)


def register_investigation(registry: Registry) -> None:
    registry.kind(KIND, KindSpec(prepare=prepare, end=end))
    registry.add("pass", kinds=(KIND,), handler=answer_pass, required=("id",))
    registry.box_kind("shell", kinds=(KIND,), start=_run_box)
