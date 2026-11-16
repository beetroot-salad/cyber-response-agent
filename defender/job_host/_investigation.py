"""The investigation kind (#1170 A3, A6, O5): the host half of run setup, its pass and its shell box.

The host half, in order, before the container (the run half is the container's `run.py --job`): the tenant's lock and
admission (`host_tenant`: an investigation waits for a busy lock, A3), the launch check (the worker's launch record),
the alert mapping, the launch-time publish, the run copy (owned by this helper, C20) and its settings check, the tenant
resolved over the copy and the tenant's current records (#1366: read once, before the alert mapping; a tenant whose
records are not known, #1470 O8, is refused), the grant (the granted systems declared `http-proxy` in the export just copied, narrowed to the
systems the tenant has enabled records of; systems the run later judges down are not subtracted, O5), the first pass (signing is set up for every
investigation, and a pass that cannot be signed refuses the job, O11; the pass itself is signed only for a non-empty grant), then
the run folder made (`materialize_run`: the alert admitted against the digest the worker handed this helper at its start, never the launch record's, #1471 P-5; input and stamp) and the knowledge-source and record-versions records beside it. The records read are handed
to the container in the launch facts. Every refusal is `SetupRefused`, its cause on the
helper's stderr, and the job-end record says `setup: refused` (A3).

This half is the operator command's too (A6): each step is `run_common`'s, the one `run.py <alert>` calls in its own
process; the helper adds only the lock, the launch check, the pass mint and its own ownership of what it made."""
from __future__ import annotations

import contextlib
import logging
import sys
import threading
from dataclasses import dataclass, field
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
    #: The write pass's decision, made once here from what the worker handed the helper (#1471 P-5): whether the job is
    #: flagged, the case system when it is reached through the proxy, and the ticket the admitted alert names.
    write: _WritePass | None = None


@dataclass
class _WritePass:
    """A flagged job's one write pass (#1471 W5, X1): what it may name, and the latch that lets one ask have it. The
    helper answers each connection on its own thread, so the check-and-set holds `lock`."""

    system: str | None
    ticket: str | None
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    ask: str | None = None
    answer: dict[str, Any] | None = None


def _alert_ticket(made: Any) -> str | None:
    """The ticket the alert names, from the facts recorded off the bytes `materialize_run` admitted: one read of the
    worker's alert file serves the digest check and the ticket (#1471 P-5)."""
    from defender.records import formats

    record = formats.parse_alert_record(made.facts.alert_record.read() or "")  # lint-run-records: ok — the alert record's own facts, off the admitted bytes
    return None if record is None else record.facts.case_key


def _case_write_system(current: Any, run_tenant: Any) -> str | None:
    """The tenant's case system when it is reached through the credential proxy, else None."""
    from defender.kit.access import AccessDeclaration

    case = current.case
    if case is None or not isinstance(run_tenant.access.get(case.system_id), AccessDeclaration):
        return None
    return str(case.system_id)


def _materialize(session: Session, accepted: Any, run: Any, launch: Any, mapping: Any, source: Any, *,
                 digest: str) -> Any:
    """The run folder, made by the helper (A6): its input and stamp, then the host-held knowledge record beside it."""
    from defender import run_common
    from defender.investigation.driver import resolve_main_model
    from defender.records.formats import TenantRefused

    try:
        made = run_common.materialize_run(launch.alert, run=run, tenant=accepted, model=resolve_main_model(None),
                                          mapping=mapping, knowledge=source, launch=launch, alert_digest=digest)
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
    if not session.alert_digest:
        raise SetupRefused("the worker handed this helper no --alert-digest: the alert is checked against it alone")
    if session.post_ticket and not session.ticket_link:
        raise SetupRefused("a flagged job needs the worker's --ticket-link")
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
    # The tenant's current records, read once here (#1366 O6): a tenant whose records are not known (#1470 O8) is
    # refused before its alert mapping is read. The container reads no database; it is handed these in the launch facts.
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
        passes = first_pass(session, accepted, records, reads, always=True)
        made = _materialize(session, accepted, run, launch, mapping, source, digest=session.alert_digest)
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
        "run_copy": str(copy.root), "proxy_url": passes.proxy_url if passes is not None and reads else None,
        "grant": [[s, "r"] for s in reads], "pass_lifetime": PASS_LIFETIME_SEC,
        # The records read above (#1366 O6), which the container builds its tenant from (it reads no database).
        "records": current.as_wire(),
        # The start token the worker minted for the run box (#1342 r5 C1); the helper stamps it on the box itself.
        "box_token": launch.record.box_token,
        # What the worker handed the helper at its start (#1471 P-5), not the launch record's: whether this job posts to
        # its ticket, and the link it posts. The container asks for a write pass only when flagged.
        "post_ticket": session.post_ticket, "ticket_link": session.ticket_link,
    }
    write = _WritePass(system=_case_write_system(current, run_tenant), ticket=_alert_ticket(made)) \
        if session.post_ticket else None
    return Prepared(launch=facts, command=list(command), passes=passes, cleanup=cleanup,
                    state=_State(made, copy, accepted, launch.record.box_token, write), exited=_exited)


def end(session: Session, cause: str) -> None:
    """The job-end record for an ending decided before the container (A3), in the job lane's vocabulary. A record that
    cannot be written raises: the helper then exits non-zero, which the worker reads as the helper's own failure."""
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


def _write_pass(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    """`pass.write_back` (#1471 W5): a flagged job's one write pass, `rw` on the case system naming the alert's ticket.
    Refused when the job is not flagged (`not-flagged`), the case system is not reached through the proxy
    (`no-write-system`), the alert names no ticket (`no-ticket`), or a pass was already signed for another ask
    (`already-signed`). The same ask again is answered the same pass (a lost answer); a sign fault leaves the latch unused."""
    ident = session.require_minted(fields["id"])
    ask = fields["ask"]
    state = session.prepared.state if session.prepared is not None else None
    write = state.write if isinstance(state, _State) else None
    if write is None:
        raise Refused("this job is not flagged to post to its ticket", "not-flagged")
    if write.system is None:
        raise Refused("the case system is not reached through the credential proxy", "no-write-system")
    if write.ticket is None:
        raise Refused("the alert names no ticket", "no-ticket")
    passes = session.prepared.passes if session.prepared is not None else None
    if passes is None or not isinstance(ask, str) or not ask:
        raise Refused("pass.write_back takes a non-empty text `ask`", "bad-fields")
    with write.lock:
        if write.answer is not None:
            if ask == write.ask:
                return dict(write.answer)
            raise Refused("a write pass was already signed for this job", "already-signed")
        try:
            answer = passes.mint_write(ident, write.system, write.ticket)
        except Exception as failed:  # noqa: BLE001 — a pass that cannot be signed is the job's to report
            raise Refused(f"the pass could not be signed: {type(failed).__name__}: {failed}", "sign-fault") from None
        write.ask, write.answer = ask, answer
        return dict(answer)


def register_investigation(registry: Registry) -> None:
    registry.kind(KIND, KindSpec(prepare=prepare, end=end))
    registry.add("pass", kinds=(KIND,), handler=answer_pass, required=("id",))
    registry.add("pass.write_back", kinds=(KIND,), handler=_write_pass, required=("id", "ask"), after_signal=True)
    registry.box_kind("shell", kinds=(KIND,), start=_run_box)
