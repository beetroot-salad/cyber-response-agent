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
from typing import Any, cast

from defender.credential_proxy import PASS_LIFETIME_SEC
from defender.job_socket import Refused

from ._common import LaunchFacts, answer_pass, start_run_box, tenant_launch_steps
from ._session import DOCKER_DID_NOT_RUN, KindSpec, Prepared, Registry, Session, SetupRefused, Signing, setup_step

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
    #: The job's signer (#1471 W-D8: every investigation has one): its read passes' and its write pass's.
    signing: Signing
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


def _alert_ticket(record_text: str | None) -> str | None:
    """The ticket the alert names, from the record text `materialize_run` derived from the bytes it admitted and handed
    over in memory: one read of the worker's alert file serves the digest check and the ticket, and no file a job can
    write is read back (#1471 P-5)."""
    from defender.records import formats

    return formats.ticket_of_record(record_text)


def _case_write_system(current: Any, run_tenant: Any) -> str | None:
    """The tenant's case system when it is reached through the credential proxy, else None."""
    from defender.kit.access import AccessDeclaration

    case = current.case
    if case is None or not isinstance(run_tenant.access.get(case.system_id), AccessDeclaration):
        return None
    return str(case.system_id)


def _materialize(session: Session, accepted: Any, run: Any, launch: Any, mapping: Any, source: Any, *,
                 digest: str, admitted: list[str]) -> Any:
    """The run folder, made by the helper (A6): its input and stamp, then the host-held knowledge record beside it."""
    from defender import run_common
    from defender.investigation.driver import resolve_main_model
    from defender.records.formats import TenantRefused

    try:
        made = run_common.materialize_run(launch.alert, run=run, tenant=accepted, model=resolve_main_model(None),
                                          mapping=mapping, knowledge=source, launch=launch, alert_digest=digest,
                                          on_admitted=admitted.append)
    except TenantRefused as refused:
        raise SetupRefused(str(refused)) from None
    except SystemExit as refused:
        raise SetupRefused(str(refused.code)) from None
    try:
        run_common.write_knowledge_record(Path(made.run_dir), source)
    except SystemExit as refused:
        raise SetupRefused(str(refused.code)) from None
    return made


def _job_tenant(session: Session) -> Any:
    """The job's own tenant over its root and inputs (`tenancy.JobTenant`): where its run is made."""
    from defender import tenancy

    if session.job_root is None or session.job_inputs is None:
        raise SetupRefused("the claim's root and inputs were not made")
    return tenancy.JobTenant(id=session.tenant_id, data_root=tenancy.data_root_from_path(session.job_root),
                             inputs=session.job_inputs)


def _launch_copies(session: Session) -> Any:
    """The launch record and the alert, written by the helper in the job's root from the claim's launch facts and the
    stored alert's exact bytes (#1546: nothing is read beside the tenant's runs), then checked as a launch is
    (`JobLane.check_launch`). The alert is admitted later against the digest the worker handed this helper."""
    import secrets as _secrets

    from defender import tenancy
    from defender.records import job_lane

    from . import _evidence

    claim = _evidence.state(session).claim
    launch = claim.launch
    alert_id = launch.get("alert_id")
    stored = session.rows.alert(session.tenant_id, str(alert_id)) if isinstance(alert_id, str) else None
    if stored is None:
        raise SetupRefused("the launch check refused the job: the claim names no alert the store holds")
    box_token = launch.get("box_token")
    record = job_lane.LaunchRecord(
        investigation_id=str(session.job_id), tenant_id=str(session.tenant_id), alert_id=str(alert_id),
        digest=str(launch.get("digest") or session.alert_digest), label=str(launch.get("label") or stored.title or ""),
        box_token=box_token if isinstance(box_token, str) else _secrets.token_hex(16))
    if session.job_root is None:
        raise SetupRefused("the claim's root was not made")
    try:
        with job_lane.JobLane.open(tenancy.data_root_from_path(session.job_root), session.tenant_id) as lane:
            lane.write_launch(record, bytes(stored.raw))
            return lane.check_launch(str(session.job_id))
    except (job_lane.JobLaneRefused, OSError) as refused:
        raise SetupRefused(f"the launch check refused the job: {refused}") from None


def prepare(session: Session, hold: contextlib.ExitStack) -> Prepared:
    from defender import run_common
    from defender.investigation.publish_launch import LAUNCH_TRIGGER

    from ._folders import copy_tenant

    inv = str(session.job_id)
    if not session.alert_digest:
        raise SetupRefused("the worker handed this helper no --alert-digest: the alert is checked against it alone")
    if session.post_ticket and not session.ticket_link:
        raise SetupRefused("a flagged job needs the worker's --ticket-link")
    job_tenant = _job_tenant(session)

    # The tenant-level steps, the readiness check's too (#1471 P-1), with the launch check after the admission; then
    # the investigation's own: the run folder and the records beside it.
    facts = tenant_launch_steps(session, hold, copy_id=inv, facts=LaunchFacts(), trigger=LAUNCH_TRIGGER,
                                launch=lambda: _launch_copies(session), job_tenant=job_tenant,
                                copy_tenant=lambda accepted: copy_tenant(session, accepted))
    accepted, launch, source, copy, current = facts.accepted, facts.launched, facts.source, facts.copy, facts.current
    cleanup, passes, reads = facts.cleanup, facts.passes, facts.reads
    try:
        record_texts: list[str] = []
        made = _materialize(session, accepted, facts.run, launch, facts.mapping, source, digest=session.alert_digest,
                            admitted=record_texts)
        setup_step(run_common.write_versions_record, Path(made.run_dir), current)
    except BaseException:
        cleanup.close()
        raise
    session.minted.add(inv)
    command = session.command or [
        "python3", str(session.defender_dir / "run.py"), "--job", inv, "--tenant", session.tenant_id]
    launch_facts = {
        "kind": KIND, "tenant": session.tenant_id, "job": inv, "tenant_state": "active",
        "export_commit": source.commit, "knowledge": source.host_record(), "run_dir": str(made.run_dir),
        "run_copy": str(copy.root), "inputs_dir": str(session.job_inputs),
        "proxy_url": passes.proxy_url if passes is not None else None,
        "grant": [[s, "r"] for s in reads], "pass_lifetime": PASS_LIFETIME_SEC,
        # The records read above (#1366 O6), which the container builds its tenant from (it reads no database).
        "records": current.as_wire(),
        # The start token the worker minted for the run box (#1342 r5 C1); the helper stamps it on the box itself.
        "box_token": launch.record.box_token,
        # What the worker handed the helper at its start (#1471 P-5), not the launch record's: whether this job posts to
        # its ticket, and the link it posts. The container asks for a write pass only when flagged.
        "post_ticket": session.post_ticket, "ticket_link": session.ticket_link,
    }
    write = _WritePass(system=_case_write_system(current, facts.run_tenant), ticket=_alert_ticket(record_texts[0] if record_texts else None)) \
        if session.post_ticket else None
    signing = cast(Signing, facts.signing)  # set by every launch not refused: signing is set up for each (W-D8)
    return Prepared(launch=launch_facts, command=list(command), passes=passes, cleanup=cleanup,
                    state=_State(made, copy, accepted, launch.record.box_token, signing, write), exited=_exited)


def end(session: Session, cause: str) -> None:
    """The outcome of an ending decided before the container (A3), staged by the helper: `setup: refused` (a setup
    refusal, the evidence store or key login unconfigured included), a start failure (`box: start_failed`), or a crash
    (`setup: crashed`). Nothing ran, so nothing was spent and no box was scrubbed."""
    from defender.records import job_facts

    from . import _evidence

    setup, box = {
        "refused": (job_facts.SETUP_REFUSED, job_facts.BOX_NOT_STARTED),
        "start-failed": (job_facts.SETUP_DONE, job_facts.BOX_START_FAILED),
    }.get(cause, (job_facts.SETUP_CRASHED, job_facts.BOX_NOT_STARTED))
    _evidence.state(session).stage("outcome", {
        "setup": setup, "box": box, "report_committed": False, "scrub": "not_run", "cut_short": None, "closing": None,
        "cost_usd": 0.0, "cost_is_lower_limit": False})


def _exited(session: Session, rc: int) -> None:
    """After the container: a `docker run` that never ran the job (and so staged no outcome) ends it as a start failure
    (A3, O11). The run page is the job's own push (A-O8): nothing is copied from its folder."""
    from . import _evidence

    ev = _evidence.state(session)
    if rc in DOCKER_DID_NOT_RUN and not (ev.has("outcome") or ev.has("refused/outcome")):
        sys.stderr.write(f"[job_host] job {session.job_id}: the job container did not start (docker exit "
                         f"{rc}); the job ran nowhere\n")
        end(session, "start-failed")


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
    if not isinstance(state, _State) or state.write is None:
        raise Refused("this job is not flagged to post to its ticket", "not-flagged")
    write = state.write
    if write.system is None:
        raise Refused("the case system is not reached through the credential proxy", "no-write-system")
    if write.ticket is None:
        raise Refused("the alert names no ticket", "no-ticket")
    if not isinstance(ask, str) or not ask:
        raise Refused("pass.write_back takes a non-empty text `ask`", "bad-fields")
    with write.lock:
        if write.answer is not None:
            if ask == write.ask:
                return dict(write.answer)
            raise Refused("a write pass was already signed for this job", "already-signed")
        try:
            answer = state.signing.mint_write(ident, write.system, write.ticket)
        except Exception as failed:  # noqa: BLE001 — a pass that cannot be signed is the job's to report
            raise Refused(f"the pass could not be signed: {type(failed).__name__}: {failed}", "sign-fault") from None
        write.ask, write.answer = ask, answer
        return dict(answer)


def register_investigation(registry: Registry) -> None:
    registry.kind(KIND, KindSpec(prepare=prepare, end=end))
    registry.add("pass", kinds=(KIND,), handler=answer_pass, required=("id",))
    registry.add("pass.write_back", kinds=(KIND,), handler=_write_pass, required=("id", "ask"), after_signal=True)
    registry.box_kind("shell", kinds=(KIND,), start=_run_box)
