"""The readiness kind (#1471 P-1, R3, R12-1, R13-1, C4): an investigation's launch, stopped before the run.

The helper runs the launch's tenant-level steps as the investigation's own code (`_common.tenant_launch_steps`: the
tenant's lock and admission, its records, its alert mapping, the launch-time publish (recorded `readiness`), the
runs-folder check, the run copy named by the check's id, the tenant over the copy, the roster, the verdict, the
grant, the signing set-up and the first pass, signed under the check's id and thrown away), and none of the
investigation's own (the launch check, the alert, the run folder, the versions record).

What it computed it writes once, create-only, in the tenant's job lane, keyed by the check's id:

- when the publish gave a source, the knowledge record (`JobLane.write_request_knowledge`), before anything below;
- a step's refusal: `{refused, step, sentence}`, our own sentence (P-2: a publish refusal names only its kind), and
  no container;
- a container that cannot be started (or its socket opened): `{failed, start_failed}`; a crash: `{failed,
  worker_error}` (R13-1.2);
- otherwise nothing: the readiness container (`run.py --readiness <id>`, `run.readiness_main`) writes the result,
  answered `launch` alone (C4).

The runs folder gone after the worker's pre-open, or a knowledge record that cannot be written, is the helper's own
failure (`HelperFault`): no record, and a non-zero exit the worker reads (R13-1.1, .2)."""
from __future__ import annotations

import contextlib
import logging
import uuid
from typing import Any

from ._common import HelperFault, LaunchFacts, StepRefused, tenant_launch_steps
from ._session import DOCKER_DID_NOT_RUN, KindSpec, Prepared, Registry, Session

_logger = logging.getLogger(__name__)

KIND = "readiness"
#: Who asked for the launch-time publish, as its outcome is recorded (design §6 "Publish trigger").
TRIGGER = "readiness"
#: The prefix every `run_common` setup refusal carries: a readiness sentence is the refusal's words without it.
_RUN_PY = "[run.py] "


def _request_id(session: Session) -> str:
    """The check's id, as the worker handed it (`--job`): a UUID in its canonical text, or the helper's own failure."""
    raw = str(session.job_id)
    try:
        canonical = str(uuid.UUID(raw))
    except ValueError:
        canonical = ""
    if canonical != raw:
        raise HelperFault(f"{raw!r} is not a readiness check's id (a UUID)")
    return raw


def _publish_sentence(report: Any) -> str:
    """A refused publish's sentence (P-2, R5): the report's kind only, never its reason (the forge's reply, which the
    helper's log carries)."""
    from defender.tenancy import run_knowledge

    kind = getattr(report, "kind", None)
    if kind == run_knowledge.MISCONFIGURED:
        return ("the launch-time publish refused the tenant's knowledge as misconfigured, so no run can start on it; "
                "the publish's own reply is in the platform's log")
    if kind == run_knowledge.STALE:
        return (f"the launch-time publish is stale ({getattr(report, 'stale_kind', None)}) and the tenant has no "
                "published knowledge a run can start on")
    return "the launch-time publish settled on no published knowledge a run can start on"


def _readiness_sentence(refused: StepRefused) -> str:
    """The readiness sentence of a step's refusal: the launch's own words (P-2), the publish's its kind alone."""
    if refused.step == "publish":
        return _publish_sentence(refused.report)
    return str(refused).removeprefix(_RUN_PY).strip()


def _write_knowledge(session: Session, source: Any) -> None:
    """The knowledge record of the source the publish gave (R13-1.2), create-only; a fault writing it is the helper's
    own failure."""
    from defender.records import job_lane

    try:
        with job_lane.JobLane.open(session.root, session.tenant_id) as lane:
            lane.write_request_knowledge(session.job_id, source)
    except (OSError, job_lane.JobLaneRefused) as fault:
        raise HelperFault(f"the check's knowledge record could not be written: {type(fault).__name__}: {fault}") from None


def _write_readiness_record(session: Session, record: Any) -> None:
    """The check's one result record, create-only: one already there is kept (and this one logged, not written)."""
    from defender.records import job_lane

    try:
        with job_lane.JobLane.open(session.root, session.tenant_id) as lane:
            lane.write_readiness(session.job_id, record)
    except FileExistsError:
        _logger.error("readiness %s: a result record is already there; it is kept, and this one (%s) is not written",
                      session.job_id, record.text())


def _readiness_refused(session: Session, facts: LaunchFacts, refused: StepRefused) -> None:
    """A tenant-level step refused the check: its knowledge record first when the publish gave a source, then the
    refusal. A refusal of the runs-folder check is no step's (R13-1.1): the helper's own failure."""
    from defender.records import job_lane

    if not job_lane.is_readiness_step(refused.step):
        raise HelperFault(f"its {refused.step} check refused: {refused}") from None
    if facts.source is not None:
        _write_knowledge(session, facts.source)
    _write_readiness_record(session, job_lane.ReadinessRecord.refused(refused.step, _readiness_sentence(refused)))


def _prepare_readiness(session: Session, hold: contextlib.ExitStack) -> Prepared:
    """The host half (module doc): the shared steps, the knowledge record, then the container's launch facts."""
    rid = _request_id(session)
    facts = LaunchFacts()
    try:
        tenant_launch_steps(session, hold, copy_id=rid, facts=facts, trigger=TRIGGER)
    except StepRefused as refused:
        _readiness_refused(session, facts, refused)
        raise
    try:
        _write_knowledge(session, facts.source)
    except BaseException:
        facts.cleanup.close()
        raise
    try:
        source, copy, current = facts.source, facts.copy, facts.current
        command = session.command or [
            "python3", str(session.defender_dir / "run.py"), "--readiness", rid, "--tenant", session.tenant_id]
        launch = {
            "kind": KIND, "tenant": session.tenant_id, "job": rid, "tenant_state": "active",
            "export_commit": source.commit, "knowledge": source.host_record(), "run_copy": str(copy.root),
            # The records read above (#1366 O6), which the container builds its tenant from (it reads no database).
            "records": current.as_wire(),
        }
        # The first pass was signed and is thrown away (R12-1): the container is handed no pass and answered none.
        return Prepared(launch=launch, command=list(command), passes=None, cleanup=facts.cleanup, exited=_readiness_exited)
    except BaseException:
        facts.cleanup.close()
        raise


def _readiness_end(session: Session, cause: str) -> None:
    """The helper's own result for an ending decided before the container (R13-1.2): a container that could not be
    started is `start_failed`, a crash `worker_error`. A refusal's record is already written (`_readiness_refused`); a helper told
    to stop before its container started writes none, so the stopping worker's own ending stands (R13-5)."""
    from defender.records import job_lane

    if cause == "refused" or (cause == "start-failed" and session.signalled.is_set()):
        return
    reason = "start_failed" if cause == "start-failed" else job_lane.WORKER_ERROR
    _write_readiness_record(session, job_lane.ReadinessRecord.failed(reason))


def _readiness_exited(session: Session, rc: int) -> None:
    """After the container: a `docker run` that never ran the entry (so wrote no record) is a start failure."""
    from defender.records import job_lane

    if rc not in DOCKER_DID_NOT_RUN:
        return
    try:
        with job_lane.JobLane.open(session.root, session.tenant_id) as lane:
            written = lane.read_readiness(session.job_id) is not None
    except (OSError, job_lane.JobLaneRefused):
        written = False
    if not written:
        _logger.warning("readiness %s: the container did not start (docker exit %s)", session.job_id, rc)
        _write_readiness_record(session, job_lane.ReadinessRecord.failed("start_failed"))


def register_readiness(registry: Registry) -> None:
    """The readiness kind: answered `launch` alone (`register_common`), never a pass or a box (C4)."""
    registry.kind(KIND, KindSpec(prepare=_prepare_readiness, end=_readiness_end))
