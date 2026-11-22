"""The readiness kind (#1471 P-1, R3, R12-1, R13-1, C4): an investigation's launch, stopped before the run.

The helper runs the launch's tenant-level steps as the investigation's own code (`_common.tenant_launch_steps`: the
tenant's lock and admission, its records, its alert mapping, the launch-time publish (recorded `readiness`), the
runs-folder check, the run copy named by the check's id, the tenant over the copy, the roster, the verdict, the
grant, the signing set-up and the first pass, signed under the check's id and thrown away), and none of the
investigation's own (the launch check, the alert, the run folder, the versions record).

What it decided before the container it stages under the check's claim (#1546), create-once:

- a step's refusal after the publish gave a source: the source's `knowledge` (served shape), before the result;
- a step's refusal: `{refused, step, sentence}`, our own sentence (P-2: a publish refusal names only its kind), and
  no container;
- a container that cannot be started (or its socket opened): `{failed, start_failed}`; a crash, or a refusal before
  the container that is no step's: `{failed, worker_error}` (R13-1.2; the shared ending, `_host_request`);
- otherwise nothing: the readiness container (`run.py --readiness <id>`, `run.readiness_main`) sends its `knowledge`
  (the launch facts' source) and its `result`, answered `launch` and those verbs alone (C4).

The runs folder gone after the worker's pre-open, or a knowledge record that cannot be written, is the helper's own
failure (`HelperFault`): no record, and a non-zero exit the worker reads (R13-1.1, .2)."""
from __future__ import annotations

import contextlib
from typing import Any

from . import _host_request
from ._common import HelperFault, LaunchFacts, StepRefused, tenant_launch_steps
from ._session import KindSpec, Prepared, Registry, Session

KIND = "readiness"
#: Who asked for the launch-time publish, as its outcome is recorded (design §6 "Publish trigger").
TRIGGER = "readiness"
#: The prefix every `run_common` setup refusal carries: a readiness sentence is the refusal's words without it.
_RUN_PY = "[run.py] "


def _readiness_lane() -> _host_request.ResultLane:
    from defender.records import job_lane

    # A refusal before the container that wrote no record is no step's refusal the check can name: the helper's error.
    return _host_request.ResultLane(kind=KIND, failed=job_lane.ReadinessRecord.failed, refused_reason=job_lane.WORKER_ERROR)


_LANE = _readiness_lane()


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
    """The readiness sentence of a step's refusal: the launch's own words (P-2: its `sentence`, never its log-only
    `detail`), the publish's its kind alone."""
    if refused.step == "publish":
        return _publish_sentence(refused.report)
    return refused.sentence.removeprefix(_RUN_PY).strip()


def _write_knowledge(session: Session, source: Any) -> None:
    """The knowledge of the source the publish gave (R13-1.2), staged by the helper in the served shape when it ends the
    check before its container; a source it cannot map is the helper's own failure."""
    from . import _evidence
    from ._records import served_knowledge

    served = served_knowledge(source.host_record())
    if served is None:
        raise HelperFault("the check's knowledge could not be mapped to its served shape")
    _evidence.state(session).stage("knowledge", served)


def _readiness_refused(session: Session, facts: LaunchFacts, refused: StepRefused) -> None:
    """A tenant-level step refused the check: its knowledge record first when the publish gave a source, then the
    refusal. A refusal of the runs-folder check is no step's (R13-1.1): the helper's own failure."""
    from defender.records import job_lane

    if not job_lane.is_readiness_step(refused.step):
        raise HelperFault(f"its {refused.step} check refused: {refused}") from None
    if facts.source is not None:
        _write_knowledge(session, facts.source)
    _host_request.write_once(session, _LANE, job_lane.ReadinessRecord.refused(refused.step, _readiness_sentence(refused)))


def _prepare_readiness(session: Session, hold: contextlib.ExitStack) -> Prepared:
    """The host half (module doc): the shared steps, the knowledge record, then the container's launch facts."""
    from defender import tenancy

    from ._folders import copy_tenant

    rid = _host_request.request_id(session)
    facts = LaunchFacts()
    if session.job_root is None or session.job_inputs is None:
        raise HelperFault("the claim's root and inputs were not made")
    job_tenant = tenancy.JobTenant(id=session.tenant_id, data_root=tenancy.data_root_from_path(session.job_root),
                             inputs=session.job_inputs)
    try:
        tenant_launch_steps(session, hold, copy_id=rid, facts=facts, trigger=TRIGGER, job_tenant=job_tenant,
                            copy_tenant=lambda accepted: copy_tenant(session, accepted))
    except StepRefused as refused:
        _readiness_refused(session, facts, refused)
        raise
    try:
        source, copy, current = facts.source, facts.copy, facts.current
        command = session.command or [
            "python3", str(session.defender_dir / "run.py"), "--readiness", rid, "--tenant", session.tenant_id]
        launch = {
            "kind": KIND, "tenant": session.tenant_id, "job": rid, "tenant_state": "active",
            "export_commit": source.commit, "knowledge": source.host_record(), "run_copy": str(copy.root),
            "inputs_dir": str(session.job_inputs),
            # The records read above (#1366 O6), which the container builds its tenant from (it reads no database).
            "records": current.as_wire(),
        }
        # The first pass was signed and is thrown away (R12-1): the container is handed no pass and answered none.
        return Prepared(launch=launch, command=list(command), passes=None, cleanup=facts.cleanup, exited=_host_request.after_container(_LANE))
    except BaseException:
        facts.cleanup.close()
        raise


def register_readiness(registry: Registry) -> None:
    """The readiness kind: answered `launch` alone (`register_common`), never a pass or a box (C4)."""
    registry.kind(KIND, KindSpec(prepare=_prepare_readiness, end=_host_request.end_before_container(_LANE)))
