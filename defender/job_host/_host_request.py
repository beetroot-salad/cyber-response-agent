"""The lifecycle both host-request kinds share (#1471 R13-1, R13-5): readiness and adoption.

Each kind names its result record once (`ResultLane`: how the tenant's job lane reads and writes it, its failed shape,
and the reason a refusal that wrote no record of its own ends with). From that, this module gives every kind the same:

- the request's id as the worker handed it (`request_id`): a `HostRequestId`, or the helper's own failure;
- the tenant's admission through the helper's records (`admit_host_tenant`, `session.directory`: the process's own when None), and
  the tenant's state as the same records say it (`tenant_state`);
- the one result, staged as the claim's `result` fact, create-once (`write_once`): one already there is kept, this one
  logged;
- the ending decided before the container (`end_before_container`): a stop writes none (the stopping worker ends the row, R13-5); any
  other writes the kind's failed record unless one is already there, so a helper that served its job always leaves one;
- after the container (`after_container`): a `docker run` that never ran the entry (so wrote no record) is a start failure."""
from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ._common import HelperFault
from ._session import DOCKER_DID_NOT_RUN, Session

_logger = logging.getLogger(__name__)

#: The helper's ending causes (`_main._start`) and the failed reason each writes; "refused" is the kind's own.
_START_FAILED = "start-failed"
_REFUSED = "refused"


@dataclass(frozen=True)
class ResultLane:
    """One host-request kind's result record, staged as the claim's `result` fact (#1546 PR2): the kind, its failed
    shape, and the reason a refusal that staged no result of its own ends with."""

    kind: str
    failed: Callable[[str], Any]
    #: The failed reason of a refusal before the container whose step wrote no record of its own.
    refused_reason: str


def request_id(session: Session) -> str:
    """The request's id, as the worker handed it (`--job`): a `HostRequestId` (canonical UUID text), or the helper's own
    failure."""
    from defender.records.formats import HostRequestId, IdRefused

    try:
        return str(HostRequestId(session.job_id))
    except IdRefused:
        raise HelperFault(f"{session.job_id!r} is not a host request's id (a UUID)") from None


def admit_host_tenant(session: Session, hold: contextlib.ExitStack, *, clone_tree: bool = True) -> Any:
    """The tenant's lock and admission through the helper's records (`host_tenant(directory=session.directory)`),
    entered on `hold`; `TenantRefused` is the caller's to word."""
    from defender.systems.run_tenant import host_tenant

    admitted = host_tenant(session.root, session.tenant_id, directory=session.directory,
                           defender_dir=session.defender_dir, clone_tree=clone_tree)
    hold.enter_context(admitted)
    session.tenant_accepted(admitted.tenant)
    return admitted


def tenant_state(session: Session) -> str | None:
    """The tenant's state as the helper's records say it now, or None when it cannot be read or the tenant is unknown."""
    from defender.records.formats import TenantId
    from defender.systems.run_tenant import entry_directory

    try:
        return entry_directory(session.directory).state(TenantId(session.tenant_id))
    except Exception:  # noqa: BLE001 — a state that cannot be read is no reason to call the refusal anything finer
        return None


def written(session: Session, _lane: ResultLane) -> bool:
    """Whether the request's result is staged (a refused one counts: it is the container's, and kept)."""
    from . import _evidence

    ev = _evidence.state(session)
    return ev.has("result") or ev.has("refused/result")


def write_once(session: Session, lane: ResultLane, record: Any) -> None:
    """The request's one result, staged create-once: one already there is kept, and this one logged, not staged."""
    import json

    from . import _evidence

    if not _evidence.state(session).stage("result", json.loads(record.text())):
        _logger.error("%s %s: a result is already staged (or the claim ended); this one (%s) is not", lane.kind,
                      session.job_id, record.text())


def end_before_container(lane: ResultLane) -> Callable[[Session, str], None]:
    """The kind's `KindSpec.end`: an ending decided before the container (module doc)."""
    from defender.records import job_lane

    def end(session: Session, cause: str) -> None:
        if cause == _START_FAILED and session.signalled.is_set():
            return
        if written(session, lane):
            return
        reason = {_REFUSED: lane.refused_reason, _START_FAILED: "start_failed"}.get(cause, job_lane.WORKER_ERROR)
        write_once(session, lane, lane.failed(reason))

    return end


def after_container(lane: ResultLane) -> Callable[[Session, int], None]:
    """The kind's `Prepared.exited`: a `docker run` that never ran the entry, and so wrote no record, is a start failure."""

    def after(session: Session, rc: int) -> None:
        if rc not in DOCKER_DID_NOT_RUN or written(session, lane):
            return
        _logger.warning("%s %s: the job container did not start (docker exit %s); the job ran nowhere",
                        lane.kind, session.job_id, rc)
        write_once(session, lane, lane.failed("start_failed"))

    return after
