"""The requests every job kind is answered: `launch`, and a box's `box.start`, `box.exec` and `box.stop` (#1170 A1,
A4, O8-O10).

`box.start(kind, id)` names a box kind and an id this helper minted; the box's shape (mounts, name, labels, host
paths) is the starter's, registered per job kind and box kind (O9), so a request carrying anything else is refused by
its fields. The box is started by this helper, under the tenant's shared lock it holds (O8), and answered by an opaque
handle. `box.exec` and `box.stop` relay to it under the box package's daemon-facing rules (`box.relay_exec`,
`box.relay_stop`, A4); both are still answered once the helper is signalled, so the job can unwind (A1)."""
from __future__ import annotations

import logging
import math
import secrets
from typing import Any

from defender.job_socket import Refused

from ._session import KINDS, Box, Registry, Session

_logger = logging.getLogger(__name__)

#: A command's timeout when the job names none: the bash tool's own.
DEFAULT_EXEC_TIMEOUT = 120.0
DEFAULT_CWD = "/runs/current"


def _answer_launch(session: Session, _fields: dict[str, Any]) -> dict[str, Any]:
    return session.launch()


def _box_start(session: Session, fields: dict[str, Any], *, registry: Registry) -> dict[str, Any]:
    box_kind, ident = fields["kind"], fields["id"]
    starter = registry.box_kinds.get((session.kind, box_kind)) if isinstance(box_kind, str) else None
    if starter is None:
        raise Refused(f"a {session.kind} job is started no {box_kind!r} box", "not-for-kind")
    ident = session.require_minted(ident)
    with session.lock:
        # One run box per id (its name is the run's); a learning job's pre-flight runs several oracle boxes at once.
        if box_kind == "shell" and any(b.ident == ident and b.kind == box_kind and b.stopped is None
                                       for b in session.boxes.values()):
            raise Refused(f"a {box_kind} box for {ident} is already running", "box-start")
    from defender.box import BoxFault

    try:
        executor = starter(session, ident)
    except BoxFault as fault:
        raise Refused(f"the {box_kind} box for {ident} did not start: {fault}", "box-start") from None
    handle = secrets.token_hex(16)
    with session.lock:
        session.boxes[handle] = Box(executor, box_kind, ident)
        late = session.signalled.is_set()
    if late:
        # Signalled while it started (O8): the box goes at the helper's end with the others, and the job unwinds.
        _logger.warning("the %s box for %s started as the helper was told to stop", box_kind, ident)
    clock = getattr(executor, "clock_file", None)
    return {"handle": handle, "clock_file": str(clock) if clock is not None else None}


def _box(session: Session, handle: object) -> Box:
    with session.lock:
        found = session.boxes.get(handle) if isinstance(handle, str) else None
    if found is None:
        raise Refused(f"{handle!r} is no box this helper started for this job", "unknown-handle")
    return found


def _box_exec(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    from defender.box import RELAY_LOST, relay_exec

    box = _box(session, fields["handle"])
    frame, cwd = fields["frame"], fields.get("cwd", DEFAULT_CWD)
    timeout = fields.get("timeout", DEFAULT_EXEC_TIMEOUT)
    if not isinstance(frame, bytes) or not isinstance(cwd, str) or not cwd.startswith("/"):
        raise Refused("box.exec takes a frame (bytes) and an absolute cwd", "bad-fields")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) \
            or timeout <= 0:
        raise Refused(f"box.exec's timeout must be a finite number of seconds above 0, not {timeout!r}",
                      "bad-fields")
    if box.stopped is not None:
        return dict(RELAY_LOST)
    return relay_exec(box.executor, session.docker, frame, cwd=cwd, timeout=float(timeout))


def _box_stop(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    from defender.box import relay_stop

    box = _box(session, fields["handle"])
    with box.lock:
        if box.stopped is None:
            answer = relay_stop(box.executor, session.docker)
            if answer.get("result") == "stopped":
                box.stopped = answer
            return answer
        return dict(box.stopped)


def stop_boxes(session: Session) -> None:
    """At the helper's end: every box it started and has not proven stopped is stopped and removed, its attached start
    ended (B10: a box ends with its helper)."""
    from defender.box import BoxFault, stop_box

    with session.lock:
        boxes = list(session.boxes.values())
    for box in boxes:
        with box.lock:
            if box.stopped is not None:
                continue
            try:
                stop_box(box.executor, docker=session.docker)
            except BoxFault as leftover:
                _logger.warning("the %s box for %s was not removed: %s", box.kind, box.ident, leftover)
            box.stopped = {"result": "stopped"}


def answer_pass(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    """`pass`: a pass for an id this helper minted, signed anew (O5); every kind with a pass mint registers it."""
    ident = session.require_minted(fields["id"])
    passes = session.prepared.passes if session.prepared is not None else None
    if passes is None:
        raise Refused("this job's grant is empty: it reaches no system through the proxy", "no-grant")
    try:
        return passes.mint(ident)
    except Exception as failed:  # noqa: BLE001 — a pass that cannot be signed is the job's to report
        raise Refused(f"the pass could not be signed: {type(failed).__name__}: {failed}", "sign-fault") from None


def register_common(registry: Registry) -> None:
    registry.add("launch", kinds=KINDS, handler=_answer_launch, after_signal=True)
    registry.add("box.start", kinds=KINDS, handler=lambda s, f: _box_start(s, f, registry=registry),
                 required=("kind", "id"))
    registry.add("box.exec", kinds=KINDS, handler=_box_exec, required=("handle", "frame"),
                 optional=("cwd", "timeout"), after_signal=True)
    registry.add("box.stop", kinds=KINDS, handler=_box_stop, required=("handle",), after_signal=True)
