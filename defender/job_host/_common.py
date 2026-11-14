"""The requests every job kind is answered: `launch`, and a box's `box.start`, `box.exec`, `box.window`, `box.halt`
and `box.stop` (#1170 A1, A4, O8-O10).

`box.start(kind, id)` names a box kind and an id this helper minted; the box's shape (mounts, name, labels, host
paths) is the starter's, registered per job kind and box kind (O9), so a request carrying anything else is refused by
its fields. The box is started by this helper, under the tenant's shared lock it holds (O8), and answered by an opaque
handle. `box.exec`, `box.window` (one agent run's window, its attached start held here), `box.halt` (stopped, kept
for a later window) and `box.stop` (removed) relay to it under the box package's daemon-facing rules (`box.relay_*`,
A4), so a lane's windows work the same whichever side holds the daemon; all but `box.window` are still answered once
the helper is signalled, so the job can unwind (A1)."""
from __future__ import annotations

import contextlib
import logging
import math
import secrets
import signal
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender.job_socket import Refused

from ._session import KINDS, Box, PassMint, Registry, Session, SetupRefused, StartFailed

if TYPE_CHECKING:
    from defender.records import Run

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
        # One run box per id (its name is the run's), reserved here before the start so a concurrent start of the same
        # id is refused; a learning job's pre-flight runs several oracle boxes at once.
        if box_kind == "shell":
            if (box_kind, ident) in session.starting or any(
                    b.ident == ident and b.kind == box_kind and b.stopped is None for b in session.boxes.values()):
                raise Refused(f"a {box_kind} box for {ident} is already running", "box-start")
            session.starting.add((box_kind, ident))
    from defender.box import BoxFault

    reserved = (box_kind, ident)
    try:
        executor = starter(session, ident)
    except BaseException as fault:
        with session.lock:
            session.starting.discard(reserved)
        if isinstance(fault, BoxFault):
            raise Refused(f"the {box_kind} box for {ident} did not start: {fault}", "box-start") from None
        raise
    handle = secrets.token_hex(16)
    with session.lock:
        # Released and registered under one hold of the lock, so no start of the same id slips between the two.
        session.starting.discard(reserved)
        session.boxes[handle] = Box(executor, box_kind, ident)
        late = session.signalled.is_set()
    if late:
        # Signalled while it started (O8): the box goes at the helper's end with the others, and the job unwinds.
        _logger.warning("the %s box for %s started as the helper was told to stop", box_kind, ident)
    clock = getattr(executor, "clock_file", None)
    return {"handle": handle, "clock_file": str(clock) if clock is not None else None}


def _session_box(session: Session, handle: object) -> Box:
    with session.lock:
        found = session.boxes.get(handle) if isinstance(handle, str) else None
    if found is None:
        raise Refused(f"{handle!r} is no box this helper started for this job", "unknown-handle")
    return found


def _box_exec(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    from defender.box import RELAY_LOST, relay_exec

    box = _session_box(session, fields["handle"])
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


def _box_window(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    """One agent run's window on a stopped box (#1344 amendment 2 over the relay): started attached by this helper,
    which holds the attached start until the job's `box.halt` or this helper's end, so the box runs no longer than
    either the window or the helper."""
    from defender.box import relay_window

    box = _session_box(session, fields["handle"])
    with box.lock:
        if box.stopped is not None:
            return {"result": "fault", "reason": f"the {box.kind} box for {box.ident} is removed"}
        return relay_window(box.window_handle())


def _box_halt(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    """The box stopped, proven, and kept for a later window; its window's attached start ended."""
    from defender.box import relay_halt

    box = _session_box(session, fields["handle"])
    with box.lock:
        if box.stopped is not None:
            return dict(box.stopped)
        return relay_halt(box.window_handle())


def _box_stop(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    from defender.box import relay_stop

    box = _session_box(session, fields["handle"])
    with box.lock:
        if box.stopped is None:
            answer = relay_stop(box.executor, session.docker, box.windows)
            if answer.get("result") == "stopped":
                box.stopped = answer
            return answer
        return dict(box.stopped)


def start_run_box(session: Session, run_dir: Path, copy: Any, *, start_token: str | None = None) -> Any:
    """A run's box over its run folder and its knowledge copy (the investigation's, a learning sibling's; #1343 B10,
    its attached start held here). Before the start, the run folder and the copy's agent half must be real folders
    inside the tenant's, and every other bind source the run lane makes under `<T>/` (its input folder, the copy's
    stage, the run clock's folder) is judged along every component with no link followed (H10)."""
    from defender import box

    session.inside_tenant(run_dir)
    session.inside_tenant(Path(copy.agent))
    session.judge_binds(box.run_lane_sources(run_dir, session.defender_dir, Path(copy.agent), Path(copy.token)),
                        must_exist=False)
    return box.start_box(run_dir, session.defender_dir, docker=session.docker, tenant_agent=copy.agent,
                         staged_token=copy.token, tenant_id=session.tenant_id, require_sandbox=True,
                         start_token=start_token, data_root=session.root_folder)


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
            if box.windows is not None:
                # A window the job left open: its attached start is this helper's to end.
                with contextlib.suppress(BoxFault):
                    box.windows.stop()
            try:
                stop_box(box.executor, docker=session.docker)
            except BoxFault as leftover:
                _logger.warning("the %s box for %s was not removed: %s", box.kind, box.ident, leftover)
            box.stopped = {"result": "stopped"}


def mirror_run_page(run: Run, tenant: Any) -> None:
    """After the container: the run page a job saved in its run folder (`run`, a run handle), copied to the tenant's
    shared publish folder (A10). The job never reaches that folder; this is every kind's one copy (an investigation's
    run, each of a learning job's siblings). No page is no copy; the copy itself never raises."""
    from defender.presentation.visualize_run import mirror_page

    try:
        page = run.observability.runtime_html.read()
    except Exception:  # noqa: BLE001 — no page is no copy; the run's own records say why
        _logger.warning("the run page of %s could not be read", run.run_dir, exc_info=True)
        return
    if page:
        mirror_page(page, run.run_dir.name, tenant)


def settle_knowledge(session: Session, accepted: Any, records: Any) -> Any:
    """The export the job reads (O5): the launch-time publish run under this helper's hold (C19), then the export it
    settled on, by run setup's shared step (`run_common.resolve_knowledge`, the operator command's too, A6). Told to
    stop while the publish ran, the helper starts no container (A1); any other refusal is `setup: refused`."""
    from defender import run_common

    try:
        return run_common.resolve_knowledge(accepted, pin=None, publish=session.publish, data_root=session.root,
                                            records=records)
    except SystemExit as refused:
        if refused.code == 128 + signal.SIGTERM:
            session.signalled.set()
            raise StartFailed("the helper was told to stop before its container started; none was started") from None
        raise SetupRefused(str(refused.code)) from None


def grant(run_tenant: Any) -> tuple[str, ...]:
    """The pass's reads: the granted systems declared `http-proxy` in the export the job reads, none subtracted as
    down (that judgement runs adapter code, O5)."""
    from defender import run_common

    return run_common.proxied_reads(run_tenant)


def first_pass(session: Session, accepted: Any, records: Any, reads: tuple[str, ...]) -> PassMint | None:
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
    registry.add("box.window", kinds=KINDS, handler=_box_window, required=("handle",))
    registry.add("box.halt", kinds=KINDS, handler=_box_halt, required=("handle",), after_signal=True)
    registry.add("box.stop", kinds=KINDS, handler=_box_stop, required=("handle",), after_signal=True)
