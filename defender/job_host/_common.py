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

import shutil

import contextlib
import dataclasses
import logging
import math
import secrets
import signal
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender.job_socket import Refused

from ._session import KINDS, Box, PassMint, Registry, Session, SetupRefused, Signing, StartFailed, setup_step

if TYPE_CHECKING:
    from defender.records import Run

_logger = logging.getLogger(__name__)

#: A command's timeout when the job names none: the bash tool's own.
DEFAULT_EXEC_TIMEOUT = 120.0
DEFAULT_CWD = "/runs/current"
#: The job kinds a box is started for (`box.*`): a host request starts none (#1471 C4).
BOX_KINDS = ("investigation", "learning", "post-step")
#: The runs-folder check's name in `StepRefused`: P-1's step 5, machinery and never a readiness refusal step
#: (#1471 R13-1.1).
RUNS_FOLDER = "runs_folder"


class StepRefused(SetupRefused):
    """A tenant-level launch step's refusal (#1471 P-1): the job's `setup: refused`, tagged with the step
    (`job_lane.READINESS_STEPS`, or `RUNS_FOLDER`) it is the refusal of, and, for the publish step, the report it was
    refused on (`run_common.KnowledgeExit.report`). Two texts, set where it is raised (P-2): `sentence`, our own words,
    the one a readiness record may carry; and `detail`, another system's reply (a signer's error), for the log only.
    The message (the helper's log, the investigation's refusal) is both."""

    def __init__(self, step: str, sentence: str, *, detail: str | None = None, report: Any = None) -> None:
        super().__init__(sentence if detail is None else f"{sentence}: {detail}")
        self.step = step
        self.sentence = sentence
        self.report = report


class HelperFault(Exception):  # noqa: N818 — named for what it reports
    """A fault of the helper's own machinery that no kind's ending records (#1471 R13-1.1, .2: a runs folder gone after
    the worker's pre-open, a host-request knowledge record that cannot be written): the helper exits non-zero, and
    the worker reads that exit as the helper's own failure."""


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
    scratch = getattr(executor, "scratch", None)
    answer = {"handle": handle, "clock_file": str(clock) if clock is not None else None}
    if scratch is not None:
        # An oracle box's scratch, inside the claim's `shared/` folder the job mounts (#1557 H3): the job saves its
        # reads there.
        answer["scratch"] = str(scratch)
    return answer


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
                # An oracle box's folders go with it, proven stopped (#1543 D1, #1552): nothing runs in them now.
                for folder in (getattr(box.executor, "scratch", None), getattr(box.executor, "runner", None)):
                    if folder is not None:
                        shutil.rmtree(folder, ignore_errors=True)
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


def settle_knowledge(session: Session, accepted: Any, records: Any, *, trigger: str, run_id: str) -> Any:
    """The export the job reads (O5): the launch-time publish run under this helper's hold (C19), told who asked for it
    (`trigger`, #1471), then the export it settled on, by run setup's shared step (`run_common.resolve_knowledge`, the
    operator command's too, A6). Told to stop while the publish ran, the helper starts no container (A1); any other
    refusal is `setup: refused` (`StepRefused` at `publish`, holding the report it was refused on)."""
    from defender import run_common

    try:
        return run_common.resolve_knowledge(accepted, pin=None, publish=session.publish, data_root=session.root,
                                            records=records, trigger=trigger, run_id=run_id)
    except SystemExit as refused:
        if refused.code == 128 + signal.SIGTERM:
            session.signalled.set()
            raise StartFailed("the helper was told to stop before its container started; none was started") from None
        report = refused.report if isinstance(refused, run_common.KnowledgeExit) else None
        raise StepRefused("publish", str(refused.code), report=report) from None


def grant(run_tenant: Any) -> tuple[str, ...]:
    """The pass's reads: the granted systems declared `http-proxy` in the export the job reads, none subtracted as
    down (that judgement runs adapter code, O5)."""
    from defender import run_common

    return run_common.proxied_reads(run_tenant)


def set_up_signing(session: Session, accepted: Any, records: Any) -> Signing:
    """The job's signer and the proxy's address (O5): a proxy address and a sign login for the tenant's live
    generation, or the job is refused (`StepRefused` at `signing`). Nothing is signed here, so a sealed signer is not
    asked yet."""
    from defender.credential_proxy import signing_access
    from defender.kit.faults import ConfigFault

    try:
        signer, address = signing_access(accepted.id, directory=records, signer=session.signer)
    except ConfigFault as refused:
        raise StepRefused("signing", f"the job's passes cannot be signed: {refused.detail}") from None
    return Signing(signer, address, str(accepted.id))


def first_pass(session: Session, accepted: Any, records: Any, reads: tuple[str, ...]) -> PassMint | None:
    """The read-pass mint over the grant, its first pass signed now (O5, O11); None for an empty grant (nothing to
    sign, so signing is not even set up)."""
    return read_passes(session, set_up_signing(session, accepted, records), reads) if reads else None


def read_passes(session: Session, signing: Signing, reads: tuple[str, ...]) -> PassMint | None:
    """The read-pass mint over a non-empty grant on `signing`, its first pass signed now under the job's id (O11;
    #1471 R12-1: a readiness check's id); None for an empty grant. A first pass that cannot be signed is `StepRefused`
    at `first_pass`."""
    if not reads:
        return None
    mint = PassMint(signing, reads)
    try:
        mint.mint(str(session.job_id))
    except Exception as failed:  # noqa: BLE001 — a first pass that cannot be signed refuses the job (O11)
        raise StepRefused("first_pass", "the job's first pass could not be signed",
                          detail=f"{type(failed).__name__}: {failed}") from None
    return mint


@dataclasses.dataclass
class LaunchFacts:
    """What the tenant-level launch steps settled (`tenant_launch_steps`, #1471 P-1), each field set as it becomes
    true, as `run._JobFacts` holds the job-end facts: a caller reads how far the launch went after a refusal (a
    readiness check writes its knowledge record when `source` is set) and everything it settled once it is done.
    `cleanup` removes what the steps made (the run copy); it is the caller's to close once the steps returned, and
    is closed by the steps themselves when they refuse."""

    accepted: Any = None
    #: The tenant records the tenant was admitted through.
    records: Any = None
    #: The tenant's current records (`TenantRecords`), read once.
    current: Any = None
    mapping: Any = None
    source: Any = None
    #: The checked launch an investigation hands in (`launch=` of `tenant_launch_steps`), and the run its runs
    #: repository builds for it at the runs-folder step.
    launched: Any = None
    run: Any = None
    copy: Any = None
    run_tenant: Any = None
    roster: Any = None
    verdict: Any = None
    reads: tuple[str, ...] = ()
    signing: Signing | None = None
    passes: PassMint | None = None
    cleanup: contextlib.ExitStack = dataclasses.field(default_factory=contextlib.ExitStack)


def _launch_step(step: str, call: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """`setup_step` (a `run_common` step's `SystemExit` is the job's refusal, its message the cause) tagged with the
    launch step it is the refusal of."""
    try:
        return setup_step(call, *args, **kwargs)
    except SetupRefused as refused:
        raise StepRefused(step, str(refused)) from None


def tenant_launch_steps(session: Session, hold: contextlib.ExitStack, *, copy_id: str, facts: LaunchFacts,
                        trigger: str, launch: Callable[[], Any] | None = None) -> LaunchFacts:
    """The launch's tenant-level steps (#1471 P-1, C2, R12-1), in order and as one code for an investigation and a
    readiness check: the tenant's lock and admission (entered on `hold`), its current records, its alert mapping, the
    launch-time publish (`trigger`: who asked), the runs-folder check, the run copy (named `copy_id`), the tenant over
    the copy, the roster, the grants x records verdict, the grant, the signing set-up (every job, W-D8) and the first
    pass (a non-empty grant only, signed under the job's id). An investigation's launch check, read after the
    admission as it always was, is `launch` (`job_lane.JobLane.check_launch` under its own refusal): its run is then
    built at the runs-folder step (`RunsRepository.launched`, which asks the same check); with none the runs-folder
    check is asked alone. Each refusal is `StepRefused` naming its step, the copy removed; `facts` holds what was
    settled, and is returned."""
    from defender import run_common
    from defender.records.formats import TenantRefused
    from defender.systems.run_tenant import host_tenant

    try:
        admitted = host_tenant(session.root, session.tenant_id, directory=session.directory,
                               defender_dir=session.defender_dir, clone_tree=False)
    except TenantRefused as refused:
        raise StepRefused("tenant", f"this job's tenant cannot be used: {refused}") from None
    hold.enter_context(admitted)
    facts.accepted, facts.records = admitted.tenant, admitted.directory
    session.tenant_accepted(facts.accepted)
    if launch is not None:
        facts.launched = launch()
    # The tenant's current records, read once here (#1366 O6): a tenant whose records are not known (#1470 O8) is
    # refused before its alert mapping is read. The container reads no database; it is handed these in the launch facts.
    facts.current = _launch_step("records", run_common.read_records, facts.records, facts.accepted.id)
    facts.mapping = _launch_step("alert_mapping", run_common.read_alert_mapping, facts.records, facts.accepted.id)
    facts.source = settle_knowledge(session, facts.accepted, facts.records, trigger=trigger, run_id=copy_id)
    repository = facts.accepted.runs_repository()
    try:
        if facts.launched is not None:
            facts.run = repository.launched(facts.launched)
        else:
            repository.require_runs_folder()
    except TenantRefused as refused:
        raise StepRefused(RUNS_FOLDER, str(refused)) from None
    try:
        _copied_steps(session, facts, copy_id)
    except BaseException:
        facts.cleanup.close()
        raise
    return facts


def _copied_steps(session: Session, facts: LaunchFacts, copy_id: str) -> None:
    """`tenant_launch_steps` from the run copy on (P-1 steps 6-12), the copy's removal on `facts.cleanup`."""
    from defender import run_common
    from defender.records.formats import TenantRefused
    from defender.systems.catalog import Catalog

    facts.copy = _launch_step("knowledge_copy", run_common.copy_knowledge, facts.accepted, facts.source, copy_id)
    facts.cleanup.callback(facts.copy.remove)
    # The catalog's roster, read once and cold (no adapter code runs here, N7): the records' reads are judged against
    # its adapters' lists (#1504 O3), then the tenant's systems are narrowed to it.
    facts.roster = _launch_step("roster", run_common.run_roster, session.defender_dir)
    try:
        facts.run_tenant = _launch_step("run_tenant", run_common.run_tenant_or_exit, facts.accepted, dispatches_lead_zero=True,
                               records=facts.current, copy=facts.copy, catalog=Catalog(facts.roster))
    except TenantRefused as refused:
        raise StepRefused("run_tenant", f"this job's tenant cannot be used: {refused}") from None
    # Its grants narrowed to the systems it has enabled records of (#1366 R12), so the pass names none it has not; the
    # container warns.
    facts.verdict = _launch_step("tenant_verdict", run_common.tenant_verdict, facts.run_tenant, facts.roster, warn=False)
    facts.reads = grant(facts.verdict.tenant)
    facts.signing = set_up_signing(session, facts.accepted, facts.records)  # every job, whatever its grant (W-D8)
    facts.passes = read_passes(session, facts.signing, facts.reads)


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
    """`launch` for every kind; the `box.*` requests for the kinds that start boxes (`BOX_KINDS`): a host request is
    answered no box request (#1471 C4)."""
    registry.add("launch", kinds=KINDS, handler=_answer_launch, after_signal=True)
    registry.add("box.start", kinds=BOX_KINDS, handler=lambda s, f: _box_start(s, f, registry=registry),
                 required=("kind", "id"))
    registry.add("box.exec", kinds=BOX_KINDS, handler=_box_exec, required=("handle", "frame"),
                 optional=("cwd", "timeout"), after_signal=True)
    registry.add("box.window", kinds=BOX_KINDS, handler=_box_window, required=("handle",))
    registry.add("box.halt", kinds=BOX_KINDS, handler=_box_halt, required=("handle",), after_signal=True)
    registry.add("box.stop", kinds=BOX_KINDS, handler=_box_stop, required=("handle",), after_signal=True)
