"""The learning kinds' part of the helper (#1170: `learning`, `post-step`): their host halves, their requests and
their boxes.

**The learning job** (`--kind learning --job <id> --tenant T --source S`). Its host half, before the container: the
tenant's lock, waited for at most 30 s (still busy: the learning entry's `stopped` word, which the worker hands back,
A3, C24), the admission (`host_tenant`), the tenant's current records read once (#1366 O6: a tenant not imported is
refused; the container, which reads no database, and every sibling's run are handed them in the launch facts), the
launch-time publish under the helper's cover (C19), the grant over the export it settled on (the granted systems
declared `http-proxy`, narrowed to those the tenant has enabled records of; down systems not subtracted, O5) and the first pass,
signed for the learning job's own id (pre-flight's pass names the row the worker fences; O5, C12 replaced). `--source`
is not checked here: the entry checks it in the container, over the tenant's own records (design correction).

Its requests: `pass` for an id this helper minted (the job's own, or a sibling's run); `copy.make(world=)`, a sibling's
run id, run copy and materialized run folder (input, stamp, knowledge record), all made here (A6, C20, C23): the world is looked up in the job's own episode only
(`<T>/episodes/<job id>`, never found by `--source`), its id is the arm roster's canonical id for it, its folder is
`<episode>/runs/<run>/`, made with no link followed out of the episode (H10), and its copy is owned by this helper.
`export.materialise(commit=)`, the export of the commit the launch pins its family to (its source's), materialised
here from the tenant's clone under the knowledge lock if absent: the container writes no export (P-A).
Boxes: `shell` (a sibling's run box over its run folder and copy) and `oracle` (the learning job's own: the
oracle's box, its bind folders in a per-claim folder under the data root, never host `/tmp`, C21).

**The post-step and the family-less check** (`--kind post-step [--job <id>] --tenant T`). Its host half: the tenant's
lock and admission (waiting as today). Its requests: `batch.start(lanes=)`, the drain's publish and draft, made here
(the draft owned by this helper, C23), its id minted here; `forge.token(min_validity=)`, a fresh token of the tenant's
forge credential, for at most 150 s (C25: fail closed above it); `record.published(commit=)` and
`record.refusal(kind=, reason=)`, the drain's publish outcomes written to the tenant records (O3, O4). Box: `batch`,
over a draft this helper made.

**Endings before the container** (A3, r4.1): a learning job's in the learning entry's own words (setup refused:
`failed: launch_refused`; cannot be started confined or the helper crashed: `failed: entry_error`; a busy lock or a
stop before the container: `stopped`); a post-step writes nothing.

Everything the helper made for the job (sibling copies, drafts, the per-claim scratch folder) goes at its end; the run
folders and the episode stay."""
from __future__ import annotations

import contextlib
import logging
import math
import os
import re
import shutil
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender import _io
from defender.credential_proxy import PASS_LIFETIME_SEC
from defender import job_socket
from defender.job_socket import Refused

from ._common import answer_pass, first_pass, grant, mirror_run_page, settle_knowledge, start_run_box
from ._session import DOCKER_DID_NOT_RUN, HandBack, KindSpec, Prepared, Registry, Session, SetupRefused, setup_step

if TYPE_CHECKING:
    from defender.records.formats import Episode

_logger = logging.getLogger(__name__)

LEARNING, POST_STEP = "learning", "post-step"
#: How long a learning job's helper waits for the tenant's host lock before handing the job back (C24).
LOCK_WAIT_SECONDS = 30.0
#: Where under the data root each claim's scratch folder lives (oracle boxes' binds): outside
#: every tenant's folder, the job socket's folder and host `/tmp` (C21).
SCRATCH = ".job-scratch"
_COMMIT = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")


# --- the kinds' state ---------------------------------------------------------------------------------------------------

@dataclass
class _Sibling:
    run: str
    world: str
    run_dir: Path
    copy: Any


@dataclass
class _Learning:
    """What a learning job's host half settled, and what its requests made."""

    tenant: Any
    commit: str
    scratch: Path
    #: The tenant's current records, read once at the job's start (#1366 O6): every sibling's run reads these.
    records: Any = None
    siblings: dict[str, _Sibling] = field(default_factory=dict)  # by run id
    by_world: dict[str, str] = field(default_factory=dict)  # world id -> run id


@dataclass
class _PostStep:
    """What a post-step's host half settled: the admitted tenant and its records, the forge credential and the drain's
    delivery once asked for, and the batches made."""

    tenant: Any
    records: Any
    opened: contextlib.ExitStack
    credential: Any = None
    delivery: Any = None
    batches: dict[str, Any] = field(default_factory=dict)


def _state(session: Session, kind: type) -> Any:
    state = session.prepared.state if session.prepared is not None else None
    if not isinstance(state, kind):
        raise Refused("the job is not set up", "internal")
    return state


# --- the host halves ----------------------------------------------------------------------------------------------------

def _hold_within_wait(session: Session, hold: contextlib.ExitStack) -> None:
    """The tenant's lock taken shared within `LOCK_WAIT_SECONDS` (held on `hold`), or `HandBack`. The admission after
    it then records this helper and holds the lock shared itself."""
    from defender.tenancy import host_lock

    fd = host_lock.acquire(session.root_folder, session.tenant_id, exclusive=False, timeout=LOCK_WAIT_SECONDS)
    if fd is None:
        raise HandBack(f"the tenant's host lock was still held after {LOCK_WAIT_SECONDS:.0f} s")
    hold.callback(host_lock.release_lock, fd)


def _admit_tenant(session: Session, hold: contextlib.ExitStack) -> Any:
    from defender.records.formats import TenantRefused
    from defender.systems.run_tenant import host_tenant

    try:
        admitted = host_tenant(session.root, session.tenant_id, defender_dir=session.defender_dir)
    except TenantRefused as refused:
        raise SetupRefused(f"this job's tenant cannot be used: {refused}") from None
    hold.enter_context(admitted)
    session.tenant_accepted(admitted.tenant)
    return admitted


def _scratch(session: Session, cleanup: contextlib.ExitStack) -> Path:
    base = session.root_folder
    folder = base / SCRATCH / session.claim
    if os.path.lexists(folder):
        raise SetupRefused(f"{folder} exists already: a claim's scratch folder is made once")
    try:
        _io.guarded_mkdir(folder, base=base)  # no link below the data root (C21)
        folder.chmod(0o700)
    except (OSError, ValueError) as e:
        raise SetupRefused(f"the claim's scratch folder {folder} could not be made: {e}") from None
    cleanup.callback(shutil.rmtree, folder, ignore_errors=True)
    return folder


def _prepare_learning(session: Session, hold: contextlib.ExitStack) -> Prepared:
    from defender import run_common
    from defender.records.formats import TenantRefused
    from defender.systems.run_tenant import run_tenant_for
    from defender.tenancy import run_knowledge

    job = str(session.job_id)
    _hold_within_wait(session, hold)
    admitted = _admit_tenant(session, hold)
    accepted, records = admitted.tenant, admitted.directory
    # The tenant's current records, read once for the whole job (#1366 O6; a tenant not imported refused, R8): the
    # container, which reads no database, is handed them in the launch facts, and so is each sibling's run.
    current = setup_step(run_common.read_records, records, accepted.id)
    source = settle_knowledge(session, accepted, records)
    try:
        export = session.inside_tenant(accepted.export_folder(source.commit))
        ready = run_tenant_for(accepted, dispatches_lead_zero=False, records=current,
                               agent_root=export / run_knowledge.AGENT_HALF,
                               settings_root=export / run_knowledge.SETTINGS_HALF)
    except (TenantRefused, Refused) as refused:
        raise SetupRefused(f"this job's tenant cannot be used: {refused}") from None
    # Narrowed to the systems the tenant has enabled records of (#1366 R12), read cold (no adapter code, N7).
    roster = setup_step(run_common.run_roster, session.defender_dir)
    ready = setup_step(run_common.tenant_verdict, ready, roster, warn=False).tenant
    # The grant is the launch export's, not the family's pinned commit (which the container settles later): the proxy
    # serves a system only by its declaration in the tenant's `current` export, and this helper holds the tenant's
    # lock for the whole job, so no publish moves `current` under it. A grant from an older pin could only add systems
    # the proxy refuses, and would miss none it serves.
    reads = grant(ready)
    passes = first_pass(session, accepted, records, reads)
    cleanup = contextlib.ExitStack()
    try:
        scratch = _scratch(session, cleanup)
    except BaseException:
        cleanup.close()
        raise
    session.minted.add(job)
    state = _Learning(accepted, source.commit, scratch, records=current)
    cleanup.callback(_remove_copies, state)
    command = session.command or ["python3", "-m", "defender.cli.learning.job", "--job", job,
                                  "--tenant", session.tenant_id, "--source", str(session.source)]
    facts = {"kind": LEARNING, "tenant": session.tenant_id, "job": job, "tenant_state": "active",
             "export_commit": source.commit, "proxy_url": passes.proxy_url if passes is not None else None,
             "grant": [[s, "r"] for s in reads], "pass_lifetime": PASS_LIFETIME_SEC,
             "records": current.as_wire()}
    return Prepared(launch=facts, command=list(command), passes=passes, state=state, cleanup=cleanup,
                    exited=_learning_exited)


def _remove_copies(state: _Learning) -> None:
    for sibling in list(state.siblings.values()):
        try:
            sibling.copy.remove()
        except OSError as e:
            _logger.warning("the run copy of sibling %s could not be removed: %s", sibling.run, e)


def _prepare_post_step(session: Session, hold: contextlib.ExitStack) -> Prepared:
    admitted = _admit_tenant(session, hold)
    opened = contextlib.ExitStack()
    state = _PostStep(admitted.tenant, admitted.directory, opened)
    cleanup = contextlib.ExitStack()
    cleanup.callback(opened.close)
    cleanup.callback(_discard_batches, state)
    job = [] if session.job_id is None else ["--job", str(session.job_id)]
    command = session.command or ["python3", "-m", "defender.learning.branch.post_step", *job,
                                  "--tenant", session.tenant_id]
    wiring = admitted.wiring
    facts = {"kind": POST_STEP, "tenant": session.tenant_id, "job": session.job_id, "tenant_state": "active",
             "forge_origin": wiring.origin if wiring is not None else None,
             "forge_repo": wiring.repo if wiring is not None else None}
    return Prepared(launch=facts, command=list(command), state=state, cleanup=cleanup)


def _discard_batches(state: _PostStep) -> None:
    for batch in list(state.batches.values()):
        batch.discard()


# --- endings before the container (A3) ----------------------------------------------------------------------------------

def _write_learning_end(session: Session, status: str, reason: str | None, message: str) -> None:
    """A learning end record the helper decided. One that cannot be written raises: the helper then exits non-zero,
    which the worker reads as the helper's own failure."""
    from defender.records import job_lane

    record = job_lane.LearningEnd(status=status, reason=reason, message=message, fork_message_id=None, stage=None)
    try:
        with job_lane.JobLane.open(session.root, session.tenant_id) as lane:
            lane.write_learning_end(str(session.job_id), record)
    except FileExistsError:
        _logger.error("job %s: a learning end record is already there; it is kept", session.job_id)


def _learning_end(session: Session, cause: str) -> None:
    """The learning entry's own word for an ending the helper decided (A3, r4.1): a stop is never a failure."""
    from defender.records import job_lane

    if cause == "busy":
        _write_learning_end(session, job_lane.LEARNING_STOPPED, None,
                            f"the tenant's host lock was still held after {LOCK_WAIT_SECONDS:.0f} s; "
                            "the job is handed back")
    elif cause == "start-failed" and session.signalled.is_set():
        _write_learning_end(session, job_lane.LEARNING_STOPPED, None,
                            "the job was stopped before its container started; it is handed back")
    elif cause == "refused":
        _write_learning_end(session, job_lane.LEARNING_FAILED, job_lane.LAUNCH_REFUSED,
                            "the job's setup was refused before its container started")
    elif cause == "start-failed":
        _write_learning_end(session, job_lane.LEARNING_FAILED, job_lane.ENTRY_ERROR,
                            "the job could not be started confined; it ran nowhere")
    else:
        _write_learning_end(session, job_lane.LEARNING_FAILED, job_lane.ENTRY_ERROR,
                            "the job's helper failed before its container started")


def _post_step_end(session: Session, cause: str) -> None:
    """A post-step stopped, refused or not started before its container writes no record (r4.1)."""
    _logger.info("post-step of %s ended before its container (%s); no record is written",
                 session.job_id or session.tenant_id, cause)


def _learning_exited(session: Session, rc: int) -> None:
    """After the container: a `docker run` that never ran the job (and so left no end record) is the learning entry's
    start failure; otherwise each sibling's run page, left in its run folder, is copied to the tenant's publish area
    (A10), as an investigation's is."""
    from defender.records import job_lane

    if rc in DOCKER_DID_NOT_RUN:
        try:
            with job_lane.JobLane.open(session.root, session.tenant_id) as lane:
                written = lane.read_learning_end(str(session.job_id)) is not None
        except (OSError, job_lane.JobLaneRefused):
            written = False
        if not written:
            sys.stderr.write(f"[job_host] learning job {session.job_id}: the job container did not start (docker "
                             f"exit {rc}); the job ran nowhere\n")
            _learning_end(session, "start-failed")
            return
    state = session.prepared.state if session.prepared is not None else None
    if isinstance(state, _Learning):
        _mirror_sibling_pages(session, state)


def _mirror_sibling_pages(session: Session, state: _Learning) -> None:
    """Each sibling's run page, opened in the job's episode by its id and copied (`mirror_run_page`). A sibling whose
    run cannot be opened is logged and skipped: the copy is the dev view's, never the job's outcome."""
    from defender.records import RunId, RunRefused
    from defender.records.formats import TenantRefused

    with session.lock:
        runs = list(state.siblings)
    if not runs:
        return
    try:
        with state.tenant.runs_repository().episode(str(session.job_id)) as view:
            for run in runs:
                try:
                    handle = view.open(RunId.parse(run))
                except (RunRefused, TenantRefused, ValueError, OSError) as refused:
                    _logger.warning("the run page of sibling %s was not copied: %s", run, refused)
                    continue
                mirror_run_page(handle, state.tenant)
    except (FileNotFoundError, RunRefused, TenantRefused, ValueError, OSError) as refused:
        _logger.warning("no sibling run page was copied: the job's episode cannot be read: %s", refused)


# --- the learning job's requests ------------------------------------------------------------------------------------------

#: The tenant's episodes folder, `<T>/episodes` (`tenancy.box_mounted_episodes`).
EPISODES = "episodes"


def _episode_folder(session: Session) -> Path:
    """The learning job's own episode, `<T>/episodes/<job id>` (episode id = job id), with no link on the way."""
    if session.tenant_folder is None:
        raise Refused("the job's tenant is not accepted yet", "internal")
    return session.inside_tenant(session.tenant_folder / EPISODES / str(session.job_id))


def _roster_id(state: _Learning, session: Session, world: str) -> str:
    """The canonical run id the job's own episode's arm roster holds for `world`, or a refusal."""
    from defender.records import RunId, RunRefused
    from defender.records.formats import TenantRefused

    try:
        with state.tenant.runs_repository().episode(str(session.job_id)) as view:
            arms = view.arm_ids()
    except (FileNotFoundError, RunRefused, TenantRefused, ValueError, OSError) as refused:
        raise Refused(f"the job's episode cannot be read: {type(refused).__name__}: {refused}",
                      "unknown-id") from None
    if arms is None or world not in arms:
        raise Refused(f"the job's episode holds no world {world!r}", "unknown-id")
    run = str(arms[world])
    try:
        canonical: str | None = str(RunId.parse(run))
    except (RunRefused, ValueError):
        canonical = None
    if canonical != run:
        raise Refused(f"the roster's id for world {world!r} is not a canonical run id", "unknown-id")
    return run


def _pinned_commit(state: _Learning, session: Session, default: str) -> str:
    """The family's knowledge pin (its siblings read that export, O-PIN), else the export the helper settled on."""
    from defender.records import RunRefused
    from defender.records.formats import PinUnreadable, TenantRefused, read_pin

    try:
        with state.tenant.runs_repository().episode(str(session.job_id)) as view:
            pin = read_pin(view.episode.view())
    except (PinUnreadable, FileNotFoundError, RunRefused, TenantRefused, OSError, ValueError, TypeError):
        return default
    return pin or default


def _copy_make(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    """A sibling's run id (the roster's), its run copy and its run folder `<episode>/runs/<run>/`, made and owned here:
    the run materialized (its input, the episode's copy of the source alert, and its stamp) as an investigation's is,
    and its host-held knowledge record beside it (A6, C20). The sibling's run half opens it."""
    from defender.tenancy import run_knowledge

    state = _state(session, _Learning)
    world = fields["world"]
    if not isinstance(world, str):
        raise Refused("copy.make takes a world id", "bad-fields")
    with session.lock:
        made = state.by_world.get(world)
        if made is not None:
            return _copy_answer(state.siblings[made])
    episode = _episode_folder(session)
    run = _roster_id(state, session, world)
    runs = episode / "runs"
    run_dir = runs / run
    session.inside_tenant(run_dir, must_exist=False)
    source = run_knowledge.KnowledgeSource(kind=run_knowledge.PINNED,
                                           commit=_pinned_commit(state, session, state.commit))
    try:
        copy = run_knowledge.copy_for_run(state.tenant, source, run)
    except (run_knowledge.KnowledgeRefused, OSError) as refused:
        raise Refused(f"the sibling's run copy could not be made: {refused}", "internal") from None
    try:
        _io.guarded_mkdir(runs, base=episode)
        session.inside_tenant(runs)
        made_dir = _materialize_sibling(session, state, world, run, source)
        session.inside_tenant(made_dir)
    except BaseException:
        copy.remove()
        raise
    sibling = _Sibling(run, world, made_dir, copy)
    with session.lock:
        state.siblings[run] = sibling
        state.by_world[world] = run
        session.minted.add(run)
    return _copy_answer(sibling)


def _export_materialise(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    """`export.materialise(commit=)`: `<T>/exports/<commit>/` for a commit the tenant's clone holds, written from its
    objects under the knowledge lock if absent (`materialise_export`), by this helper (P-A, C20: no export is written
    and no knowledge lock is taken inside the container). The learning launch pins its family to its source's
    commit; the job reads the export it is answered."""
    from defender.learning.author.version_control import DeliveryRefused, LockBusy, materialise_export

    commit = fields["commit"]
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        raise Refused("export.materialise takes a full commit id", "bad-fields")
    state = _state(session, _Learning)
    try:
        export = materialise_export(state.tenant, commit)
    except (DeliveryRefused, LockBusy) as refused:
        raise Refused(f"the export of {commit} could not be materialised: {refused}", "delivery") from None
    session.inside_tenant(Path(export.path))
    return {"commit": export.commit, "path": str(export.path)}


def _source_alert(episode: Episode) -> Path:
    """The episode's copy of the source alert (the sibling's input), by the episode handle."""
    return Path(episode.source_alert.path)


def _materialize_sibling(session: Session, state: _Learning, world: str, run: str, source: Any) -> Path:
    """The sibling's run, made by run setup's shared half (`run_common.materialize_run`) at the roster's arm id."""
    from defender import run_common
    from defender.investigation.driver import resolve_main_model
    from defender.records import RunRefused, artifact_file, formats
    from defender.records.formats import TenantRefused

    try:
        with state.tenant.runs_repository().episode(str(session.job_id)) as view:
            arms = view.arm_ids() or {}
            family = formats.load_family(view.episode.view(), expected_episode_id=str(session.job_id))
            label = family.world_by_id(world).label
            resumed = formats.resume_world_from(family, label, view.episode.dir, arm_ids=arms)
            alert = _source_alert(view.episode)
            if not artifact_file(alert):
                raise Refused("the episode's copy of the source alert is not a plain file", "confinement")
            arm = view.create(arms[world])
            if str(arm.run_dir.name) != run:
                raise Refused("the roster moved while the sibling's run was made", "internal")
            made = run_common.materialize_run(alert, run=arm, tenant=state.tenant, model=resolve_main_model(None),
                                              world=resumed, knowledge=source)
    except (FileNotFoundError, RunRefused, TenantRefused, KeyError, ValueError, OSError) as refused:
        raise Refused(f"the sibling's run could not be made: {type(refused).__name__}: {refused}",
                      "internal") from None
    except SystemExit as refused:
        raise Refused(f"the sibling's run could not be made: {refused.code}", "internal") from None
    try:
        run_common.write_knowledge_record(Path(made.run_dir), source)
        run_common.write_versions_record(Path(made.run_dir), state.records)
    except SystemExit as e:
        raise Refused(f"could not write the sibling's start records: {e.code}", "internal") from None
    return Path(made.run_dir)


def _copy_answer(sibling: _Sibling) -> dict[str, Any]:
    copy = sibling.copy
    return {"run": sibling.run, "world": sibling.world, "run_dir": str(sibling.run_dir), "path": str(copy.root),
            "agent": str(copy.agent), "settings": str(copy.settings), "token": str(copy.token)}


def _sibling_box(session: Session, ident: str) -> Any:
    """A sibling's run box over its run folder and copy. The learning job itself is started `oracle` boxes only
    (r4.1): a `shell` box is a sibling's."""
    sibling = _state(session, _Learning).siblings.get(ident)
    if sibling is None:
        raise Refused(f"a shell box is served only for a sibling's run, not {ident!r}", "not-for-kind")
    return start_run_box(session, sibling.run_dir, sibling.copy)


def _oracle_box(session: Session, _ident: str) -> Any:
    """The oracle's box (#1224), its runner and scratch folders made in a fresh folder under the claim's scratch
    folder (C21: never host `/tmp`), removed with it at the helper's end."""
    from defender import box

    state = _state(session, _Learning)
    folder = state.scratch / f"oracle-{uuid.uuid4().hex[:12]}"
    _io.guarded_mkdir(folder, base=state.scratch)
    try:
        return box.start_oracle_box(env=os.environ, tenant_id=session.tenant_id, folder=folder,
                                    docker=session.docker, data_root=session.root_folder)
    except box.BoxStartRefused as refused:
        raise box.BoxFault(str(refused)) from None


# --- the post-step's requests -------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _TenantCredential:
    """The forge seam's credential as the forge client reads it: the tenant it is for, and its tokens."""

    inner: Any = field(repr=False)
    tenant_id: str

    def token(self, *, min_validity: float = 0.0) -> str:
        return str(self.inner.token(min_validity=min_validity))


def _drain_credential(session: Session, state: _PostStep) -> Any:
    if state.credential is None:
        if session.forge is not None:
            state.credential = _TenantCredential(session.forge(session.tenant_id, "drain"), session.tenant_id)
        else:
            from defender.learning.author.version_control import forge_credential

            built = forge_credential(state.tenant.id, "drain", directory=state.records, config=None)
            state.opened.callback(built.close)
            state.credential = built
    return state.credential


def _forge_token(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    validity = fields["min_validity"]
    if isinstance(validity, bool) or not isinstance(validity, (int, float)) or not math.isfinite(validity) \
            or not 0 <= validity <= job_socket.FORGE_TOKEN_CAP:
        raise Refused(f"forge.token's min_validity is a number of seconds from 0 to "
                      f"{job_socket.FORGE_TOKEN_CAP:.0f}",
                      "bad-fields")
    state = _state(session, _PostStep)
    try:
        token = _drain_credential(session, state).token(min_validity=float(validity))
    except Exception as failed:  # noqa: BLE001 — a token that cannot be minted is the job's to report
        raise Refused(f"the forge token could not be minted: {type(failed).__name__}: {failed}",
                      "forge-fault") from None
    return {"token": str(token)}


def _record_published(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    from defender.tenancy import record_published

    commit = fields["commit"]
    if not isinstance(commit, str) or not _COMMIT.fullmatch(commit):
        raise Refused("record.published takes a full commit id", "bad-fields")
    state = _state(session, _PostStep)
    record_published(state.records, state.tenant.id, commit, by="drain")
    return {"recorded": True}


def _record_refusal(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    from defender.tenancy import OPERATOR, TRANSIENT, record_refusal

    kind, reason = fields["kind"], fields["reason"]
    if kind not in (TRANSIENT, OPERATOR) or not isinstance(reason, str):
        raise Refused(f"record.refusal takes a kind ({TRANSIENT} or {OPERATOR}) and a reason", "bad-fields")
    state = _state(session, _PostStep)
    record_refusal(state.records, state.tenant.id, kind=kind, reason=reason, by="drain")
    return {"recorded": True}


def _drain_delivery(session: Session, state: _PostStep) -> Any:
    if state.delivery is None:
        from defender.learning.author.version_control import opened_delivery

        state.delivery = state.opened.enter_context(opened_delivery(
            state.tenant, defender_dir=session.defender_dir, directory=state.records, purpose="drain",
            client=session.client, identity=_drain_credential(session, state)))
    return state.delivery


def _batch_start(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    """The drain's publish and its draft (`TenantDelivery.start_batch`), at an id minted here."""
    from defender.learning.author.version_control import DeliveryRefused, ForgejoAuthError
    from defender.records.formats import TenantRefused

    lanes = fields["lanes"]
    if not isinstance(lanes, list) or not lanes or not all(isinstance(lane, str) for lane in lanes):
        raise Refused("batch.start takes its lanes, a list of names", "bad-fields")
    state = _state(session, _PostStep)
    ident = uuid.uuid4().hex[:12]
    try:
        batch = _drain_delivery(session, state).start_batch(ident, lanes=lanes)
    except (DeliveryRefused, ForgejoAuthError, TenantRefused) as refused:
        raise Refused(f"the batch could not start: {refused}", "delivery") from None
    with session.lock:
        state.batches[batch.id] = batch
        session.minted.add(batch.id)
    return {"batch": batch.id, "path": str(batch.draft_root.parent), "branch": batch.branch,
            "base": batch.export.commit, "export": str(batch.export.path), "lanes": list(batch.lanes)}


def _batch_box(session: Session, ident: str) -> Any:
    state = _state(session, _PostStep)
    batch = state.batches.get(ident)
    if batch is None:
        raise Refused(f"no draft of this helper's is {ident!r}", "unknown-id")
    # Judged on the request the box is started with: the draft's stage (read-only) and each lane (writable), every
    # component from `<T>/` down (H10), not only the draft's folder.
    request = batch.box_request()
    session.judge_binds(m.source for m in request.mounts)
    return _drain_delivery(session, state).start_box(request, docker=session.docker)


def register(registry: Registry) -> None:
    """The learning kinds' hooks, requests and boxes (module doc)."""
    registry.kind(LEARNING, KindSpec(prepare=_prepare_learning, end=_learning_end))
    registry.kind(POST_STEP, KindSpec(prepare=_prepare_post_step, end=_post_step_end))
    registry.add("pass", kinds=(LEARNING,), handler=answer_pass, required=("id",))
    registry.add("copy.make", kinds=(LEARNING,), handler=_copy_make, required=("world",))
    registry.add("export.materialise", kinds=(LEARNING,), handler=_export_materialise, required=("commit",))
    registry.add("batch.start", kinds=(POST_STEP,), handler=_batch_start, required=("lanes",))
    registry.add("forge.token", kinds=(POST_STEP,), handler=_forge_token, required=("min_validity",),
                 after_signal=True)
    registry.add("record.published", kinds=(POST_STEP,), handler=_record_published, required=("commit",),
                 after_signal=True)
    registry.add("record.refusal", kinds=(POST_STEP,), handler=_record_refusal, required=("kind", "reason"),
                 after_signal=True)
    registry.box_kind("shell", kinds=(LEARNING,), start=_sibling_box)
    registry.box_kind("oracle", kinds=(LEARNING,), start=_oracle_box)
    registry.box_kind("batch", kinds=(POST_STEP,), start=_batch_box)
