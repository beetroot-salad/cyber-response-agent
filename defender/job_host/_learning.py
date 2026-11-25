"""The learning kinds' part of the helper (#1170: `learning`, `post-step`; #1546 D7: `drain`): their host halves, their
requests and their boxes.

**The learning job** (`--kind learning --job <id> --tenant T --source S`). Its host half, before the container: the
tenant's lock, waited for at most 30 s (still busy: the learning entry's `stopped` word, which the worker hands back,
A3, C24), the admission (`host_tenant`), the tenant's current records read once (#1366 O6: a tenant that is not active is
refused, #1470 O8; the container, which reads no database, and every sibling's run are handed them in the launch facts), the
knowledge fetch (the grant read: `main` fetched by the fetch child into a copy the helper owns and removes once the
grant is read, #1618 F3), the grant over it (the granted systems declared `http-proxy`, narrowed to those the tenant
has enabled records of; down systems not subtracted, O5) and the first pass,
signed for the learning job's own id (pre-flight's pass names the row the worker fences; O5, C12 replaced). `--source`
is not checked here: the entry checks it in the container, over the tenant's own records (design correction).

Its requests: `pass` for an id this helper minted (the job's own, or a sibling's run); `copy.make(world=)`, a sibling's
run id and run copy (A6, C20, C23): its id is the one the job staged in its `arms` roster for the world (#1546 D12, PR2),
its copy is of the claim's pin (`knowledge_commit`), fetched by the fetch child into the claim's inputs and held to the
settings check, and the helper makes the episode's `runs/` folder with no link followed out of the root (H10). It reads
nothing from the episode (the job writes it): the container makes the run folder `<episode>/runs/<run>/` and its start
records itself (#1546 r10, D-2). `copy.make(commit=)` answers the claim's pin only and `copy.make()` `main`'s tip, each a
copy in the claim's `shared/` folder fetched by the fetch child (the helper holds no credential): the judge's bodies,
#1618 F3. The container writes no copy of its own. The job's records (`outcome`, `arms`, `arm`, `progress`) and objects
are `_evidence`'s. Its grant is read from `main`, fetched once into the claim's spool (`.job-spool/<claim>/grant/`, bound
into nothing) and removed before the container starts.
Boxes: `shell` (a sibling's run box over its run folder and copy) and `oracle` (the learning job's own: the
oracle's box, its bind folders in a per-claim folder under the data root, never host `/tmp`, C21).

**The post-step and the family-less check** (`--kind post-step [--job <id>] --tenant T`). Its host half: the tenant's
lock and admission (waiting as today). Its requests: `batch.start(lanes=)`, the drain's draft of `main`'s `agent/` (read through a delivery
of the helper's own, no fetch child call), made here (the draft owned by this helper, C23), its id minted here; `forge.token(min_validity=)`, a fresh token of the tenant's
forge credential, for at most 150 s (C25: fail closed above it); and the tick's
store, `store.*` (#1487 Flow 2, `_store_relay`). Box: `batch`, over a draft this helper made.

**The drain request** (`--kind drain --job <request id> --tenant T`, #1546 D7): the post-step's host half and requests,
plus `owner.unusable` and `evidence.pull`; its tick the lead-author lane's. The helper hands its claim's input set in the
launch facts (`input_set`) and unpacks nothing: the container pulls and unpacks each bundle into its own root (r10, H3).
Its result is the tick's exit status (`result`, an int).

**Endings before the container** (A3, r4.1): a learning job's in the learning entry's own words, staged as its outcome
(setup refused: `failed: launch_refused`; cannot be started confined or the helper crashed: `failed: entry_error`; a
busy lock or a stop before the container: `stopped`); a post-step and a drain stage nothing.

Everything the helper made for the job (the claim's root, inputs and spool, drafts, the per-claim scratch folder) goes
at its end: what the job keeps is what it pushed."""
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
from typing import Any

from defender import _io
from defender.credential_proxy import PASS_LIFETIME_SEC
from defender import job_socket
from defender.job_socket import SCRATCH_ROOT, Refused

from ._common import answer_pass, first_pass, grant, settle_knowledge, start_run_box
from ._session import DOCKER_DID_NOT_RUN, HandBack, KindSpec, Prepared, Registry, Session, SetupRefused, setup_step

_logger = logging.getLogger(__name__)

LEARNING, POST_STEP, DRAIN = "learning", "post-step", "drain"
#: The kinds that run the author lanes' tick over the tenant's folder: the post-step's author drain, the drain request's
#: lead-author drain (#1546 D7).
TICK_KINDS = (POST_STEP, DRAIN)
#: How long a learning job's helper waits for the tenant's host lock before handing the job back (C24).
LOCK_WAIT_SECONDS = 30.0
#: Where under the data root each claim's scratch folder lives (oracle boxes' binds): outside
#: every tenant's folder, the job socket's folder and host `/tmp` (C21).
SCRATCH = SCRATCH_ROOT
#: The claim scratch folder's one subfolder the job container mounts read-write, where its oracle boxes' scratch
#: folders are made, so the job's own process writes the oracle's saved reads into them (#1557 H3, amending #1543
#: D1). The rest of the claim folder (the boxes' runners) is not mounted into the job.
SHARED = "shared"
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
    #: The family's knowledge pin (the claim's launch facts): the commit every sibling's copy is fetched at.
    pin: str = ""
    #: Where `copy.make` makes its copies: the claim's `shared/` folder, the one folder of it the job container mounts (they go with the claim, F3).
    copies: Path | None = None
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
    #: The tick's store relay (`_store_relay`), made at the first store request.
    relay: Any = None


def post_step_state(session: Session) -> _PostStep:
    """The post-step's state, or `Refused` (`internal`) before it is set up."""
    return _state(session, _PostStep)


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
        admitted = host_tenant(session.root, session.tenant_id, directory=session.directory,
                               defender_dir=session.defender_dir)
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


def _shared(scratch: Path) -> Path:
    """`<claim scratch>/shared/`, mode 0700: the job container's read-write mount (`SHARED`)."""
    folder = scratch / SHARED
    try:
        _io.guarded_mkdir(folder, base=scratch)
        folder.chmod(0o700)
    except (OSError, ValueError) as e:
        raise SetupRefused(f"the claim's shared folder {folder} could not be made: {e}") from None
    return folder


def _prepare_learning(session: Session, hold: contextlib.ExitStack) -> Prepared:
    from defender import run_common
    from defender.records.formats import TenantRefused
    from defender.systems.catalog import Catalog
    from defender.systems.run_tenant import run_tenant_for
    from defender.tenancy import run_knowledge

    job = str(session.job_id)
    pin = _claim_pin(session)  # before any fetch: a family that cannot be pinned is never served another commit
    _hold_within_wait(session, hold)
    admitted = _admit_tenant(session, hold)
    accepted, records = admitted.tenant, admitted.directory
    # The tenant's current records, read once for the whole job (#1366 O6; a tenant not active refused, #1470 O8): the
    # container, which reads no database, is handed them in the launch facts, and so is each sibling's run.
    current = setup_step(run_common.read_records, records, accepted.id)
    # The roster, read cold (no adapter code, N7) once: the records' reads are judged against it (#1504 O3) and the
    # tenant's systems are narrowed to it (#1366 R12).
    roster = setup_step(run_common.run_roster, session.defender_dir)
    cleanup = contextlib.ExitStack()
    try:
        # The grant is `main`'s (F3, r5.1-a): its copy is fetched by the fetch child into a folder this helper owns, read
        # once and removed, so a Forgejo that cannot serve `main` refuses the job here, before any container (K4). The
        # proxy serves a system only by its declaration in `main`'s settings; a grant from an older pin could only add
        # systems the proxy refuses, and would miss none it serves.
        # The copy is the helper's alone (#1546 r10, D-1): in the claim's spool, outside the tenant folder (which a
        # post-step or a drain binds read-write) and bound into nothing, removed before the container starts.
        grant_for = _grant_tenant(session, accepted)
        cleanup.callback(shutil.rmtree, grant_for.run_knowledge, ignore_errors=True)
        source = settle_knowledge(session, grant_for, records, run_id=job)
        try:
            grant_copy = run_knowledge.adopt_copy(grant_for, job)
        except (run_knowledge.KnowledgeRefused, OSError) as refused:
            raise SetupRefused(f"this job's knowledge could not be copied: {refused}") from None
        try:
            ready = run_tenant_for(accepted, dispatches_lead_zero=False, records=current, catalog=Catalog(roster),
                                   agent_root=grant_copy.agent, settings_root=grant_copy.settings)
        except (TenantRefused, Refused) as refused:
            raise SetupRefused(f"this job's tenant cannot be used: {refused}") from None
        # Narrowed to the systems the tenant has enabled records of (#1366 R12), over the same roster.
        ready = setup_step(run_common.tenant_verdict, ready, roster, warn=False).tenant
        reads = grant(ready)
        grant_copy.remove()
        shutil.rmtree(grant_for.run_knowledge, ignore_errors=True)
        passes = first_pass(session, accepted, records, reads)
        scratch = _scratch(session, cleanup)
        shared = _shared(scratch)
    except BaseException:
        cleanup.close()
        raise
    session.minted.add(job)
    state = _Learning(accepted, source.commit, scratch, records=current, pin=pin, copies=shared)
    cleanup.callback(_remove_copies, state)
    command = session.command or ["python3", "-m", "defender.cli.learning.job", "--job", job,
                                  "--tenant", session.tenant_id, "--source", str(session.source)]
    facts = {"kind": LEARNING, "tenant": session.tenant_id, "job": job, "tenant_state": "active",
             "export_commit": source.commit, "proxy_url": passes.proxy_url if passes is not None else None,
             "grant": [[s, "r"] for s in reads], "pass_lifetime": PASS_LIFETIME_SEC,
             "records": current.as_wire(), "inputs_dir": str(session.job_inputs), "knowledge_commit": pin}
    return Prepared(launch=facts, command=list(command), passes=passes, state=state, cleanup=cleanup,
                    exited=_learning_exited, shared=shared)


def _claim_pin(session: Session) -> str:
    """The family's pin: the claim's launch fact `knowledge_commit`, the source run's commit the store wrote (#1546 r10).
    A claim with none, or one that is no full commit id, is refused here: there is no fallback to `main` (#1618 r5.1-b),
    nor to the commit the grant read fetched."""
    from . import _evidence

    pin = _evidence.state(session).claim.launch.get("knowledge_commit")
    if not isinstance(pin, str) or not _COMMIT.fullmatch(pin):
        raise SetupRefused(f"the source run's knowledge cannot be pinned: the claim's knowledge_commit {pin!r} is no "
                           "full commit id")
    return pin


def _grant_tenant(session: Session, accepted: Any) -> Any:
    """The grant read's copy tenant: the tenant's id, its one copy made under `<spool>/grant/` (a folder this helper
    makes, mode 0700)."""
    from ._folders import CopyTenant

    if session.job_spool is None:
        raise SetupRefused("the claim's spool was not made")
    folder = session.job_spool / "grant"
    try:
        _io.guarded_mkdir(folder, base=session.job_spool)
        folder.chmod(0o700)
    except (OSError, ValueError) as e:
        raise SetupRefused(f"the grant read's folder {folder} could not be made: {e}") from None
    return CopyTenant(accepted.id, folder)


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
    return Prepared(launch=facts, command=list(command), state=state, cleanup=cleanup, exited=_post_step_exited)


def _prepare_drain(session: Session, hold: contextlib.ExitStack) -> Prepared:
    """A drain request (#1546 D7): the post-step's host half (the tenant's admission, its store relay, its drafts and
    forge tokens), and its claim's fixed input set handed in the launch facts (`input_set`, each `{owner, object}`). The
    helper pulls and unpacks nothing (r10, H3): the container pulls each member through `evidence.pull` and unpacks it
    into its own root."""
    from . import _host_request

    rid = _host_request.request_id(session)
    from . import _evidence

    prepared = _prepare_post_step(session, hold)
    claim = _evidence.state(session).claim
    prepared.command = list(session.command or ["python3", "-m", "defender.learning.branch.drain_job", "--job", rid,
                                                "--tenant", session.tenant_id])
    prepared.launch.update({"kind": DRAIN, "job": rid, "job_root": str(session.job_root),
                            "inputs_dir": str(session.job_inputs),
                            "input_set": [{"owner": owner, "object": obj} for owner, obj in claim.inputs]})
    prepared.exited = None
    return prepared


def _drain_end(session: Session, cause: str) -> None:
    """A drain ended before its container stages nothing: its result is its tick's exit status, which no tick gave."""
    _logger.info("drain %s ended before its container (%s); no result is staged", session.job_id, cause)


def _discard_batches(state: _PostStep) -> None:
    for batch in list(state.batches.values()):
        batch.discard()


# --- endings before the container (A3) ----------------------------------------------------------------------------------

def _write_learning_end(session: Session, status: str, reason: str | None, message: str) -> None:
    """A learning outcome the helper decided, staged under the job's claim: nothing ran, nothing was spent, no findings."""
    from . import _evidence

    _evidence.state(session).stage("outcome", {
        "status": status, "reason": reason, "message": message, "fork_message_id": None, "stage": None,
        "sibling_cost_usd": 0.0, "findings": None})


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
        why = session.ending_why.removeprefix("setup refused: ") if session.ending_why else None
        _write_learning_end(session, job_lane.LEARNING_FAILED, job_lane.LAUNCH_REFUSED,
                            "the job's setup was refused before its container started"
                            + (f": {why}"[:2000] if why else ""))
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


def _post_step_exited(session: Session, _rc: int) -> None:
    """After a post-step's container: whether work still waits, the helper's exit status (#1487 Flow 3, Amendment r5.2).
    Asked of the store the tick's relay bound (made now if the tick asked nothing), before the cleanup closes it. A
    stopped post-step, or a question that fails (logged), leaves the status 0, which the worker reads as unknown."""
    from . import NOTHING_WAITS, WORK_WAITS
    from ._store_relay import answer_waiting

    if session.signalled.is_set():
        return
    waiting = answer_waiting(session)
    if waiting is not None:
        session.served_status = WORK_WAITS if waiting else NOTHING_WAITS


def _learning_exited(session: Session, rc: int) -> None:
    """After the container: a `docker run` that never ran the job (and so staged no outcome) is the learning entry's start
    failure. Each page is the job's own push (A-O8): nothing is copied from its arms' folders."""
    from . import _evidence

    ev = _evidence.state(session)
    if rc in DOCKER_DID_NOT_RUN and not (ev.has("outcome") or ev.has("refused/outcome")):
        sys.stderr.write(f"[job_host] learning job {session.job_id}: the job container did not start (docker "
                         f"exit {rc}); the job ran nowhere\n")
        _learning_end(session, "start-failed")


# --- the learning job's requests ------------------------------------------------------------------------------------------

#: The tenant's episodes folder, `<T>/episodes` (`tenancy.box_mounted_episodes`).
EPISODES = "episodes"


def _episode_folder(session: Session) -> Path:
    """The learning job's own episode, `<job root>/<T>/episodes/<job id>` (episode id = job id), with no link on the way
    from the data root down."""
    return session.inside(session.job_tenant_root / EPISODES / str(session.job_id))


def _roster_id(session: Session, world: str) -> str:
    """The run id the staged `arms` roster holds for `world` (PR2: the roster is a staged fact), or a refusal."""
    from . import _evidence

    roster = _evidence.state(session).fact("arms")
    entries = roster.get("roster") if isinstance(roster, dict) else None
    if not isinstance(entries, list):
        raise Refused("no arms roster is staged: a sibling's run is made only for a run the roster names", "unknown-id")
    from defender.records import RunId, RunRefused

    for entry in entries:
        if isinstance(entry, dict) and entry.get("world_id") == world:
            try:
                return str(RunId.parse(entry.get("run_id")))  # parsed on receipt; a path segment only as an id
            except RunRefused:
                raise Refused(f"the staged roster's run id for {world!r} is not canonical", "unknown-id") from None
    raise Refused(f"the staged roster holds no world {world!r}", "unknown-id")


def _copy_make(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    """`copy.make(world=)`: a sibling's run id (the staged roster's), its run copy of the claim's pin, owned here, and
    the episode's `runs/` folder; the container makes the run folder `<episode>/runs/<run>/` at the answered `run_dir`
    (A6, C20; #1546 r10, D-2). `copy.make(commit=)`, the claim's pin only, or `copy.make()`, `main`'s tip: a copy in the
    claim's `shared/` folder (F3; r10 H1). A sibling's pin is the family's, chosen here and never named by the container."""
    state = _state(session, _Learning)
    world, commit = fields.get("world"), fields.get("commit")
    if world is None:
        return _scratch_copy(session, state, commit)
    if commit is not None:
        raise Refused("copy.make takes a world or a commit, not both: a sibling's commit is its family's", "bad-fields")
    return _sibling_copy(session, state, world)


def _scratch_copy(session: Session, state: _Learning, commit: Any) -> dict[str, Any]:
    """The fetch child's copy of `commit` (`main` when none) in a folder of the claim's scratch this helper owns, which
    goes with the claim (F3). The helper holds no credential: the child mints its own. A `commit` other than the claim's
    pin is refused before any folder or fetch (#1546 r10, H1: least privilege; the forge is never asked what it is)."""
    from defender import run_common
    from defender.tenancy import run_knowledge
    from defender.tenancy import owned_temporary

    if commit is not None and commit != state.pin:
        raise Refused(f"copy.make(commit=) answers only the claim's pinned commit {state.pin}, not {commit!r}",
                      "not-for-kind")
    assert state.copies is not None
    dest = state.copies / owned_temporary("copy")
    try:
        _io.guarded_mkdir(dest, base=state.copies)
        dest.chmod(0o700)
    except (OSError, ValueError) as e:
        raise Refused(f"the copy's folder could not be made: {e}", "internal") from None
    report = run_common.fetch_report(session.fetch, state.tenant.id, dest, session.root, commit=commit)
    if report.kind != run_knowledge.OK or (commit is not None and report.commit != commit):
        shutil.rmtree(dest, ignore_errors=True)
        why = report.reason if report.kind != run_knowledge.OK else f"the fetch brought {report.commit}"
        raise Refused(f"the knowledge of {commit or 'main'} could not be fetched: {why}", "delivery")
    return {"path": str(dest), "commit": report.commit}


def _sibling_copy(session: Session, state: _Learning, world: object) -> dict[str, Any]:
    from defender.tenancy import run_knowledge

    if not isinstance(world, str):
        raise Refused("copy.make takes a world id", "bad-fields")
    with session.lock:
        made = state.by_world.get(world)
        if made is not None:
            return _copy_answer(state.siblings[made])
    episode = _episode_folder(session)
    run = _roster_id(session, world)
    runs = episode / "runs"
    run_dir = runs / run
    session.inside(run_dir, must_exist=False)
    try:
        # The episode's arm folder, no link followed out of the episode; the run folder is the container's to make
        # (run setup makes it exclusively: a run folder is never resumed).
        _io.guarded_mkdir(runs, base=episode)
    except (OSError, ValueError) as unmade:
        raise Refused(f"the episode's runs folder could not be made: {unmade}", "confinement") from None
    session.inside(runs)
    source = run_knowledge.KnowledgeSource(kind=run_knowledge.PINNED, commit=state.pin)
    copy = _sibling_run_copy(session, state, source, run)
    sibling = _Sibling(run, world, run_dir, copy)
    with session.lock:
        state.siblings[run] = sibling
        state.by_world[world] = run
        session.minted.add(run)
    return _copy_answer(sibling)


def _sibling_run_copy(session: Session, state: _Learning, source: Any, run: str) -> Any:
    """A sibling's run copy of the family's pinned commit, fetched by id by the fetch child into the claim's inputs
    (run setup's own copy operation over the claim's `CopyTenant`), held to the settings rules a run's copy is."""
    from defender import run_common
    from defender.tenancy import run_knowledge

    from ._folders import copy_tenant

    try:
        # The copy's tenant is the claim's (`CopyTenant`: its id, and where the copy goes), which `resolve_knowledge`
        # and `adopt_copy` read as they read a `Tenant`'s.
        copy_for: Any = copy_tenant(session, state.tenant)
        run_common.resolve_knowledge(copy_for, pin=source.commit, fetch=session.fetch, data_root=session.root,
                                     records=state.records, run_id=run)
        return run_knowledge.adopt_copy(copy_for, run)
    except run_common.KnowledgeExit as refused:
        why = str(refused.code).removeprefix("[run.py] ")
        raise Refused(f"the sibling's run copy could not be made: {why}", "settings") from None
    except (run_knowledge.KnowledgeRefused, OSError) as refused:
        raise Refused(f"the sibling's run copy could not be made: {refused}", "settings") from None


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
    """The oracle's box (#1224): its runner made in a fresh folder under the claim's scratch folder (C21: never host
    `/tmp`), removed with it at the helper's end; its scratch made inside the claim's `shared/` folder (#1557 H3),
    which the job container mounts, so the job's process can save the oracle's reads where its code reads them. The
    box binds the scratch read-only. Nothing is made in the tenant's folder."""
    from defender import box

    state = _state(session, _Learning)
    folder = state.scratch / f"oracle-{uuid.uuid4().hex[:12]}"
    _io.guarded_mkdir(folder, base=state.scratch)
    try:
        return box.start_oracle_box(env=os.environ, tenant_id=session.tenant_id, folder=folder,
                                    docker=session.docker, data_root=session.root_folder,
                                    scratch_folder=state.scratch / SHARED)
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


def forge_token_answer(fields: dict[str, Any], credential: Any) -> dict[str, Any]:
    """`forge.token` for a kind that holds a forge credential (the post-step's drain, an adoption): a token valid for
    `min_validity` more seconds (0 to `FORGE_TOKEN_CAP`) from `credential`, or the request's refusal."""
    validity = fields["min_validity"]
    if isinstance(validity, bool) or not isinstance(validity, (int, float)) or not math.isfinite(validity) \
            or not 0 <= validity <= job_socket.FORGE_TOKEN_CAP:
        raise Refused(f"forge.token's min_validity is a number of seconds from 0 to "
                      f"{job_socket.FORGE_TOKEN_CAP:.0f}",
                      "bad-fields")
    try:
        token = credential().token(min_validity=float(validity))
    except Exception as failed:  # noqa: BLE001 — a token that cannot be minted is the job's to report
        raise Refused(f"the forge token could not be minted: {type(failed).__name__}: {failed}",
                      "forge-fault") from None
    return {"token": str(token)}


def _forge_token(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    state = _state(session, _PostStep)
    return forge_token_answer(fields, lambda: _drain_credential(session, state))


def _drain_delivery(session: Session, state: _PostStep) -> Any:
    """A delivery of this helper's own, opened afresh (a private repository fetched at the moment: `main`'s tip then),
    held open to the helper's end; the batch's box is started through the latest."""
    from defender.learning.author.version_control import opened_delivery

    state.delivery = state.opened.enter_context(opened_delivery(
        state.tenant, defender_dir=session.defender_dir, directory=state.records, purpose="drain",
        client=session.client, identity=_drain_credential(session, state)))
    return state.delivery


def _batch_start(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    """The drain's draft (`TenantDelivery.start_batch`) of `main`'s `agent/` as this helper's own delivery fetched it, at
    an id minted here. No fetch child is asked: the helper holds the drain credential its delivery fetches with (F6)."""
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
            "base": batch.base_commit, "lanes": list(batch.lanes)}


def _batch_box(session: Session, ident: str) -> Any:
    state = _state(session, _PostStep)
    batch = state.batches.get(ident)
    if batch is None:
        raise Refused(f"no draft of this helper's is {ident!r}", "unknown-id")
    # Judged on the request the box is started with: the draft's stage (read-only) and each lane (writable), every
    # component from `<T>/` down (H10), not only the draft's folder.
    request = batch.box_request()
    session.judge_binds(m.source for m in request.mounts)
    return state.delivery.start_box(request, docker=session.docker)


def _answer_owner_unusable(session: Session, fields: dict[str, Any]) -> dict[str, Any]:
    """`owner.unusable(run_id=)`, a drain's (#1546 PR6, D7): whether the claim's tenant's investigation `run_id` can never
    be an input (the job store's `run_unusable`), so the tick ends its absent request dead rather than waiting. The
    container opens no database; the tenant is the claim's, never the container's word."""
    from . import _evidence

    run = fields["run_id"]
    if not isinstance(run, str):
        raise Refused("owner.unusable takes a run id", "bad-fields")
    ev = _evidence.state(session)
    try:
        unusable = ev.rows.run_unusable(ev.claim.tenant_id, run)
    except Exception as fault:  # noqa: BLE001 — an unread state is no verdict: the container's request waits
        raise Refused(f"the owner of run {run!r} could not be read: {type(fault).__name__}", "internal") from None
    return {"unusable": bool(unusable)}


def register(registry: Registry) -> None:
    """The learning kinds' hooks, requests and boxes (module doc)."""
    registry.kind(LEARNING, KindSpec(prepare=_prepare_learning, end=_learning_end))
    registry.kind(POST_STEP, KindSpec(prepare=_prepare_post_step, end=_post_step_end))
    registry.kind(DRAIN, KindSpec(prepare=_prepare_drain, end=_drain_end))
    registry.add("pass", kinds=(LEARNING,), handler=answer_pass, required=("id",))
    registry.add("copy.make", kinds=(LEARNING,), handler=_copy_make, optional=("world", "commit"))
    registry.add("owner.unusable", kinds=(DRAIN,), handler=_answer_owner_unusable, required=("run_id",))
    registry.add("batch.start", kinds=TICK_KINDS, handler=_batch_start, required=("lanes",))
    registry.add("forge.token", kinds=TICK_KINDS, handler=_forge_token, required=("min_validity",),
                 after_signal=True)
    registry.box_kind("shell", kinds=(LEARNING,), start=_sibling_box)
    registry.box_kind("oracle", kinds=(LEARNING,), start=_oracle_box)
    registry.box_kind("batch", kinds=TICK_KINDS, start=_batch_box)
