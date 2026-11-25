"""The worker (#1342, #1343): claims queued investigations up to its slots, runs each as a child
process through the job lane, keeps each row's lease alive while it holds it, and records how it
ended.

Every child is the per-job host helper (#1170 H7), `python -m defender.job_host --kind <kind> ...`: it
does the privileged work for its one job of one tenant and starts the job's container as its own child.
The worker spawns, supervises, stops and sweeps the helper as it did the job entry before: the helper is
tied to the worker's pid, a stop or fence is its SIGTERM (it stops the container gracefully), and the
kill of its group ends it and, with it, the container. The worker's start removes the job containers a
dead worker's helpers left (`serve`).

Every claim is the store's (#1546 PR7): the store mints its token in the claim's own transaction, with the claim row
that names the row, its launch facts and its fixed input set. The child is handed that token (`box.CLAIM_ENV`), so every
container its process tree starts carries it and its per-claim folders are named by it; its helper writes the job's
copies of the launch facts and alert into the claim's own root (the worker writes nothing beside the run).

Per claimed row, as a task: the tenant's state, read by the claim itself, must be `active` (#1342 r7 R7-1: no host lock
is taken and the worker is recorded as no holder, so a teardown never waits for it or signals it), the tenant's runs
container must be usable (opened and let go; the worker never makes it), the child is spawned from the event loop's
thread in a session of its own with its output inherited, its exit awaited, every container its process tree started
removed (the sweep, by the claim's label), then the claim's folders (once its helper is gone, link-safe). The task owns
its child: however the row ends once the child exists (its exit, a stop, a fence, even mid-spawn), the child's process
group is killed and the sweep runs (r7 D-ac).

The row's end is a decision, then one write (#1546 PR9, A-O2): the worker reads what the claim's helper staged and
uploaded (`JobStore.staged`), never a file the job wrote and never a session database, has `jobs.ending.decide` decide
the ending from those rows and what ended the child (its exit, or this worker's stop), and hands the decision to the
store's one applier (`JobStore.apply`). A decision the store refuses is weakened (`ending.lesser`) and applied again.

A row belongs to the worker that keeps renewing its lease (B-P1) and stays its worker's until the
last write for it lands (B-P2): the one end write (B4) is the applied decision; a row someone else already ended
(a cancel, an offboard, a take-over) keeps that ending and its staged cost (D15), and a deliberate stop ends the
children and hands back the rows that decided nothing (B11). A write that fails as an outage is retried each second
and nothing new is claimed meanwhile (B5).

A database outage ends no child, however long it lasts (T2): a renewal that fails, or outlives
`store_call_limit`, is tried again, and a late renewal revives a row nobody took over. A worker whose
own store calls hit an outage within the last lease takes nothing over: other workers' leases lapsed
in the same outage, and their next renewal has not had its chance.

Learning jobs (#1344) share the slots: a worker with a free slot claims the oldest queued job when
fewer than `learning_slots` learning-class tasks (family steps and post-steps) run, and otherwise
the oldest investigation. A job runs as the job entry's child, with the same death tie, stop and
fence as an investigation; the worker copies its staged progress onto the row on its renewal loop, and the row's end
is decided from its staged outcome, whose findings its helper screened on receipt (#1546 D11) and the applier stores
with the ending. After a job whose child started, a post-step child runs the
drain gate, in the same slot and the same supervision registry, with no lease of its own: its claim is the tenant's
check-clock hold, whose token the store mints (PR7). Its helper
says by its exit status whether work still waits (Flow 3, #1487 Amendment r5.2: `job_host.NOTHING_WAITS`
or `WORK_WAITS`); the worker opens no learning store, and the tenant's check clock goes idle only on
`NOTHING_WAITS`.

A family-less post-step (#1344 amendment 1) wakes a tenant no family has followed for a while: a
worker with learning slots, not stopping, checks each `active` tenant with learning jobs once its
last post-step (or, before any, the worker's start) is `learning_check_interval` old. That check
runs the same child without a job, and so the drain's own gate: a retained delivery, an open batch
and findings at threshold are each decided there, never by a second gate here. An overdue check is
claimed before a queued job, within the learning slots, so sustained load cannot starve it.

Host requests (#1471: readiness checks and adoptions; #1546 D7: the lead-author drain) have a pool of their own,
`host_request_slots`, outside `slots`: while fewer host requests run, the oldest queued one of any kind is claimed.
Before its helper starts, the tenant's runs container is opened as an investigation's is (R13-1.1: an unusable one ends
the row `worker_error`, and no helper starts). Once the helper has exited, its staged `result` decides the row whatever
the exit status and a stop (R13-1.5, R13-5); a `refused/result` is `bad_record`; none is `worker_error` after a failed
helper, `worker_stopped` after a stop, or `no_record` after one that exited 0. A host request is never handed back."""
from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender import _log
from defender._url import check_origin
from defender.jobs import FindingsNotStored, LearningProgress, ending, is_outage, is_refusal
from defender.jobs.audit import SYSTEM, announce
from defender.box import CLAIM_ENV, container_name
from defender.execution import kill_group, wait_group_gone
from defender.job_socket import CLAIM_ROOTS, OWNERS_ROOT
from defender.records import job_lane
from defender.records.formats import DataRoot, digest_of
from defender.tenancy import data_root_for_child, data_root_from_path, owner_alive

from ._containers import Containers, DockerContainers
from ._held import HOST_REQUEST, INVESTIGATION, LEARNING, POST_STEP, Held, StagedProgress

if TYPE_CHECKING:
    from defender.jobs import Claim, HostRequestClaim, LearningClaim

_logger = logging.getLogger(__name__)

#: How long an idle serving worker waits between claims (M10: a fixed interval, no NOTIFY).
POLL_INTERVAL = 1.0

#: The pause between tries of an end write that failed as an outage (B5).
END_RETRY_DELAY = 1.0

#: How long a tenant goes without a post-step before the worker checks it without a family
#: (#1344 amendment 1), in seconds.
LEARNING_CHECK_INTERVAL = 300.0

#: How long a post-step may run before the worker ends it as it would at a stop (#1487 Amendment r5.4), in seconds:
#: well past a long authoring tick, so that only a hang (a database that never answers, a container that never exits)
#: meets it.
POST_STEP_LIMIT = 4 * 3600.0

#: The per-job host helper (#1170 H7): every job of every kind is its child, started with `-m` from the
#: code tree's root (the worker's code copy, as `child_cwd`).
JOB_HOST_MODULE = "defender.job_host"

#: The host-request kinds (#1471, #1546 D7), as the store's rows name them.
_READINESS, _ADOPTION, _DRAIN = "readiness", "adoption", "drain"

#: The worker's words for a job whose tenant's runs container cannot be opened before its child starts (#1342 R1):
#: one sentence, the investigation's and a host request's alike (#1471 R13-1.1).
_RUNS_UNUSABLE = "the tenant's runs container cannot be used on this host"

#: What a claim found (`Worker._claim_one`): a row claimed; nothing queued in any pool that had room; or a pool full, so
#: its queue was not asked (a drain is not over then).
_CLAIMED, _NOTHING, _NO_SLOT = "claimed", "nothing", "no_slot"

#: The kind `ending.decide` reads for each held kind (a post-step decides nothing: it holds no row).
_DECIDES = {INVESTIGATION: ending.INVESTIGATION, LEARNING: ending.LEARNING, HOST_REQUEST: ending.HOST_REQUEST}

#: The one staged fact a helper replaces as the job runs: its cost so far (an investigation) or its progress (a
#: learning job's fork pick, stage and siblings' cost).
_PROGRESS = "progress"


@dataclass(frozen=True)
class Launch:
    """What a child is started for: the investigation (its id is the run id), its tenant, and
    the worker's pid, which the child checks is its parent."""

    investigation_id: str
    tenant_id: str
    parent_pid: int
    #: What the helper is handed at its own start, never through the tenant folder (#1471 P-5): the alert's digest,
    #: whether the job posts to its ticket, and the screen link it posts.
    alert_digest: str | None = None
    update_ticket: bool = False
    ticket_link: str | None = None


@dataclass(frozen=True)
class LearningLaunch:
    """What a learning job's child is started for: the job (its id is the episode id), its
    tenant, the worker's pid, and the investigation whose run it learns from."""

    job_id: str
    tenant_id: str
    parent_pid: int
    source_investigation_id: str


@dataclass(frozen=True)
class PostStepLaunch:
    """What a post-step child is started for: the job it follows (None: a family-less post-step,
    #1344 amendment 1), its tenant and the worker's pid. It is handed no jobs (#1487: findings are
    stored with their job's ending)."""

    job_id: str | None
    tenant_id: str
    parent_pid: int


@dataclass(frozen=True)
class ReadinessLaunch:
    """What a readiness check's helper is started for (#1471): the request, its tenant and the worker's pid."""

    request_id: str
    tenant_id: str
    parent_pid: int


@dataclass(frozen=True)
class AdoptionLaunch:
    """What an adoption's helper is started for (#1471): the request, its tenant, the worker's pid and the system whose
    base files it adopts."""

    request_id: str
    tenant_id: str
    parent_pid: int
    system_id: str

@dataclass(frozen=True)
class DrainLaunch:
    """What a lead-author drain's helper is started for (#1546 D7): the request, its tenant and the worker's pid."""

    request_id: str
    tenant_id: str
    parent_pid: int



@dataclass(frozen=True)
class _PostStepOf:
    """What a post-step's entry in the supervision registry names: its tenant and the job it
    follows (None: family-less). It holds no row."""

    tenant_id: str
    learning_job_id: str | None


def _helper_argv(kind: str, *, job: str | None, tenant: str, parent_pid: int, source: str | None = None,
                 extra: Sequence[str] = ()) -> list[str]:
    """`python -m defender.job_host --kind <kind> [--job <id>] --tenant <T> [--source <run>] --parent-pid <pid>`, then `extra`."""
    return [sys.executable, "-m", JOB_HOST_MODULE, "--kind", kind,
            *([] if job is None else ["--job", job]), "--tenant", tenant,
            *([] if source is None else ["--source", source]), "--parent-pid", str(parent_pid), *extra]


def run_argv(launch: Launch) -> list[str]:
    """The default investigation child: the per-job host helper,
    `-m defender.job_host --kind investigation --job <id> --tenant <T> --parent-pid <pid>`."""
    return _helper_argv("investigation", job=launch.investigation_id, tenant=launch.tenant_id,
                        parent_pid=launch.parent_pid, extra=_ticket_argv(launch))


def _ticket_argv(launch: Launch) -> list[str]:
    """`--alert-digest <hex>` always, `--post-ticket --ticket-link <url>` only for a flagged job (#1471 C-1, P-5): the
    helper's own start carries what steers the write, so no file a job can reach does."""
    return [*([] if launch.alert_digest is None else ["--alert-digest", launch.alert_digest]),
            *(["--post-ticket", "--ticket-link", launch.ticket_link]
              if launch.update_ticket and launch.ticket_link is not None else [])]


def screen_link(origin: str, tenant: str, investigation: str) -> str:
    """The investigation screen's address a ticket comment links to (#1471 W3): `<origin>/t/<tenant>/investigations/<id>`."""
    return f"{origin}/t/{tenant}/investigations/{investigation}"


def run_argv_in(root: Path) -> Callable[[Launch], list[str]]:
    """The investigation child of the code tree at `root`: the same helper as `run_argv`, found as a
    module from the working directory (the worker starts every child in its code copy, `child_cwd`),
    so the tree is the child's working directory and not part of its command."""
    del root  # the working directory names the tree, as for the learning children
    return run_argv


def job_entry_argv(launch: LearningLaunch) -> list[str]:
    """The learning job's child: the helper of kind `learning`, which checks `--source` inside the container."""
    return _helper_argv("learning", job=launch.job_id, tenant=launch.tenant_id,
                        parent_pid=launch.parent_pid, source=launch.source_investigation_id)


def post_step_argv(launch: PostStepLaunch) -> list[str]:
    """The post-step's child: the helper of kind `post-step`; a family-less one has no `--job`."""
    return _helper_argv("post-step", job=launch.job_id, tenant=launch.tenant_id, parent_pid=launch.parent_pid)


def readiness_argv(launch: ReadinessLaunch) -> list[str]:
    """A readiness check's child: the helper of kind `readiness`, `--job` the request id."""
    return _helper_argv(_READINESS, job=launch.request_id, tenant=launch.tenant_id, parent_pid=launch.parent_pid)


def adoption_argv(launch: AdoptionLaunch) -> list[str]:
    """An adoption's child: the helper of kind `adoption`, `--job` the request id, then `--system <id>`."""
    return _helper_argv(_ADOPTION, job=launch.request_id, tenant=launch.tenant_id, parent_pid=launch.parent_pid,
                        extra=["--system", launch.system_id])

def drain_argv(launch: DrainLaunch) -> list[str]:
    """A drain's child: the helper of kind `drain`, `--job` the request id (#1546 D7)."""
    return _helper_argv(_DRAIN, job=launch.request_id, tenant=launch.tenant_id, parent_pid=launch.parent_pid)


def _exit_words(returncode: int) -> str:
    return (f"was killed by signal {-returncode}" if returncode < 0
            else f"exited with code {returncode}")


def _post_step_answer(returncode: int | None) -> bool | None:
    """Whether work still waits, as a post-step's helper said it by its exit status (#1487 Amendment r5.2): None for any
    status that is neither answer, which is never "nothing waits"."""
    from defender.job_host import NOTHING_WAITS, WORK_WAITS

    return None if returncode is None else {NOTHING_WAITS: False, WORK_WAITS: True}.get(returncode)


def _ended_by(held: Held, returncode: int) -> ending.EndedBy:
    """What ended the child, as `decide` reads it: this worker's deliberate stop, else the helper's own exit (0 once it
    served the job to its end, whatever its container's status; anything else its own failure)."""
    return ending.Stopped() if held.signalled else ending.Exited(returncode)


def _not_launched(kind: str, words: str) -> ending.Decision:
    """The ending of a row whose helper never ran (the worker's own fault, a fence before the start): `failed` /
    `worker_error` in the worker's `words`, nothing staged."""
    return ending.decide({}, {}, ending.NotLaunched(words), kind=_DECIDES[kind])


def _host_stopped() -> ending.Decision:
    """A host request this worker's stop ended before its helper staged a result (R13-5): `worker_stopped`."""
    return ending.decide({}, {}, ending.Stopped(), kind=ending.HOST_REQUEST)


def _is_cost(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _staged_progress(body: object) -> StagedProgress | None:
    """A learning job's staged `progress` fact as the renewal copies it, or None for a body not of its shape."""
    if not isinstance(body, Mapping) or not _is_cost(body.get("sibling_cost_usd")):
        return None
    pick, stage = body.get("fork_message_id"), body.get("stage")
    if not all(v is None or isinstance(v, str) for v in (pick, stage)):
        return None
    return StagedProgress(pick, stage, float(body["sibling_cost_usd"]))


def _progress_kw(progress: LearningProgress | None) -> dict[str, Any]:
    """A learning job's hand-back values from its last staged progress; with none, the row keeps what it was given."""
    if progress is None:
        return {"sibling_cost_usd": None}
    return {"sibling_cost_usd": progress.sibling_cost_usd, "fork_message_id": progress.fork_message_id,
            "family_stage": progress.stage}


class _SpawnAbandoned(Exception):
    """A host request's child was still being started when the worker stopped: the row is not held for it (R13-5)."""


def _end_late_child(spawn: asyncio.Future[asyncio.subprocess.Process]) -> None:
    """A child whose start finished after its row stopped waiting for it (`_SpawnAbandoned`): its group is killed."""
    if spawn.cancelled() or spawn.exception() is not None:
        return
    proc = spawn.result()
    _logger.warning("a child (pid %d) started after its worker stopped waiting for it; killing its group", proc.pid)
    kill_group(proc.pid)


def _remove_claim_entry(entry: Path) -> None:
    """Remove one entry under a claim root by plain removal (a folder's links are removed, never followed); one
    already gone counts as removed. Any other failure is an error naming it, left for the next start (#1557 O6)."""
    from defender.box import remove_data_folder

    try:
        remove_data_folder(entry)
    except FileNotFoundError:
        pass
    except Exception:  # noqa: BLE001 — what a job left may defeat removal (a deep tree: RecursionError); logged
        _logger.error("the per-job folder %s could not be removed; the next worker start tries again", entry,
                      exc_info=True)


def _remove_claim_folders(root: Path, claim: str) -> None:
    """A claim's folders under every claim root (`job_socket.CLAIM_ROOTS`), then its helper's record, once that helper
    is gone (#1557 O5): a claim whose record names a process that runs is that helper's still, and is left."""
    record = root / OWNERS_ROOT / claim
    try:
        alive = not record.is_symlink() and record.is_dir() and owner_alive(record)
    except Exception:  # noqa: BLE001 — a record that cannot be read leaves the claim for the next start (O6)
        _logger.error("the per-job folder %s could not be read; the next worker start tries again", record,
                      exc_info=True)
        return
    if alive:
        _logger.info("the claim %s's folders are left to its helper, which still runs", claim)
        return
    for name in (*CLAIM_ROOTS, OWNERS_ROOT):
        _remove_claim_entry(root / name / claim)


def _remove_leftover_claim_folders(root: Path) -> None:
    """At a worker's start, before it claims: every claim's folders found under a claim root or with a record, by
    `_remove_claim_folders` (a predecessor's helper still ending its job keeps its own; #1557 O5)."""
    claims: set[str] = set()
    for name in (*CLAIM_ROOTS, OWNERS_ROOT):
        try:
            claims.update(entry.name for entry in (root / name).iterdir())
        except FileNotFoundError:
            continue
        except OSError:
            _logger.error("the per-job folders under %s could not be listed; the next worker start tries again",
                          root / name, exc_info=True)
    for claim in sorted(claims):
        _remove_claim_folders(root, claim)


async def _spawn_outcome(spawn: asyncio.Future[asyncio.subprocess.Process]) -> asyncio.subprocess.Process | None:
    """The child a cancelled row's spawn made, waiting for the spawn to finish however many
    further cancels arrive (r7 D-ac: a child made after the cancel is still this row's to end);
    None when the spawn failed. Waiting on it never cancels the spawn itself."""
    while not spawn.done():
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait({spawn})
    if spawn.cancelled() or spawn.exception() is not None:
        return None
    return spawn.result()


class _WorkerFault(Exception):
    """A worker-side failure for one row (O6): the row ends `failed` / `worker_error` with this
    message, which is the worker's own words."""


class Worker:
    """Runs claimed investigations, up to `slots` at once. `drain()` claims until nothing is
    queued and waits for every row's last write; `serve()` polls until SIGTERM/SIGINT and also
    takes over rows whose holders were lost. A tenant's state comes with its claim (#1342 r7
    R7-1); the children read their tenant records from `DEFENDER_DATABASE_DSN`, which they
    inherit. Cadences (#1343): the lease is renewed every `renewal_interval`, the cost so far (the claim's staged
    `progress`, #1546) is read per row every `cost_interval` and copied by the renewal that follows, and take-over
    runs every `takeover_interval`.

    `learning_slots` (#1344 O5) is both the guarantee and the limit of learning-class tasks; a bare
    worker has none. Above 0 it needs both `learning_argv` and `post_step_argv`. `child_cwd` is the
    working directory of every child (the code copy, for `-m` starts). `learning_check_interval`
    (seconds, above 0) is how long a tenant goes without a post-step before a family-less one
    checks it (amendment 1); each tenant's clock starts at the start of `serve` or `drain`.
    `post_step_limit` (seconds, above 0) is how long a post-step runs before the worker ends it, SIGTERM then SIGKILL
    after `stop_grace`, and leaves its tenant's clock not idle (#1487 Amendment r5.4).

    `host_request_slots` (#1471 R13-6, at least 1) caps the host requests (readiness checks, adoptions and drains) that
    run at once, outside `slots` and with no share of `learning_slots`: every worker claims every kind, through
    `readiness_argv`, `adoption_argv` and `drain_argv` (#1546 D7)."""

    def __init__(  # noqa: PLR0913 — the ratified signature
        self, store: Any, *, data_root: Path | DataRoot,
        child_argv: Callable[[Launch], list[str]] = run_argv,
        containers: Containers | None = None, slots: int = 3,
        clock: Callable[[], _dt.datetime], frontend_origin: str, stop_grace: float = 30,
        renewal_interval: float = 1.0, cost_interval: float = 15.0, takeover_interval: float = 5.0,
        open_lane: Callable[[DataRoot, object], job_lane.JobLane] = job_lane.JobLane.open,
        store_call_limit: float = 10.0,
        spawn: Callable[..., Awaitable[asyncio.subprocess.Process]] = asyncio.create_subprocess_exec,
        learning_slots: int = 0,
        learning_argv: Callable[[LearningLaunch], list[str]] | None = None,
        post_step_argv: Callable[[PostStepLaunch], list[str]] | None = None,
        child_cwd: Path | None = None,
        learning_check_interval: float = LEARNING_CHECK_INTERVAL,
        post_step_limit: float = POST_STEP_LIMIT,
        wait_group: Callable[[int], bool] = wait_group_gone,
        host_request_slots: int = 1,
        readiness_argv: Callable[[ReadinessLaunch], list[str]] = readiness_argv,
        adoption_argv: Callable[[AdoptionLaunch], list[str]] = adoption_argv,
        drain_argv: Callable[[DrainLaunch], list[str]] = drain_argv,
    ) -> None:
        try:
            self._frontend_origin = check_origin(frontend_origin)
        except ValueError as bad:
            raise ValueError(f"the worker's frontend origin {frontend_origin!r} {bad}") from None
        if slots < 1:
            raise ValueError(f"a worker needs at least one slot, not {slots!r}")
        if host_request_slots < 1:
            raise ValueError(f"a worker needs at least one host-request slot, not {host_request_slots!r}")
        if not 0 <= learning_slots <= slots - 1:
            raise ValueError(f"learning slots must be between 0 and slots - 1 ({slots - 1}), not {learning_slots!r}")
        if learning_slots > 0 and (learning_argv is None or post_step_argv is None):
            raise ValueError("a worker with learning slots needs both the learning and the post-step child commands")
        if not learning_check_interval > 0:
            raise ValueError(f"the learning check interval must be above 0 seconds, not {learning_check_interval!r}")
        if not post_step_limit > 0:
            raise ValueError(f"the post-step limit must be above 0 seconds, not {post_step_limit!r}")
        self._post_step_limit = post_step_limit
        self._host_request_slots = host_request_slots
        self._readiness_argv = readiness_argv
        self._adoption_argv = adoption_argv
        self._drain_argv = drain_argv
        # The host requests' tasks (#1471 R13-6): in `_tasks` with every other, and counted apart from `slots`.
        self._host_tasks: set[asyncio.Task[None]] = set()
        self._learning_slots = learning_slots
        self._learning_argv = learning_argv
        self._post_step_argv = post_step_argv
        self._child_cwd = child_cwd
        self._learning_tasks: set[asyncio.Task[None]] = set()
        # Family-less checks (#1344 amendments 1, 3): each tenant's clock is its row in the store;
        # this is only when a failed claim of one lets the next claim try again (monotonic).
        self._learning_check_interval = learning_check_interval
        self._checks_resume_at = 0.0
        self._store = store
        self._data_root = data_root if isinstance(data_root, DataRoot) else data_root_from_path(data_root)
        self._child_argv = child_argv
        self._containers: Containers = containers if containers is not None else DockerContainers()
        self._slots = slots
        self._clock = clock
        self._stop_grace = stop_grace
        self._renewal_interval = renewal_interval
        self._cost_interval = cost_interval
        self._takeover_interval = takeover_interval
        self._open_lane = open_lane  # the job lane's door; a test hands in one that faults
        self._store_call_limit = store_call_limit  # how long one renewal or take-over call may take
        self._create_process = spawn  # the process door; a test lands an event inside it
        self._wait_group = wait_group  # the wait for a killed group to be gone; a test slows or stalls it
        self._lease = float(store.lease_seconds)
        self._store_outage_at: float | None = None  # this worker's last store call that hit an outage
        self._tasks: set[asyncio.Task[None]] = set()
        self._held: dict[str, Held] = {}
        self._stopping = False
        self._stop_signal = asyncio.Event()
        self._takeover: asyncio.Task[None] | None = None  # serving only; a stop ends it first
        # Store writes that are failing now: claims wait for them all to recover (B5, r5 item 14).
        self._renewal_failing = False
        self._end_failing: set[str] = set()
        self._last_cost_copy = 0.0

    # -- entry points -----------------------------------------------------------------------------

    async def drain(self) -> None:
        """Claim while a slot is free until nothing is queued, then wait until every held row's
        last write has landed. Renews its rows but takes nothing over (r5 item 10). A store fault
        in the claim ends it (raised) and, like a cancellation, stops as a deliberate stop does
        (`_leave`)."""
        await self._claim_loop(stop=None)

    async def serve(self) -> None:
        """Poll for queued rows at a fixed interval until SIGTERM or SIGINT, then stop: each child
        gets SIGTERM, a child still alive after `stop_grace` has its group killed, the sweep
        runs, and each row it ended is handed back (B11). A store fault is logged and the claim
        retried. Installs its own handlers and removes them on return."""
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        signals = (signal.SIGTERM, signal.SIGINT)
        previous = {s: signal.getsignal(s) for s in signals}
        for s in signals:
            loop.add_signal_handler(s, stop.set)
        try:
            await self._remove_leftover_job_containers()
            await self._claim_loop(stop=stop)
        finally:
            for s in signals:
                loop.remove_signal_handler(s)
                if previous[s] is not None:
                    signal.signal(s, previous[s])

    async def _remove_leftover_job_containers(self) -> None:
        """At start, before anything is claimed: every container carrying the job-container label
        (`job_socket.JOB_LABEL`) whose helper no longer runs is removed; its helper died with a previous
        worker, claim tokens included (#1170 A5). A live helper's container, another worker's on a
        shared daemon, is spared (`tenancy.mark_alive`). Never an error: what
        cannot be removed is logged, and the tenant's teardown removes it by the tenant's label."""
        try:
            await asyncio.to_thread(self._containers.remove_job_containers)
        except Exception:  # noqa: BLE001 — the sweep is best effort
            _logger.exception("the job containers a previous worker's helpers left could not all be removed")

    async def _claim_loop(self, *, stop: asyncio.Event | None) -> None:
        """The one claim loop of `drain` and `serve`: claim while a slot is free and no store write
        is failing, else wait for a slot to free (or, serving, for the poll interval or the stop).

        Draining (`stop` is None), the loop ends once a claim finds nothing queued, then waits
        for every task; a store fault is raised. Serving, a store fault is logged and retried,
        and the stop is the deliberate one (`_stop`). However the loop leaves by an exception
        (a store fault, a cancellation), it stops as a deliberate stop does (`_leave`). The
        renewal runs beside the loop until every row's last write has landed; serving, the
        take-over runs beside it until a stop begins (`_stop`)."""
        # Before anything is claimed, serving or draining: what a predecessor's gone helpers left (#1557 O5).
        await asyncio.to_thread(_remove_leftover_claim_folders, data_root_for_child(self._data_root))
        services = self._start_services(takeover=stop is not None)
        wake = asyncio.Event()
        try:
            try:
                await self._claim_until_done(stop, wake)
            except BaseException:
                await self._leave()
                raise
        finally:
            await _end_tasks(services)

    async def _claim_until_done(self, stop: asyncio.Event | None, wake: asyncio.Event) -> None:
        while stop is None or not stop.is_set():
            wake.clear()  # before the claim: a slot freed while it runs wakes the wait below
            if not self._writes_failing():
                found = await self._claim_or_retry(on_done=wake.set, retry=stop is not None)
                if found == _CLAIMED:
                    continue
                # Drained: nothing is queued in a pool that had room, and no pool was full (a full one's queue was not
                # asked). With learning slots, not while tasks run: a finish still to come queues a job this drain
                # claims (#1344 O5); nor when a task ended during the claim, which may have looked while its learning
                # slot was still taken.
                if stop is None and found == _NOTHING and (
                        self._learning_slots == 0 or not (self._tasks or wake.is_set())):
                    break
            await self._wait(wake, stop)
        if stop is None:
            if self._tasks:
                await asyncio.wait(set(self._tasks))
        else:
            _logger.info("the worker was asked to stop; ending %d run(s)", len(self._children()))
            await self._stop()

    def _start_services(self, *, takeover: bool) -> list[asyncio.Task[None]]:
        services = [asyncio.create_task(self._renewal_loop())]
        if takeover:
            self._takeover = asyncio.create_task(self._takeover_loop())
            services.append(self._takeover)
        return services

    def _writes_failing(self) -> bool:
        return self._renewal_failing or bool(self._end_failing)

    async def _claim_or_retry(self, *, on_done: Callable[[], None], retry: bool) -> str:
        """`_claim_one`; with `retry`, a store fault is logged and read as nothing claimed."""
        if not retry:
            return await self._claim_one(on_done=on_done)
        try:
            return await self._claim_one(on_done=on_done, retry=True)
        except Exception as fault:  # noqa: BLE001 — a store fault is waited out, never ends serving
            self._note_store_fault(fault)
            _logger.exception("the worker could not claim an investigation; retrying")
            return _NOTHING

    @staticmethod
    async def _wait(wake: asyncio.Event, stop: asyncio.Event | None) -> None:
        """Until a task ends (`wake`), the stop, or the poll interval, whichever is first."""
        waits = [asyncio.ensure_future(wake.wait())]
        if stop is not None:
            waits.append(asyncio.ensure_future(stop.wait()))
        try:
            await asyncio.wait(waits, timeout=POLL_INTERVAL, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for w in waits:
                w.cancel()

    # -- slots ------------------------------------------------------------------------------------

    async def _claim_one(self, *, on_done: Callable[[], None] | None = None, retry: bool = False) -> str:
        """Claim one queued row into a task (`_CLAIMED`): while fewer host requests than `host_request_slots` run, the
        oldest of either kind (#1471 R13-6); else, while fewer jobs than `slots` run, the oldest job
        (`_claim_job`). `_NOTHING` when every pool with room found nothing queued, `_NO_SLOT` when a pool was full.
        With `retry` (serving), a fault claiming a host request is logged and the jobs are still claimed: the host pool
        sits beside the jobs, never in front of them. Without it (a drain), the fault raises."""
        if self._stopping:
            return _NOTHING
        full = False
        if len(self._host_tasks) < self._host_request_slots:
            try:
                if await self._claim_host_request(on_done):
                    return _CLAIMED
            except Exception as fault:  # noqa: BLE001 — serving waits a store fault out; the jobs are claimed below
                if not retry:
                    raise
                self._note_store_fault(fault)
                _logger.exception("the worker could not claim a host request; claiming the jobs")
        else:
            full = True
        if len(self._tasks) - len(self._host_tasks) < self._slots:
            if await self._claim_job(on_done):
                return _CLAIMED
        else:
            full = True
        return _NO_SLOT if full else _NOTHING

    async def _claim_host_request(self, on_done: Callable[[], None] | None) -> bool:
        """The oldest queued host request of either kind, into a task of the host pool; False when none is queued."""
        claim = await self._store.claim_host_request()
        if claim is None:
            return False
        held = Held(claim.record, kind=HOST_REQUEST, token=claim.token)
        self._held[claim.record.request_id] = held
        self._start_task(self._run_host_request(claim, held), on_done=on_done, pool=HOST_REQUEST)
        return True

    async def _claim_job(self, on_done: Callable[[], None] | None) -> bool:
        """One job into a task; False when nothing is queued. While fewer learning-class tasks than `learning_slots`
        run: a tenant's overdue family-less check (#1344 amendment 1), else the oldest learning job; otherwise the
        oldest investigation (#1344 O5)."""
        if len(self._learning_tasks) < self._learning_slots:
            check = await self._claim_check()
            if check is not None:
                self._start_task(self._check_tenant(*check), on_done=on_done, pool=LEARNING)
                return True
            learning = await self._store.claim_learning_job()
            if learning is not None:
                held = Held(learning.record, kind=LEARNING, token=learning.token)
                self._held[learning.record.learning_job_id] = held
                self._start_task(self._run_learning(learning, held), on_done=on_done, pool=LEARNING)
                return True
        claim = await self._store.claim()
        if claim is None:
            return False
        held = Held(claim.record, token=claim.token)
        self._held[claim.record.investigation_id] = held
        self._start_task(self._run_row(claim, held), on_done=on_done, pool=INVESTIGATION)
        return True

    def _start_task(self, work: Awaitable[None], *, on_done: Callable[[], None] | None, pool: str) -> None:
        """`work` as a task of `pool`: every task is in `_tasks`; a learning-class one also in `_learning_tasks`, a host
        request's in `_host_tasks` (which `slots` does not count)."""
        task: asyncio.Task[None] = asyncio.ensure_future(work)
        self._tasks.add(task)
        if pool == LEARNING:
            self._learning_tasks.add(task)
        elif pool == HOST_REQUEST:
            self._host_tasks.add(task)

        def _done(t: asyncio.Task[None]) -> None:
            self._tasks.discard(t)
            self._learning_tasks.discard(t)
            self._host_tasks.discard(t)
            if on_done is not None:
                on_done()
        task.add_done_callback(_done)

    def _children(self) -> list[Held]:
        return [h for h in self._held.values() if h.proc is not None and h.proc.returncode is None]

    async def _stop(self) -> None:
        """The deliberate stop, in order: no more claims and no more take-over (a pass under way
        is cancelled and waited for), each child ended (`_end_child`), then wait for the tasks:
        each runs its sweep and its last write, which for a row the stop ended is the hand-back
        (B11). A hand-back lapses the row's lease and the row leaves `_held`, so a take-over still
        running here would take this worker's own rows over; other workers' passes retry them.
        Renewal keeps running meanwhile (the caller ends it)."""
        self._stopping = True
        self._stop_signal.set()
        if self._takeover is not None:
            await _end_tasks([self._takeover])
        await asyncio.gather(*(self._end_child(h, by_stop=True) for h in self._children()))
        if self._tasks:
            await asyncio.wait(set(self._tasks))

    async def _leave(self) -> None:
        """The loop is leaving by an exception: it stops as a deliberate stop does (r5 item 3). A
        cancel that lands during that stop's wait means leave now: every child's group is killed
        at once, so no child outlives its row's lease, and each row task is cancelled and waited
        for, so its cleanup has run when the worker leaves (a cancelled row writes nothing; its
        lease lapses into a take-over)."""
        try:
            await self._stop()
        except asyncio.CancelledError:
            _logger.warning("the worker was cancelled again while stopping; killing %d child(ren)",
                            len(self._children()))
            for held in self._children():
                if held.proc is not None:
                    kill_group(held.proc.pid)
            await _end_tasks(list(self._tasks))
            raise

    async def _end_child(self, held: Held, *, by_stop: bool = False) -> None:
        """SIGTERM, then after `stop_grace` SIGKILL to the child's whole group (its own session,
        so its group id is its pid and the worker is not in it). `by_stop` marks a child a
        deliberate stop signalled while it was alive: its row is handed back (B11)."""
        proc = held.proc
        if proc is None or proc.returncode is not None:
            return
        if by_stop:
            held.signalled = True
        with contextlib.suppress(ProcessLookupError):
            proc.send_signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(asyncio.shield(proc.wait()), timeout=self._stop_grace)
        except TimeoutError:
            _logger.warning("child %d did not end within %gs of SIGTERM; killing its group",
                            proc.pid, self._stop_grace)
            if not await self._end_group(proc.pid):
                held.group_left = True
            await proc.wait()

    # -- the lease: renewal, cost so far, take-over -------------------------------------------------

    async def _end_group(self, pgid: int) -> bool:
        """The child's whole group killed and waited for: the SIGKILL goes out here, at once, so a
        cancel landing in the wait cannot keep it from being sent; the wait for every member to be
        gone (`wait_group_gone` by default: bounded, logged if one never goes) runs in a thread.
        False when a member still ran at the limit."""
        kill_group(pgid)
        return await asyncio.to_thread(self._wait_group, pgid)

    async def _renewal_loop(self) -> None:
        """Every `renewal_interval`, renew every held row in one store call. A call that errors
        covers nothing and fences nothing (r5 item 14): claims wait and the next tick retries."""
        while True:
            await self._renew_once()
            await asyncio.sleep(self._renewal_interval)

    async def _renew_once(self) -> None:
        held = self._leased()
        checks = {h.check_holder: key for key, h in self._held.items() if h.check_holder is not None}
        if not held and not checks:
            self._renewal_failing = False
            return
        costs = self._costs_due(held)
        progress = self._progress_due(held) if costs is not None else None
        try:
            async with asyncio.timeout(self._store_call_limit):  # not `wait_for`: on 3.11 it can lose a cancel
                covered = set(await self._store.renew(set(held), costs=costs, **(
                    {"progress": progress} if progress else {}), **({"checks": set(checks)} if checks else {})))
        except Exception as fault:  # noqa: BLE001 — a failed renewal is waited out, never ends the worker
            self._renewal_failing = True
            self._note_store_fault(fault)
            _logger.warning("the worker could not renew its leases; retrying", exc_info=True)
            return
        self._renewal_failing = False
        if costs is not None:
            self._last_cost_copy = time.monotonic()
        for inv, row in held.items():
            if inv not in covered:
                self._fence(inv, row)
        for token, key in checks.items():
            entry = self._held.get(key)
            if token not in covered and entry is not None:
                self._fence(key, entry)  # its tenant's check clock was taken by another post-step

    def _note_store_fault(self, fault: BaseException) -> None:
        if is_outage(fault):
            self._store_outage_at = time.monotonic()

    def _leased(self) -> dict[str, Held]:
        """The held entries whose rows' leases this worker renews: not the post-steps."""
        return {key: h for key, h in self._held.items() if h.leased}

    def _costs_due(self, held: dict[str, Held]) -> dict[str, float] | None:
        """The figures this renewal copies (B2), or None between cost ticks."""
        if time.monotonic() - self._last_cost_copy < self._cost_interval:
            return None
        return {inv: h.cost_so_far for inv, h in held.items() if h.kind == INVESTIGATION and h.cost_so_far is not None}

    @staticmethod
    def _progress_due(held: dict[str, Held]) -> dict[str, LearningProgress]:
        """The learning jobs' progress this renewal copies (#1344 O13), on the cost ticks."""
        return {job: h.progress for job, h in held.items() if h.kind == LEARNING and h.progress is not None}

    def _fence(self, inv: str, held: Held) -> None:
        """A renewal that succeeded no longer covers the row (cancelled, taken over or deleted,
        B3): its child is ended at once; the row's one end path runs as for any child exit. A row
        fenced before its child exists is never launched (`_run_claimed`)."""
        if held.fenced or (held.proc is not None and held.proc.returncode is not None):
            return  # already fenced, or its child already exited: the row is writing its own end
        held.fenced = True
        _logger.warning("%s %s: it was cancelled, taken over, moved or deleted; ending its child", held.kind, inv)
        held.enders.append(asyncio.create_task(self._end_child(held)))

    async def _takeover_loop(self) -> None:
        """Every `takeover_interval`, take over every lapsed row this worker does not hold (B7),
        unless this worker's own store calls hit an outage within the last lease. A pass that
        raises is logged; the next tick tries again. Serving only, until a stop begins."""
        while True:
            if self._store_settled():
                try:
                    async with asyncio.timeout(self._store_call_limit):  # not `wait_for`: on 3.11 it can lose a cancel
                        await self._store.take_over(held=frozenset(self._leased()))
                except Exception as fault:  # noqa: BLE001 — one failed pass never ends the task
                    self._note_store_fault(fault)
                    _logger.exception("the worker's take-over pass failed; retrying")
            await asyncio.sleep(self._takeover_interval)

    def _store_settled(self) -> bool:
        return self._store_outage_at is None or time.monotonic() - self._store_outage_at >= self._lease

    async def _progress_loop(self, held: Held) -> None:
        """Every `cost_interval`, read the claim's last staged `progress` (#1546: a row its helper typed, never a file or
        a session database) into `held.cost_so_far` (an investigation) or `held.progress` (a learning job), bounded by
        `store_call_limit`, so a read that hangs delays nothing else (r5 item 4). The renewal copies it to the row (B2,
        O13). A read that fails, or a body not of its shape, keeps the last good figure."""
        while True:
            await asyncio.sleep(self._cost_interval)
            try:
                async with asyncio.timeout(self._store_call_limit):  # not `wait_for`: on 3.11 it can lose a cancel
                    facts, _uploads = await self._store.staged(held.token)
            except Exception as fault:  # noqa: BLE001 — keep the last good figure
                self._note_store_fault(fault)
                _logger.debug("%s: its staged progress could not be read", _what(held), exc_info=True)
                continue
            body = facts.get(_PROGRESS)
            if held.kind == LEARNING:
                held.progress = _staged_progress(body) or held.progress
            elif isinstance(body, Mapping) and _is_cost(body.get("cost_usd")):
                held.cost_so_far = float(body["cost_usd"])

    async def _redecided(self, held: Held) -> ending.Decision | None:
        """After a fault of the worker's once the child was launched (#1625): the fault is no verdict on the job, so the
        end is the one its staged rows decide, when its child has exited and they can be read; else None, and a kind
        that can be handed back is, for its take-over to decide from the same rows."""
        proc = held.proc
        if proc is None or proc.returncode is None:
            return None
        try:
            return await self._decided(held, proc.returncode)
        except Exception:  # noqa: BLE001 — the hand-back (or a host request's worker_error) follows
            _logger.exception("%s: its staged rows could not be read after the fault", _what(held))
            return None

    async def _decided(self, held: Held, returncode: int) -> ending.Decision:
        """The row's ending once its child is gone (#1546 PR9): decided from what the claim's helper staged and uploaded,
        and what ended the child. Nothing the job wrote is read (A-O2)."""
        facts, uploads = await self._store.staged(held.token)
        return ending.decide(facts, uploads, _ended_by(held, returncode), kind=_DECIDES[held.kind])

    # -- one row ----------------------------------------------------------------------------------

    async def _run_row(self, claim: Claim, held: Held) -> None:
        record = claim.record
        inv, tenant = record.investigation_id, record.tenant_id
        with _log.log_context(run_id=inv, tenant_id=tenant):
            try:
                decision = await self._decide(held, claim.tenant_state)
                await self._write_end(held, decision)
            except Exception:  # noqa: BLE001 — one row's fault never ends the worker
                _logger.exception("investigation %s: the worker failed while ending it", inv)
            finally:
                self._held.pop(inv, None)
                self._end_failing.discard(inv)

    async def _decide(self, held: Held, tenant_state: str) -> ending.Decision:
        """Run one claimed row and decide its last write; the caller makes it (`_write_end`)."""
        inv = held.record.investigation_id
        try:
            return await self._run_claimed(held, tenant_state)
        except Exception as fault:  # noqa: BLE001 — one row's fault never ends the worker
            _logger.exception("investigation %s: the worker failed while running it", inv)
            if is_outage(fault) or held.signalled:
                # Nothing about the job failed: it is handed back, with what it had spent. Nothing launched: exactly 0. A
                # child that ran with no figure read yet is handed back with an unknown cost (null); its take-over
                # decides it from its staged rows (D8, D15).
                return ending.HandBack(ending.INVESTIGATION, cost_usd=(
                    0.0 if held.proc is None and held.cost_so_far is None else held.cost_so_far))
            if held.proc is not None:
                return await self._redecided(held) or ending.HandBack(ending.INVESTIGATION, cost_usd=held.cost_so_far)
            return _not_launched(INVESTIGATION, "the worker failed while running the job")

    async def _run_claimed(self, held: Held, tenant_state: str) -> ending.Decision:
        record = held.record
        inv, tenant = record.investigation_id, record.tenant_id
        if self._stopping:  # claimed as the stop landed: handed back with nothing launched or spent
            return ending.HandBack(ending.INVESTIGATION, cost_usd=0.0)
        started = self._clock()
        try:
            digest = await self._admit(record, tenant_state)
        except _WorkerFault as fault:
            _logger.error("investigation %s: %s", inv, fault)
            return _not_launched(INVESTIGATION, str(fault))
        if self._stopping:  # claimed but not started when the stop landed: handed back, nothing spent
            return ending.HandBack(ending.INVESTIGATION, cost_usd=0.0)
        if held.fenced:  # B3: ended before its child exists; the write that follows is fenced
            _logger.info("investigation %s: it was fenced before its child started; not launched", inv)
            return _not_launched(INVESTIGATION, "the job was ended before it started")
        flagged = record.update_ticket
        launch = Launch(inv, tenant, os.getpid(), alert_digest=digest, update_ticket=flagged,
                        ticket_link=screen_link(self._frontend_origin, tenant, inv) if flagged else None)

        async def name_left() -> None:
            await self._name_left(inv)

        proc = await self._run_child(held, lambda: self._child_argv(launch), watch=self._progress_loop,
                                     after_sweep=name_left)
        if proc is None:
            return _not_launched(INVESTIGATION, "the worker could not start the job's child process")
        returncode = await proc.wait()
        _logger.info("investigation %s: child %d %s after %s", inv, proc.pid,
                     _exit_words(returncode), self._clock() - started)
        return await self._decided(held, returncode)

    async def _run_child(
        self, held: Held, argv: Callable[[], list[str]], *,
        watch: Callable[[Held], Coroutine[Any, Any, None]] | None = None,
        after_sweep: Callable[[], Awaitable[None]] | None = None,
        abandon_on_stop: bool = False,
    ) -> asyncio.subprocess.Process | None:
        """Start the entry's child and wait for it to end, then run its cleanup; None when the
        child could not be started. `watch` runs beside the child (the cost or progress reads).
        The task owns its child: cancelled, it ends the child and writes nothing.

        Every child, of every kind, is handed its claim's token (`box.CLAIM_ENV`), the store's (#1546 PR7): each box
        started anywhere in its process tree carries it, and once the child is gone every container
        carrying it is removed (`_sweep`), so nothing a killed or crashed child started is left
        behind. `after_sweep` is a kind's own step after it (an investigation's check of its box's
        name). With `abandon_on_stop` (a host request, which a stop ends rather than hands back: #1471 R13-5), a stop
        that lands while the child is still being started does not wait for the start: None is returned, and a child
        the start makes later has its group killed (`_end_late_child`)."""
        what = _what(held)
        proc: asyncio.subprocess.Process | None = None
        watch_task: asyncio.Task[None] | None = None
        claim = held.token
        assert claim is not None  # every held entry carries its claim's token (#1546 PR7)
        # The start runs as its own task, so a cancel cannot land inside it and lose the child
        # it makes (r7 D-ac): a cancelled row waits for it, and the child is ended below.
        spawn = asyncio.ensure_future(self._spawn(argv, claim))
        try:
            try:
                proc = await self._spawned(spawn, abandon_on_stop=abandon_on_stop)
            except _SpawnAbandoned:
                _logger.warning("%s: the worker stopped while its child was being started; not waiting for it", what)
                return None
            except asyncio.CancelledError:
                proc = await _spawn_outcome(spawn)
                held.proc = proc
                _logger.warning("%s: the worker is leaving; ending its child", what)
                await self._end_child(held)
                raise
            except (OSError, ValueError) as unstarted:
                _logger.error("%s: the child could not be started: %s", what, unstarted)
                return None
            held.proc = proc
            if watch is not None:
                watch_task = asyncio.create_task(watch(held))
            await self._wait_for_child(held, proc)
        finally:
            if watch_task is not None:
                await _end_tasks([watch_task])
            if proc is not None:
                # One cleanup however the row ended (r7 D-ac): whatever the child left running in
                # its session is killed and waited for, then its box, if it outlived it, is
                # removed. The sweep runs however the wait ends, a cancel included; a group an
                # earlier wait already gave up on is killed again but not waited for twice.
                try:
                    if held.group_left:
                        kill_group(proc.pid)
                    elif not await self._end_group(proc.pid):
                        held.group_left = True
                finally:
                    await self._sweep(what, claim)
                    if after_sweep is not None:
                        await after_sweep()
                    # Last, the claim's folders, whatever the child's helper left, once that helper is gone (#1557 O5).
                    await asyncio.to_thread(_remove_claim_folders, data_root_for_child(self._data_root), claim)
        return proc

    async def _spawned(self, spawn: asyncio.Future[asyncio.subprocess.Process], *,
                       abandon_on_stop: bool) -> asyncio.subprocess.Process:
        """The spawn's child, waited for without cancelling the spawn; with `abandon_on_stop`, `_SpawnAbandoned` once
        the stop lands first (the late child is ended when it comes, `_end_late_child`)."""
        if not abandon_on_stop:
            return await asyncio.shield(spawn)
        stopping = asyncio.ensure_future(self._stop_signal.wait())
        waits: set[asyncio.Future[Any]] = {spawn, stopping}
        try:
            await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
        finally:
            stopping.cancel()
        if not spawn.done():
            spawn.add_done_callback(_end_late_child)
            raise _SpawnAbandoned
        return spawn.result()

    async def _sweep(self, what: str, claim: str) -> None:
        """Remove every container the child's process tree started (its claim's label). Never an
        error, never the row's business: what it cannot remove is logged, and the tenant's
        teardown removes it by the tenant's label."""
        try:
            await asyncio.to_thread(self._containers.remove_claimed, claim)
        except Exception:  # noqa: BLE001 — the sweep is best effort
            _logger.exception("%s: the containers its child started could not all be removed", what)

    async def _wait_for_child(self, held: Held, proc: asyncio.subprocess.Process) -> None:
        try:
            if self._stopping or held.fenced:  # spawned as the stop or a fence landed
                await self._end_child(held, by_stop=self._stopping)
            await proc.wait()
        except asyncio.CancelledError:
            # The task owns its child: cancelled (the loop itself was cancelled), it ends the
            # child, and writes nothing.
            _logger.warning("%s: the worker is leaving; ending child %d", _what(held), proc.pid)
            await self._end_child(held)
            raise

    async def _spawn(self, argv: Callable[[], list[str]], claim: str) -> asyncio.subprocess.Process:
        """The entry's child, in a session of its own (its group id is its pid), output inherited,
        in `child_cwd` when one is set, its boxes stamped with `claim` (`box.CLAIM_ENV`)."""
        where = {} if self._child_cwd is None else {"cwd": str(self._child_cwd)}
        return await self._create_process(
            *argv(),
            stdin=subprocess.DEVNULL, stdout=None, stderr=None, start_new_session=True,
            env={**os.environ, "DEFENDER_DATA_ROOT": str(data_root_for_child(self._data_root)), CLAIM_ENV: claim},
            **where)

    async def _admit(self, record: Any, tenant_state: str) -> str:
        """Before an investigation's child starts: its tenant's state at the claim was `active` (r7 R7-1; a teardown
        always wins, and a job racing it fails), its alert is in the store, and the tenant's runs container can be used
        (`_preopen_lane`). Answers the alert's digest, which the helper is handed at its start (#1471 P-5). Nothing is
        written beside the run: the claim row carries the launch facts, and the helper writes the job's copies (#1546)."""
        if tenant_state != "active":
            raise _WorkerFault(f"the tenant is {tenant_state}, not active; the job was not started")
        alert = await self._store.get_alert(record.tenant_id, record.alert_id)
        if alert is None:
            raise _WorkerFault("the job's alert is not in the store")
        await asyncio.to_thread(self._preopen_lane, record.tenant_id, f"investigation {record.investigation_id}")
        return digest_of(alert.raw)

    def _usable_lane(self, tenant: str, what: str) -> job_lane.JobLane:
        """The tenant's job lane, opened before a child starts; a refusal is `_WorkerFault` in the one sentence an
        investigation and a host request share (`_RUNS_UNUSABLE`, #1471 R13-1.1), its detail logged for `what`."""
        try:
            return self._open_lane(self._data_root, tenant)
        except job_lane.JobLaneRefused as refused:
            _logger.error("%s: %s", what, refused)
            raise _WorkerFault(_RUNS_UNUSABLE) from None

    def _preopen_lane(self, tenant: str, what: str) -> None:
        """The tenant's job lane opened and closed before the helper starts (R13-1.1): `_WorkerFault` when it cannot be
        used, so no helper ever runs over a runs container that cannot be used. The worker never makes the runs folder,
        and reads nothing in it."""
        self._usable_lane(tenant, what).close()

    async def _name_left(self, inv: str) -> None:
        """After the sweep removed every container the child's tree started, a container still
        under the run box's name is not this job's: left in place and logged (r5 C1). Never an
        error, never the row's business."""
        name = container_name(inv)
        try:
            present = await asyncio.to_thread(self._containers.present, name)
        except Exception:  # noqa: BLE001 — best effort
            _logger.exception("investigation %s: could not ask whether %s is still there", inv, name)
            return
        if present:
            _logger.warning("investigation %s: a container named %s is not this job's (the sweep of what its "
                            "child started left it); left in place", inv, name)

    # -- one host request (#1471, #1546 D7) ----------------------------------------------------------

    async def _run_host_request(self, claim: HostRequestClaim, held: Held) -> None:
        """One claimed host request: its helper as the child, then the row's one end write. Its tenant's state is not
        judged here: the helper's own admission refuses a tenant that is not active."""
        record = claim.record
        with _log.log_context(tenant_id=record.tenant_id):
            try:
                await self._write_end(held, await self._decide_host_request(held))
            except Exception:  # noqa: BLE001 — one row's fault never ends the worker
                _logger.exception("%s: the worker failed while ending it", _what(held))
            finally:
                self._held.pop(record.request_id, None)
                self._end_failing.discard(record.request_id)

    async def _decide_host_request(self, held: Held) -> ending.Decision:
        """Run one claimed host request and decide its end; a fault of the worker's is `worker_error`, or, during a
        stop, `worker_stopped` (a host request is never handed back, B2)."""
        try:
            return await self._run_host(held)
        except Exception:  # noqa: BLE001 — one row's fault never ends the worker
            _logger.exception("%s: the worker failed while running it", _what(held))
            if self._stopping or held.signalled:
                return _host_stopped()
            # A host request is never handed back (B2): when its staged rows cannot decide it, `worker_error` stands.
            decided = await self._redecided(held) if held.proc is not None else None
            return decided or _not_launched(HOST_REQUEST, "the worker failed while running the request")

    async def _run_host(self, held: Held) -> ending.Decision:
        record = held.record
        if self._stopping:  # claimed as the stop landed: ended, nothing started (R13-5)
            return _host_stopped()
        try:
            await asyncio.to_thread(self._preopen_lane, record.tenant_id, f"{record.kind} {record.request_id}")
        except _WorkerFault as fault:
            _logger.error("%s: %s; no helper started", _what(held), fault)
            return _not_launched(HOST_REQUEST, str(fault))
        if self._stopping:
            return _host_stopped()
        if held.fenced:  # ended (an offboard) before its child exists: never launched; the finish below is fenced
            return _not_launched(HOST_REQUEST, "the request was ended before it started")
        proc = await self._run_child(held, self._host_argv(record), abandon_on_stop=True)
        if proc is None:
            if self._stopping:
                return _host_stopped()
            return _not_launched(HOST_REQUEST, "the worker could not start the request's child process")
        returncode = await proc.wait()
        _logger.info("%s: child %d %s", _what(held), proc.pid, _exit_words(returncode))
        # The staged `result` decides, whatever the exit status and a stop (R13-1.5, R13-5).
        return await self._decided(held, returncode)

    def _host_argv(self, record: Any) -> Callable[[], list[str]]:
        """The request's child command, by its kind (surface §4)."""
        if record.kind == _READINESS:
            readiness = ReadinessLaunch(record.request_id, record.tenant_id, os.getpid())
            return lambda: self._readiness_argv(readiness)
        if record.kind == _ADOPTION and record.system_id is not None:
            adoption = AdoptionLaunch(record.request_id, record.tenant_id, os.getpid(), record.system_id)
            return lambda: self._adoption_argv(adoption)
        if record.kind == _DRAIN:
            drain = DrainLaunch(record.request_id, record.tenant_id, os.getpid())
            return lambda: self._drain_argv(drain)
        raise ValueError(f"not a host request this worker runs: {record.kind!r}")

    # -- one learning job (#1344) -----------------------------------------------------------------

    async def _run_learning(self, claim: LearningClaim, held: Held) -> None:
        """One claimed job: its family step as the job entry's child, the row's one end write, then,
        after a job whose child started and that ended (not handed back), the post-step, in this
        same task and so the same slot (O8). A stopping worker starts no post-step."""
        record = claim.record
        job, tenant = record.learning_job_id, record.tenant_id
        with _log.log_context(tenant_id=tenant):
            decision: ending.Decision | None = None
            started = False
            try:
                decision, started = await self._decide_learning(held, claim.tenant_state)
                await self._write_end(held, decision)
            except Exception:  # noqa: BLE001 — one row's fault never ends the worker
                _logger.exception("learning job %s: the worker failed while ending it", job)
            finally:
                self._held.pop(job, None)
                self._end_failing.discard(job)
            if started and not self._stopping and isinstance(decision, ending.End):
                try:
                    await self._post_step(tenant, job)
                except Exception:  # noqa: BLE001 — a post-step's fault leaves the job's row as it is
                    _logger.exception("learning job %s: its post-step failed", job)

    async def _decide_learning(self, held: Held, tenant_state: str) -> tuple[ending.Decision, bool]:
        """Run one claimed job's family step and decide its last write; also whether its child
        started."""
        try:
            return await self._run_family(held, tenant_state)
        except Exception as fault:  # noqa: BLE001 — one row's fault never ends the worker
            _logger.exception("learning job %s: the worker failed while running it", _key(held))
            started = held.proc is not None
            if is_outage(fault) or held.signalled:  # a stop can never permanently fail or skip a job: handed back
                return ending.HandBack(ending.LEARNING, **_progress_kw(held.progress)), started
            if started:
                return (await self._redecided(held) or ending.HandBack(ending.LEARNING, **_progress_kw(held.progress)),
                        started)
            return _not_launched(LEARNING, "the worker failed while running the job"), started

    async def _run_family(self, held: Held, tenant_state: str) -> tuple[ending.Decision, bool]:
        record = held.record
        job, tenant = record.learning_job_id, record.tenant_id
        if self._stopping:  # claimed as the stop landed: handed back with nothing started
            return ending.HandBack(ending.LEARNING, sibling_cost_usd=None), False
        if tenant_state != "active":
            return _not_launched(LEARNING, f"the tenant is {tenant_state}, not active; the job was not started"), False
        if held.fenced:
            return _not_launched(LEARNING, "the job was ended before it started"), False
        learning_argv = self._learning_argv
        assert learning_argv is not None  # a worker with learning slots has it (constructor)
        launch = LearningLaunch(job, tenant, os.getpid(), record.investigation_id)
        started = self._clock()
        proc = await self._run_child(held, lambda: learning_argv(launch), watch=self._progress_loop)
        if proc is None:
            return _not_launched(LEARNING, "the worker could not start the job's child process"), False
        returncode = await proc.wait()
        _logger.info("learning job %s: child %d %s after %s", job, proc.pid, _exit_words(returncode),
                     self._clock() - started)
        # The staged outcome decides (its findings screened by the helper on receipt, D11); a stop that landed after it
        # does not override it, and an outcome that says the job stopped hands it back (#1344 r5).
        return await self._decided(held, returncode), True

    async def _claim_check(self) -> tuple[str, str] | None:
        """A tenant due a family-less check, held for it, and the hold's token (#1344 amendments 1,
        3; minted by the store with the post-step's claim row, #1546 PR7), or None: the store picks the most overdue one
        no post-step holds. A claim that fails is logged and the next is tried an interval later: it never stops a job's
        claim."""
        if time.monotonic() < self._checks_resume_at:
            return None
        try:
            held = await self._store.claim_learning_check(self._learning_check_interval)
        except Exception as fault:  # noqa: BLE001 — a failed claim delays the checks, never the jobs
            self._note_store_fault(fault)
            _logger.warning("the worker could not claim a tenant's learning check; retrying in %gs",
                            self._learning_check_interval, exc_info=True)
            self._checks_resume_at = time.monotonic() + self._learning_check_interval
            return None
        return None if held is None else (str(held.tenant_id), held.token)

    async def _check_tenant(self, tenant: str, holder: str) -> None:
        """One family-less post-step for `tenant` under the hold `holder` (#1344 amendment 1),
        as a learning-class task: none once the worker is stopping, and a fault never ends the
        worker. The hold is let go however it ends."""
        with _log.log_context(tenant_id=tenant):
            try:
                if self._stopping:
                    await self._end_check(tenant, holder, idle=False)
                    return
                _logger.info("tenant %s: its last post-step left work waiting %gs ago; checking its learning "
                             "without a family", tenant, self._learning_check_interval)
                await self._post_step(tenant, None, holder=holder)
            except Exception:  # noqa: BLE001 — a failed check changes no job's row; the next one retries
                _logger.exception("tenant %s: its family-less post-step failed", tenant)

    async def _post_step(self, tenant: str, job: str | None, *, holder: str | None = None) -> None:
        """The post-step after `job` (O8, O14), or, with `job` None, a family-less one under the
        hold `holder` (amendment 1): a child in the one supervision registry, handed nothing but its claim, whose token
        is the hold's (#1546 PR7: the store mints it with the post-step's claim row, whose inputs are empty). A
        job's post-step first holds the tenant's check clock; when another post-step holds it, this
        one does not start and the tenant is checked at the next claim instead (amendment 3).
        Either kind restarts the tenant's check clock when it ends, idle only when its helper exited
        saying that no work waits (#1487 O7, Flow 3, Amendment r5.2: the helper asks the learning
        store once the container exited); a post-step that cannot start, a stop, or any other exit
        leaves it not idle, a post-step ended for running past `post_step_limit` included."""
        post_step = self._post_step_argv
        assert post_step is not None  # a worker with learning slots has it (constructor)
        if holder is None:
            holder = await self._store.hold_learning_check(tenant)
            if holder is None:
                _logger.info("learning job %s: no post-step started: another post-step of its tenant is running "
                             "(the tenant is checked again once it ends), or the tenant is being removed (nothing "
                             "new starts for it)", job)
                return
        held = Held(_PostStepOf(tenant, job), kind=POST_STEP, token=holder, check_holder=holder)
        key = f"{POST_STEP}:{job if job is not None else 'tenant:' + tenant}"
        idle = False
        try:
            self._held[key] = held
            launch = PostStepLaunch(job, tenant, os.getpid())
            proc = await self._run_child(held, lambda: post_step(launch), watch=self._post_step_deadline)
            if proc is None:
                return
            stopped = held.signalled or held.overran or self._stopping
            waiting = None if stopped else _post_step_answer(proc.returncode)
            idle = waiting is False
            announce("learning_post_step", actor=SYSTEM, tenant_id=tenant,
                     target=job if job is not None else tenant,
                     detail={True: "work still waits", False: "nothing waits", None: "whether work waits is unknown"}[
                         waiting])
        finally:
            self._held.pop(key, None)
            await self._end_check(tenant, holder, idle=idle)

    async def _post_step_deadline(self, held: Held) -> None:
        """Beside a post-step's child: once it has run `post_step_limit`, end it as a stop would (#1487 Amendment r5.4),
        logged. Its answer is then unknown, so its tenant's clock stays not idle."""
        await asyncio.sleep(self._post_step_limit)
        held.overran = True
        _logger.error("%s: the post-step ran past its limit of %gs; ending it", _what(held), self._post_step_limit)
        await self._end_child(held)

    async def _end_check(self, tenant: str, holder: str, *, idle: bool) -> None:
        """Let go of the hold `holder` on the tenant's check clock, restarting it (amendment 3). A
        failure is logged: the hold then lapses with its lease and the clock keeps its last time."""
        try:
            if not await self._store.end_learning_check(tenant, holder, idle=idle):
                _logger.warning("tenant %s: its check clock was no longer held by this post-step", tenant)
        except Exception as fault:  # noqa: BLE001 — the hold lapses on its own
            self._note_store_fault(fault)
            _logger.warning("tenant %s: its check clock could not be let go; it lapses with its lease", tenant,
                            exc_info=True)

    # -- the last write ---------------------------------------------------------------------------

    async def _write_end(self, held: Held, decision: ending.Decision) -> None:
        """The row's one end write (B4): `decision` applied by the store's one applier (#1546 PR9), made until it lands
        or there is nothing left to write. A failure that is an outage is retried each second while claims wait (B5). A
        decision the store refuses is never dropped, since a dropped one would lapse into a take-over that re-runs the
        job: it is applied again weakened (`ending.lesser`), down to the barest end. Any other failure decides nothing
        about the job: it is logged and the row left to lapse, as it is when even the barest end is refused. During a
        deliberate stop an outage gets one try: the stop gives up on it (B11). A learning job's findings the store could
        not store for a reason neither their content nor an outage explains (`FindingsNotStored`, #1487 Amendment
        r5.3) are retried the same way, logged once as an error, without pausing claims: only the job's slot waits."""
        what = _what(held)
        attempt = decision
        while not await self._applied(held, attempt):
            weaker = ending.lesser(attempt)
            if weaker == attempt:
                _logger.error("%s: the store refused even its barest end; it is dropped, and its "
                              "lease will lapse and it will be taken over", what)
                return
            _logger.error("%s: the store refused its end; writing it with less: %s", what, _what_end(weaker))
            attempt = weaker

    async def _applied(self, held: Held, attempt: ending.Decision) -> bool:
        """`attempt` applied, tried again while `_end_retries` says so: True once it landed or the write is given up,
        False when the store refused it (the caller weakens it)."""
        what, key = _what(held), _key(held)
        told: set[str] = set()
        while True:
            tried_stopping = self._stopping
            try:
                await self._apply_once(held, attempt)
                return True
            except Exception as fault:  # noqa: BLE001 — classified below
                if is_refusal(fault):
                    _logger.error("%s: the store refused its end (%s)", what, _what_end(attempt), exc_info=True)
                    return False
                if not self._end_retries(what, key, fault, stopping=tried_stopping, told=told):
                    return True
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop_signal.wait(), timeout=END_RETRY_DELAY)

    async def _apply_once(self, held: Held, attempt: ending.Decision) -> None:
        """One try: the decision on the row if it is still this worker's (the applier's fence); a row that moved (a
        cancel, an offboard, a take-over ended it, or it is gone) keeps its own ending and its staged cost (D15), and
        nothing is written."""
        written = await self._store.apply(held.record.tenant_id, _key(held), attempt)
        if written is None:
            _logger.info("%s: the row is no longer this worker's; nothing written", _what(held))
            return
        found = getattr(written, "publish_state", None)
        _logger.info("%s: %s%s", _what(held), _what_end(attempt),
                     f", findings {found}" if held.kind == LEARNING and found is not None else "")

    def _end_retries(self, what: str, key: str, fault: Exception, *, stopping: bool, told: set[str]) -> bool:
        """Whether a failed end write that the store did not refuse is tried again, logged: an outage pauses claims while
        it lasts (B5); findings not stored for a reason neither their content nor an outage explains
        (`FindingsNotStored`) are logged once as an error and pause nothing but the job's slot. During a deliberate
        stop neither is tried again (B11). Anything else is dropped: the row lapses into a take-over."""
        unstored = isinstance(fault, FindingsNotStored)
        if not (unstored or is_outage(fault)):
            _logger.exception("%s: its end could not be recorded and is dropped; its "
                              "lease will lapse and it will be taken over", what)
            return False
        if unstored:
            if "unstored" not in told:
                _logger.error("%s: its findings could not be stored (%s), which neither their content nor an outage "
                              "explains; its end is retried until it is stored", what, fault,
                              exc_info=fault.__cause__ or fault)
                told.add("unstored")
            if stopping:
                _logger.warning("%s: its findings could not be stored while stopping; its lease will lapse and the "
                                "job will be run again", what)
                return False
            return True
        self._note_store_fault(fault)
        if stopping:
            _logger.warning("%s: its end could not be recorded while stopping; "
                            "its lease will lapse on its own", what, exc_info=True)
            return False
        self._end_failing.add(key)
        _logger.warning("%s: its end could not be recorded (%s); retrying", what, fault)
        return True


def _what_end(decision: ending.Decision) -> str:
    if isinstance(decision, ending.HandBack):
        return "a hand-back"
    what = decision.stage + (f" ({decision.failure_reason})" if decision.failure_reason else "")
    if decision.kind == ending.HOST_REQUEST:
        return what
    if decision.kind == ending.LEARNING:
        return what + (", findings refused" if decision.stage == "completed" and decision.findings is None else "")
    return (f"{what}, cost {decision.cost_usd}, knowledge {'kept' if decision.knowledge is not None else 'none'}, "
            f"evidence {decision.evidence_state}")


def _key(held: Held) -> str:
    """The registry key of a held row."""
    record = held.record
    if held.kind == HOST_REQUEST:
        return str(record.request_id)
    return str(record.learning_job_id if held.kind != INVESTIGATION else record.investigation_id)


def _what(held: Held) -> str:
    """How the log names a held entry."""
    if held.kind == POST_STEP and held.record.learning_job_id is None:
        return f"the family-less post-step of tenant {held.record.tenant_id}"
    if held.kind == HOST_REQUEST:
        return f"{held.record.kind} {held.record.request_id}"
    names = {INVESTIGATION: "investigation", LEARNING: "learning job", POST_STEP: "the post-step after learning job"}
    return f"{names[held.kind]} {_key(held)}"


async def _end_tasks(tasks: list[asyncio.Task[None]]) -> None:
    """Cancel service tasks and wait for them to finish."""
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
