"""A learning job's family step (#1344), inside its job container (#1170): started by the per-job host
helper as `python -m defender.cli.learning.job --job <id> --tenant <T> --source <investigation id>`, which hands in the
role-model preflight learning may not import.

The helper took the tenant's host lock (waiting at most 30 s, else it wrote the `stopped` hand-back itself), admitted the
tenant and signed the first pass before the container started (A3, P-C), so the entry takes no lock and runs no
admission: it asks the job socket for its `launch` facts (`container.JobContainer`), opens the tenant's runs container
(the job lane's door), installs its own SIGTERM handler, and runs the launcher's job lane (`cli.launch_job`): the fork
pick (O3), the questioner, pre-flight, the siblings one at a time with the control first (O4), verification and the
judge's job-lane pass. Its passes and boxes are the helper's, asked over the socket. With no job socket (a host shell)
it does nothing and exits non-zero (A6: there is no host mode).

It writes no record to a folder (#1546 PR2): first it pulls its source's bundle, the one input of its claim, and unpacks
it into its root (`<T>/runs/<source>/`, A-O1); it sends the `progress` record (fork, stage, sibling cost) as each
changes, the `arms` roster before the first sibling starts and each arm's `arm/<run id>` fact (scrub, page) once its
sibling has exited (D12; an arm that never ran is sent `not_run` at the end), its page's bytes when it rendered; then
the one `outcome` at every exit, with the outcome table's status and reason (a `completed` one carries the findings the
judge's pass left in the episode, #1487 Flow 1 step 1), and only after it the episode page and the job's bundle (PR8):
its tenant folder in the root, without the pulled source. The entry opens no store.

**The ending.** A reason is never read from message text: every ending the outcome table gives
the entry is raised typed where it is decided (`endings.JobEnding`), and anything else is
`failed: entry_error`, its message naming only the exception's type. Messages are our own words
and carry no run text, path or secret.

**Stopping.** The first SIGTERM raises `JobStopped` where the entry is (every later one is
ignored), so the launcher unwinds and terminates the sibling it runs; the job records `stopped`,
a hand-back. The end of the entry's stdin (the helper's end of the container, A5) is that SIGTERM. Two endings are
decided before that and stand whatever signal arrives: a job with no fork point (`skipped: no_fork_point`), and a
judge pass that returned (`completed`).
"""
from __future__ import annotations

import argparse
import logging
import math
import signal
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from defender import job_socket, tenancy
from defender.investigation import branch
from defender.learning.branch import cli
from defender.learning.branch.container import JobContainer, NotInContainer, sigterm_on_stdin_eof
from defender.learning.branch.endings import (
    ENTRY_ERROR,
    HISTORY_UNREADABLE,
    LAUNCH_REFUSED,
    NO_FORK_POINT,
    SOURCE_UNAVAILABLE,
    JobEnding,
    JobLaneHooks,
    ending,
)
from defender.learning.branch.fork_pick import fork_candidates, pick_fork
from defender.records import EpisodeRuns, Run, RunRefused, session_store
from defender.records.formats import TenantRefused
from defender.records.job_facts import EPISODE_PAGE, arm_page
from defender.records.job_lane import (
    LEARNING_COMPLETED,
    LEARNING_FAILED,
    LEARNING_SKIPPED,
    LEARNING_STOPPED,
    CostUnreadable,
    LearningEnd,
    sibling_cost,
    unreadable_findings,
)

_logger = logging.getLogger(__name__)

__all__ = ["JobStopped", "main"]

class JobStopped(BaseException):
    """The entry's first SIGTERM, raised where the entry was. A `BaseException`, so no broad
    `except Exception` on the way out swallows the stop."""


def parse_learning_job_args(argv: list[str]) -> argparse.Namespace:
    """`--job <id> --tenant <T> --source <investigation id>`; a `--parent-pid` (the host entry's, retired) is
    accepted and not read: inside the container the death tie is the stdin's end (A5)."""
    p = argparse.ArgumentParser(prog="python -m defender.cli.learning.job",
                                description="A learning job's family step, run in its job container.")
    p.add_argument("--job", required=True, help="the learning job's id; the episode's id too")
    p.add_argument("--tenant", required=True, help="the job's tenant")
    p.add_argument("--source", required=True, help="the finished investigation to fork, by its id")
    p.add_argument("--parent-pid", default=None, type=int, help=argparse.SUPPRESS)
    return p.parse_args(argv)


class _Job:
    """One job's records and its ending: what the hooks learn, the SIGTERM handler, and the end
    record written once, whatever ends the entry."""

    def __init__(self, ask: Callable[..., dict[str, Any]], job_id: str) -> None:
        self.ask, self.job_id = ask, job_id
        #: The arm roster once written (`{world id: arm id}`), the arms whose fact was sent, and the episode's view.
        self.roster: dict[str, Any] = {}
        self.arms_sent: set[str] = set()
        self.view: EpisodeRuns | None = None
        self.fork: str | None = None
        self.stage: str | None = None
        self.cost = 0.0
        #: An ending decided before the entry ends, which no later signal overrides: the job's
        #: `no_fork_point`, or `completed` once the judge's pass returned.
        self.decided: LearningEnd | None = None
        self.stopped = False

    # -- the SIGTERM handler ---------------------------------------------------------------

    def on_term(self, _signum: int, _frame: Any) -> None:
        """The first SIGTERM stops the job unless its ending is decided; every later one is
        ignored, so the unwind (and the sibling's termination) is not itself interrupted."""
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if self.decided is not None:
            return
        self.stopped = True
        raise JobStopped

    # -- the progress record ---------------------------------------------------------------

    def progress(self) -> None:
        """Send the progress record (#1546: staged by the helper, replaced whole). Progress is advisory (the outcome
        carries the fork, stage and cost again): a helper that refuses it is logged and the job goes on; a socket that
        fails raises, so the entry ends `failed: entry_error` there."""
        cost = self.cost if math.isfinite(self.cost) and self.cost >= 0 else 0.0
        try:
            self.ask("progress", record={"fork_message_id": self.fork, "stage": self.stage, "sibling_cost_usd": cost})
        except job_socket.Refused as refused:
            _logger.warning(f"job {self.job_id}: the helper did not take its progress ({refused})")

    def at_stage(self, name: str) -> None:
        self.stage = str(name)
        self.progress()

    # -- the hooks ---------------------------------------------------------------------------

    def pick(self, source: Run, candidates: Callable[..., Any]) -> int:
        """The fork pick (O3): the source's admitted gather responses, one chosen uniformly and
        recorded before any spend; none is the decided `skipped: no_fork_point`."""
        found = _candidates_of(source, candidates)
        ids = list(found.ids)
        if not ids:
            kinds = _refusal_kinds(found)
            brief = ("the source investigation has no fork point: no response of its main agent "
                     "that called gather is admitted"
                     + (f" (refused: {'; '.join(kinds)})" if kinds else ""))
            self.decided = self._end(LEARNING_SKIPPED, NO_FORK_POINT, brief)
            raise ending(f"[learning job] {brief}", reason=NO_FORK_POINT, brief=brief)
        picked = pick_fork(ids)
        self.fork = str(picked)
        self.progress()
        return picked

    def runs_started(self, arms: Mapping[str, Any]) -> None:
        """The arm roster, sent as the `arms` record before the first sibling starts (#1546 D12)."""
        self.roster = dict(arms)
        self.ask("arms", record={"roster": [{"run_id": str(arm), "world_id": str(world)}
                                            for world, arm in self.roster.items()]})

    def sibling_ended(self, view: EpisodeRuns, world_ids: Sequence[str]) -> None:
        """What the siblings that have run cost so far, carried to the progress record; the arm that just exited sent
        as its `arm` fact (and its page, when it rendered)."""
        self.view = view
        if world_ids:
            self.send_arm(world_ids[-1])
        try:
            cost = _family_cost(view, world_ids)
        except Exception as unreadable:  # noqa: BLE001 — a cost the entry cannot read keeps the last one
            _logger.warning(f"job {self.job_id}: the siblings' cost could not be read ({unreadable!r})")
        else:
            if math.isfinite(cost) and cost >= 0:
                self.cost = cost
            else:
                _logger.warning(f"job {self.job_id}: the siblings' cost read as {cost!r}, which is no cost")
        self.progress()

    def judged(self, graded: Any, held: Callable[[], tuple[dict[str, Any], int]]) -> None:
        """The judge's pass returned: the ending is `completed`, decided here, before anything
        else (from now on a SIGTERM is ignored), its findings `unreadable` until read (#1487 Flow 1
        step 1). `held()` then reads the findings the pass left in the episode as the record's
        findings field and its row count (`enqueue.held_findings`: `ok` with their text, `malformed` or `over_cap`),
        which replaces `unreadable` only once it has returned; a read that fails keeps
        `unreadable`, and the ending stands either way."""
        not_graded = getattr(graded, "not_graded", None)
        word = None if not_graded is None else getattr(not_graded, "outcome", None)
        self.decided = self._end(LEARNING_COMPLETED, None, _judged_message(word, None),
                                 findings=unreadable_findings())
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            found, count = held()
        except Exception as unreadable:  # noqa: BLE001 — the findings are the record's, the ending stands
            _logger.warning(f"job {self.job_id}: the findings could not be read ({type(unreadable).__name__})")
            return
        self.decided = self._end(LEARNING_COMPLETED, None, _judged_message(word, count), findings=found)

    # -- the end record ----------------------------------------------------------------------

    def _end(self, status: str, reason: str | None, message: str | None, *,
             findings: dict[str, Any] | None = None) -> LearningEnd:
        cost = self.cost if math.isfinite(self.cost) and self.cost >= 0 else 0.0
        return LearningEnd(status=status, reason=reason, message=message, fork_message_id=self.fork,
                           stage=self.stage, sibling_cost_usd=cost,
                           findings=findings)

    def ending_for(self, raised: BaseException | None) -> LearningEnd:
        """The end record for an entry that raised `raised` (`None`: it returned)."""
        if self.decided is not None:
            return self.decided
        if self.stopped or isinstance(raised, JobStopped):
            return self._end(LEARNING_STOPPED, None, "the job was stopped before its judge's pass "
                                                     "returned; it is handed back")
        if isinstance(raised, JobEnding):
            return self._end(raised.status, raised.reason, raised.brief)
        if raised is None:
            return self._end(LEARNING_FAILED, ENTRY_ERROR, "the launch returned without a judge's pass")
        return self._end(LEARNING_FAILED, ENTRY_ERROR,
                         f"the family step failed with {type(raised).__name__}")

    # -- the arms' facts ----------------------------------------------------------------------

    def _arm_dir(self, arm: Any) -> Path | None:
        if self.view is None:
            return None
        try:
            return Path(self.view.open(arm).run_dir)
        except (RunRefused, OSError):
            return None

    def send_arm(self, world_id: str) -> None:
        """`arm/<id>` for `world_id`'s arm, once: its tree's scrub (its verdict, else walked here once its sibling has
        exited) and its page, then the page's bytes when it rendered (PR8: the fact first)."""
        arm = self.roster.get(world_id)
        if arm is None or str(arm) in self.arms_sent:
            return
        self.arms_sent.add(str(arm))
        run_dir = self._arm_dir(arm)
        scrub, page = _arm_scrub(run_dir), "none"
        page_file = None if run_dir is None else run_dir / "runtime.html"  # lint-run-records: ok — the arm's own page
        if page_file is not None and page_file.is_file() and scrub == "clean":
            page = "rendered"
        try:
            self.ask("arm", run_id=str(arm), record={"scrub": scrub, "page": page})
            if page == "rendered" and page_file is not None:
                job_socket.push_object(self.ask, arm_page(str(arm)), page_file)
        except (job_socket.Refused, OSError, ValueError) as unsent:
            _logger.error(f"job {self.job_id}: arm {arm}'s fact or page was not sent ({unsent!r})")

    def send_remaining_arms(self) -> None:
        """Every roster arm whose sibling never ran (an unservable world, a stop) sent too: each arm stages a fact."""
        for world_id in self.roster:
            self.send_arm(world_id)

    # -- the outcome ------------------------------------------------------------------------

    def send_end(self, end: LearningEnd) -> bool:
        """The ending, sent once as the `outcome` record (#1546 PR2); False when the helper did not take it."""
        record = {"status": end.status, "reason": end.reason, "message": end.message,
                  "fork_message_id": end.fork_message_id, "stage": end.stage,
                  "sibling_cost_usd": end.sibling_cost_usd, "findings": end.findings}
        try:
            self.ask("outcome", record=record)
        except (job_socket.Refused, OSError, ValueError) as unsent:
            _logger.error(f"job {self.job_id}: the outcome was not taken ({unsent!r})")
            return False
        return True


def _arm_scrub(run_dir: Path | None) -> str:
    """An arm tree's scrub: its verdict when its sibling walked it, else walked here (the sibling has exited, its box
    with it); no tree is `not_run`."""
    from defender import box

    if run_dir is None or not run_dir.is_dir():
        return "not_run"
    verdict = box.verdict_state(run_dir)
    if verdict in ("clean", "tainted", "not_run"):
        return str(verdict)
    try:
        # Judged, not recorded: the walk writes no verdict, so family verification reads only the sibling's own.
        return str(box.scrub(run_dir, write_verdict=lambda _doc: None))
    except box.RunTainted:
        return "tainted"
    except Exception as unwalked:  # noqa: BLE001 — a walk that faults judged nothing
        _logger.warning(f"arm {run_dir.name}: its tree could not be walked ({unwalked!r})")
        return "not_run"


def _refusal_kinds(found: Any) -> list[str]:
    """The kinds of refusal among the dropped candidates (`ForkCandidates.refusal_kinds`), each
    once: fixed names in our own words, never a refusal's text."""
    kinds = getattr(found, "refusal_kinds", None) or ()
    return list(dict.fromkeys(str(kind) for kind in kinds))


def _judged_message(word: str | None, findings: int | None) -> str:
    """The completed job's message: the judge's verdict word when it graded nothing."""
    if word is not None:
        return f"the judge graded nothing: the family is {word}"
    if findings is None:
        return "the judge graded the family"
    return f"the judge graded the family: {findings} finding(s) wait in the episode"


def _candidates_of(source: Run, candidates: Callable[..., Any]) -> Any:
    """`candidates(store, source)` over the source's own session store, opened here.

    A source whose session pointer is absent is a run recorded before #1235 (its link still
    inside the folder: `LegacyRunLink`, `failed: launch_refused`) or one whose store is gone
    (`failed: source_unavailable`), as is a pointer naming a database that is not there. Only a
    typed refusal of the history is `history_unreadable`, its message naming the refusal's type
    (a legacy link or a store of another schema version is `failed: launch_refused` with that
    kind's fixed wording instead, as at the launcher): a store format's (`session_store.StoreError`), or the one read of MAIN's session refusing the
    store (`branch.BranchError`: no single root session; each fork point's own admission refusal
    is the candidates' and never raises). Anything else propagates, and the entry records
    `failed: entry_error`."""
    if source.observability.session_pointer.read_result().absent:
        try:
            session_store.refuse_legacy_link(source.run_dir)
        except session_store.StoreError as unreadable:
            raise _history_unreadable(unreadable) from unreadable
        brief = "the source run carries no session store, so it has no fork point to read"
        raise ending(f"[learning job] {brief}", reason=SOURCE_UNAVAILABLE, brief=brief)
    try:
        database = session_store.resolve_store_path(source)
    except session_store.StoreError as unreadable:
        raise _history_unreadable(unreadable) from unreadable
    if not database.is_file():
        brief = "the source run's session database is gone"
        raise ending(f"[learning job] {brief}", reason=SOURCE_UNAVAILABLE, brief=brief)
    try:
        opened = branch.source_store_if_any(source.run_dir, source_run=source)
        if opened is None:
            brief = "the source run's session pointer is gone"
            raise ending(f"[learning job] {brief}", reason=SOURCE_UNAVAILABLE, brief=brief)
        with opened as store:
            return candidates(store, source)
    except (session_store.StoreError, branch.BranchError) as unreadable:
        raise _history_unreadable(unreadable) from unreadable


def _history_unreadable(refusal: BaseException) -> JobEnding:
    """`skipped: history_unreadable` for a typed format refusal, its message naming the type; a
    legacy link or another schema version is `failed: launch_refused` with the kind's wording."""
    from defender.records import closing

    for kind, refused in (("legacy-link", session_store.LegacyRunLink),
                          ("schema-version", session_store.UnknownSchemaVersion)):
        if isinstance(refusal, refused):
            wording = closing.FAULT_WORDING[kind]
            return ending(f"[learning job] {wording}", reason=LAUNCH_REFUSED, brief=wording, cause=refusal)
    brief = (f"the source run's session history cannot be read by current code "
             f"({type(refusal).__name__})")
    return ending(f"[learning job] {brief}", reason=HISTORY_UNREADABLE, brief=brief, cause=refusal)


def _family_cost(view: EpisodeRuns, world_ids: Sequence[str]) -> float:
    """What the siblings of `world_ids` have cost: each one's own spend ledger in the database they
    share, read under its run id (`records.job_lane.sibling_cost`, #1377 r7.5). A sibling with no
    session pointer, or none naming its own session, spent nothing that can be read yet."""
    ids = view.arm_ids()
    if ids is None:
        raise CostUnreadable("the episode's arm roster is gone")
    arms = [ids[world_id] for world_id in world_ids if world_id in ids]
    total = 0.0
    with view.arms(arms) as handout:
        for arm_id in arms:
            arm = handout[arm_id]
            if isinstance(arm, RunRefused):
                continue
            try:
                session_id = session_store.resolve_session_id(arm)
                database = session_store.resolve_store_path(arm)
            except (FileNotFoundError, session_store.LegacyRunLink):
                continue  # a world that never recorded a session spent nothing
            if session_id is None or not database.is_file():
                continue
            with session_store.open_store_for_read(database) as store:
                total += sibling_cost(store, str(arm.id))
    return total


def main(  # noqa: PLR0913 — the entry's inputs plus the launcher's seams
    argv: list[str], *,
    candidates: Callable[..., Any] = fork_candidates,
    grade: Callable[..., Any] | None = None,
    preflight: Callable[..., int],
    environ: Mapping[str, str] | None = None,
    watch_stdin: bool = False,
    **seams: Any,
) -> int:
    """The learning job's family step in its job container (`environ`: the container's environment, default this
    process's); returns 0 unless the job ended `failed` (1). The worker reads the end record, never this exit. With no
    job socket in `environ` it exits non-zero having done nothing: no record, no lock, no step (A6). `watch_stdin`
    (the process's own entry point): the end of stdin is a SIGTERM (A5), watched once the handler is in place."""
    ns = parse_learning_job_args(argv)
    try:
        ask = JobContainer.client(environ)
    except NotInContainer as outside:
        sys.exit(f"[learning job] job {ns.job}: {outside}; nothing was done")
    try:
        # The container's own root (#1546: the claim's), from the environment the entry was handed.
        data_root = tenancy.data_root_for_child(tenancy.resolve_data_root(environ))
    except TenantRefused as refused:
        sys.exit(f"[learning job] job {ns.job}: its root cannot be used: {refused}")
    on_main = threading.current_thread() is threading.main_thread()
    job = _Job(ask, ns.job)
    pulled: set[str] = set()
    previous = signal.signal(signal.SIGTERM, job.on_term) if on_main else None
    raised: BaseException | None = None
    try:
        if watch_stdin:
            sigterm_on_stdin_eof()
        pulled = _pull_source(ask, data_root, ns)
        _run(job, ns, ask, candidates=candidates, grade=grade, preflight=preflight, environ=environ, **seams)
    except BaseException as caught:  # noqa: BLE001 — every exit is recorded, then decided below
        raised = caught
    finally:
        # No signal interrupts the record: from here a SIGTERM is ignored.
        if on_main:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
    end = job.ending_for(raised)
    if raised is not None and not isinstance(raised, (JobEnding, JobStopped)):
        _logger.error(f"job {ns.job}: the family step raised", exc_info=raised)
    job.send_remaining_arms()
    sent = job.send_end(end)
    _push_episode(ask, data_root, ns, pulled)
    if on_main:
        signal.signal(signal.SIGTERM, previous if previous is not None else signal.SIG_DFL)
    if not sent:
        return 1
    return 1 if end.status == LEARNING_FAILED else 0


def _tenant_files(top: Path) -> set[str]:
    return {p.relative_to(top).as_posix() for p in top.rglob("*") if p.is_file() and not p.is_symlink()} \
        if top.is_dir() else set()


def _pull_source(ask: Callable[..., dict[str, Any]], data_root: Path, ns: argparse.Namespace) -> set[str]:
    """The source's bundle, the one input of the job's claim (#1546 A-O1), pulled through the helper and unpacked into
    the job's root (`<T>/runs/<source>/`, its session store beside it); the files it placed, root-relative. A source the
    helper cannot hand over is `failed: source_unavailable`."""
    from defender.evidence import bundle

    tenant_root = data_root / ns.tenant
    spool = data_root / f".{ns.job}.source"
    before = _tenant_files(tenant_root)
    try:
        job_socket.pull_object(ask, ns.source, "bundle", spool)
        bundle.unpack(spool, tenant_root)
    except (job_socket.Refused, bundle.BundleRefused, OSError, ValueError) as unusable:
        code = getattr(unusable, "code", type(unusable).__name__)
        brief = f"the source run's evidence could not be read ({code})"
        raise ending(f"[learning job] {brief}", reason=SOURCE_UNAVAILABLE, brief=brief, cause=unusable) from unusable
    finally:
        spool.unlink(missing_ok=True)
    return _tenant_files(tenant_root) - before


def _push_episode(ask: Callable[..., dict[str, Any]], data_root: Path, ns: argparse.Namespace,
                  pulled: set[str]) -> None:
    """After the outcome (PR8): the episode page when it rendered, then the job's bundle: its tenant folder in the root
    without the pulled source, the launch record and the helper's copies (those are in the inputs, never the root)."""
    from defender.evidence import bundle

    tenant_root = data_root / ns.tenant
    page = tenant_root / "episodes" / ns.job / "learning.html"  # lint-run-records: ok — the episode's own page
    try:
        if page.is_file():
            job_socket.push_object(ask, EPISODE_PAGE, page)
    except (job_socket.Refused, OSError, ValueError) as unsent:
        _logger.error(f"job {ns.job}: the episode page was not pushed ({unsent!r})")
    packed = data_root / f".{ns.job}.bundle"
    # The pulled source's run folder and listing are left out; the pulled session store is kept: the arms fork into it,
    # and every arm's session database rides in the bundle (D12).
    excludes = sorted({f"runs/{ns.source}", f"runs/{ns.job}.launch.json", "scrub-findings.json",
                       *(rel for rel in pulled if not rel.startswith("sessions/"))})
    try:
        bundle.push(ask, tenant_root, packed, exclude=excludes)
    except (bundle.BundleRefused, job_socket.Refused, OSError, ValueError) as unsent:
        _logger.error(f"job {ns.job}: the job's bundle was not pushed ({unsent!r})")


def _run(job: _Job, ns: argparse.Namespace, ask: Callable[..., dict[str, Any]], *,
         candidates: Callable[..., Any], grade: Callable[..., Any] | None, preflight: Callable[..., int],
         **seams: Any) -> None:
    """The job socket's launch facts, then the launcher's job lane in the container, its hooks reporting to `job`.
    No lock is taken here: the helper holds the tenant's for the whole job."""
    job.at_stage("launch")
    container = JobContainer.connect(ask, tenant=ns.tenant)
    hooks = JobLaneHooks(
        job_id=ns.job, pick=lambda source: job.pick(source, candidates), stage=job.at_stage,
        runs_started=job.runs_started, sibling_ended=job.sibling_ended, judged=job.judged, grade=grade)
    cli.launch_job(tenant=ns.tenant, source_run_id=ns.source, lane=hooks, preflight=preflight,
                   container=container, **seams)
