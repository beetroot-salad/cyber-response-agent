#!/usr/bin/env python3
"""Fork one finished run into a questioner-authored family of worlds, calibrate it, and run it.

The operator names a source run and the message to branch at; this module runs the episode's
steps (`branch/steps.py::Step`) in order:

1. **Launch checks** (not a `Step`). Everything that can refuse before anything is spent: the
   tenant's gather grant serves at least one system, the branch point is in range, the source
   alert is a plain file, the source's stamp can anchor a family, and every role a branch uses
   has a usable model (the oracle's two included, M25).
2. **`Step.QUESTIONER`.** A deny-all role authors the family: a base story and worlds that each
   carry natural-language facts over the tenant's served systems. Its output is validated into
   `Family` and held to one identity gate; a reply that does not validate records `refused`.
3. **`Step.PREFLIGHT`.** Every original call is replayed through each fact world's oracle and
   verifier to calibrate it (`preflight_replay`). The forged rows and recorded facts it verifies
   are frozen as that world's store; no served answer is kept. The write-once outcome record
   (`outcome.yaml`) says `accepted`, `unusable` or `refused` before any sibling starts.
4. **`Step.RUNS`.** On `accepted`, each servable world runs as its own
   `run.py --tenant T --episode <episode_id> --world <label>` process, started together in the
   episode's container (`runs/`, made with the tenant's record just before), each holding an
   equal slice of the episode's query rate. A sibling that exits without its own world record is recorded
   `did not finish`; once two worlds have failed the family is unusable and the siblings still
   running are stopped (N18).
5. **`Step.VERIFY`, then `Step.JUDGE`.** Every sibling's scrub verdict and provenance stamp is
   checked and each verified world archived (a world the archive refuses is recorded
   `not archived`); agreeing stamps on an `accepted` family write the family stamp. The judge
   grades the archive.

Siblings are always `run.py` processes (for the box lifecycle, reap scan, role preflight and
provenance stamp); this module never runs an investigation in-process. A launch never reuses an
episode directory: a relaunch, or a second launch beside a running one, is a new episode (N17).
Each sibling is tied to its launcher, and a launcher that unwinds terminates the one it runs (O9).

**The job lane** (#1344; `--job-id`, or the learning job entry through `launch_job`): the episode's
id is the job's, the fork point is the job's pick, the siblings run one at a time with the control
first and the episode's whole rate each (a failed control ends the family), every ending the
outcome table names is raised typed where it is decided (`endings.JobEnding`), and the judge's
findings wait in the episode instead of reaching the queue, a failed pass failing the job.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import functools
import os
import sqlite3
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

_DEFENDER_DIR = Path(__file__).resolve().parents[2]

#: Renders an episode's page from its runs repository and id; the entry supplies it.
PageRenderer = Callable[["RunsRepository[Tenant]", str], Path]

from defender.records import formats
from defender.records.formats import Episode
from defender.records.formats import pin_text
from defender._io import (
    NotPlainEntry,
)
from defender._paths import PATHS
from defender.knowledge import KnowledgePaths
from defender.records import (
    EpisodeRuns,
    Run,
    RunId,
    RunRefused,
    RunsRepository,
)
from defender.systems.run_tenant import RunTenant
from defender.tenancy import Tenant
from defender.learning.branch import outcome as outcome_mod
from defender.learning.branch import seams
from defender.learning.branch import timing as timing_mod
from defender.learning.branch.steps import Step
from defender.learning.branch.container import JobContainer
from defender.learning.branch.capture import PrimeReport, prime_base
from defender.learning.branch.estate.registry import EstateError
from defender.learning.branch.ledger import Ledger, LedgerError
from defender.learning.branch.endings import (
    CONTROL_FAILED,
    FAMILY_UNUSABLE,
    HISTORY_UNREADABLE,
    JUDGE_FAILED,
    LAUNCH_REFUSED,
    SOURCE_UNAVAILABLE,
    VERIFY_REFUSED,
    JobEnding,
    JobLaneHooks,
    ending,
)
from defender._parent_tie import tied_argv
from defender import tenancy
from defender._git import REPO_ROOT
from defender.investigation import branch
from defender.records import session_store
from defender.records.formats import FamilyError, load_family, runnable_worlds
from defender.systems.verb_grant import GrantError

from defender.learning.branch.questioner_launch import (
    _SAMPLES_PER_VERB as _SAMPLES_PER_VERB,
    _SAMPLE_CAP as _SAMPLE_CAP,
    _author as _author,
    _fence_count as _fence_count,
    _joined_leads as _joined_leads,
    _logger as _logger,
    _sample_text as _sample_text,
    branch_point_clock as branch_point_clock,
    reachable_systems as reachable_systems,
    served_systems as served_systems,
    system_samples as system_samples,
    write_questioner_samples as write_questioner_samples,
)


from defender.learning.branch.preflight import (
    ACCEPTED as ACCEPTED,
    DIRT as DIRT,
    ENVIRONMENT_REFUSED as ENVIRONMENT_REFUSED,
    ENVIRONMENT_CAUSES as ENVIRONMENT_CAUSES,
    LauncherRefused as LauncherRefused,
    MAX_BRANCH_MESSAGE_ID as MAX_BRANCH_MESSAGE_ID,
    REFUSED as REFUSED,
    STAMP_FIELD_CLASSES as STAMP_FIELD_CLASSES,
    UNPROVEN_KNOWLEDGE as UNPROVEN_KNOWLEDGE,
    UNUSABLE as UNUSABLE,
    _ANCHORED as _ANCHORED,
    _Fault as _Fault,
    _HELD as _HELD,
    _HELD_RULES as _HELD_RULES,
    _HeldRule as _HeldRule,
    _Judgement as _Judgement,
    _Original as _Original,
    _as_recorded as _as_recorded,
    _as_stamp as _as_stamp,
    _check_branch_point as _check_branch_point,
    _check_oracle_side as _check_oracle_side,
    _clean_stamp as _clean_stamp,
    _family_faults as _family_faults,
    _family_refusal as _family_refusal,
    _knowledge_commit as _knowledge_commit,
    _member_faults as _member_faults,
    _no_stamp as _no_stamp,
    _not_admitted as _not_admitted,
    _not_certified_clean as _not_certified_clean,
    _off_knowledge as _off_knowledge,
    _originals as _originals,
    _preflight_context as _preflight_context,
    _source_store as _source_store,
    _stamp_of as _stamp_of,
    _stamp_speaks as _stamp_speaks,
    _unknown_faults as _unknown_faults,
    _unprovable as _unprovable,
    preflight_episode as preflight_episode,
    preflight_replay as preflight_replay,
)



class SourceInputReplaced(JobEnding, Exception):
    """The source run's stored alert does not match its record (#1222 A1). An operator's exit
    like every launcher refusal, and ALSO an `Exception`, so a caller that guards a launch with
    `except Exception` sees the refusal instead of the process leaving. For a learning job it
    is `skipped: history_unreadable`: a source whose input current code cannot verify (one
    recorded before its alert carried a record, or one damaged since) can never be run."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail, reason=HISTORY_UNREADABLE,
                         brief="the source run's alert does not match its record, or one of the "
                               "two is missing")


# ---------------------------------------------------------------------------------------
# preflight — before the first `Step`
# ---------------------------------------------------------------------------------------


#: The launcher's primer: an empty capture primes an empty base, and `_prime_once` warns.
_PRIME_ALLOWING_EMPTY = functools.partial(prime_base, allow_empty=True)


#: The job's fixed brief for each cause of an environment refusal at pre-flight (#1363 O6): who
#: failed is the first thing the operator reads, so a down system is never put as our failure.
_ENVIRONMENT_BRIEFS = {
    "sign": "pre-flight refused: the read token for the credential proxy cannot be signed",
    "access": "pre-flight refused: the credential proxy could not be used",
    "setup": "pre-flight refused: our setup for a system failed",
    "down-systems": "pre-flight refused: every system the source run's calls reached is down "
                    "for this run",
}


def source_input(source: Run) -> tuple[bytes, str]:
    """The source run's alert bytes and its record's text, the bytes checked against the digest
    the record carries — or the launcher's refusal, naming the run and carrying no byte of
    either file. The ONE read of the source's input a launch makes; what it returns is copied
    into the episode, and everything downstream reads the copy."""
    try:
        return formats.verified_input(
            source.facts.alert.path, source.facts.alert_record.path, run_name=str(source.id))
    except formats.AlertReplaced as replaced:
        raise SourceInputReplaced(f"[branch] {replaced}") from replaced


def _copy_source_input(episode: Episode, raw: bytes, record_text: str,
                       knowledge_commit: str | None = None) -> None:
    """Put the source run's alert and its record in the episode, once (A1): the judge's whole
    input about the alert, and every sibling's own; and the family's knowledge pin, when the
    launcher decided one (`records._knowledge_pin`)."""
    episode.source_alert.create(raw)
    episode.source_record.create(record_text)
    if knowledge_commit is not None:
        episode.knowledge_pin.create(pin_text(knowledge_commit))


def prepare_episode(
    runs: RunsRepository[Tenant], source: Run, *,
    prime: Callable[[Path, Episode], PrimeReport] = _PRIME_ALLOWING_EMPTY,
    knowledge_commit: str | None = None, episode_id: str | None = None,
) -> EpisodeRuns:
    """Claim a fresh episode (at `episode_id`, a learning job's id, when given; else a minted
    one), copy the source's input (and the family's knowledge pin, `knowledge_commit`) into it,
    prime the family's base into it once, and hand back its view held open: the launcher's
    door, whose caller closes it."""
    # Judged before an episode is claimed, so a refused source leaves no debris.
    raw, record_text = source_input(source)
    try:
        view = runs.create_episode(episode_id)
    except (RunRefused, TenantRefused) as refused:
        raise ending(f"[branch] a fresh episode could not be claimed: {refused}",
                     reason=LAUNCH_REFUSED,
                     brief=f"the job's episode could not be claimed ({type(refused).__name__})",
                     cause=refused) from refused
    try:
        _copy_source_input(view.episode, raw, record_text, knowledge_commit)
        _prime_once(view.episode, view.episode_id, source.run_dir, prime)
    except BaseException:
        view.close()
        raise
    return view


def _prime_once(
    episode: Episode, episode_id: str, source_run_dir: Path,
    prime: Callable[[Path, Episode], PrimeReport],
) -> None:
    """`prepare_episode`'s priming, under the exclusive claim it takes and always releases."""
    episode.served.ensure()
    claim = episode.priming_lock
    try:
        claim.create("")
    except (FileExistsError, NotPlainEntry) as taken:
        # Occupied, or anything at the name that is not a plain file (the core's refusal, left
        # in place): either way this launcher does not hold the claim.
        raise LedgerError(
            f"another launcher is priming episode {episode_id!r} ({claim.path} exists) — a "
            "family's capture is written once, before any sibling forks") from taken
    try:
        report = prime(source_run_dir, episode)
    finally:
        # Released on every exit. A refusal here is logged, never raised: it must not mask the
        # exception this `finally` is unwinding.
        try:
            claim.delete()
        except OSError as stuck:
            _logger.warning(f"could not release the priming claim {claim.path}: {stuck}")
    if report.primed == 0:
        # Pre-flight records what this means for the episode (`refused` when nothing is
        # replayable); the warning is for the operator reading the launch.
        _logger.warning(
            f"{source_run_dir} captured no replayable query — the family's base is EMPTY")
        return
    # Log the skips too: each is a key read live rather than replayed.
    _logger.info(
        f"primed {report.primed} captured row(s) into {episode.served_base.path}; "
        f"{report.skipped} skipped ({report}) — a skipped key is read live per world rather "
        "than replayed")


def _open_launch_source(runs: RunsRepository[Tenant], source_run_id: str) -> Run:
    """The source run, by id, in the request's tenant's natural container — or the refusal,
    before anything is spent. `runs.open` walks `<T>/runs` from the tenant's folder no-follow
    (a link at any level is refused) and takes only a real directory at the id; a path, or an
    id from before #1187, where the id belongs is refused by `RunId.parse`."""
    try:
        return runs.open(RunId.parse(source_run_id))
    except RunRefused as refusal:
        raise ending(
            f"[branch] source run {source_run_id!r} of tenant {runs.tenant_id!r}: "
            f"{refusal}", reason=SOURCE_UNAVAILABLE,
            brief=f"the source run cannot be opened ({type(refusal).__name__})", cause=refusal) from refusal


def _source_stamp_agrees(source: Run, tenant_id: TenantId) -> None:
    """Refuse a source whose provenance stamp names another tenant than the request's. The
    stamp is in the box's writable run dir, so it is never the tenant's authority — the
    request is, and the source was opened under that tenant's own folder — but a disagreement
    is refused, not settled, and a stamp with no tenant gets no fallback."""
    stamp = _stamp_of(source)
    if stamp is None:
        raise _no_stamp(source.run_dir)
    if stamp.get("tenant_id") != tenant_id:
        raise ending(
            f"[branch] source run {source.run_dir}'s stamp names tenant "
            f"{stamp.get('tenant_id')!r} but the request names {tenant_id!r}, under whose "
            "folder the source was opened — the stamp is in the box's writable run dir, so a "
            "disagreement is refused, not settled", reason=LAUNCH_REFUSED,
            brief="the source run's stamp names another tenant than the job's")


# ---------------------------------------------------------------------------------------
# `Step.RUNS` — the family as processes
# ---------------------------------------------------------------------------------------


def sibling_argv(
    episode_id: str, world_label: str, *, tenant_id: TenantId, model: str | None = None,
    knowledge_commit: str | None = None,
) -> list[str]:
    """One sibling's command line: its tenant, its episode and which arm of it this process is
    — ids only, never a path (#1105 PR 2) — the model, and the knowledge commit every sibling
    is pinned to (O-PIN, #1108 P4: the source run's, so no publish moves a family's knowledge)."""
    argv = [sys.executable, str(PATHS.defender_dir / "run.py"),
            # EVERY RUN NAMES ITS TENANT (#1078), a sibling included: the episode's, which this
            # launcher accepted once. The child looks its episode up under that tenant only.
            "--tenant", tenant_id, "--episode", episode_id, "--world", world_label]
    if knowledge_commit is not None:
        argv += ["--knowledge-commit", knowledge_commit]
    if model is not None:
        argv += ["--model", model]
    return argv


#: The job's message for a source whose knowledge the family cannot be pinned to.
_UNPINNABLE = "the source run's knowledge cannot be pinned for the family"


def _materialised(tenant: RunTenant, commit: str, container: JobContainer | None) -> Any:
    """`<T>/exports/<commit>/`, materialised from the tenant clone when absent: by this process for an operator's
    launch; inside a job container by its per-job host helper (#1170 P-A, C20: the container writes no export and
    takes no knowledge lock), the folder it answers held to the one this tenant names for that commit. A helper
    refusal, or a helper that cannot be reached, is `DeliveryRefused`."""
    from defender import job_socket
    from defender.learning.author.version_control import DeliveryRefused, TenantExport, materialise_export

    if container is None:
        return materialise_export(tenant.tenant, commit)
    try:
        answer = container.materialised_export(commit)
        folder = tenant.tenant.export_folder(commit)
    except job_socket.Refused as refused:
        raise DeliveryRefused(f"the job's host helper did not materialise it ({refused.code}): {refused}") from None
    except (OSError, ValueError, TenantRefused) as lost:
        raise DeliveryRefused(f"no export from the job's host helper: {type(lost).__name__}: {lost}") from None
    if answer.get("commit") != commit or str(answer.get("path")) != str(folder):
        raise DeliveryRefused(f"the job's host helper answered another export ({answer.get('path')!r}) than "
                              f"{folder}")
    return TenantExport(commit=commit, path=folder)


def _pinned_export(tenant: RunTenant, source: Run, container: JobContainer | None = None) -> Any:
    """The export every sibling is pinned to and the questioner's corpus is read from (flow 7,
    O-PIN): the knowledge commit the source run's HOST-HELD knowledge record names (U12, beside
    the run folder, where no box writes), materialised from the tenant clone when absent —
    never its provenance stamp, which sits in the box's rw bind (the stamp is compared against
    this pin at pre-flight, never read for it). A record that cannot be read has no commit to
    pin to, so it refuses — `--allow-dirty` does not waive it (OD9) — as does a commit the
    clone cannot materialise; both before anything is spent. Only a source from before records
    were written (no record, and a stamp naming no knowledge source) is judged by its stamp, as
    before: a commit it names, a refusal for `unversioned`/`unavailable`, or with none recorded
    the tenant's published `current` (pre-flight still refuses that unless `--allow-dirty`). Inside a job
    container the export is materialised by the job's host helper (`_materialised`)."""
    from defender.learning.author.version_control import (
        DeliveryRefused,
        LockBusy,
        current_export,
    )
    status = source.knowledge_status()
    commit = None if status is None else status.commit
    try:
        if status is None:
            # A source from before host records: its stamp is all there is (#1204's rules).
            revision = formats.KnowledgeRevision.from_wire(
                (_stamp_of(source) or {}).get("knowledge"))
            if revision is None:
                return current_export(tenant.tenant)
            if revision.commit is None:
                why = (f"unavailable knowledge ({revision.unavailable})"
                       if revision.unavailable is not None else "unversioned knowledge")
                raise ending(
                    f"[branch] source run {source.run_dir}'s stamp names {why}: there is no "
                    "knowledge commit to pin its siblings to, so the family cannot be launched "
                    "(not waived by --allow-dirty)", reason=LAUNCH_REFUSED, brief=_UNPINNABLE)
            commit = revision.commit
        elif commit is None:
            raise ending(
                f"[branch] source run {source.run_dir}'s knowledge record is unreadable: there "
                "is no knowledge commit to pin its siblings to, so the family cannot be "
                "launched (not waived by --allow-dirty)", reason=LAUNCH_REFUSED, brief=_UNPINNABLE)
        return _materialised(tenant, commit, container)
    except (DeliveryRefused, LockBusy) as refused:
        at = "" if commit is None else f" ran at knowledge commit {commit}, which"
        raise ending(
            f"[branch] source run {source.run_dir}{at} cannot be pinned to a knowledge "
            f"export: {refused}", reason=LAUNCH_REFUSED, brief=_UNPINNABLE, cause=refused) from refused


#: The exit code recorded for an arm whose process never started (spawn raised, or the
#: rendezvous broke). Distinct from `run.py`'s own 0/1/2 so "never started" is distinguishable
#: from "ran and failed".
SPAWN_FAILED_EXIT = 70


def start_family(  # noqa: PLR0913, PLR0915, C901 — the family's arms, the tenant every arm runs on, the rate they share, the failures already counted and the width
    episode: Episode, world_ids: Sequence[str], *,
    spawn: Callable[..., int] | None = None, model: str | None = None,
    tenant_id: TenantId | None, rate: float | None = None, failed_before: int = 0,
    knowledge_commit: str | None = None, width: int | None = None, control: str | None = None,
    on_ended: Callable[[str, int], None] | None = None,
) -> dict[str, int]:
    """Start the selected world UUIDs, returning exits keyed by those UUIDs.

    One mechanism with a width (#1344 O4, D9): at most `width` siblings run at once, from one
    pool, each holding an equal share of the episode's `rate` (`rate / width`). `width=None` is
    every world at once, started together (the operator's lane); a learning job runs `width=1`,
    one sibling after another with the whole rate each. `control`, when named, starts first, and
    its failure stops the family: no world after it starts. Either way, once `UNUSABLE_AT`
    worlds have failed the family is unusable: the siblings still running are stopped and no
    other world starts. A world that never started is recorded `did not finish` and exits
    `SPAWN_FAILED_EXIT`. `on_ended(world_id, code)` is called as each sibling's process exits.

    A `BaseException` reaching this frame while siblings run (a stop's signal) stops the family
    the same way, waits for the running siblings to end, and is re-raised."""
    from defender import tenancy
    from defender.learning.core.config import KNOB_RATE

    if tenant_id is None or not tenancy.is_valid_tenant_id(tenant_id):
        # A ValueError, not `LauncherRefused`: `_launch`'s host acceptance already admitted the tenant, so
        # this is a caller bug and takes the episode's normal abort path.
        raise ValueError(
            f"episode {episode.dir} has no usable tenant ({tenant_id!r}) to run its siblings "
            "on — refused before any sibling started")
    stop = threading.Event()
    # Every spawn is handed the family's stop (`spawn(argv, *, env, stop)`): set, the sibling it
    # runs is terminated (N18, and the unwind below).
    start = functools.partial(_default_spawn if spawn is None else spawn, stop=stop)
    family = load_family(episode.view(), expected_episode_id=episode.dir.name)
    order = sorted(world_ids, key=lambda world_id: world_id != control)
    worlds = {world_id: family.world_by_id(world_id) for world_id in order}
    if not worlds:
        return {}
    at_once = len(worlds) if width is None else max(1, min(width, len(worlds)))
    together = at_once == len(worlds)
    ready = threading.Barrier(at_once) if together else None
    exits: dict[str, int] = {}
    failed = [failed_before]
    tally = threading.Lock()

    def ended(world_id: str, code: int, why: str) -> None:
        label = worlds[world_id].label
        exits[world_id] = code
        if not code:
            return
        if outcome_mod.write_world_record(episode, world_id, outcome_mod.DID_NOT_FINISH,
                                          detail=why):
            _logger.warning(f"world {label}: {why}; recorded as did not finish")
        with tally:
            failed[0] += 1
            if world_id == control and not stop.is_set():
                _logger.warning(f"episode {episode.dir.name}: the control world failed, so no "
                                "other world starts")
                stop.set()
            if failed[0] >= outcome_mod.UNUSABLE_AT and not stop.is_set():
                _logger.warning(
                    f"episode {episode.dir.name}: {failed[0]} worlds have failed, so the "
                    "family is unusable; stopping the siblings still running")
                stop.set()

    def never_started(world_id: str) -> None:
        exits[world_id] = SPAWN_FAILED_EXIT
        why = "it never started: the family was stopped before its turn"
        if outcome_mod.write_world_record(episode, world_id, outcome_mod.DID_NOT_FINISH,
                                          detail=why):
            _logger.warning(f"world {worlds[world_id].label}: {why}; recorded as did not finish")

    def launch_one(world_id: str) -> None:
        label = worlds[world_id].label
        env = dict(os.environ)
        if rate is not None:
            env[KNOB_RATE] = str(rate / at_once)
        if ready is not None:
            # Rendezvous first, so "started together" does not depend on the pool's scheduling.
            ready.wait(timeout=30)
        elif stop.is_set():
            never_started(world_id)
            return
        try:
            code = start(sibling_argv(episode.dir.name, label, tenant_id=tenant_id,
                                      model=model, knowledge_commit=knowledge_commit), env=env)
        except Exception as never_ran:  # noqa: BLE001 — one arm's failure, not the family's
            ended(world_id, SPAWN_FAILED_EXIT, f"its process never started ({never_ran!r})")
            return
        ended(world_id, code, f"its process exited {code} without a record of its own"
              + (" (the family was stopped while it ran)" if stop.is_set() else ""))
        if on_ended is not None:
            on_ended(world_id, code)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=at_once)
    try:
        futures = {world_id: pool.submit(launch_one, world_id) for world_id in worlds}
        concurrent.futures.wait(futures.values())
    except BaseException:
        stop.set()
        pool.shutdown(wait=True, cancel_futures=True)
        raise
    pool.shutdown(wait=True)
    # A thread that died outside `start` (a broken barrier fails all N at once) is recorded as a
    # result, not re-raised: raising would skip `verify_family`, leaving completed siblings
    # unarchived.
    for world_id, future in futures.items():
        try:
            future.result()
        except Exception as never_ran:  # noqa: BLE001 — one arm's failure, not the family's
            if world_id not in exits:
                ended(world_id, SPAWN_FAILED_EXIT, f"its process never started ({never_ran!r})")
    return exits


#: How long a stopped sibling is given to exit on SIGTERM before it is killed.
_STOP_GRACE_SECONDS = 20.0


def _default_spawn(argv: list[str], *, env: dict[str, str] | None = None,
                   stop: threading.Event | None = None) -> int:
    """Run one sibling to completion in its own process, inheriting nothing but `env`; when
    `stop` is set first (the family became unusable, N18), terminate it and return its exit.

    Nothing outlives its launcher (#1344 O9): the child is tied to this process (it dies with
    it, `_parent_tie.tied_argv`), and when this frame unwinds on anything (a stop's signal), the
    child is terminated, and killed after a grace, before the unwind goes on."""
    import subprocess

    child = subprocess.Popen(tied_argv(argv), env=env)  # noqa: S603 — fixed argv
    try:
        while True:
            try:
                return child.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                if stop is not None and stop.is_set():
                    break
        return _stopped_child(child)
    except BaseException:
        _stopped_child(child)
        raise


def _stopped_child(child: Any) -> int:
    """`child` asked to exit (SIGTERM), killed when it outlasts the grace; its exit."""
    import subprocess

    if child.poll() is not None:
        return child.returncode
    child.terminate()
    try:
        return child.wait(timeout=_STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        child.kill()
        return child.wait()

from defender.learning.branch.verification import (
    _archive_worlds as _archive_worlds,
    _cross_tenant_fault as _cross_tenant_fault,
    _scrub_ran as _scrub_ran,
    _write_family_stamp as _write_family_stamp,
    verify_family as verify_family,
)
from defender.records.formats import TenantId, TenantRefused

if _missing := [f for f in _ANCHORED if _HELD[f].off_anchor is None]:
    raise RuntimeError(f"anchored stamp field(s) {_missing} have no refusal text in _HELD_RULES")


# ---------------------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------------------


def _job_id(raw: str) -> str:
    """`--job-id`: a learning job's id, a UUID, which becomes the episode's id."""
    try:
        return str(RunId.parse(raw))
    except RunRefused as bad:
        raise argparse.ArgumentTypeError(f"not a job id: {bad}") from None


def parse_branch_args(argv: list[str]) -> argparse.Namespace:
    """The operator's whole command line: a tenant, a source run of it, a branch point, and
    what to say."""
    p = argparse.ArgumentParser(prog="branch", description=__doc__)
    p.add_argument("--tenant", required=True,
                   help="the tenant whose run is forked; required, with no default")
    p.add_argument("source_run_id", help="the finished run to fork, by its run id")
    p.add_argument("branch_message_id", type=int, help="the message to resume from")
    p.add_argument(
        "--allow-dirty", action="store_true",
        help="launch, and record the family stamp, even though the source run, the live tree "
             "or a sibling reported a tree git could not certify clean, or tenant knowledge "
             "whose commit nothing proves (unversioned, unreadable, or not recorded); waives "
             "only those — never a commit, scope or knowledge-commit mismatch, an absent stamp "
             "or a stamp with no commit — and the override is NAMED in the stamp")
    p.add_argument("--model", default=None)
    p.add_argument(
        "--job-id", type=_job_id, default=None,
        help="run as learning job JOB_ID (#1344): the episode's id is the job's, the siblings "
             "run one at a time, the control first, each with the episode's whole rate, and the "
             "judge's findings wait in the episode instead of reaching the queue")
    ns = p.parse_args(argv)
    if ns.job_id is not None and ns.allow_dirty:
        p.error("--allow-dirty is an operator's waiver; a learning job (--job-id) takes none")
    return ns


def main(  # noqa: PLR0913 — the launcher's inputs plus its injection seams
    argv: list[str],
    *,
    spawn: Callable[..., int] | None = None,
    questioner: Any = None,
    preflight: Callable[..., int],
    render_page: PageRenderer | None = None,
    judge: Any = None,
    lessons_dir: Path | None = None,
    live_tree: Callable[[], formats.RunProvenance] | None = None,
    oracle: Any = None,
    verifier: Any = None,
    roster: Any = None,
    directory: Any = None,
    signer: Any = None,
    proxy_url: str | None = None,
    issuer_transport: Any = None,
    clock: Callable[[], float] = time.time,
) -> int:
    """Launch one episode, reporting a refusal as an operator exit rather than a traceback.
    `preflight` (the role-model check) and `render_page` (the episode page) are handed in by the
    entry, which sits above both. `--job-id` runs the job lane (`JobLaneHooks` with no hooks)."""
    ns = parse_branch_args(argv)
    lane = None if ns.job_id is None else JobLaneHooks(job_id=ns.job_id)
    try:
        return _launch(ns, lane=lane, spawn=spawn, questioner=questioner, preflight=preflight,
                       render_page=render_page, judge=judge, lessons_dir=lessons_dir, live_tree=live_tree,
                       oracle=oracle, verifier=verifier, roster=roster, directory=directory,
                       signer=signer, proxy_url=proxy_url, issuer_transport=issuer_transport,
                       clock=clock)
    except (branch.BranchError, LedgerError, EstateError, FamilyError, GrantError,
            session_store.StoreError, sqlite3.Error) as refusal:
        raise LauncherRefused(f"[branch] {refusal}") from refusal


def launch_job(  # noqa: PLR0913 — the job's identity plus the launcher's seams
    *, tenant: str, source_run_id: str, lane: JobLaneHooks, preflight: Callable[..., int],
    **seams: Any,
) -> int:
    """A learning job's family step (#1344), for the job entry: the job lane's launch over
    `source_run_id`, its fork point decided by `lane.pick`. Nothing is wrapped: every ending the
    outcome table names is raised as a `JobEnding`, and anything else reaches the entry as it
    was raised, for the entry to record as `entry_error`."""
    if lane.pick is None:
        raise ValueError("a learning job's launch needs its fork pick (`lane.pick`)")
    ns = argparse.Namespace(tenant=tenant, source_run_id=source_run_id, branch_message_id=None,
                            allow_dirty=False, model=None, job_id=lane.job_id)
    return _launch(ns, lane=lane, preflight=preflight, **seams)


class _ContainerAdmitted:
    """The tenant of a launch inside a job container (#1170): accepted by the folder rules alone. The per-job host
    helper holds the tenant's host lock and admitted it before the container started (P-C), so no lock is taken, no
    record read and no database opened here; it has no tenant records (`directory` None)."""

    directory: Any = None

    def __init__(self, tenant: Tenant) -> None:
        self.tenant = tenant

    def __enter__(self) -> _ContainerAdmitted:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def _admitted(data_root: Any, tenant_id: TenantId, *, box_mounted: tuple[Any, ...]) -> _ContainerAdmitted:
    """The tenant of a launch inside a job container: the folder rules alone (`_ContainerAdmitted`). An operator's
    launch opens the one host acceptance in `_launch` itself, the command that holds it."""
    return _ContainerAdmitted(tenancy.accept_tenant(data_root, tenant_id, defender_dir=_DEFENDER_DIR,
                                                    box_mounted=box_mounted))


def _launch(  # noqa: PLR0913, PLR0915, C901 — see `main`; the launch checks, then the episode, in order
    ns: argparse.Namespace, *, lane: JobLaneHooks | None, spawn: Any = None, questioner: Any = None,
    preflight: Callable[..., int], render_page: PageRenderer | None = None, judge: Any = None,
    lessons_dir: Path | None = None,
    live_tree: Callable[[], formats.RunProvenance] | None = None,
    oracle: Any = None, verifier: Any = None, roster: Any = None, directory: Any = None,
    signer: Any = None, proxy_url: str | None = None, issuer_transport: Any = None,
    container: JobContainer | None = None,
    clock: Callable[[], float] = time.time,
) -> int:
    # Injected seams are resolved once and threaded inward non-`None`, so no two frames can
    # disagree about which preflight, roster or model an episode used.
    # The episode's tenant first, from the request: pre-flight's reader, the served systems,
    # the source run and the siblings all resolve through it.
    try:
        tenant_id = tenancy.requested_tenant_id(ns.tenant)
        data_root = tenancy.resolve_data_root()
    except TenantRefused as refusal:
        raise ending(f"[branch] {refusal}", reason=LAUNCH_REFUSED,
                     brief=f"the job's tenant was refused ({type(refusal).__name__})",
                     cause=refusal) from refusal
    # The one host acceptance (r10 A1), held for the whole launch: this process recorded under
    # the tenant's host lock (prepare and teardown wait for the launch, and a teardown finds it to
    # stop it; its siblings hold their own), the tenant `active` with its forge wiring, its folder
    # accepted. THE TREES A BOX MOUNTS, as the launcher knows them: acceptance already holds the
    # tenant's own runs base against its settings; every sibling's arm container lies inside the
    # tenant's episodes folder, which is the launcher's to add — no environment names it (S-acc).
    # A settings half inside either would hand the model the tenant's endpoints, so it is
    # refused here at launch exactly as a run refuses one inside its runs base (#1107 MF-13).
    from defender.systems import run_tenant as run_tenant_mod

    admitted: Any
    try:
        box_mounted = (tenancy.box_mounted_episodes(data_root, tenant_id),)
        admitted = (run_tenant_mod.host_tenant(data_root, tenant_id, directory=directory, defender_dir=_DEFENDER_DIR,
                                               box_mounted=box_mounted)
                    if container is None else _admitted(data_root, tenant_id, box_mounted=box_mounted))
    except TenantRefused as refusal:
        raise ending(f"[branch] the episode's tenant: {refusal}", reason=LAUNCH_REFUSED,
                     brief=f"the job's tenant was refused ({type(refusal).__name__})",
                     cause=refusal) from refusal
    with admitted:
        # The tenant's readiness over its own folder; siblings dispatch no turn-0 lead.
        try:
            tenant = run_tenant_mod.run_tenant_for(admitted.tenant, dispatches_lead_zero=False)
        except TenantRefused as refusal:
            raise ending(f"[branch] the episode's tenant: {refusal}", reason=LAUNCH_REFUSED,
                         brief=f"the job's tenant was refused ({type(refusal).__name__})",
                         cause=refusal) from refusal
        runs = tenant.tenant.runs_repository()
        source = _open_launch_source(runs, ns.source_run_id)
        _source_stamp_agrees(source, tenant.tenant_id)
        if lane is not None and lane.pick is not None:
            # The job's fork point (O3): picked here, once the source is open and its stamp
            # agrees, before anything is spent.
            lane.stage("fork pick")
            ns.branch_message_id = lane.pick(source)
        if ns.branch_message_id is None:
            raise ValueError("no branch point: the command line names one, or the job lane's pick")
        if lane is not None:
            lane.stage("launch checks")
        # N05 / O-20: a tenant whose gather grant serves no variable system has nothing a world
        # could change. Refused here, before the question-writer or anything else is spent.
        served = served_systems(tenant.grants.gather)
        if not served:
            raise ending(
                f"[branch] tenant {tenant.tenant_id!r}: its gather grant serves no system a world "
                "can vary (no read verb other than health-check on any system but the "
                "platform-served ones, which answer the same in every world), so no world of a "
                "branch could be served — grant gather a read verb on at least one other system "
                "before branching this tenant", reason=LAUNCH_REFUSED,
                brief="the tenant's gather grant serves no system a world can vary")
        # O1: any tenant branches. No system of the lab's is assumed, so a tenant with no
        # corpus-engine part (or one whose part does not resolve) launches like any other.
        # SAME RULE, #1007 M8/O7: production's questioner-lessons root is `PATHS.lessons_
        # questioner_dir`, resolved here rather than as a literal default so a test can hand in a
        # `tmp_path` corpus and this frame is the only one that ever sees the production path.
        # #1108 P4 flow 7: the family's knowledge is the source's commit, its export materialised
        # here (git-capable) before anything is spent; the questioner's corpus is that export's.
        pinned = _pinned_export(tenant, source, container)
        questioner_lessons_dir = (
            KnowledgePaths(Path(pinned.path) / "agent").lessons_questioner_dir
            if lessons_dir is None else lessons_dir)
        # Injectable so end-to-end tests aren't compared against the suite's own HEAD. The
        # knowledge half is the export every sibling is pinned to, as every sibling's stamp will
        # be (#1204 D3, O-B): never the clone's HEAD, which a publish moves.
        live_capture = ((lambda: dataclasses.replace(
            formats.capture_tree(REPO_ROOT),
            knowledge=formats.KnowledgeRevision.at(pinned.commit)))
                        if live_tree is None else live_tree)
        checked = preflight_episode(
            source=source, branch_message_id=ns.branch_message_id,
            preflight=preflight, model=ns.model,
            allow_dirty=ns.allow_dirty,
            live_tree=live_capture, oracle=oracle, verifier=verifier)
        if roster is None:
            from defender._paths import adapters_under
            from defender.systems.verbs import read_roster

            roster = read_roster(adapters_under(_DEFENDER_DIR))

        view = prepare_episode(runs, source, knowledge_commit=pinned.commit,
                               episode_id=None if lane is None else lane.job_id)
        episode = view.episode
        # Set once the first sibling is about to start: past it, the abort message below ("no
        # sibling started") would be false, so anything raised later is re-raised unchanged.
        started = threading.Event()
        with view:
            try:
                # The claimed episode's view: its arm container and roster are made only once the
                # first sibling is about to start (`start_runs`).
                author = seams.model_seam(episode.dir) if questioner is None else questioner
                return _run_episode(
                    ns, source=source, source_stamp=checked.source_stamp,
                    launch_waived=checked.waived, episode=episode, view=view,
                    questioner=author, spawn=spawn, judge=judge, lessons_dir=questioner_lessons_dir,
                    tenant=tenant, runs=runs, served=served, oracle=oracle,
                    verifier=verifier, roster=roster, started=started,
                    knowledge_commit=pinned.commit, render_page=render_page,
                    signer=signer, proxy_url=proxy_url, issuer_transport=issuer_transport,
                    directory=admitted.directory, lane=lane, container=container,
                    token_clock=clock)
            except SystemExit:
                raise
            except BaseException as failed:  # noqa: BLE001 — one abort rule, see `main`'s docstring
                # A job's launch is never re-worded: the entry records what was raised by its
                # type (a stop's signal included), never by this text.
                if started.is_set() or lane is not None:
                    raise
                raise LauncherRefused(
                    f"[branch] episode {episode.dir.name} aborted: {failed!r} — no sibling "
                    "started") from failed


def _run_episode(  # noqa: PLR0913, PLR0912, PLR0915, C901 — the episode's whole identity plus its seams
    ns: argparse.Namespace, *, source: Run, source_stamp: dict, launch_waived: Sequence[str] = (),
    episode: Episode,
    view: EpisodeRuns, questioner: Any, spawn: Any, lessons_dir: Path, judge: Any = None,
    tenant: RunTenant, runs: RunsRepository[Tenant], served: Sequence[str], oracle: Any,
    verifier: Any, roster: Any, started: threading.Event, render_page: PageRenderer | None,
    knowledge_commit: str | None = None, signer: Any = None, proxy_url: str | None = None,
    issuer_transport: Any = None, directory: Any = None, lane: JobLaneHooks | None = None,
    container: JobContainer | None = None,
    token_clock: Callable[[], float] = time.time,
) -> int:
    """Every `Step`, `QUESTIONER` through `JUDGE`.

    `source_stamp` is the anchor the launch checks read and judged, handed to `verify_family`
    unchanged. `view` is the episode's view in `runs`, the request's tenant's repository: RUNS
    starts through it — the arm container, then the arm roster naming every manifest world —
    just before the first sibling starts, and every finished arm is opened through it by the
    roster's id. Returns 0 when every launched sibling exited cleanly, 1 otherwise — including
    an episode pre-flight did not accept, where no sibling ran (and so no roster exists).

    In the job lane (`lane`), each ending the outcome table names is raised, typed, where it is
    decided: a family pre-flight did not accept, a failed control, a refused verification and a
    failed judge pass. The judge writes the episode's findings, not the queue, and its return
    is reported to `lane.judged`."""
    from defender.learning.core.config import process_oracle_settings

    episode_id = episode.dir.name
    stage = lane.stage if lane is not None else (lambda _name: None)
    # One clock for the episode; every step frame is drawn here, in launch order.
    clock = timing_mod.StageClock(episode)
    stage(Step.QUESTIONER)
    with clock.step(Step.QUESTIONER):
        try:
            family = _author(ns, source=source, episode=episode, questioner=questioner,
                             lessons_dir=lessons_dir, served=served,
                             reachable=reachable_systems(tenant.grants.gather))
        except (FamilyError, branch.BranchError) as unparsed:
            # N05 / M05=A: nothing to calibrate, for a reason that belongs to no world.
            outcome_mod.write_outcome(
                episode, REFUSED,
                reason=f"the question-writer's family could not be used: {unparsed}")
            raise ending(
                f"[branch] episode {episode_id}: the question-writer's family could not be "
                f"used ({unparsed}); recorded as refused in {episode.outcome.path}",
                reason=FAMILY_UNUSABLE,
                brief=f"the question-writer's family could not be used ({type(unparsed).__name__}); "
                      "the episode's outcome is refused", cause=unparsed) from unparsed
    stage(Step.PREFLIGHT)
    with clock.step(Step.PREFLIGHT):
        record = preflight_replay(episode, source=source, roster=roster, tenant=tenant,
                                  oracle=oracle, verifier=verifier, signer=signer,
                                  proxy_url=proxy_url, issuer_transport=issuer_transport,
                                  directory=directory, container=container,
                                  job_id=None if lane is None else lane.job_id,
                                  clock=token_clock)
    if record["outcome"] != ACCEPTED:
        _logger.info(f"episode {episode_id}: {record['outcome']} before any sibling started "
                     f"({record['reason']})")
        if lane is not None:
            detail = (f"[branch] episode {episode_id}: pre-flight recorded {record['outcome']!r} "
                      f"({record['reason']})")
            cause = record.get(ENVIRONMENT_REFUSED)
            if cause:
                # The environment's refusal, not the family's: the job fails, it is not skipped.
                # The brief is the cause's own (#1363 O6).
                raise ending(detail, reason=LAUNCH_REFUSED,
                             brief=_ENVIRONMENT_BRIEFS[cause] + "; no sibling started")
            raise ending(detail, reason=FAMILY_UNUSABLE,
                         brief=f"pre-flight recorded the family {record['outcome']}; no sibling started")
        return 1
    unservable = {entry["world"] for entry in record["unservable_worlds"]}
    worlds = [w for w in runnable_worlds(family) if w.label not in unservable]
    world_ids = [w.world_id for w in worlds]
    control = next((w.world_id for w in worlds if w.role == formats.BASE_ROLE), None)
    started.set()
    stage(Step.RUNS)
    with clock.step(Step.RUNS):
        # The arm container, then the roster — one fresh id for EVERY manifest world, the
        # unservable and the `role: null` replicate included — before the first sibling
        # starts: each sibling's run start checks the roster names its world, and takes its
        # run id from it.
        view.start_runs([world.world_id for world in family.worlds])
        ran: list[str] = []

        def sibling_ended(world_id: str, _code: int) -> None:
            ran.append(world_id)
            if lane is not None:
                lane.sibling_ended(view, list(ran))

        # A job's siblings run one at a time, the control first (O4); an operator's together.
        exits = start_family(episode, world_ids, spawn=spawn, model=ns.model,
                             tenant_id=tenant.tenant_id, rate=process_oracle_settings().rate,
                             failed_before=len(unservable), knowledge_commit=knowledge_commit,
                             width=None if lane is None else 1,
                             control=None if lane is None else control,
                             on_ended=sibling_ended)
    if lane is not None and control is not None and exits.get(control, 0) != 0:
        raise ending(
            f"[branch] episode {episode_id}: the control world exited {exits[control]}, so no "
            "other world started", reason=CONTROL_FAILED,
            brief="the control world's run failed, so no other world started")
    finished = [world_id for world_id in world_ids if exits.get(world_id) == 0]
    stage(Step.VERIFY)
    with clock.step(Step.VERIFY):
        report = verify_family(
            episode, _finished_arms(view, finished), source=source_stamp,
            allow_dirty=ns.allow_dirty, launch_waived=launch_waived)
    failed = sorted(world_id for world_id, code in exits.items() if code)
    for world_id in failed:
        _logger.warning(f"world {family.world_by_id(world_id).label} exited {exits[world_id]}")
    if not report["comparable"]:
        _logger.warning(f"episode {episode_id}: the family stamp is withheld "
                        f"({report['not_comparable']})")
    elif report["reason"]:
        _logger.warning(f"episode {episode_id}: per-world faults, each on its own world's "
                        f"record ({report['reason']})")
    _logger.info(f"episode {episode_id}: {len(report['archived'])}/{len(world_ids)} worlds "
                 "archived")
    stage(Step.JUDGE)
    with clock.step(Step.JUDGE):
        if lane is None:
            _grade(runs, episode_id=episode_id, judge=judge)
        else:
            _grade_job(runs, episode_id=episode_id, judge=judge, lane=lane)
    # Rendered after the JUDGE frame closes so the page sees the judge's timing row;
    # non-fatal.
    if render_page is not None:
        _render_page(runs, render_page, episode_id=episode_id)
    return 1 if failed else 0


def _finished_arms(view: EpisodeRuns, world_ids: Sequence[str]) -> dict[str, Run | RunRefused]:
    """Every finished arm, at the id the episode's roster holds for it (`view.arm_ids()`, read
    once), from ONE hold of the arm container (`view.arms`), each arm judged at its own entry
    (only a real directory is a run) — or the refusal for it, which `verify_family` records as
    that world's own fault: a roster id with no folder is "not started" (`RunAbsent`), an entry
    that is not a real directory its own; a container that went bad after the siblings ran is
    every arm's `RunUnreachable` (or `RunAbsent` when it is gone)."""
    try:
        ids = view.arm_ids()
    except RunRefused as refused:
        raise ending(f"[branch] episode {view.episode_id}: VERIFY refuses: {refused}",
                     reason=VERIFY_REFUSED,
                     brief=f"verification refused: the arm roster cannot be read ({type(refused).__name__})",
                     cause=refused) from refused
    if ids is None:
        raise ending(
            f"[branch] episode {view.episode_id}: its arm roster is gone, so no finished arm "
            "can be named — VERIFY refuses rather than guess an arm's id", reason=VERIFY_REFUSED,
            brief="verification refused: the episode's arm roster is gone")
    with view.arms([ids[world_id] for world_id in world_ids]) as handout:
        return {world_id: handout[ids[world_id]] for world_id in world_ids}


def _render_page(runs: RunsRepository[Tenant], render_page: PageRenderer, *, episode_id: str) -> None:
    """Render the episode page, by id in the request's tenant's repository. Never fatal to the
    launch: a failure is logged, not raised."""
    try:
        page = render_page(runs, episode_id)
        _logger.info(f"episode {episode_id}: page {page}")
    except Exception as render_failed:  # noqa: BLE001 — a render fault is non-fatal to the launch
        _logger.warning(f"episode {episode_id}: the page could not be rendered "
                        f"({render_failed!r})")


def _grade(runs: RunsRepository[Tenant], *, episode_id: str, judge: Any) -> None:
    """The grade, the body of the `JUDGE` frame; any failure is logged, never raised. The
    judge opens the episode by id through `runs`, the request's tenant's repository."""
    try:
        from defender.learning import judge as judge_mod
        from defender.learning.core.config import LoopPaths
        from defender.learning.core.state import LearningState, StateRefused

        # The root is resolved and opened here, once, and handed to the grade (RF5). A missing
        # root or a refused entry is logged below like any judge failure: grading never fails a
        # launch.
        with LearningState.open(LoopPaths.for_tenant(runs.tenant)) as state:
            judge_mod.grade_episode(runs, episode_id, judge=judge, state=state)
    # Imports are inside the `try` too, so an import or config fault is a judge failure
    # rather than reaching `_launch`'s abort arm with a false "no sibling started" message.
    # `StateRefused` is named: the judge is one of its declared exemptions, and it is not an
    # `Exception`.
    except (Exception, StateRefused) as judge_failed:  # noqa: BLE001 — a judge failure is non-fatal, see below
        # Every class: the grade reads model-authored archives, a shared queue and an injected
        # model seam, any of which can raise anything. Logged in full so the launch's status
        # stays about the launch without hiding the failure.
        _logger.warning(f"episode {episode_id}: the judge pass failed ({judge_failed!r}); the "
                        "episode itself is otherwise unaffected", exc_info=True)


def _grade_job(runs: RunsRepository[Tenant], *, episode_id: str, judge: Any, lane: JobLaneHooks) -> None:
    """A learning job's grade (#1344, "Judge modes"): the judge's job lane, whose findings wait
    in the episode and whose pass touches no queue. A pass that fails is the job's
    `judge_failed`, never swallowed; its message names only the failure's type. Its return is
    the job's ending, decided: `lane.judged` is told at once."""
    from defender.learning.core.state import StateRefused

    from defender.learning.judge import grade_episode

    grade = grade_episode if lane.grade is None else lane.grade
    try:
        graded = grade(runs, episode_id, judge=judge, job_lane=True)
    except (Exception, StateRefused) as judge_failed:  # noqa: BLE001 — every failure of the pass is the job's judge_failed
        raise ending(f"[branch] episode {episode_id}: the judge pass failed ({judge_failed!r})",
                     reason=JUDGE_FAILED,
                     brief=f"the judge's pass failed ({type(judge_failed).__name__})",
                     cause=judge_failed) from judge_failed
    lane.judged(graded, functools.partial(_held_findings, runs, episode_id))


def _held_findings(runs: RunsRepository[Tenant], episode_id: str) -> int:
    """How many findings a job's judge left in its episode, through the repository's walk."""
    from defender.learning.judge.enqueue import held_findings_count

    with runs.episode_files(episode_id) as episode:
        return held_findings_count(episode)


__all__ = [
    "ACCEPTED",
    "JobEnding",
    "JobLaneHooks",
    "Ledger",
    "LedgerError",
    "REFUSED",
    "UNUSABLE",
    "launch_job",
    "main",
    "parse_branch_args",
    "preflight_replay",
    "prepare_episode",
    "sibling_argv",
    "served_systems",
    "start_family",
    "system_samples",
    "verify_family",
]

