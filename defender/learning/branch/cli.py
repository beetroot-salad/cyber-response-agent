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
"""

from __future__ import annotations

import argparse
import concurrent.futures
import functools
import os
import sqlite3
import sys
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

# Run by path, so Python puts only `learning/branch/` on `sys.path`: re-exec into the project
# venv when it exists, then add the workspace root before any `defender` import.
_DEFENDER_DIR = Path(__file__).resolve().parents[2]
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender.records import _alert_input
from defender.records import _provenance
from defender.episodes._episode_handle import Episode
from defender.episodes._episodes_root import (
    EPISODES_BASE_ENV,
    EpisodeRefused,
    episode_dir,
    episodes_root,
    refuse_bad_episode_id,
)
from defender._io import (
    NotPlainEntry,
)
from defender._paths import PATHS
from defender.run_repository import (
    EpisodeRuns,
    Run,
    RunId,
    RunRefused,
    RunsRepository,
)
from defender.runtime.run_tenant import RunTenant
from defender.learning.branch import outcome as outcome_mod
from defender.learning.branch import seams
from defender.learning.branch import timing as timing_mod
from defender.learning.branch.steps import Step
from defender.learning.branch.capture import PrimeReport, prime_base
from defender.learning.branch.estate.registry import EstateError
from defender.learning.branch.ledger import Ledger, LedgerError
from defender.tenancy import _tenant
from defender.run_common import REPO_ROOT
from defender.runtime import branch, session_store
from defender.runtime.branch._family import (
    FamilyError,
    runnable_worlds,
)
from defender.runtime.verb_grant import GrantError

from defender.learning.branch.questioner_launch import (
    _SAMPLES_PER_VERB as _SAMPLES_PER_VERB,
    _SAMPLE_CAP as _SAMPLE_CAP,
    _author as _author,
    _fence_count as _fence_count,
    _joined_leads as _joined_leads,
    _logger as _logger,
    _sample_text as _sample_text,
    branch_point_clock as branch_point_clock,
    served_systems as served_systems,
    system_samples as system_samples,
    write_questioner_samples as write_questioner_samples,
)


from defender.learning.branch.preflight import (
    ACCEPTED as ACCEPTED,
    DIRT as DIRT,
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
    _off_commit as _off_commit,
    _off_knowledge as _off_knowledge,
    _off_scope as _off_scope,
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



class SourceInputReplaced(LauncherRefused, Exception):
    """The source run's stored alert does not match its record (#1222 A1). An operator's exit
    like every launcher refusal, and ALSO an `Exception`, so a caller that guards a launch with
    `except Exception` sees the refusal instead of the process leaving."""


# ---------------------------------------------------------------------------------------
# where an episode lives
# ---------------------------------------------------------------------------------------


def _owner_refusal(refused: EpisodeRefused) -> LauncherRefused:
    """The episode owner's refusal (an unusable episodes root, a bad episode id), as the
    launcher's operator-facing exit."""
    return LauncherRefused(f"[branch] {refused}")


def episode_id_for(source_run_id: str, branch_message_id: int) -> str:
    """The episode id this source and branch point derive: the first launch's.

    Derived rather than chosen, so one (source run, branch point) pair always maps to one
    episode name family. Case-folded because it names a directory, and case-folding filesystems
    would merge two spellings. A relaunch takes the next free `-r<n>` beside it
    (`prepare_episode`).
    """
    return f"{source_run_id}-n{branch_message_id}".casefold()


#: How many launches one (source run, branch point) pair may have before the launcher refuses
#: to mint another directory name for it.
MAX_LAUNCHES = 99


# ---------------------------------------------------------------------------------------
# preflight — before the first `Step`
# ---------------------------------------------------------------------------------------


#: The launcher's primer: an empty capture primes an empty base, and `_prime_once` warns.
_PRIME_ALLOWING_EMPTY = functools.partial(prime_base, allow_empty=True)


def source_input(source: Run) -> tuple[bytes, str]:
    """The source run's alert bytes and its record's text, the bytes checked against the digest
    the record carries — or the launcher's refusal, naming the run and carrying no byte of
    either file. The ONE read of the source's input a launch makes; what it returns is copied
    into the episode, and everything downstream reads the copy."""
    try:
        return _alert_input.verified_input(
            source.facts.alert.path, source.facts.alert_record.path, run_name=str(source.id))
    except _alert_input.AlertReplaced as replaced:
        raise SourceInputReplaced(f"[branch] {replaced}") from replaced


def _copy_source_input(episode: Episode, raw: bytes, record_text: str) -> None:
    """Put the source run's alert and its record in the episode, once (A1): the judge's whole
    input about the alert, and every sibling's own."""
    episode.source_alert.create(raw)
    episode.source_record.create(record_text)


def prepare_episode(
    episode_id: str, source: Run, *, data_root: Path,
    prime: Callable[[Path, Episode], PrimeReport] = _PRIME_ALLOWING_EMPTY,
) -> Episode:
    """Claim a fresh episode directory, prime the family's base into it once, and hand it back
    held open: the launcher's door, whose caller closes it.

    N17: a launch never reuses an episode directory. The derived id is tried first; a name
    already taken (a finished episode, a dead launch's debris, a launch still running beside
    this one) moves on to `<id>-r2`, `<id>-r3`, ... — the episode owner's exclusive create
    (`Episode.create(<root>/<id>)`, the id judged by `refuse_bad_episode_id` as `episode_dir`
    judges it, under the configured root for `data_root` — resolved once — the one the
    request's tenant was accepted under) is the claim, so two launchers racing for one name cannot both
    win it, and nothing a dead launch left is adopted. The minted id is the directory's name;
    every later record derives from it.

    `source_run_dir` is the source run's folder, as its opened `Run` hands it out. `prime` is
    injectable so a test can observe whether priming ran; it is handed the episode this
    returns.
    """
    # An id that cannot name a directory is refused first, before anything is read or made.
    try:
        refuse_bad_episode_id(episode_id)
    except EpisodeRefused as refused:
        raise _owner_refusal(refused) from refused
    # Judged before an episode directory is claimed, so a refused source leaves no debris.
    raw, record_text = source_input(source)
    try:
        root = episodes_root(data_root)
    except EpisodeRefused as refused:
        raise _owner_refusal(refused) from refused

    for n in range(1, MAX_LAUNCHES + 1):
        candidate = episode_id if n == 1 else f"{episode_id}-r{n}"
        try:
            episode = Episode.create(root / refuse_bad_episode_id(candidate), exclusive=True)
        except EpisodeRefused as refused:
            raise _owner_refusal(refused) from refused
        except FileExistsError:
            continue
        break
    else:
        raise LauncherRefused(
            f"[branch] {MAX_LAUNCHES} episodes of {episode_id!r} already exist under {root} — "
            "a launch never reuses one; remove the ones you no longer need")
    try:
        _copy_source_input(episode, raw, record_text)
        _prime_once(episode, episode.dir.name, source.run_dir, prime)
    except BaseException:
        episode.close()
        raise
    return episode


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


def _episode_tenant(tenant_id: _tenant.TenantId, data_root: Path) -> RunTenant:
    """The episode's tenant: the request's (`--tenant`), accepted under `data_root` — or the
    refusal, before anything is spent (S2: the tenant comes from the request, never from a
    record or a stamp).

    The same acceptance a sibling's run start uses, asked once up front so a tenant a sibling
    would refuse is refused before any spend. Siblings dispatch no turn-0 lead."""
    from defender.runtime import run_tenant as run_tenant_mod

    try:
        # THE TREES A BOX MOUNTS, as the launcher knows them: acceptance already holds the
        # tenant's own runs base (every run dir in it is a box's rw bind) against its settings;
        # the configured episodes base is the launcher's to add. A settings half inside either
        # would hand the model the tenant's endpoints, so it is refused here at launch exactly
        # as a run refuses one inside its runs base (#1107 MF-13).
        episodes_raw = os.environ.get(EPISODES_BASE_ENV)
        return run_tenant_mod.resolve_tenant(
            data_root, tenant_id, defender_dir=_DEFENDER_DIR, dispatches_lead_zero=False,
            box_mounted=(Path(episodes_raw),) if episodes_raw else ())
    except run_tenant_mod.TenantRefused as refusal:
        raise LauncherRefused(f"[branch] the episode's tenant: {refusal}") from refusal


def _open_launch_source(runs: RunsRepository, source_run_id: str) -> Run:
    """The source run, by id, in the request's tenant's natural container — or the refusal,
    before anything is spent. `runs.open` holds `<T>/runs` no-follow (a link there is refused),
    judges its `_tenant.json` against the tenant, and takes only a real directory at the id; a
    path where the id belongs is refused by `RunId.parse`."""
    try:
        return runs.open(RunId.parse(source_run_id))
    except RunRefused as refusal:
        raise LauncherRefused(
            f"[branch] source run {source_run_id!r} of tenant {runs.tenant_id!r}: "
            f"{refusal}") from refusal


def _source_stamp_agrees(source: Run, tenant_id: _tenant.TenantId) -> None:
    """Refuse a source whose provenance stamp names another tenant than the request's. The
    stamp is in the box's writable run dir, so it is never the tenant's authority — the
    request is, and the open judged the runs folder's record against it — but a disagreement is
    refused, not settled, and a stamp with no tenant gets no fallback."""
    stamp = _stamp_of(source)
    if stamp is None:
        raise _no_stamp(source.run_dir)
    if stamp.get("tenant_id") != tenant_id:
        raise LauncherRefused(
            f"[branch] source run {source.run_dir}'s stamp names tenant "
            f"{stamp.get('tenant_id')!r} but the request names {tenant_id!r}, whose runs "
            f"folder's record ({_tenant.TENANT_RECORD_NAME}) the source was opened under — the "
            "stamp is in the box's writable run dir, so a disagreement is refused, not settled")


# ---------------------------------------------------------------------------------------
# `Step.RUNS` — the family as processes
# ---------------------------------------------------------------------------------------


def sibling_argv(
    episode_id: str, world_label: str, *, tenant_id: _tenant.TenantId, model: str | None = None,
) -> list[str]:
    """One sibling's command line: its tenant, its episode and which arm of it this process is
    — ids only, never a path (#1105 PR 2) — and the model.

    Everything else a sibling needs is derived from the episode's manifest, which the child
    opens through the episode owner under the configured episodes root, and the data root from
    the environment it inherits: the child re-accepts its tenant there and holds it to the
    episode container's record. `sys.executable` so the child uses the same venv interpreter.

    The model is not in the manifest, so it is passed here; without it every arm would silently
    agree on the default model rather than the one the preflight checked.
    """
    argv = [sys.executable, str(PATHS.defender_dir / "run.py"),
            # EVERY RUN NAMES ITS TENANT (#1078), a sibling included: the episode's, which this
            # launcher accepted once. The child checks it against the container's record.
            "--tenant", tenant_id, "--episode", episode_id, "--world", world_label]
    if model is not None:
        argv += ["--model", model]
    return argv


#: The exit code recorded for an arm whose process never started (spawn raised, or the
#: rendezvous broke). Distinct from `run.py`'s own 0/1/2 so "never started" is distinguishable
#: from "ran and failed".
SPAWN_FAILED_EXIT = 70


def start_family(  # noqa: PLR0913, C901 — the family's arms, the tenant every arm runs on, the rate they share and the failures already counted
    episode: Episode, world_labels: Sequence[str], *,
    spawn: Callable[..., int] | None = None, model: str | None = None,
    tenant_id: _tenant.TenantId | None, rate: float | None = None, failed_before: int = 0,
) -> dict[str, int]:
    """Start every servable sibling together, and wait for all of them.

    The children are spawned from N threads that rendezvous first, so the arms overlap in time;
    run serially they would be compared across a moving estate, which the primed capture and
    shared T0 exist to prevent.

    Each child's runs base is the episode's container, which the launcher made with the
    episode tenant's record just before (`EpisodeRuns.create_container`): the child reaches it
    through its episode, so the launcher exports no `DEFENDER_RUNS_BASE`, and siblings stay out
    of runs-base walkers' reach. `--tenant` and `--episode` ride on each command line, and the
    child inherits this process's environment — `DEFENDER_DATA_ROOT` and
    `DEFENDER_EPISODES_BASE` with it — and re-accepts.

    `rate` is the episode's tenant-query rate R: each child's environment carries its slice
    R/k as `ORACLE_RATE` (k = the worlds launched, the control included; S18), so the slices sum
    to R and no limiter state crosses a process (S16).

    A child that exits non-zero without its own world record (killed, refused at start, never
    spawned) is recorded `did not finish` by this launcher, after the process is gone (S8).
    Once `failed_before` (pre-flight's unservable worlds) plus the arms that failed reach two,
    the family is unusable (O5) and the arms still running are stopped (N18): the production
    spawn terminates its child; an injected `spawn` seam has no handle on its child and is
    left to finish.
    """
    from defender.tenancy import _tenant
    from defender.learning.core.config import KNOB_RATE

    if tenant_id is None or not _tenant.is_valid_tenant_id(tenant_id):
        # A ValueError, not `LauncherRefused`: `_episode_tenant` already resolved the tenant, so
        # this is a caller bug and takes the episode's normal abort path.
        raise ValueError(
            f"episode {episode.dir} has no usable tenant ({tenant_id!r}) to run its siblings "
            "on — refused before any sibling started")
    stop = threading.Event()
    start = functools.partial(_default_spawn, stop=stop) if spawn is None else spawn
    labels = list(world_labels)
    if not labels:
        return {}
    ready = threading.Barrier(len(labels))
    exits: dict[str, int] = {}
    failed = [failed_before]
    tally = threading.Lock()

    def ended(label: str, code: int, why: str) -> None:
        exits[label] = code
        if not code:
            return
        if outcome_mod.write_world_record(episode, label, outcome_mod.DID_NOT_FINISH,
                                          detail=why):
            _logger.warning(f"world {label}: {why}; recorded as did not finish")
        with tally:
            failed[0] += 1
            if failed[0] >= outcome_mod.UNUSABLE_AT and not stop.is_set():
                _logger.warning(
                    f"episode {episode.dir.name}: {failed[0]} worlds have failed, so the "
                    "family is unusable; stopping the siblings still running")
                stop.set()

    def launch_one(label: str) -> None:
        env = dict(os.environ)
        if rate is not None:
            env[KNOB_RATE] = str(rate / len(labels))
        # Rendezvous first, so "started together" does not depend on the pool's scheduling.
        ready.wait(timeout=30)
        try:
            code = start(sibling_argv(episode.dir.name, label, tenant_id=tenant_id,
                                      model=model), env=env)
        except Exception as never_started:  # noqa: BLE001 — one arm's failure, not the family's
            ended(label, SPAWN_FAILED_EXIT, f"its process never started ({never_started!r})")
            return
        ended(label, code, f"its process exited {code} without a record of its own"
              + (" (stopped: the family became unusable)" if stop.is_set() else ""))

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(labels)) as pool:
        futures = {label: pool.submit(launch_one, label) for label in labels}
    # A thread that died outside `start` (a broken barrier fails all N at once) is recorded as a
    # result, not re-raised: raising would skip `verify_family`, leaving completed siblings
    # unarchived.
    for label, future in futures.items():
        try:
            future.result()
        except Exception as never_started:  # noqa: BLE001 — one arm's failure, not the family's
            if label not in exits:
                ended(label, SPAWN_FAILED_EXIT, f"its process never started ({never_started!r})")
    return exits


#: How long a stopped sibling is given to exit on SIGTERM before it is killed.
_STOP_GRACE_SECONDS = 30.0


def _default_spawn(argv: list[str], *, env: dict[str, str] | None = None,
                   stop: threading.Event | None = None) -> int:
    """Run one sibling to completion in its own process, inheriting nothing but `env`; when
    `stop` is set first (the family became unusable, N18), terminate it and return its exit."""
    import subprocess

    child = subprocess.Popen(argv, env=env)  # noqa: S603 — fixed argv
    while True:
        try:
            return child.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            if stop is None or not stop.is_set():
                continue
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

if _missing := [f for f in _ANCHORED if _HELD[f].off_anchor is None]:
    raise RuntimeError(f"anchored stamp field(s) {_missing} have no refusal text in _HELD_RULES")


# ---------------------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------------------


def parse_branch_args(argv: list[str]) -> argparse.Namespace:
    """The operator's whole command line: a tenant, a source run of it, a branch point, and
    what to say.

    `--tenant` is required, with no default (J8): the tenant comes from the request, never
    from a record or a stamp. The source is named by its run id (O1(d)): the launcher opens it
    through the tenant's repository, so a path where the id belongs is refused. No episode id
    argument: it is derived from the source run and branch point.

    No continuation prompt (#1255 D1, P4): an arm resumes with no user message, so there is no
    instrument text for an operator to author.
    """
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
    return p.parse_args(argv)


def main(  # noqa: PLR0913 — the launcher's inputs plus its injection seams
    argv: list[str],
    *,
    spawn: Callable[..., int] | None = None,
    questioner: Any = None,
    preflight: Callable[..., int] | None = None,
    judge: Any = None,
    lessons_dir: Path | None = None,
    live_tree: Callable[[], _provenance.RunProvenance] | None = None,
    oracle: Any = None,
    verifier: Any = None,
    roster: Any = None,
) -> int:
    """Launch one episode, reporting a refusal as an operator exit rather than a traceback.

    `oracle` / `verifier` are pre-flight's oracle and verifier models (pydantic-ai `Model`s;
    `None` builds each from its knobs, `ORACLE_MODEL` / `ORACLE_CHECK_MODEL`). `roster` is the
    adapters roster pre-flight's grant-decided reader serves through (`None`: the checkout's
    adapters, read once here). The siblings build their own from their own process.

    The delegated checks (source store, branch point, primer, family loader, grant) raise their
    own classes with operator-ready messages; they are converted here. `sqlite3.Error` is
    included because a corrupt source store raises it, not `BranchError`.

    One abort rule: anything else raised before the first sibling starts is also reported as a
    refusal (in `_launch`), naming the episode it ended.
    """
    try:
        return _launch(argv, spawn=spawn, questioner=questioner, preflight=preflight,
                       judge=judge, lessons_dir=lessons_dir, live_tree=live_tree,
                       oracle=oracle, verifier=verifier, roster=roster)
    except (branch.BranchError, LedgerError, EstateError, FamilyError, GrantError,
            session_store.StoreError, sqlite3.Error) as refusal:
        raise LauncherRefused(f"[branch] {refusal}") from refusal


def _launch(  # noqa: PLR0913 — see `main`
    argv: list[str], *, spawn: Any, questioner: Any,
    preflight: Callable[..., int] | None, judge: Any = None,
    lessons_dir: Path | None = None,
    live_tree: Callable[[], _provenance.RunProvenance] | None = None,
    oracle: Any = None, verifier: Any = None, roster: Any = None,
) -> int:
    from defender.run import preflight_role_models

    ns = parse_branch_args(argv)
    # Injected seams are resolved once here and threaded inward non-`None`, so no two frames can
    # disagree about which preflight, roster or model an episode used.
    role_preflight = preflight_role_models if preflight is None else preflight
    # The episode's tenant first, from the request: pre-flight's reader, the served systems,
    # the source run and the siblings all resolve through it.
    try:
        tenant_id = _tenant.requested_tenant_id(ns.tenant)
        data_root = _tenant.resolve_data_root()
    except _tenant.TenantRefused as refusal:
        raise LauncherRefused(f"[branch] {refusal}") from refusal
    tenant = _episode_tenant(tenant_id, data_root)
    runs = tenant.tenant.runs_repository()
    source = _open_launch_source(runs, ns.source_run_id)
    _source_stamp_agrees(source, tenant.tenant_id)
    # N05 / O-20: a tenant whose gather grant serves no system has nothing a world could
    # change. Refused here, before the question-writer or anything else is spent.
    served = served_systems(tenant.grants.gather)
    if not served:
        raise LauncherRefused(
            f"[branch] tenant {tenant.tenant_id!r}: its gather grant serves no system (no read "
            "verb other than health-check is granted), so no world of a branch could be served "
            "— grant gather a read verb on at least one system before branching this tenant")
    # O1: any tenant branches. No system of the lab's is assumed, so a tenant with no
    # corpus-engine part (or one whose part does not resolve) launches like any other.
    # SAME RULE, #1007 M8/O7: production's questioner-lessons root is `PATHS.lessons_
    # questioner_dir`, resolved here rather than as a literal default so a test can hand in a
    # `tmp_path` corpus and this frame is the only one that ever sees the production path.
    questioner_lessons_dir = PATHS.lessons_questioner_dir if lessons_dir is None else lessons_dir
    # Injectable so end-to-end tests aren't compared against the suite's own HEAD. The
    # knowledge half reads the EPISODE tenant's clone, as every sibling's stamp will (#1204 D3).
    live_capture = ((lambda: _provenance.capture_run(REPO_ROOT, tenant.tenant.knowledge))
                    if live_tree is None else live_tree)
    episode_id = episode_id_for(str(source.id), ns.branch_message_id)
    # Checks the id and the configured root before anything is spent.
    try:
        episode_dir(data_root, episode_id)
    except EpisodeRefused as refused:
        raise _owner_refusal(refused) from refused
    source_stamp = preflight_episode(
        source=source, branch_message_id=ns.branch_message_id,
        preflight=role_preflight, model=ns.model,
        allow_dirty=ns.allow_dirty,
        live_tree=live_capture, oracle=oracle, verifier=verifier)
    if roster is None:
        from defender._paths import adapters_under
        from defender.runtime.verbs import read_roster

        roster = read_roster(adapters_under(_DEFENDER_DIR))

    episode = prepare_episode(episode_id, source, data_root=data_root)
    # Set once the first sibling is about to start: past it, the abort message below ("no
    # sibling started") would be false, so anything raised later is re-raised unchanged.
    started = threading.Event()
    with episode:
        try:
            # The episode's view adopts the handle just claimed: its container is created
            # (and T's record written in it) only once the first sibling is about to start.
            view = runs.episode(episode.dir.name, held=episode)
            author = seams.model_seam(episode.dir) if questioner is None else questioner
            return _run_episode(
                ns, source=source, source_stamp=source_stamp, episode=episode, view=view,
                questioner=author, spawn=spawn, judge=judge, lessons_dir=questioner_lessons_dir,
                tenant=tenant, runs=runs, served=served, oracle=oracle,
                verifier=verifier, roster=roster, started=started)
        except SystemExit:
            raise
        except BaseException as failed:  # noqa: BLE001 — one abort rule, see `main`'s docstring
            if started.is_set():
                raise
            raise LauncherRefused(
                f"[branch] episode {episode.dir.name} aborted: {failed!r} — no sibling "
                "started") from failed


def _run_episode(  # noqa: PLR0913 — the episode's whole identity plus its seams
    ns: argparse.Namespace, *, source: Run, source_stamp: dict, episode: Episode,
    view: EpisodeRuns, questioner: Any, spawn: Any, lessons_dir: Path, judge: Any = None,
    tenant: RunTenant, runs: RunsRepository, served: Sequence[str], oracle: Any,
    verifier: Any, roster: Any, started: threading.Event,
) -> int:
    """Every `Step`, `QUESTIONER` through `JUDGE`.

    `source_stamp` is the anchor the launch checks read and judged, handed to `verify_family`
    unchanged. `view` is the episode's view in `runs`, the request's tenant's repository: the
    container is created through it just before the first sibling starts, and every finished
    arm is opened through it by id. Returns 0 when every launched sibling exited cleanly, 1
    otherwise — including an episode pre-flight did not accept, where no sibling ran."""
    from defender.learning.core.config import process_oracle_settings

    episode_id = episode.dir.name
    # One clock for the episode; every step frame is drawn here, in launch order.
    clock = timing_mod.StageClock(episode)
    with clock.step(Step.QUESTIONER):
        try:
            family = _author(ns, source=source, episode=episode, questioner=questioner,
                             lessons_dir=lessons_dir, served=served)
        except (FamilyError, branch.BranchError) as unparsed:
            # N05 / M05=A: nothing to calibrate, for a reason that belongs to no world.
            outcome_mod.write_outcome(
                episode, REFUSED,
                reason=f"the question-writer's family could not be used: {unparsed}")
            raise LauncherRefused(
                f"[branch] episode {episode_id}: the question-writer's family could not be "
                f"used ({unparsed}); recorded as refused in {episode.outcome.path}") from unparsed
    with clock.step(Step.PREFLIGHT):
        record = preflight_replay(episode, source=source, roster=roster, tenant=tenant,
                                  oracle=oracle, verifier=verifier)
    if record["outcome"] != ACCEPTED:
        _logger.info(f"episode {episode_id}: {record['outcome']} before any sibling started "
                     f"({record['reason']})")
        return 1
    unservable = {entry["world"] for entry in record["unservable_worlds"]}
    labels = [w.world_id for w in runnable_worlds(family) if w.world_id not in unservable]
    started.set()
    with clock.step(Step.RUNS):
        # The siblings' container, with T's record, before the first one starts: each
        # sibling's run start judges that record against its own tenant.
        view.create_container()
        exits = start_family(episode, labels, spawn=spawn, model=ns.model,
                             tenant_id=tenant.tenant_id, rate=process_oracle_settings().rate,
                             failed_before=len(unservable))
    finished = [label for label in labels if exits.get(label) == 0]
    with clock.step(Step.VERIFY):
        report = verify_family(
            episode, _finished_arms(view, finished), source=source_stamp,
            allow_dirty=ns.allow_dirty, base_world_id=_container_base_world(view, episode_id))
    failed = sorted(label for label, code in exits.items() if code)
    for label in failed:
        _logger.warning(f"world {label} exited {exits[label]}")
    if not report["comparable"]:
        _logger.warning(f"episode {episode_id}: the family stamp is withheld "
                        f"({report['not_comparable']})")
    elif report["reason"]:
        _logger.warning(f"episode {episode_id}: per-world faults, each on its own world's "
                        f"record ({report['reason']})")
    _logger.info(f"episode {episode_id}: {len(report['archived'])}/{len(labels)} worlds "
                 "archived")
    with clock.step(Step.JUDGE):
        _grade(runs, episode_id=episode_id, judge=judge)
    # Rendered after the JUDGE frame closes so the page sees the judge's timing row;
    # non-fatal.
    _render_page(runs, episode_id=episode_id)
    return 1 if failed else 0


def _finished_arms(view: EpisodeRuns, labels: Sequence[str]) -> dict[str, Run | RunRefused]:
    """Every finished arm, from ONE hold of the episode's container (`view.arms`, its
    `_tenant.json` judged once), each arm judged at its own entry (only a real directory is a
    run) — or the refusal for it, which `verify_family` records as that world's own fault: an
    arm that is missing or not a real directory is its own; a container that went bad after the
    siblings ran is every arm's `RunUnreachable` (or `RunAbsent` when it is gone). A label no
    run id can carry is that arm's `RunRefused`. So no refusal escapes VERIFY."""
    arms: dict[str, Run | RunRefused] = {}
    ids: dict[str, RunId] = {}
    for label in labels:
        try:
            ids[label] = view.arm_id(label)
        except RunRefused as refused:
            arms[label] = refused
    with view.arms(list(ids.values())) as handout:
        for label, arm_id in ids.items():
            arms[label] = handout[arm_id]
    return {label: arms[label] for label in labels}


def _container_base_world(view: EpisodeRuns, episode_id: str) -> str | None:
    """The base world the siblings' container's record names, for the family stamp; `None`
    (logged) when the record cannot be read back — no member stamps it, and the stamp is
    written without it rather than withheld."""
    try:
        return view.base_world_id()
    except (RunRefused, _tenant.TenantRefused) as unread:
        _logger.warning(f"episode {episode_id}: the siblings' container record could not be "
                        f"read back for the family's base world ({unread})")
        return None


def _render_page(runs: RunsRepository, *, episode_id: str) -> None:
    """Render the episode page, by id in the request's tenant's repository. Never fatal to the
    launch: a failure is logged, not raised."""
    try:
        from defender.presentation import visualize_episode

        page = visualize_episode.render_episode(runs, episode_id)
        _logger.info(f"episode {episode_id}: page {page}")
    except Exception as render_failed:  # noqa: BLE001 — a render fault is non-fatal to the launch
        _logger.warning(f"episode {episode_id}: the page could not be rendered "
                        f"({render_failed!r})")


def _grade(runs: RunsRepository, *, episode_id: str, judge: Any) -> None:
    """The grade, the body of the `JUDGE` frame; any failure is logged, never raised. The
    judge opens the episode by id through `runs`, the request's tenant's repository."""
    try:
        from defender.learning import judge as judge_mod
        from defender.learning.core.config import loop_paths
        from defender.learning.core.state import LearningState, StateRefused

        # The root is resolved and opened here, once, and handed to the grade (RF5). A missing
        # root or a refused entry is logged below like any judge failure: grading never fails a
        # launch.
        with LearningState.open(loop_paths()) as state:
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


__all__ = [
    "ACCEPTED",
    "EPISODES_BASE_ENV",
    "Ledger",
    "LedgerError",
    "REFUSED",
    "UNUSABLE",
    "episode_id_for",
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


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    raise SystemExit(main(sys.argv[1:]))
