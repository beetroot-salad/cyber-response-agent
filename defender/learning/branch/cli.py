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
4. **`Step.RUNS`.** On `accepted`, each servable world runs as its own `run.py --resume`
   process, started together under `{episode_dir}/runs/`, each holding an equal slice of the
   episode's query rate. A sibling that exits without its own world record is recorded
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
import json
import logging
import os
import sqlite3
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

# Run by path, so Python puts only `learning/branch/` on `sys.path`: re-exec into the project
# venv when it exists, then add the workspace root before any `defender` import.
_DEFENDER_DIR = Path(__file__).resolve().parents[2]
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender import _provenance
from defender._episode_handle import Episode
from defender._episode_paths import EpisodePaths
from defender._io import (
    NotPlainEntry,
    load_json_artifact,
    read_text_soft,
    read_text_utf8,
)
from defender._paths import PATHS
from defender.run_repository import RunPaths, artifact_file
from defender.runtime.run_tenant import RunTenant
from defender.learning.branch import outcome as outcome_mod
from defender.learning.branch import seams
from defender.learning.branch import timing as timing_mod
from defender.learning.branch.steps import Step
from defender.learning.branch.capture import PrimeReport, prime_base
from defender.learning.branch.estate.registry import EstateError
from defender.learning.branch.ledger import Ledger, LedgerError
from defender import _tenant
from defender.run_common import REPO_ROOT
from defender.runtime import branch, session_store
from defender.runtime.branch import _family
from defender.runtime.branch._family import (
    Family,
    FamilyError,
    check_identities,
    parse_family,
    runnable_worlds,
)
from defender.runtime.verb_grant import GrantError
from defender import _yaml

_logger = logging.getLogger(__name__)

#: Where episodes live. No default: deriving it from the runs base would put `episodes/` inside
#: the tree corpus walkers descend and inside the checkout provenance is stamped from.
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"

#: The words pre-flight's outcome record may hold (`outcome.OUTCOMES`); there is no fourth.
ACCEPTED, UNUSABLE, REFUSED = outcome_mod.ACCEPTED, outcome_mod.UNUSABLE, outcome_mod.REFUSED


class LauncherRefused(SystemExit):
    """An episode this launcher will not run, reported as an operator's exit with an
    explanation rather than a traceback."""


# ---------------------------------------------------------------------------------------
# where an episode lives
# ---------------------------------------------------------------------------------------


def episodes_root(*, tenant: _tenant.Tenant) -> Path:
    """The configured root every episode directory is a child of.

    Must be outside the data root (every tenant's tree lives there, so walkers indexing a
    tenant's runs or episodes would count it) and outside the checkout (or an untracked episode
    dir makes every sibling's provenance stamp dirty, so no family can complete). Being
    configured also keeps it independent of the data root. `tenant` is the launcher's
    accepted `Tenant`, which carries the data root it was accepted under.
    """
    raw = os.environ.get(EPISODES_BASE_ENV)
    if not raw:
        raise LauncherRefused(
            f"[branch] {EPISODES_BASE_ENV} is not set — an episode's directory is a CONFIGURED "
            "location, and there is deliberately no default: derived from the data root it "
            "would be walked by every consumer that indexes a tenant's runs, and derived from "
            "the checkout it would dirty the tree every sibling stamps itself against. Name a "
            "directory outside both")
    # Resolved even when it does not exist yet (every first launch): an unresolved relative path
    # has `.parents == (Path("."),)`, so neither refusal below would fire.
    root = Path(raw)
    candidate = root.resolve()
    data_root = Path(tenant.data_root).resolve()
    for forbidden, why in (
        (data_root, "the data root — every tenant's tree lives there, so an episode inside it "
                    "would be indexed as a tenant's own runs or episodes"),
        (REPO_ROOT, "the checkout — an untracked directory there is what a sibling's own "
                    "provenance stamp reports as a dirty tree"),
    ):
        forbidden = Path(forbidden).resolve()
        if candidate == forbidden or forbidden in candidate.parents:
            raise LauncherRefused(
                f"[branch] {EPISODES_BASE_ENV}={root} resolves inside {why}")
    # A base containing the data root (its parent, say) is refused too; one containing the
    # checkout is not.
    if candidate in data_root.parents:
        raise LauncherRefused(
            f"[branch] {EPISODES_BASE_ENV}={root} contains the data root {data_root} — keep "
            "episodes and tenants' trees apart")
    # Return the resolved path the refusals judged: paths built from it reach child processes,
    # which would re-resolve a relative one against their own cwd.
    return candidate


def refuse_bad_episode_id(episode_id: str) -> None:  # lint-dup: ok — one rule, two error classes: `_family` owns the predicate and raises `FamilyError`; this wrapper raises the operator-facing `SystemExit`
    """`_family.refuse_bad_episode_id`, raised as the launcher's operator-facing refusal."""
    try:
        _family.refuse_bad_episode_id(episode_id)
    except FamilyError as bad:
        raise LauncherRefused(f"[branch] {bad}") from bad


def episode_dir_for(episode_id: str, *, tenant: _tenant.Tenant) -> Path:
    """Where one episode's shared records live.

    A single path component under the configured episodes root. The id is checked here because
    `prepare_episode` writes through this path before anything else judges it; an id carrying a
    separator would plant the capture outside the root or onto another episode's.
    """
    refuse_bad_episode_id(episode_id)
    return episodes_root(tenant=tenant) / episode_id


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


def prepare_episode(
    episode_id: str, source_run_dir: Path, *, tenant: _tenant.Tenant,
    prime: Callable[[Path, Episode], PrimeReport] = _PRIME_ALLOWING_EMPTY,
) -> Episode:
    """Claim a fresh episode directory, prime the family's base into it once, and hand it back
    held open: the launcher's door, whose caller closes it.

    N17: a launch never reuses an episode directory. The derived id is tried first; a name
    already taken (a finished episode, a dead launch's debris, a launch still running beside
    this one) moves on to `<id>-r2`, `<id>-r3`, ... — the exclusive create is the claim, so two
    launchers racing for one name cannot both win it, and nothing a dead launch left is
    adopted. The minted id is the directory's name; every later record derives from it.

    `prime` is injectable so a test can observe whether priming ran; it is handed the episode
    this returns.
    """
    root = episodes_root(tenant=tenant)
    for n in range(1, MAX_LAUNCHES + 1):
        candidate = episode_id if n == 1 else f"{episode_id}-r{n}"
        refuse_bad_episode_id(candidate)
        try:
            episode = Episode.create(root / candidate, exclusive=True)
        except FileExistsError:
            continue
        break
    else:
        raise LauncherRefused(
            f"[branch] {MAX_LAUNCHES} episodes of {episode_id!r} already exist under {root} — "
            "a launch never reuses one; remove the ones you no longer need")
    try:
        _prime_once(episode, episode.dir.name, Path(source_run_dir), prime)
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


def preflight_episode(  # noqa: PLR0913 — every refusal knowable before a model call is asked in this one block
    *, source_run_dir: Path, branch_message_id: int,
    preflight: Callable[..., int], model: str | None,
    continuation_prompt: str, allow_dirty: bool,
    live_tree: Callable[[], _provenance.RunProvenance],
) -> dict:
    """Everything that can refuse before the questioner is paid for, in one block, so an
    operator with several problems hears about them all before spending anything.

    Returns the source's stamp, so later steps use exactly the value judged here: it is the
    anchor `verify_family` compares siblings against; re-reading it from the prior box's rw
    bind could see a changed file.

    `live_tree` returns the checkout's stamp, called at most once; injectable so tests don't
    compare against whatever HEAD the suite runs under. It is only an early exit (siblings stamp
    themselves and `verify_family` compares those) — a launcher on the wrong commit would
    otherwise spend N investigations on a family verify will refuse.

    The role preflight is asked with `branching=True` (M25=A): a branch launch whose oracle or
    oracle-check model cannot be used refuses here, as an operator's configuration error, before
    pre-flight spends anything or charges any world.
    """
    _check_branch_point(source_run_dir, branch_message_id,
                        continuation_prompt=continuation_prompt)
    # The live tree is judged as a one-member family by `verify_family`'s own rules, before the
    # paid role preflight.
    source_stamp = _stamp_of(source_run_dir)
    if source_stamp is None:
        raise _no_stamp(source_run_dir)
    # Capturing the live tree runs git (up to 60 s per call); skip it when the source names no
    # commit, since the refusal is then the source's own.
    members: dict[str, dict | None] = (
        {"the live tree": _as_stamp(live_tree())} if _stamp_speaks(source_stamp) else {})
    refusal = _family_refusal(
        source_stamp, members,
        source_who=f"source run {source_run_dir}", allow_dirty=allow_dirty).refusal
    if refusal is not None:
        raise LauncherRefused(f"[branch] {refusal}")
    # The source run dir is a prior box's rw bind, so a link planted at `alert.json` would copy
    # its target's bytes into the questioner's prompt.
    alert = RunPaths(Path(source_run_dir)).alert
    if not artifact_file(alert):
        raise LauncherRefused(
            f"[branch] source alert {alert} is not a plain file — it is the case input the "
            "questioner is shown and every sibling investigates, and a link wearing its name "
            "would put bytes from outside the source run into a model-facing prompt")
    rc = preflight(model, branching=True)
    if rc:
        raise LauncherRefused(
            f"[branch] the role-model preflight refused (exit {rc}) — every role a branch uses, "
            "the oracle and its verifier included, is checked at launch so a missing key or an "
            "unroutable model surfaces before anything is spent, never as a world's failure")
    return source_stamp


def served_systems(grant: Any) -> list[str]:
    """The systems a branch over this gather grant serves, sorted and once each.

    @owns served_systems — the manifest's `served_systems`, written by `_author` from this and
    nowhere else. M20: a system is served when the grant admits at least one read verb on it
    other than `health-check` (which reaches no data). The live grant still decides every query
    at query time (M21); this list governs the judge, lessons and the question-writer."""
    from defender.runtime.verb_dispositions import HEALTH_CHECK

    return sorted({system for system, verb, verb_class in grant.entries
                   if verb_class == "r" and verb != HEALTH_CHECK})


def _no_stamp(source_run_dir: Path) -> LauncherRefused:
    return LauncherRefused(
        f"[branch] source run {source_run_dir} carries no usable provenance stamp — a "
        "family is anchored to the commit its source ran, and a source with no readable "
        "stamp cannot anchor one")


def _episode_tenant(source_run_dir: Path, data_root: Path) -> RunTenant:
    """The episode's tenant: the source run's, accepted under `data_root` — or the refusal,
    before anything is spent.

    Siblings, the review and the manifest check all use this tenant, so it is read from the
    source's runs-base record (`_tenant.tenant_of_run_dir`), which the box cannot write; the
    stamp in the box's run dir could have been rewritten by a model. The stamp must agree with
    the record, and a stamp with no tenant gets no fallback: a family on a tenant nobody chose
    may not measure the source's estate."""
    from defender import _tenant

    try:
        # The record, at the source's tenant location under the data root, naming a tenant
        # whose row exists (#1078 D3/O5) — a source anywhere else is refused, never trusted,
        # and before its box-writable stamp is read at all. The data root itself is guarded
        # before the record is read.
        tenant_id = _tenant.tenant_of_run_dir(data_root, source_run_dir)
    except _tenant.TenantRefused as refusal:
        raise LauncherRefused(
            f"[branch] source run {source_run_dir}'s tenant: its runs base's record is the "
            f"authority for it, and {refusal}") from refusal
    stamp = _stamp_of(source_run_dir)
    if stamp is None:
        raise _no_stamp(source_run_dir)
    if stamp.get("tenant_id") != tenant_id:
        raise LauncherRefused(
            f"[branch] source run {source_run_dir}'s stamp names tenant "
            f"{stamp.get('tenant_id')!r} but its runs base's record "
            f"({_tenant.record_path(Path(source_run_dir).parent)}) names {tenant_id!r} — the "
            "stamp is in the box's writable run dir, so a disagreement is refused, not settled")
    # The same acceptance a sibling's run start uses, asked once up front so a tenant a sibling
    # would refuse is refused before any spend. Siblings dispatch no turn-0 lead.
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
        raise LauncherRefused(f"[branch] the source run's tenant: {refusal}") from refusal


#: A generous ceiling on any session's message id, far beyond `DEFAULT_REQUEST_LIMIT` times the
#: messages per request. Only a sanity bound: where a store exists, the session itself decides
#: which messages may be branched from.
MAX_BRANCH_MESSAGE_ID = 100 * 60


def _check_branch_point(source_run_dir: Path, branch_message_id: int, *,
                        continuation_prompt: str) -> None:
    """Refuse a branch point the source run could not have produced.

    Where a session store exists, `branch.validate` is asked here — before the questioner is
    paid — rather than only inside each sibling, where every child would refuse identically
    after the whole episode was spent. Some of its preconditions also govern what the
    questioner is shown. `as_of` comes from `branch_point_time`, which `validate`
    cross-checks.

    A source with no session store (imported, replayed, pruned) is still branchable; only the
    range check above applies to it.
    """
    if branch_message_id < 0:
        raise LauncherRefused(
            f"[branch] branch message id {branch_message_id} is negative — it names a message "
            "in the source run's own session, and there is no message before the first")
    if branch_message_id > MAX_BRANCH_MESSAGE_ID:
        raise LauncherRefused(
            f"[branch] branch message id {branch_message_id} is beyond {MAX_BRANCH_MESSAGE_ID}, "
            "the most any one investigation's session could hold — no run produced a message "
            "there, so this is a typo rather than a branch point")
    store = _source_store(Path(source_run_dir))
    if store is None:
        return
    try:
        as_of = branch.branch_point_time(store, Path(source_run_dir), branch_message_id)
        # An empty capture is not refused here: pre-flight records it as a `refused` episode
        # (M05=A), so the operator finds the reason in the outcome record.
        branch.validate(store, branch.BranchSpec(
            source_run_dir=Path(source_run_dir),
            branch_message_id=branch_message_id,
            continuation_prompt=continuation_prompt,
            as_of=as_of,
        ), require_capture=False)
    except branch.BranchError as bad:
        raise LauncherRefused(f"[branch] {bad}") from bad
    finally:
        store.close()


def _source_store(source_run_dir: Path) -> Any:
    """The source run's own session store, or `None` when it does not carry one.

    Only an absent session pointer means "no session". `open_source_store` raises one class
    for both a missing pointer and one that does not reconcile, so the presence check is made
    here and a mismatch still propagates as a refusal rather than silently taking the
    storeless fallback (wrong T0, the finished document's frontier).
    """
    run_dir = Path(source_run_dir)
    if not artifact_file(RunPaths(run_dir).session_pointer):
        return None
    return branch.open_source_store(run_dir)


def branch_point_clock(source_run_dir: Path, branch_message_id: int) -> Any:
    """T0 — the moment every sibling resumes into — derived once for the whole family so the
    siblings share one clock.

    With a session store this is `branch_point_time`. Without one it falls back to the newest
    mtime in the source run dir — the moment its evidence stopped, which is closer to a branch
    point than the launch time.
    """
    import datetime as _dt

    store = _source_store(Path(source_run_dir))
    if store is not None:
        try:
            return branch.branch_point_time(store, Path(source_run_dir), branch_message_id)
        finally:
            store.close()
    newest = max(
        (p.stat().st_mtime for p in Path(source_run_dir).rglob("*") if artifact_file(p)),
        default=Path(source_run_dir).stat().st_mtime)
    return _dt.datetime.fromtimestamp(newest, tz=_dt.UTC).replace(microsecond=0)


# ---------------------------------------------------------------------------------------
# `Step.PREFLIGHT` — calibrating every world through its own oracle
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Original:
    """One distinct call the source run made: replayed once per key (N15)."""

    system: str
    verb: str
    params: dict
    lead_id: str
    #: The capture recorded an error for it (no base answer was primed).
    failed: bool

    @property
    def entry(self) -> dict[str, Any]:
        return {"system": self.system, "verb": self.verb, "params": dict(self.params)}


def _originals(source_run_dir: Path) -> list[_Original]:
    """The source run's calls, first occurrence of each key, in capture order. Sentinels (a
    `∅.` row never reached a system) are not calls (N15)."""
    from defender.learning.branch.ledger import request_key
    from defender.learning.lead_repository import load_queries_report

    rows, _unreadable = load_queries_report(Path(source_run_dir))
    seen: set[str] = set()
    out: list[_Original] = []
    for row in rows:
        if row.is_sentinel or not row.system or not row.verb:
            continue
        key = request_key(row.system, row.verb, row.params)
        if key in seen:
            continue
        seen.add(key)
        out.append(_Original(system=row.system, verb=row.verb, params=dict(row.params),
                             lead_id=row.lead_id, failed=row.exit_code != 0))
    return out


def _not_admitted(reader: Any, call: _Original) -> str | None:
    """Why the live gather grant does not admit `call` for replay, or `None` when it does
    (M22=A: every replayed call goes through `decide`; only read verbs are replayed)."""
    from defender.runtime.verbs import GRANTED, verb_class_of

    try:
        decision = reader.decide(call.system, call.verb)
    except Exception as refused:  # noqa: BLE001 — a grant/declaration disagreement is a refusal
        return f"the grant decision refused it: {refused}"
    if decision.outcome != GRANTED:
        return decision.refusal or f"{call.system}.{call.verb}: {decision.outcome}"
    fn = reader.verbs(call.system).get(call.verb)
    if fn is None or verb_class_of(fn) != "r":
        return f"{call.system}.{call.verb} is not a read verb, and only reads are replayed"
    return None


def _inherited_leads(source_run_dir: Path, branch_message_id: int) -> set[str] | None:
    """The leads the source run held at the branch point (their calls are the fixed prefix,
    M01=A), or `None` for a source with no session store, which cannot say."""
    store = _source_store(Path(source_run_dir))
    if store is None:
        return None
    try:
        session = branch.session_for_run(store, Path(source_run_dir))
        return set(branch.leads_at(store, session, branch_message_id, Path(source_run_dir)))
    finally:
        store.close()


def _preflight_context(episode_dir: Path, tenant: Any, as_of: Any) -> Any:
    """The host-side context pre-flight's reads run in: the episode's tenant record, the
    family's branch-point clock, and no capture (pre-flight is not a run and writes no query
    row). `DEFENDER_RUNS_BASE` is the tenant's runs base, not `run_env`'s `run_dir.parent`."""
    from defender.run_common import DEFENDER_DIR, run_env
    from defender.runtime.verbs import VerbContext

    env = run_env(DEFENDER_DIR, Path(episode_dir))
    runs = getattr(getattr(tenant, "tenant", None), "runs", None)
    if runs is not None:
        env["DEFENDER_RUNS_BASE"] = str(runs)
    return VerbContext(defender_dir=DEFENDER_DIR, run_dir=Path(episode_dir), env=env,
                       capture=None, tenant=tenant, as_of=as_of)


def preflight_replay(  # noqa: C901, PLR0912, PLR0915 — one pass: admit, refuse, read drift, calibrate, record
    episode: Episode | Path, *, roster: Any, tenant: RunTenant, oracle: Any = None,
    verifier: Any = None, **knobs: Any,
) -> dict[str, Any]:
    """`Step.PREFLIGHT`: replay every original call through each fact world's oracle and
    verifier, and write the episode's write-once outcome record (`outcome.write_outcome`).

    Pre-flight only CALIBRATES (Amendment 2 change 1). For each world that carries a fact, every
    replayable original call gets one oracle turn and verifier pass against its base answer
    (`registry.calibrate_one`): the forged rows and recorded facts it verifies are frozen as the
    world's store, so a sibling is later served the same telemetry (O2); no served answer is
    cached and no world-ledger row written (S1). A world whose call cannot be served — retries
    spent, budget spent, or a change to a call made before the branch point (M01=A) — failed
    calibration; once two have failed the family is unusable and no further oracle turn is
    spent on a world still replaying (N18). The control world (`facts: []`) spends nothing.

    Every tenant read goes through `roster` under the live gather grant's decision (a call the
    grant no longer admits is never sent, and is listed `not_replayable`), at the family's
    branch-point clock, and under ONE limiter holding the episode rate for the whole pass
    (S18). Each call is read live once, to compare against the recording (`drift`: `drifted`, or
    `unknown` when the read fails; drift never changes the outcome, N16). A call the capture
    recorded as an error is read live too: still failing, it is the world's own telemetry and
    no oracle's to serve; answering now, it is calibrated against that answer and recorded as
    drift (M22=A).

    `refused` (no world carries a fact, the source made no call, or none is replayable) spends
    no oracle turn. `knobs` are `WorldRegistry`'s (`retry_cap=`, `budget=`, `turn_deadline=`,
    `box=`, `restart_after=`) and `rate=` (the episode rate R; default `ORACLE_RATE`).
    Returns the record as written.
    """
    from defender.learning.branch.estate.limiter import RateLimiter
    from defender.learning.branch.estate.oracle import OracleUnservable
    from defender.learning.branch.estate.registry import (
        PrebranchChanged,
        WorldRegistry,
        calibrate_one,
    )
    from defender.learning.branch.estate.checks import canonical_json
    from defender.learning.branch.ledger import payload_text
    from defender.learning.core.config import process_oracle_settings
    from defender.runtime.verbs import ModuleVerbRegistry

    # The reader first, unguarded: a tenant with no gather grant refuses here (`GrantError`),
    # before anything is read or sent (O-16).
    reader = ModuleVerbRegistry(roster, tenant.grants.gather, grant_home=tenant.table_pointer)
    if not isinstance(episode, Episode):
        with Episode.open(Path(episode)) as held:
            return preflight_replay(held, roster=roster, tenant=tenant, oracle=oracle,
                                    verifier=verifier, **knobs)
    family = _family.load_family(episode.view())
    source = Path(family.source_run_dir)
    originals = _originals(source)
    not_replayable: list[dict[str, Any]] = []
    replayable: list[_Original] = []
    for call in originals:
        why = _not_admitted(reader, call)
        if why is None:
            replayable.append(call)
        else:
            not_replayable.append({**call.entry, "reason": why})
    fact_worlds = [w for w in runnable_worlds(family) if w.facts]

    def record(outcome: str, reason: str, *, unservable: Sequence[Mapping[str, Any]] = (),
               drift: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
        outcome_mod.write_outcome(episode, outcome, reason=reason, unservable_worlds=unservable,
                                  not_replayable=not_replayable, drift=drift)
        return {"outcome": outcome, "reason": reason,
                "unservable_worlds": [dict(u) for u in unservable],
                "not_replayable": list(not_replayable), "drift": [dict(d) for d in drift]}

    # M05=A: nothing to calibrate, for a reason that belongs to no world — refused before any
    # tenant read or oracle turn.
    if not fact_worlds:
        return record(REFUSED, "no world of the family carries a fact, so there is no world "
                               "change to calibrate and nothing a sibling could measure")
    if not originals:
        return record(REFUSED, "the source run made no call that reached a system, so there "
                               "is no original call to replay")
    if not replayable:
        return record(REFUSED, f"none of the source run's {len(originals)} call(s) can be "
                               "replayed: the live gather grant admits none of them (see "
                               "not_replayable)")

    rate = knobs.pop("rate", None)
    limiter = RateLimiter(process_oracle_settings().rate if rate is None else rate)
    ctx = _preflight_context(episode.dir, tenant, family.as_of)
    resumed = {w.world_id: _family.resume_world_from(family, w.world_id, episode.dir)
               for w in fact_worlds}
    recording = Ledger.for_world(episode, resumed[fact_worlds[0].world_id].world_id)
    fixed_leads = _inherited_leads(source, family.branch_message_id)

    drift: list[dict[str, Any]] = []
    calibrated: list[tuple[_Original, Any, bool]] = []
    for call in replayable:
        recorded = recording.base_payload(call.system, call.verb, call.params)
        limiter.acquire()
        try:
            live_text = payload_text(reader.verbs(call.system)[call.verb](ctx, **call.params))
        except Exception:  # noqa: BLE001 — a tenant error on a drift read is drift-unknown (N16)
            if recorded is None:
                # The capture's own failure, still failing: world telemetry, passed through as
                # itself to any sibling that asks (`real-error`), never the oracle's to serve.
                continue
            drift.append({**call.entry, "status": "unknown"})
            base_text = recorded
        else:
            if recorded is None:
                drift.append({**call.entry, "status": "drifted" if call.failed else "unknown"})
                base_text = live_text
            else:
                if canonical_json(json.loads(recorded)) != canonical_json(json.loads(live_text)):
                    drift.append({**call.entry, "status": "drifted"})
                base_text = recorded
        fixed = fixed_leads is not None and call.lead_id in fixed_leads
        calibrated.append((call, json.loads(base_text), fixed))

    stop = threading.Event()
    failures: list[dict[str, Any]] = []
    tally = threading.Lock()

    def fail(label: str, call: _Original, reason: str) -> None:
        with tally:
            failures.append({"world": label, "reason": reason, "call": call.entry})
            if len(failures) >= outcome_mod.UNUSABLE_AT:
                stop.set()

    def calibrate(label: str) -> None:
        world = resumed[label]
        registry = WorldRegistry(
            roster, tenant.grants.gather, world=world,
            ledger=Ledger.for_world(episode, world.world_id), as_of=family.as_of,
            tenant=tenant, grant_home=tenant.table_pointer, oracle=oracle, verifier=verifier,
            limiter=limiter, **knobs)
        try:
            for call, base, fixed in calibrated:
                if stop.is_set():
                    return
                try:
                    calibrate_one(registry, ctx, call.system, call.verb, call.params, base,
                                  fixed=fixed)
                except OracleUnservable as unservable:
                    fail(label, call, f"{unservable.reason}: {unservable.detail}")
                    return
                except PrebranchChanged as changed:
                    fail(label, call, str(changed))
                    return
        finally:
            registry.close()

    # One thread per world: worlds calibrate side by side and finish in any order; the outcome
    # is written once, from every world's result.
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(fact_worlds)) as pool:
        futures = [pool.submit(calibrate, w.world_id) for w in fact_worlds]
    for future in futures:
        # Anything but a world's own failure is the launch's, and leaves no outcome record.
        future.result()

    unservable = sorted(failures, key=lambda entry: entry["world"])
    names = ", ".join(entry["world"] for entry in unservable)
    if len(unservable) >= outcome_mod.UNUSABLE_AT:
        return record(UNUSABLE, f"{len(unservable)} worlds failed calibration ({names}), so "
                                "the family cannot be compared (O5)",
                      unservable=unservable, drift=drift)
    reason = ("every fact world calibrated" if not unservable else
              f"world {names} failed calibration and runs no sibling; the family is graded "
              "on the rest")
    return record(ACCEPTED, reason, unservable=unservable, drift=drift)


# ---------------------------------------------------------------------------------------
# `Step.RUNS` — the family as processes
# ---------------------------------------------------------------------------------------


def sibling_runs_base(episode_dir: Path) -> Path:
    """The runs base each sibling process is handed: inside the episode.

    Runs-base walkers (held-out index, lesson tracer, orientation corpus) cannot tell a sibling
    from a real run, so siblings are kept out of the runs base entirely.
    """
    return EpisodePaths(episode_dir).runs


def sibling_argv(
    episode_dir: Path, world_label: str, *, tenant_id: _tenant.TenantId, model: str | None = None,
) -> list[str]:
    """One sibling's command line: the manifest, which arm of it this process is, its tenant
    and the model.

    Everything else a sibling needs is derived from the manifest, and the data root from the
    environment it inherits: the child re-accepts its tenant there. `sys.executable` so the
    child uses the same venv interpreter.

    The model is not in the manifest, so it is passed here; without it every arm would silently
    agree on the default model rather than the one the preflight checked.
    """
    argv = [sys.executable, str(PATHS.defender_dir / "run.py"),
            "--resume", str(EpisodePaths(episode_dir).family), "--world", world_label,
            # EVERY RUN NAMES ITS TENANT (#1078), a sibling included: the episode's, which this
            # launcher resolved once. The child checks it against the source's record.
            "--tenant", tenant_id]
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

    Each child's runs base is inside the episode: the child derives it from the manifest, so
    the launcher exports no `DEFENDER_RUNS_BASE`, and siblings stay out of runs-base walkers'
    reach. The child's runs-base record is seeded with the episode's `tenant_id` before it
    starts, `--tenant` rides on each command line, and the child inherits this process's
    environment — `DEFENDER_DATA_ROOT` with it — and re-accepts.

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
    from defender import _tenant
    from defender.learning.core.config import KNOB_RATE

    if tenant_id is None or not _tenant.is_valid_tenant_id(tenant_id):
        # A ValueError, not `LauncherRefused`: `_episode_tenant` already resolved the tenant, so
        # this is a caller bug and takes the episode's normal abort path.
        raise ValueError(
            f"episode {episode.dir} has no usable tenant ({tenant_id!r}) to run its siblings "
            "on — refused before any sibling started")
    stop = threading.Event()
    start = functools.partial(_default_spawn, stop=stop) if spawn is None else spawn
    runs = sibling_runs_base(episode.dir)
    episode.runs.ensure()
    # Minted with the episode's tenant, or read back and refused when it names another
    # (`TenantRefused`) — before any sibling started.
    _tenant.ensure_runs_base_record(runs, tenant_id)
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
            code = start(sibling_argv(episode.dir, label, tenant_id=tenant_id, model=model),
                         env=env)
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


# ---------------------------------------------------------------------------------------
# `Step.VERIFY` — verification, the family stamp, and the archive
# ---------------------------------------------------------------------------------------


def _world_label_of(run_dir: Path) -> str:
    """Which arm a sibling's run dir belongs to: the last component of its run id."""
    return Path(run_dir).name.rsplit("-", 1)[-1]


def _scrub_ran(run_dir: Path) -> bool:
    """Did the reap scan walk this sibling's tree and say so?

    Read at the sidecar path beside the run dir: the verdict lives outside the tree it judges,
    where the box that is root on that mount cannot forge it.
    """
    from defender.runtime import scrub as scrub_mod

    verdict = scrub_mod.verdict_path(Path(run_dir))
    if not artifact_file(verdict):
        return False
    try:
        record = json.loads(read_text_utf8(verdict))
    except (OSError, ValueError):
        return False
    return isinstance(record, dict) and record.get("ran") is True


def _stamp_of(run_dir: Path) -> dict | None:
    """A run dir's own provenance record, or `None` when it has none this reader can use.

    Used for both the source and every sibling, so both ends of the comparison share one shape.
    Absent and unreadable both answer `None`: neither is an agreeing stamp.

    Read through `_provenance.read`, which refuses aliases and type-checks fields: the file is
    in a box's rw bind, and a forged `"commit": ["x"]` would otherwise crash `verify_family`
    before anything was archived. Returned as the record's wire-shape mapping, which
    `_write_family_stamp` publishes verbatim.
    """
    record = _provenance.read(RunPaths(Path(run_dir)).provenance)
    return None if record is None else _as_stamp(record)


def _as_stamp(record: _provenance.RunProvenance) -> dict:
    """A typed provenance record as the mapping every comparison below asks."""
    # lint-parse: ok — a round-trip of a typed record through its own `as_json`, not untyped
    # input.
    return json.loads(record.as_json())


#: The kinds of fault `--allow-dirty` waives: a tree git did not certify clean, and tenant
#: knowledge no commit proves (unversioned, unavailable, or not recorded). The family stamp
#: records which of them a waived family actually had (`waived`).
DIRT = "dirt"
UNPROVEN_KNOWLEDGE = "knowledge"


#: One reason a family cannot be archived as a comparison against its source. `kind` is the
#: waivable kind, or `None` for a fault `--allow-dirty` never reaches — so waivability is a
#: property of the fault, not the site.
class _Fault(NamedTuple):
    kind: str | None
    text: str

    @property
    def waivable(self) -> bool:
        return self.kind is not None


#: Every `RunProvenance` field, classed by how the fork check judges it (#1204 D4). The
#: comparison below is driven by this table, and `test_1204` holds its keys to the record's
#: fields, so a new stamp field cannot be silently left out of the check.
#: - `anchored`: each member must match the source, when the source pins a value; siblings
#:   must agree with each other when it does not;
#: - `constant`: siblings must agree with each other;
#: - `dedicated`: judged by its own rule (`_clean_stamp`, `_cross_tenant_fault`);
#: - `informational`: recorded, never compared;
#: - `expected_to_differ`: differs between siblings by design.
STAMP_FIELD_CLASSES: dict[str, str] = {
    "commit": "anchored", "scope": "anchored", "knowledge": "anchored",
    "model": "constant",
    "dirty": "dedicated", "tenant_id": "dedicated",
    "dirty_paths": "informational", "dirty_path_count": "informational",
    "unavailable": "informational",
    "world_id": "expected_to_differ", "parent_run_id": "expected_to_differ",
    "fork_turn": "expected_to_differ",
}

class _HeldRule(NamedTuple):
    """How the fork check holds one `anchored` or `constant` field: the value compared, the
    waivable kind a stamp with no such value is faulted as (`None`: an absent value is just a
    value), and, for an anchored field, the refusal for a member off the source's value."""

    compared: Callable[[dict], object]
    unknown_kind: str | None = None
    off_anchor: Callable[[str, object, object], str] | None = None


def _knowledge_commit(stamp: dict) -> str | None:
    """Knowledge is compared as its commit alone, so two unavailable reasons with different
    text are not a disagreement."""
    revision = _provenance.KnowledgeRevision.from_wire(stamp.get("knowledge"))
    return None if revision is None else revision.commit


def _off_commit(who: str, got: object, want: object) -> str:
    return (f"{who} is at commit {got!r} while the source run it continues ran at {want!r} — a "
            "family is anchored to its source's commit, and a comparison against other code is "
            "never archived as comparable")


def _off_scope(who: str, got: object, want: object) -> str:
    return (f"the dirt of {who} was measured over scope {got!r} and the source's over {want!r} "
            "— the two clean bits answer different questions, so agreeing on the commit does not "
            "make them a match")


def _off_knowledge(who: str, got: object, want: object) -> str:
    return (f"{who} read tenant knowledge at commit {got!r} while the source run it continues "
            f"read {want!r} — a family is anchored to the knowledge its source read, and a "
            "comparison against other settings and lessons is never archived as comparable")


#: The rule of every held field that is more than "compare the value as recorded". An anchored
#: field must have one (its refusal text), which is held at import below, so no anchored field
#: falls back to a vague message.
_HELD_RULES: dict[str, _HeldRule] = {
    "commit": _HeldRule(compared=lambda stamp: stamp.get("commit"), off_anchor=_off_commit),
    "scope": _HeldRule(compared=lambda stamp: stamp.get("scope"), off_anchor=_off_scope),
    "knowledge": _HeldRule(compared=_knowledge_commit, unknown_kind=UNPROVEN_KNOWLEDGE,
                           off_anchor=_off_knowledge),
}


def _as_recorded(field: str) -> _HeldRule:
    return _HeldRule(compared=lambda stamp: stamp.get(field))


_ANCHORED = tuple(f for f, c in STAMP_FIELD_CLASSES.items() if c == "anchored")
_HELD = {f: _HELD_RULES.get(f) or _as_recorded(f)
         for f, c in STAMP_FIELD_CLASSES.items() if c in ("anchored", "constant")}
if _missing := [f for f in _ANCHORED if _HELD[f].off_anchor is None]:
    raise RuntimeError(f"anchored stamp field(s) {_missing} have no refusal text in _HELD_RULES")


def _unknown_faults(who: str, stamp: dict) -> list[_Fault]:
    """The waivable faults of a stamp with no value on a field whose unknown is its own fault."""
    return [_Fault(rule.unknown_kind, _unprovable(field, who, stamp))
            for field, rule in _HELD.items()
            if rule.unknown_kind is not None and rule.compared(stamp) is None]


def _family_faults(
    source: dict, members: dict[str, dict | None], *, source_who: str,
) -> list[_Fault]:
    """Every reason `members` are not provably one family continuing `source`.

    One judgement for both tiers: at preflight the members are the live tree alone, at verify
    the siblings' stamps. Verify re-judges the source rather than trusting that preflight ran.

    The source is checked first; a source with no commit ends anchoring there, so the fault
    names the source rather than the members. Each member must match the source on every
    `anchored` field the source pins (`STAMP_FIELD_CLASSES`), and any non-clean tree on either
    side is a fault — an unknown is not clean. Members must also agree with each other on every
    `constant` field, and on each anchored field the source does not pin.

    Waivable: dirt, and knowledge nothing proves (unversioned, unavailable, or not recorded —
    a source stamped before #1204 must stay forkable). A wrong or missing commit, a different
    scope or knowledge commit, or siblings disagreeing is a confound, and a silent member waived
    would drop out of the agreement and let another arm's value stand as the family's.
    """
    faults: list[_Fault] = []
    anchored = _stamp_speaks(source)
    if not anchored:
        faults.append(_Fault(None, (
            f"{source_who} names no commit (unavailable={source.get('unavailable')!r}) — a "
            "family is anchored to the commit its source ran, and there is none to anchor to")))
    else:
        if not _clean_stamp(source):
            faults.append(_Fault(DIRT, _not_certified_clean(source_who, source)))
        faults.extend(_unknown_faults(source_who, source))
    for who, stamp in members.items():
        faults.extend(_member_faults(who, stamp, anchor=source if anchored else None))
    # Agreement is over every stamp that names a commit, dirty ones included: excluding dirty
    # arms would let `--allow-dirty` waive the whole agreement, since siblings share one
    # checkout and are all dirty together.
    comparable = {who: stamp for who, stamp in members.items()
                  if stamp is not None and _stamp_speaks(stamp)}
    for field, rule in _HELD.items():
        # A field the anchor pinned was compared member by member above.
        if anchored and field in _ANCHORED and rule.compared(source) is not None:
            continue
        values = {who: rule.compared(stamp) for who, stamp in comparable.items()}
        if rule.unknown_kind is not None:
            # An unknown here is its own (waivable) fault, not a disagreeing value.
            values = {who: value for who, value in values.items() if value is not None}
        if len(set(values.values())) > 1:
            faults.append(_Fault(None, (
                f"siblings disagree on {field}: {values} — the family is held constant on it, "
                "so a comparison across two values is never archived as comparable")))
    return faults


def _member_faults(who: str, stamp: dict | None, *, anchor: dict | None) -> list[_Fault]:
    """One tree's faults against the anchor. `anchor` is `None` when the source could not
    anchor (already reported); the tree is then judged on its own stamp alone."""
    if stamp is None:
        return [_Fault(None, (
            f"{who} carries no readable provenance stamp — an absent or unreadable stamp is "
            "not an agreeing one"))]
    if not _stamp_speaks(stamp):
        return [_Fault(None, (
            f"{who} names no commit (unavailable={stamp.get('unavailable')!r}) — a silent "
            "stamp cannot be held to anything"))]
    faults: list[_Fault] = []
    for field in _ANCHORED:
        rule = _HELD[field]
        want = None if anchor is None else rule.compared(anchor)
        got = rule.compared(stamp)
        # The source pins nothing here, or the member's unknown is its own fault (below).
        if want is None or (got is None and rule.unknown_kind is not None):
            continue
        if got != want and rule.off_anchor is not None:
            faults.append(_Fault(None, rule.off_anchor(who, got, want)))
    faults.extend(_unknown_faults(who, stamp))
    if not _clean_stamp(stamp):
        faults.append(_Fault(DIRT, _not_certified_clean(who, stamp)))
    return faults


def _unprovable(field: str, who: str, stamp: dict) -> str:
    """The waivable fault text for a stamp with no value on `field` (today only knowledge)."""
    revision = _provenance.KnowledgeRevision.from_wire(stamp.get(field))
    if revision is None:
        what = f"records no tenant {field} revision (stamped before #1204, or it does not say)"
    elif revision.unavailable is not None:
        what = f"could not name its tenant {field} commit ({revision.unavailable})"
    else:
        what = f"read an unversioned tenant {field} folder"
    return (f"{who} {what} — nothing proves it read the same {field} as the rest of the "
            "family")


def _not_certified_clean(who: str, stamp: dict) -> str:
    return (f"{who} was not certified clean by git (dirty={stamp.get('dirty')!r}, "
            f"commit={stamp.get('commit')!r}, unavailable={stamp.get('unavailable')!r}) — its "
            "commit does not name the bytes that ran")


class _Judgement(NamedTuple):
    #: The faults `--allow-dirty` did not waive, as one refusal — or `None`.
    refusal: str | None
    #: The kinds of fault the flag waived, sorted; `[]` when nothing was waived.
    waived: list[str]


def _family_refusal(
    source: dict, members: dict[str, dict | None], *, source_who: str, allow_dirty: bool,
) -> _Judgement:
    """The family's faults as one refusal, and the kinds the override waived.

    Non-waivable faults are listed first, and `--allow-dirty` is suggested only when passing it
    would let the family through; fault messages themselves never mention the flag.
    """
    found = _family_faults(source, members, source_who=source_who)
    waived = sorted({f.kind for f in found if f.kind is not None}) if allow_dirty else []
    faults = [fault for fault in found if not (fault.waivable and allow_dirty)]
    if not faults:
        return _Judgement(None, waived)
    text = "; ".join(fault.text for fault in sorted(faults, key=lambda fault: fault.waivable))
    if all(fault.waivable for fault in faults):
        text += " — pass --allow-dirty to waive these faults, recorded in the family stamp as such"
    return _Judgement(text, waived)


def _clean_stamp(stamp: dict | None) -> bool:
    """Did git answer for this sibling's tree, and say it was clean?

    Only `dirty is False` with a commit counts; a dirty tree, an unreachable git, or a sha with
    no answer for the tree are all unknowns, and an unknown is not clean.
    """
    if stamp is None:
        return False
    return stamp.get("dirty") is False and bool(stamp.get("commit"))


def _stamp_speaks(stamp: dict | None) -> bool:
    """Did git answer at all for this tree — whatever it said about dirt?

    The agreement is taken over stamps that speak. A stamp with no commit is a silence, held to
    nothing and never waived; a dirty stamp still speaks.
    """
    return stamp is not None and bool(stamp.get("commit"))


def verify_family(
    episode: Episode, run_dirs: Sequence[Path], *, source: dict, allow_dirty: bool = False,
) -> dict:
    """Check every sibling, archive each verified one, and write the family stamp when every
    check holds.

    `source` is the source run's stamp as judged by `preflight_episode`. Required with no
    default, so siblings are always held to the source's commit rather than only to each other.

    Runs only after an `accepted` pre-flight (no sibling starts otherwise), and never touches
    the outcome record pre-flight wrote (S6). Only scrub-verified worlds are archived, each on
    its own: a world whose tree the archive refuses is one the judge cannot see, and gets its
    own `not archived` record (S10) while the others are still archived. Any fault withholds
    the family stamp, and is returned (and logged by the caller) as the reason.
    """
    from defender.learning.branch import archive as archive_mod

    dirs = {_world_label_of(d): Path(d) for d in run_dirs}
    scrub_verified = [label for label in dirs if _scrub_ran(dirs[label])]
    unverified = sorted(set(dirs) - set(scrub_verified))
    stamps = {label: _stamp_of(path) for label, path in dirs.items()}

    reasons: list[str] = []
    if not dirs:
        reasons.append("the family has no sibling — a comparison over no arm is not one, so "
                       "there is nothing to hold to the source's commit or to archive")
    if unverified:
        reasons.append(
            f"sibling(s) {unverified} have no scrub verdict recording a completed walk — an "
            "unwalked tree is one nothing has certified as free of what the box left behind")
    judged = _family_refusal(
        source, {f"sibling {label!r}": stamps[label] for label in scrub_verified},
        source_who="the source run", allow_dirty=allow_dirty)
    if judged.refusal is not None:
        reasons.append(judged.refusal)
    cross_tenant = _cross_tenant_fault(stamps, scrub_verified)
    if cross_tenant is not None:
        reasons.append(cross_tenant)

    # `worlds/` exists whatever happens below; a world's own record says why one is missing.
    episode.worlds.ensure()
    archived: list[str] = []
    for label in sorted(scrub_verified):
        try:
            archive_mod.archive_episode(episode, {label: dirs[label]})
        except Exception as refused:  # noqa: BLE001 — one world's archive, recorded; the rest go on
            reasons.append(f"world {label}'s tree could not be archived ({refused})")
            outcome_mod.write_world_record(
                episode, label, outcome_mod.NOT_ARCHIVED,
                detail=f"the archive refused its finished tree: {refused}")
            continue
        archived.append(label)

    reason = "; ".join(reasons)
    if not reasons:
        _write_family_stamp(
            episode, stamps, source=source, allow_dirty=allow_dirty, waived=judged.waived,
            dirs=dirs)
    return {"comparable": not reasons, "reason": reason, "scrub_verified": scrub_verified,
            "archived": archived, "worlds": sorted(dirs)}


def _cross_tenant_fault(stamps: dict[str, dict | None], labels: Sequence[str]) -> str | None:
    """Siblings disagreeing on `tenant_id`, or a mix of stamps with and without the field.

    A missing field is its own fault, never treated as agreeing. Siblings with no readable
    stamp are skipped (`_member_faults` reports them) and the skip count is recorded."""
    readable: dict[str, dict] = {
        label: stamp for label in labels
        if isinstance(stamp := stamps.get(label), dict)}
    skipped = len(labels) - len(readable)
    no_field = sorted(label for label, s in readable.items() if s.get("tenant_id") is None)
    # All siblings silent on tenant (older stamps) is fine; only a mix is a fault.
    if no_field and len(no_field) == len(readable):
        no_field = []
    parts: list[str] = []
    if no_field:
        parts.append(
            f"sibling(s) {no_field} carry no tenant field at all — treated as its own named "
            "fault, never as agreeing with the rest")
    else:
        values = {label: s.get("tenant_id") for label, s in readable.items()}
        if len(set(values.values())) > 1:
            parts.append(f"siblings disagree on tenant: {values}")
    if skipped:
        # Recorded so an unstamped sibling cannot silently shrink the comparison. Always
        # accompanies `_member_faults`'s own fault for that sibling, so this note alone never
        # makes a family incomplete.
        parts.append(
            f"the cross-tenant comparison ran over the {len(readable)} sibling(s) already "
            f"stamped and skipped {skipped} unstamped one(s)")
    return "; ".join(parts) if parts else None


def _write_family_stamp(
    episode: Episode, stamps: dict[str, dict | None], *, source: dict, allow_dirty: bool,
    waived: list[str] | None = None, dirs: dict[str, Path] | None = None,
) -> None:
    """The family's one stamp: what every sibling agreed on, what it was anchored to, and
    whether it was waved through.

    @owns source — the family stamp's `source` key, the source run's whole provenance record as
    `_stamp_of` read it at preflight. Copied verbatim so a waived dirty source shows
    `source.dirty` beside `allow_dirty`, and the archive never reads as anchored to a clean sha.

    @owns waived — the family stamp's `waived` key: the kinds of fault (`DIRT`,
    `UNPROVEN_KNOWLEDGE`) `--allow-dirty` actually waived for this family, from
    `_family_refusal`'s judgement; `[]` when nothing was. `allow_dirty` alone cannot tell a
    dirty-code family from one whose source merely predates the knowledge stamp.

    The agreed record (about the siblings), the source (what they were held to) and the
    override (the operator's flag, and what it waived) are kept separate so a clean family and
    a waived one read differently.
    """
    present = [stamp for stamp in stamps.values() if stamp is not None]
    # Every held field is the agreed record's, since `_family_refusal` passed: the first
    # sibling's value, except where an unknown is its own waived fault — there the agreed value
    # is one a sibling actually named, or `None` when none did. Dirt fields may differ under
    # `--allow-dirty` and here are the first sibling's; each sibling's own is archived in
    # `worlds/<label>/provenance.json`. `verify_family` guarantees at least one sibling.
    agreed = {k: v for k, v in present[0].items() if k != "world_id"}
    for field, rule in _HELD.items():
        if rule.unknown_kind is not None:
            agreed[field] = next(
                (stamp.get(field) for stamp in present if rule.compared(stamp) is not None), None)
    # The family's base world, from the tenant record at the siblings' runs base: no member
    # stamps it, and lessons attribution keys on it.
    base_world_id = _family_base_world_id(dirs)
    doc: dict[str, object] = {
        "agreed": agreed, "allow_dirty": bool(allow_dirty), "source": dict(source),
        "waived": list(waived or [])}
    if base_world_id is not None:
        doc["base_world_id"] = base_world_id
    episode.family_stamp.write(
        json.dumps(doc, indent=2, sort_keys=True) + "\n")


def _family_base_world_id(dirs: dict[str, Path] | None) -> str | None:
    """The family's base world, from the tenant record at the siblings' shared runs base."""
    from defender import _tenant

    if not dirs:
        return None
    run_dir = next(iter(dirs.values()))
    try:
        return _tenant.read_tenant(Path(run_dir).parent).base_world_id
    except Exception:  # noqa: BLE001 — best-effort; the family stamp is not blocked on it
        return None


# ---------------------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------------------


def parse_branch_args(argv: list[str]) -> argparse.Namespace:
    """The operator's whole command line: a source run, a branch point, and what to say.

    No episode id argument: it is derived from the source run and branch point.

    The continuation prompt is required because it is part of the measured instrument (its
    wording can bias siblings toward closing over gathering), and nothing else should author it.
    """
    p = argparse.ArgumentParser(prog="branch", description=__doc__)
    p.add_argument("source_run_dir", type=Path, help="the finished run to fork")
    p.add_argument("branch_message_id", type=int, help="the message to resume from")
    p.add_argument(
        "--continuation-prompt", required=True,
        help="what every sibling is told on arrival — part of the measured instrument, so it is "
             "the operator's rather than the seam's")
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
    # The episode's tenant first: pre-flight's reader, the served systems and the siblings all
    # resolve through it.
    source = Path(ns.source_run_dir).resolve()
    try:
        data_root = _tenant.resolve_data_root()
    except _tenant.TenantRefused as refusal:
        raise LauncherRefused(f"[branch] {refusal}") from refusal
    tenant = _episode_tenant(source, data_root)
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
    runs_base = tenant.tenant.runs
    # SAME RULE, #1007 M8/O7: production's questioner-lessons root is `PATHS.lessons_
    # questioner_dir`, resolved here rather than as a literal default so a test can hand in a
    # `tmp_path` corpus and this frame is the only one that ever sees the production path.
    questioner_lessons_dir = PATHS.lessons_questioner_dir if lessons_dir is None else lessons_dir
    # Injectable so end-to-end tests aren't compared against the suite's own HEAD. The
    # knowledge half reads the EPISODE tenant's clone, as every sibling's stamp will (#1204 D3).
    live_capture = ((lambda: _provenance.capture_run(REPO_ROOT, tenant.tenant.knowledge))
                    if live_tree is None else live_tree)
    episode_id = episode_id_for(source.name, ns.branch_message_id)
    # Checks the id and the configured root before anything is spent.
    episode_dir_for(episode_id, tenant=tenant.tenant)
    source_stamp = preflight_episode(
        source_run_dir=source, branch_message_id=ns.branch_message_id,
        preflight=role_preflight, model=ns.model,
        continuation_prompt=ns.continuation_prompt, allow_dirty=ns.allow_dirty,
        live_tree=live_capture)
    if roster is None:
        from defender._paths import adapters_under
        from defender.runtime.verbs import read_roster

        roster = read_roster(adapters_under(_DEFENDER_DIR))

    episode = prepare_episode(episode_id, source, tenant=tenant.tenant)
    # Set once the first sibling is about to start: past it, the abort message below ("no
    # sibling started") would be false, so anything raised later is re-raised unchanged.
    started = threading.Event()
    with episode:
        try:
            author = seams.model_seam(episode.dir) if questioner is None else questioner
            return _run_episode(
                ns, source=source, source_stamp=source_stamp, episode=episode,
                questioner=author, spawn=spawn, judge=judge, lessons_dir=questioner_lessons_dir,
                tenant=tenant, runs_base=runs_base, served=served, oracle=oracle,
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
    ns: argparse.Namespace, *, source: Path, source_stamp: dict, episode: Episode,
    questioner: Any, spawn: Any, lessons_dir: Path, judge: Any = None, tenant: RunTenant,
    runs_base: Path, served: Sequence[str], oracle: Any, verifier: Any, roster: Any,
    started: threading.Event,
) -> int:
    """Every `Step`, `QUESTIONER` through `JUDGE`.

    `source_stamp` is the anchor the launch checks read and judged, handed to `verify_family`
    unchanged. Returns 0 when every launched sibling exited cleanly, 1 otherwise — including an
    episode pre-flight did not accept, where no sibling ran."""
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
        record = preflight_replay(episode, roster=roster, tenant=tenant, oracle=oracle,
                                  verifier=verifier)
    if record["outcome"] != ACCEPTED:
        _logger.info(f"episode {episode_id}: {record['outcome']} before any sibling started "
                     f"({record['reason']})")
        return 1
    unservable = {entry["world"] for entry in record["unservable_worlds"]}
    labels = [w.world_id for w in runnable_worlds(family) if w.world_id not in unservable]
    started.set()
    with clock.step(Step.RUNS):
        exits = start_family(episode, labels, spawn=spawn, model=ns.model,
                             tenant_id=tenant.tenant_id, rate=process_oracle_settings().rate,
                             failed_before=len(unservable))
    runs = sibling_runs_base(episode.dir)
    finished = [label for label in labels if exits.get(label) == 0]
    with clock.step(Step.VERIFY):
        report = verify_family(
            episode, [runs / f"{episode_id}-{label}" for label in finished],
            source=source_stamp, allow_dirty=ns.allow_dirty)
    failed = sorted(label for label, code in exits.items() if code)
    for label in failed:
        _logger.warning(f"world {label} exited {exits[label]}")
    if not report["comparable"]:
        _logger.warning(f"episode {episode_id}: the family stamp is withheld "
                        f"({report['reason']})")
    _logger.info(f"episode {episode_id}: {len(report['archived'])}/{len(labels)} worlds "
                 "archived")
    with clock.step(Step.JUDGE):
        _grade(episode.dir, episode_id=episode_id, judge=judge, runs_base=runs_base)
    # Rendered after the JUDGE frame closes so the page sees the judge's timing row;
    # non-fatal.
    _render_page(episode.dir, episode_id=episode_id)
    return 1 if failed else 0


def _render_page(episode_dir: Path, *, episode_id: str) -> None:
    """Render the episode page. Never fatal to the launch: a failure is logged, not raised."""
    try:
        from defender.scripts.visualize import visualize_episode

        page = visualize_episode.render_episode(episode_dir)
        _logger.info(f"episode {episode_id}: page {page}")
    except Exception as render_failed:  # noqa: BLE001 — a render fault is non-fatal to the launch
        _logger.warning(f"episode {episode_id}: the page could not be rendered "
                        f"({render_failed!r})")


def _grade(episode_dir: Path, *, episode_id: str, judge: Any, runs_base: Path) -> None:
    """The grade, the body of the `JUDGE` frame; any failure is logged, never raised.
    `runs_base` is the tenant's, threaded from the launcher."""
    try:
        from defender.learning import judge as judge_mod
        from defender.learning.core.config import loop_paths
        from defender.learning.core.state import LearningState, StateRefused

        # The root is resolved and opened here, once, and handed to the grade (RF5). A missing
        # root or a refused entry is logged below like any judge failure: grading never fails a
        # launch.
        with LearningState.open(loop_paths()) as state:
            judge_mod.grade_episode(episode_dir, judge=judge, runs_base=runs_base, state=state)
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


def write_questioner_samples(episode: Episode, samples: Mapping[str, Any]) -> Path:
    """Write `samples.yaml`, the per-system samples document (`system_samples`), into the
    episode, so the judge is shown the same bytes the question-writer was even after the source
    run is pruned. Normalised to one `dict` before dumping, so the file never relies on a YAML
    loader's handling of repeated keys."""
    record = episode.samples
    record.write(_yaml.safe_dump(dict(samples), sort_keys=False, allow_unicode=True,
                                default_flow_style=False))
    return record.path


#: How many example answers one verb of one system keeps.
_SAMPLES_PER_VERB = 2
#: The most characters one example answer keeps; a longer one is cut, with a marker saying so.
_SAMPLE_CAP = 4000


def system_samples(source_run_dir: Path, served_systems: Sequence[str]) -> dict[str, dict]:
    """The samples document: real example answers from the source run's capture, keyed by
    served system and grouped per verb (O16, N26).

    @owns samples — the shipped `samples.yaml` shape: `{<system>: {verbs: {<verb>: [<answer
    text>, ...]}}}`, or `{<system>: {unavailable: <reason>}}` when the system's captured answers
    could not be read. Every served system has a section, one the capture never asked included
    (an empty `verbs`); a captured system the tenant no longer serves has none. Which verbs
    exist is whatever the capture called, never a verb-name heuristic.

    Each example is the answer's canonical JSON, ASCII-escaped (no raw control or binary byte
    survives), cut at `_SAMPLE_CAP` characters with a marker. The source run dir is a prior
    box's rw bind, so every read is the screened surface (`lead_repository`), and a read fault
    is an `unavailable` reason, never a crash.
    """
    from defender.learning.lead_repository import load_queries_report

    served = list(dict.fromkeys(served_systems))
    rows, unreadable = load_queries_report(Path(source_run_dir))
    if unreadable and not rows:
        reason = (f"the source run's queries table could not be read ({unreadable} unreadable "
                  "record(s)), so no answer was captured to show")
        return {system: {"unavailable": reason} for system in served}
    verbs: dict[str, dict[str, list[str]]] = {system: {} for system in served}
    lost: dict[str, int] = dict.fromkeys(served, 0)
    for row in rows:
        if row.system not in verbs or row.is_sentinel or row.exit_code != 0:
            continue
        kept = verbs[row.system].get(row.verb, [])
        if len(kept) >= _SAMPLES_PER_VERB:
            continue
        text = _sample_text(row.raw_ref)
        if text is None:
            lost[row.system] += 1
            continue
        verbs[row.system][row.verb] = [*kept, text]
    out: dict[str, dict] = {}
    for system in served:
        if not verbs[system] and lost[system]:
            out[system] = {"unavailable": f"{lost[system]} captured {system} answer(s) could "
                                          "not be read back from the source run"}
        else:
            out[system] = {"verbs": verbs[system]}
    return out


def _sample_text(source_answer: Path | None) -> str | None:
    """One captured answer (a file in the source run) as sample text, or `None` when it cannot
    be read as JSON."""
    if source_answer is None:
        return None
    text = read_text_soft(source_answer)[0]
    if text is None:
        return None
    payload, unreadable = load_json_artifact(text)
    if unreadable is not None:
        return None
    shown = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
    if len(shown) > _SAMPLE_CAP:
        shown = (f"{shown[:_SAMPLE_CAP]} ... [cut: the answer is {len(shown)} characters, the "
                 f"first {_SAMPLE_CAP} are shown]")
    return shown


def _author(  # noqa: PLR0913 — the step's inputs
    ns: argparse.Namespace, *, source: Path, episode: Episode, questioner: Any,
    lessons_dir: Path, served: Sequence[str],
) -> Family:
    """`Step.QUESTIONER`: the questioner authors the family, and it is validated before anything
    reads it.

    The launcher's derived fields (episode id, source run, branch point, T0, continuation prompt,
    served systems) overwrite whatever the model returned, so a family cannot name a different
    source, or a different set of served systems, than it was authored from. One identity gate
    runs over the whole manifest before it is written."""
    from defender._corpus import iter_lesson_paths
    from defender.learning.branch import questioner as questioner_mod
    from defender.learning.lead_repository import joined, questioner_leads

    as_of = branch_point_clock(source, ns.branch_message_id)
    fences = _fence_count(source, ns.branch_message_id,
                          continuation_prompt=ns.continuation_prompt, as_of=as_of)
    leads = _joined_leads(source, joined)
    samples = system_samples(source, served)
    # Archived before the model call, so the judge sees exactly what the questioner saw.
    write_questioner_samples(episode, samples)
    # Paths only; `author_family` opens and screens them.
    lessons = iter_lesson_paths(lessons_dir)
    # The question-writer's own keywords (`stageable_patterns`, `corpus_samples`) are renamed
    # with its prompt (#1224's question-writer stage); handed the served systems and the
    # per-system samples here.
    document = questioner_mod.author_family(
        source_run_dir=source, episode_dir=episode.dir,
        invoke=questioner,
        leads=questioner_leads(leads),
        alert=_alert_document(source),
        frontier=questioner_mod.read_frontier(source, fences_at=fences),
        stageable_patterns=tuple(served),
        corpus_samples=samples,
        lessons=lessons,
    )
    document.update({
        "episode_id": episode.dir.name,
        "source_run_dir": str(source),
        "source_run_id": source.name,
        "branch_message_id": ns.branch_message_id,
        "fences_at": fences,
        "as_of": as_of.isoformat().replace("+00:00", "Z"),
        "continuation_prompt": ns.continuation_prompt,
        # The tenant's served systems as this launch's grant decided them (`served_systems`):
        # the judge, lessons and question-writer read them from here (M21).
        "served_systems": list(served),
    })
    family = parse_family(document)
    check_identities(family)
    _family.write_family(episode, document)
    return family


def _fence_count(source: Path, branch_message_id: int, *,
                 continuation_prompt: str, as_of: Any) -> int:
    """How many invlang fences the source run's document closed at the branch point.

    Through `branch.fence_count_at`: the document says how many fences the run ever wrote,
    and only the session says which had landed by the branch message. A source with no session
    store falls back to the document's total, as `branch_point_clock` falls back to its last
    mtime.
    """
    from defender.runtime.branch import BranchSpec, fence_count_at, source_session
    from defender.skills.invlang.parser import scan_fences

    path = RunPaths(source).investigation
    if not artifact_file(path):
        return 0
    document = read_text_utf8(path)
    total = len(scan_fences(document).bodies)  # lint-row-drop: ok — a count of fences, not a read of their content; `fence_count_at` below answers whenever a session exists  # noqa: E501
    store = _source_store(source)
    if store is None:
        return total
    try:
        spec = BranchSpec(source_run_dir=Path(source), branch_message_id=branch_message_id,
                          continuation_prompt=continuation_prompt, as_of=as_of)
        return fence_count_at(store, source_session(store, spec), branch_message_id, document)
    finally:
        store.close()


def _joined_leads(source: Path, joined: Callable[[Path], list[Any]]) -> list[Any]:
    """`lead_repository.joined` over the source: the launcher's one read of the two tables.

    The surface already absorbs bad content; what can still raise is the host (a directory it
    refuses to walk), which yields a thinner prompt rather than no episode."""
    try:
        return joined(source)
    except Exception as unreadable:  # noqa: BLE001 — a fault at the read is a thinner prompt, not no episode
        _logger.warning(f"could not join the source's leads ({unreadable!r}); the questioner is "
                        "shown none")
        return []


def _alert_document(source: Path) -> dict:
    """The source run's alert, already screened by the preflight."""
    path = RunPaths(source).alert
    try:
        text = read_text_utf8(path)
    except OSError:
        return {}
    loaded, unreadable = load_json_artifact(text)
    return loaded if unreadable is None and isinstance(loaded, dict) else {}


__all__ = [
    "ACCEPTED",
    "EPISODES_BASE_ENV",
    "Ledger",
    "LedgerError",
    "REFUSED",
    "UNUSABLE",
    "episode_dir_for",
    "episode_id_for",
    "episodes_root",
    "main",
    "parse_branch_args",
    "preflight_replay",
    "prepare_episode",
    "refuse_bad_episode_id",
    "sibling_argv",
    "sibling_runs_base",
    "served_systems",
    "start_family",
    "system_samples",
    "verify_family",
]


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    raise SystemExit(main(sys.argv[1:]))
