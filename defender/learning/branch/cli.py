#!/usr/bin/env python3
"""Fork one finished run into a questioner-authored triplet of worlds, and run them.

The operator names a source run and the message to branch at; this module runs the episode's
steps (`branch/steps.py::Step`) in order:

1. **Preflight** (not a `Step`). Everything that can refuse before anything is spent: the
   branch point is in range, the source alert is a plain file, the configured corpus patterns
   can carry a view name, the write door reaches the cluster, the sweep of this episode's
   namespace completes, and every registered role has a usable model.
2. **`Step.QUESTIONER`.** A deny-all role authors the triplet; its output is validated into
   `Family` and held to one identity gate before anything is staged.
3. **`Step.STAGING`.** Each world's corpus is written into the `wv-` namespace, every name
   recorded in `staged.yaml` before it is created.
4. **`Step.REVIEW`, by replay.** The captured set is replayed through each world; a world that
   contradicts the capture, or whose declared difference is unreachable, is rejected, and any
   rejection ends the episode before a sibling starts.
5. **`Step.RUNS`.** Each accepted world runs as its own `run.py --resume` process, started
   together, under `{episode_dir}/runs/` — never beside the source or under the runs base.
6. **`Step.VERIFY`, then `Step.JUDGE`.** Every sibling's scrub verdict and provenance stamp is
   checked; agreeing stamps write the family stamp, anything else records the episode as
   `incomplete` with a reason. The judge grades the archive after the cluster is handed back.

Siblings are always `run.py` processes (for the box lifecycle, reap scan, role preflight and
provenance stamp); this module never runs an investigation in-process.

Teardown runs on every exit: rejection, clean completion, `incomplete`, and any exception
raised after the first staging append.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import functools
import json
import logging
import os
import sqlite3
import sys
import threading
from collections.abc import Callable, Iterator, Sequence
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
from defender._io import NotPlainEntry, load_json_artifact
from defender._paths import PATHS
from defender._run_paths import RunPaths, artifact_dir, artifact_file
from defender._tenants import default_tenants_root
from defender.runtime.run_tenant import RunTenant
from defender.learning.branch import seams
from defender.learning.branch import staging as staging_mod
from defender.learning.branch import timing as timing_mod
from defender.learning.branch.steps import Step
from defender.learning.branch.capture import PrimeReport, prime_base
from defender.learning.branch.estate.registry import EstateError
from defender.learning.branch.estate.stagers.elastic import configured_patterns  # noqa: E501 # lint-shippable: ok — the one import of the per-vendor stager's configured-pattern reader; the vendor knowledge stays behind it
from defender.learning.branch.ledger import Ledger, LedgerError, base_file
from defender import _tenant
from defender.run_common import REPO_ROOT
from defender.runtime import branch, session_store
from defender.runtime.branch import _family
from defender.runtime.branch._family import (
    Family,
    FamilyError,
    check_identities,
    episode_token_for,
    parse_family,
    runnable_worlds,
)

_logger = logging.getLogger(__name__)

#: Where episodes live. No default: deriving it from the runs base would put `episodes/` inside
#: the tree corpus walkers descend and inside the checkout provenance is stamped from.
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"

#: The three outcomes an episode can end in. `incomplete` is an explicit outcome with a reason,
#: not inferred from a missing file.
ACCEPTED, REJECTED, INCOMPLETE = "accepted", "rejected", "incomplete"


class LauncherRefused(SystemExit):
    """An episode this launcher will not run, reported as an operator's exit with an
    explanation rather than a traceback."""


# ---------------------------------------------------------------------------------------
# where an episode lives
# ---------------------------------------------------------------------------------------


def episodes_root(*, tenant: Any) -> Path:
    """The configured root every episode directory is a child of.

    Must be outside the data root (every tenant's tree lives there, so walkers indexing a
    tenant's runs or episodes would count it) and outside the checkout (or an untracked episode
    dir makes every sibling's provenance stamp dirty, so no family can complete). Being
    configured also keeps it independent of the data root. `tenant` is the launcher's
    `TenantPaths`; its folder's parent is the data root.
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
    data_root = Path(tenant.dir).parent.resolve()
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


def episode_dir_for(episode_id: str, *, tenant: Any) -> Path:
    """Where one episode's shared records live.

    A single path component under the configured episodes root. The id is checked here because
    `prepare_episode` writes through this path before anything else judges it; an id carrying a
    separator would plant the capture outside the root or onto another episode's.
    """
    refuse_bad_episode_id(episode_id)
    return episodes_root(tenant=tenant) / episode_id


def episode_id_for(source_run_id: str, branch_message_id: int) -> str:
    """The episode id this source and branch point derive.

    Derived rather than chosen, so one (source run, branch point) pair always maps to one
    episode. Case-folded because it names a directory, and case-folding filesystems would merge
    two spellings.
    """
    return f"{source_run_id}-n{branch_message_id}".casefold()




# ---------------------------------------------------------------------------------------
# preflight — before the first `Step`
# ---------------------------------------------------------------------------------------


#: The launcher's primer: an empty capture primes an empty base, and `_prime_once` warns.
_PRIME_ALLOWING_EMPTY = functools.partial(prime_base, allow_empty=True)


def prepare_episode(
    episode_id: str, source_run_dir: Path, *, tenant: Any,
    prime: Callable[[Path, Episode], PrimeReport] = _PRIME_ALLOWING_EMPTY,
) -> Episode:
    """Prime the family's base once, exclusively, and hand back the episode, held open: the
    launcher's door, whose caller closes it (`with prepare_episode(...) as episode:`).

    The claim is the core's exclusive create, not check-then-act: two launchers on one source and
    branch point derive one episode id, and both priming would stack two captures that
    `_absorb` reads first-row-wins.

    An episode dir with no manifest is adopted, so a launcher killed mid-prime does not make the
    branch point permanently unbranchable. Once a manifest exists, the episode is that family.

    `prime` is injectable so a test can observe whether priming ran; it is handed the episode
    this returns.
    """
    episode_dir = episode_dir_for(episode_id, tenant=tenant)
    refuse_claimed_episode(episode_dir, episode_id)
    # Only a directory that got no further than a mid-prime death is adoptable: a world ledger
    # left by an earlier attempt would be absorbed first-row-wins and silently answer this
    # episode's live reads with the earlier estate.
    base = base_file(episode_dir)
    stale = sorted(p.name for p in base.parent.glob("*.jsonl")
                   if p.name != base.name) if artifact_dir(episode_dir) else []
    if stale:
        raise LedgerError(
            f"episode {episode_id!r} at {episode_dir} already holds per-world rows {stale} from "
            "an earlier attempt — those rows are absorbed first-row-wins and would answer this "
            "episode's live reads with the earlier one's estate. Remove the episode directory "
            "to re-prime it")
    # Made (or adopted) from its parent, never through a link at its name, and held: nothing
    # below reopens it by name.
    episode = Episode.create(episode_dir)
    try:
        _prime_once(episode, episode_id, Path(source_run_dir), prime)
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
        # in place): either way this launcher does not hold the claim. A linked folder on the
        # way is the core's folder refusal and propagates as itself.
        raise LedgerError(
            f"another launcher is priming episode {episode_id!r} ({claim.path} exists) — a "
            "family's capture is written once, before any sibling forks. If no launcher is "
            "running, that file is the wreck of one that was killed mid-prime; remove it to "
            "retry") from taken
    try:
        report = prime(source_run_dir, episode)
    finally:
        # Released on every exit, so a refused prime does not make the episode unbranchable. A
        # refusal here (something not plain at the claim's name, left for the reap scan) is
        # logged, never raised: it must not mask the exception this `finally` is unwinding.
        try:
            claim.delete()
        except OSError as stuck:
            _logger.warning(f"could not release the priming claim {claim.path}: {stuck}")
    if report.primed == 0:
        # A source that captured nothing is still branchable here (the launcher's primer allows
        # an empty base): the review records what it could replay per world. Only a source with
        # no session store reaches this (an imported run, replayed fixture or pruned store); one
        # with a session was already refused by `branch.validate` at preflight.
        _logger.warning(
            f"{source_run_dir} captured no replayable query — the family's base is "
            "EMPTY, so every key each sibling asks reaches the live estate and any difference "
            "between siblings includes the estate's own drift. The review records what it "
            "replayed; read it before comparing.")
        return
    # Log the skips too: each is a key read live rather than replayed.
    _logger.info(
        f"primed {report.primed} captured row(s) into {episode.served_base.path}; "
        f"{report.skipped} skipped ({report}) — a skipped key is read live per world rather "
        "than replayed")


def preflight_episode(  # noqa: PLR0913 — every refusal knowable before a model call is asked in this one block
    *, source_run_dir: Path, branch_message_id: int, episode_id: str, episode_dir: Path,
    door: Any, preflight: Callable[[str | None], int], model: str | None,
    continuation_prompt: str, allow_dirty: bool,
    live_tree: Callable[[], _provenance.RunProvenance], settings_dir: Path,
) -> tuple[str, tuple[str, ...], dict]:
    """Everything that can refuse before the questioner is paid for, in one block, so an
    operator with several problems hears about them all before spending anything.

    Returns the episode token, the configured corpus patterns and the source's stamp, so later
    steps use exactly the values judged here. In particular the stamp is the anchor
    `verify_family` compares siblings against; re-reading it from the prior box's rw bind could
    see a changed file.

    `live_tree` returns the checkout's stamp, called at most once; injectable so tests don't
    compare against whatever HEAD the suite runs under. It is only an early exit (siblings stamp
    themselves and `verify_family` compares those) — a launcher on the wrong commit would
    otherwise spend N investigations on a family verify will refuse.
    """
    token = _episode_token(episode_id)
    # The episode tenant's corpus patterns; `settings_dir` was resolved by `_episode_tenant`.
    patterns = staging_mod.check_configured_patterns(configured_patterns(settings_dir))
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
        source_who=f"source run {source_run_dir}", allow_dirty=allow_dirty)
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
    rc = preflight(model)
    if rc:
        raise LauncherRefused(
            f"[branch] the role-model preflight refused (exit {rc}) — every registered role's "
            "model config is checked at family level so a missing key surfaces before the base "
            "is primed, not once per sibling after N forks have committed")
    _probe_cluster(door, patterns)
    # Before the sweep: a second launcher on the same pair derives the same token, and its
    # sweep would delete a running family's staged corpus (which then reads as zero hits, not
    # an error). Staged names exist only after a manifest, so this closes the window.
    refuse_claimed_episode(episode_dir, episode_id)
    # The sweep is the first thing to touch the namespace, so no world is authored over an
    # earlier attempt's live aliases under the same token.
    staging_mod.sweep(episode_dir, episode_token=token, door=door)
    return token, patterns, source_stamp


def _no_stamp(source_run_dir: Path) -> LauncherRefused:
    return LauncherRefused(
        f"[branch] source run {source_run_dir} carries no usable provenance stamp — a "
        "family is anchored to the commit its source ran, and a source with no readable "
        "stamp cannot anchor one")


def _episode_tenant(source_run_dir: Path, tenants_root: Path) -> RunTenant:
    """The episode's tenant: the source run's, resolved under `tenants_root` — or the refusal,
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
        # and before its box-writable stamp is read at all.
        tenant_id = _tenant.tenant_of_run_dir(source_run_dir)
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
    # The same acceptance check a sibling's run start uses, asked once up front so a tenant a
    # sibling would refuse is refused before any spend. Siblings dispatch no turn-0 lead.
    from defender.runtime import run_tenant as run_tenant_mod

    try:
        return run_tenant_mod.resolve_tenant(
            tenants_root, tenant_id, defender_dir=_DEFENDER_DIR, dispatches_lead_zero=False)
    except run_tenant_mod.TenantRefused as refusal:
        raise LauncherRefused(f"[branch] the source run's tenant: {refusal}") from refusal


def refuse_claimed_episode(episode_dir: Path, episode_id: str) -> None:
    """Refuse an episode id whose family has already been authored.

    Asked by `prepare_episode` (priming under an existing family would merge two captures) and
    by `preflight_episode` (its sweep would delete that family's live staged names).
    """
    manifest = EpisodePaths(episode_dir).family
    if manifest.exists() or manifest.is_symlink():
        raise LedgerError(
            f"episode {episode_id!r} already holds a manifest at {manifest} — an episode id "
            "names one immutable family capture and the triplet authored over it. Reusing it "
            "would mix an earlier estate into this run under first-row-wins; name a fresh "
            "source run or branch point")


def _episode_token(episode_id: str) -> str:
    """The episode's token, or the operator-facing refusal.

    The token is always derived, never operator-named, so two episode ids cannot share a
    namespace. The real launcher has already refused bad ids via `episode_dir_for`; this wrapper
    gives direct callers of `preflight_episode` the same refusal class.
    """
    try:
        return episode_token_for(episode_id)
    except FamilyError as bad:
        raise LauncherRefused(f"[branch] {bad}") from bad


def _probe_cluster(door: Any, patterns: Sequence[str]) -> None:
    """Refuse an episode whose write door cannot reach the cluster.

    Probed with a real call, since the door only fails at use (container down, docker context
    unresolved); found at `Step.STAGING`, the questioner would already be paid for.
    """
    if not patterns:
        return
    try:
        door.count(patterns[0])
    except Exception as unreachable:  # noqa: BLE001 — the door owns its own fault classes
        raise LauncherRefused(
            f"[branch] the cluster's write door cannot reach {patterns[0]!r} "
            f"({unreachable!r}) — staging, teardown and the sweep all go through it, so an "
            "episode that cannot reach it can neither stage a world nor clean up after "
            "itself") from unreachable


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
        branch.validate(store, branch.BranchSpec(
            source_run_dir=Path(source_run_dir),
            branch_message_id=branch_message_id,
            continuation_prompt=continuation_prompt,
            as_of=as_of,
        ))
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
    tenants_root: Path | None = None,
) -> list[str]:
    """One sibling's command line: the manifest, which arm of it this process is, its tenant
    and the model.

    Everything else a sibling needs is derived from the manifest. `sys.executable` so the child
    uses the same venv interpreter.

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
    # So the child uses the tenants root the launcher resolved, not its own default.
    if tenants_root is not None:
        argv += ["--tenants-root", str(tenants_root)]
    return argv


#: The exit code recorded for an arm whose process never started (spawn raised, or the
#: rendezvous broke). Distinct from `run.py`'s own 0/1/2 so "never started" is distinguishable
#: from "ran and failed".
SPAWN_FAILED_EXIT = 70


def start_family(  # noqa: PLR0913 — the family's arms plus the tenant every arm runs on
    episode: Episode, world_labels: Sequence[str], *,
    spawn: Callable[..., int] | None = None, model: str | None = None,
    tenant_id: _tenant.TenantId | None, tenants_root: Path,
) -> dict[str, int]:
    """Start every accepted sibling together, and wait for all of them.

    The children are spawned from N threads that rendezvous first, so the arms overlap in time;
    run serially they would be compared across a moving estate, which the primed capture and
    shared T0 exist to prevent.

    Each child's runs base is inside the episode: the child derives it from the manifest, so
    the launcher exports no `DEFENDER_RUNS_BASE`, and siblings stay out of runs-base walkers'
    reach.

    `spawn` is the process seam.

    The child's runs-base record is seeded with the episode's `tenant_id` before it starts, and
    `--tenant` and `tenants_root` ride on each command line. No tenant refuses before anything
    is written.
    """
    from defender import _tenant

    if tenant_id is None or not _tenant.is_valid_tenant_id(tenant_id):
        # A ValueError, not `LauncherRefused`: `_episode_tenant` already resolved the tenant, so
        # this is a caller bug and takes the episode's normal abort path.
        raise ValueError(
            f"episode {episode.dir} has no usable tenant ({tenant_id!r}) to run its siblings "
            "on — refused before any sibling started")
    start = _default_spawn if spawn is None else spawn
    runs = sibling_runs_base(episode.dir)
    episode.runs.ensure()
    # Minted with the episode's tenant, or read back and refused when it names another
    # (`TenantRefused`, a ValueError) — before any sibling started.
    _tenant.ensure_runs_base_record(runs, tenant_id)
    labels = list(world_labels)
    if not labels:
        return {}
    ready = threading.Barrier(len(labels))
    exits: dict[str, int] = {}

    def launch_one(label: str) -> None:
        env = dict(os.environ)
        # Rendezvous first, so "started together" does not depend on the pool's scheduling.
        ready.wait(timeout=30)
        exits[label] = start(
            sibling_argv(episode.dir, label, tenant_id=tenant_id, model=model,
                         tenants_root=tenants_root), env=env)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(labels)) as pool:
        futures = {label: pool.submit(launch_one, label) for label in labels}
    # A thread that died is recorded as a result, not re-raised: raising would skip
    # `verify_family`, leaving completed siblings unarchived and misreporting "no sibling
    # started". (A broken barrier fails all N at once.) Recorded as a non-zero exit, since a
    # missing key would read as success.
    for label, future in futures.items():
        try:
            future.result()
        except Exception as never_started:  # noqa: BLE001 — one arm's failure, not the family's
            exits[label] = SPAWN_FAILED_EXIT
            _logger.warning(f"world {label} was never started: {never_started!r}")
    return exits


def _default_spawn(argv: list[str], *, env: dict[str, str] | None = None) -> int:
    """Run one sibling to completion in its own process, inheriting nothing but `env`."""
    import subprocess

    return subprocess.run(argv, env=env, check=False).returncode  # noqa: S603 — fixed argv


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
        record = json.loads(verdict.read_text(encoding="utf-8"))
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


#: One reason a family cannot be archived as a comparison against its source. `--allow-dirty`
#: drops exactly the `waivable` faults, so waivability is a property of the fault, not the site.
class _Fault(NamedTuple):
    waivable: bool
    text: str


def _family_faults(
    source: dict, members: dict[str, dict | None], *, source_who: str,
) -> list[_Fault]:
    """Every reason `members` are not provably one family continuing `source`.

    One judgement for both tiers: at preflight the members are the live tree alone, at verify
    the siblings' stamps. Verify re-judges the source rather than trusting that preflight ran.

    The source is checked first; a source with no commit ends anchoring there, so the fault
    names the source rather than the members. Each member must match the anchor's commit (and
    scope, when the source has one), and any non-clean tree on either side is a fault — an
    unknown is not clean. Members must also agree with each other on the model, which is not
    anchored to the source but must be constant across siblings.

    Only dirt is waivable. A wrong or missing commit or a different scope is a code confound,
    and a silent member waived would drop out of the agreement and let another arm's commit
    stand as the family's.
    """
    faults: list[_Fault] = []
    anchored = _stamp_speaks(source)
    if not anchored:
        faults.append(_Fault(False, (
            f"{source_who} names no commit (unavailable={source.get('unavailable')!r}) — a "
            "family is anchored to the commit its source ran, and there is none to anchor to")))
    elif not _clean_stamp(source):
        faults.append(_Fault(True, _not_certified_clean(source_who, source)))
    for who, stamp in members.items():
        faults.extend(_member_faults(who, stamp, anchor=source if anchored else None))
    # Agreement is over every stamp that names a commit, dirty ones included: excluding dirty
    # arms would let `--allow-dirty` waive the whole agreement, since siblings share one
    # checkout and are all dirty together.
    comparable = {who: stamp for who, stamp in members.items()
                  if stamp is not None and _stamp_speaks(stamp)}
    # Skip fields the anchor already pinned; disagreements there were reported above.
    pinned: set[str] = set()
    if anchored:
        pinned.add("commit")
        if source.get("scope") is not None:
            pinned.add("scope")
    for field in ("commit", "scope", "model"):
        if field in pinned:
            continue
        values = {who: stamp.get(field) for who, stamp in comparable.items()}
        if len(set(values.values())) > 1:
            faults.append(_Fault(False, (
                f"siblings disagree on {field}: {values} — the family is held constant on it, "
                "so a comparison across two values is never archived as comparable")))
    return faults


def _member_faults(who: str, stamp: dict | None, *, anchor: dict | None) -> list[_Fault]:
    """One tree's faults against the anchor. `anchor` is `None` when the source could not
    anchor (already reported); the tree is then judged on its own stamp alone."""
    if stamp is None:
        return [_Fault(False, (
            f"{who} carries no readable provenance stamp — an absent or unreadable stamp is "
            "not an agreeing one"))]
    if not _stamp_speaks(stamp):
        return [_Fault(False, (
            f"{who} names no commit (unavailable={stamp.get('unavailable')!r}) — a silent "
            "stamp cannot be held to anything"))]
    faults: list[_Fault] = []
    if anchor is not None and stamp.get("commit") != anchor.get("commit"):
        faults.append(_Fault(False, (
            f"{who} is at commit {stamp.get('commit')!r} while the source run it continues "
            f"ran at {anchor.get('commit')!r} — a family is anchored to its source's commit, "
            "and a comparison against other code is never archived as comparable")))
    scope = None if anchor is None else anchor.get("scope")
    if scope is not None and stamp.get("scope") != scope:
        faults.append(_Fault(False, (
            f"the dirt of {who} was measured over scope {stamp.get('scope')!r} and the "
            f"source's over {scope!r} — the two clean bits answer different questions, so "
            "agreeing on the commit does not make them a match")))
    if not _clean_stamp(stamp):
        faults.append(_Fault(True, _not_certified_clean(who, stamp)))
    return faults


def _not_certified_clean(who: str, stamp: dict) -> str:
    return (f"{who} was not certified clean by git (dirty={stamp.get('dirty')!r}, "
            f"commit={stamp.get('commit')!r}, unavailable={stamp.get('unavailable')!r}) — its "
            "commit does not name the bytes that ran")


def _family_refusal(
    source: dict, members: dict[str, dict | None], *, source_who: str, allow_dirty: bool,
) -> str | None:
    """The faults `--allow-dirty` did not waive, as one refusal — or `None`.

    Non-waivable faults are listed first, and `--allow-dirty` is suggested only when passing it
    would let the family through; fault messages themselves never mention the flag.
    """
    faults = [fault for fault in _family_faults(source, members, source_who=source_who)
              if not (fault.waivable and allow_dirty)]
    if not faults:
        return None
    text = "; ".join(fault.text for fault in sorted(faults, key=lambda fault: fault.waivable))
    if all(fault.waivable for fault in faults):
        text += " — pass --allow-dirty to waive the dirt, recorded in the family stamp as such"
    return text


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
    door: Any = None,
) -> dict:
    """Check every sibling, archive what is clean, and record the episode's outcome.

    `source` is the source run's stamp as judged by `preflight_episode`. Required with no
    default, so siblings are always held to the source's commit rather than only to each other.

    The outcome is recorded with a reason. An incomplete family still archives each clean
    sibling and withholds only the family stamp: each is a real, expensive investigation.
    Teardown runs on this path too.
    """
    dirs = {_world_label_of(d): Path(d) for d in run_dirs}
    scrub_verified = [label for label in dirs if _scrub_ran(dirs[label])]
    unverified = sorted(set(dirs) - set(scrub_verified))
    stamps = {label: _stamp_of(path) for label, path in dirs.items()}

    reasons: list[str] = []
    # With no siblings every check below passes vacuously, and `_write_family_stamp` would
    # raise after the archive was written. The launcher never gets here with none.
    if not dirs:
        reasons.append("the family has no sibling — a comparison over no arm is not one, so "
                       "there is nothing to hold to the source's commit or to archive")
    if unverified:
        reasons.append(
            f"sibling(s) {unverified} have no scrub verdict recording a completed walk — an "
            "unwalked tree is one nothing has certified as free of what the box left behind")
    refusal = _family_refusal(
        source, {f"sibling {label!r}": stamps[label] for label in scrub_verified},
        source_who="the source run", allow_dirty=allow_dirty)
    if refusal is not None:
        reasons.append(refusal)
    cross_tenant = _cross_tenant_fault(stamps, scrub_verified)
    if cross_tenant is not None:
        reasons.append(cross_tenant)

    outcome = INCOMPLETE if reasons else ACCEPTED
    reason = "; ".join(reasons)
    # `worlds/` exists whatever the outcome; the recorded outcome, not its absence, says why it
    # may be empty.
    episode.worlds.ensure()
    # Only scrub-verified siblings are archived: an unscrubbed tree is uncertified.
    from defender.learning.branch import archive as archive_mod

    try:
        archive_mod.archive_episode(
            episode, {label: dirs[label] for label in scrub_verified})
    except Exception as archive_refused:  # noqa: BLE001 — recorded, then re-raised unchanged
        # Record `incomplete` before re-raising: `archive_episode` can fail partway, and
        # readers (`episode._refuse_incomplete`) gate on a recorded outcome, so a partial
        # archive with none would read as complete. A refused review record cannot take it;
        # the archive's failure stays the one raised, carrying that as a note.
        try:
            _record_episode_outcome(
                episode, outcome=INCOMPLETE,
                reason="; ".join([*reasons, f"the archive refused: {archive_refused}"]))
        except staging_mod.StagingRefused as unrecorded:
            archive_refused.add_note(f"the incomplete outcome was not recorded: {unrecorded}")
        raise
    if outcome == ACCEPTED:
        _write_family_stamp(
            episode, stamps, source=source, allow_dirty=allow_dirty, dirs=dirs)
    _record_episode_outcome(episode, outcome=outcome, reason=reason)
    if door is not None:
        staging_mod.teardown(episode, door=door)
    return {"outcome": outcome, "reason": reason, "scrub_verified": scrub_verified,
            "worlds": sorted(dirs)}


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
    dirs: dict[str, Path] | None = None,
) -> None:
    """The family's one stamp: what every sibling agreed on, what it was anchored to, and
    whether it was waved through.

    @owns source — the family stamp's `source` key, the source run's whole provenance record as
    `_stamp_of` read it at preflight. Copied verbatim so a waived dirty source shows
    `source.dirty` beside `allow_dirty`, and the archive never reads as anchored to a clean sha.

    The agreed record (about the siblings), the source (what they were held to) and the
    override (the operator's flag) are kept separate so a clean family and a waived one read
    differently.
    """
    # Any sibling's stamp is the agreed record on commit, scope and model, since
    # `_family_refusal` passed. Dirt fields may differ under `--allow-dirty` and here are the
    # first sibling's; each sibling's own is archived in `worlds/<label>/provenance.json`.
    # `verify_family` guarantees at least one sibling, so `next` cannot raise.
    agreed = {k: v for k, v in next(
        stamp for stamp in stamps.values() if stamp is not None).items() if k != "world_id"}
    # The family's base world, from the tenant record at the siblings' runs base: no member
    # stamps it, and lessons attribution keys on it.
    base_world_id = _family_base_world_id(dirs)
    doc: dict[str, object] = {
        "agreed": agreed, "allow_dirty": bool(allow_dirty), "source": dict(source)}
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


def _record_episode_outcome(
    episode: Episode, *, outcome: str, reason: str, decision: str | None = None,
) -> None:
    """Merge the episode's own verdict into its review record, never over the worlds it holds.

    Through `staging.merge_review`, the single merger for this file, so both writers serialise
    it identically.
    """
    block: dict[str, Any] = {"outcome": outcome, "reason": reason}
    if decision is not None:
        block["decision"] = decision
    staging_mod.merge_review(episode, "episode", block)


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
             "or a sibling reported a tree git could not certify clean; waives dirt and ONLY "
             "dirt — never a commit or scope mismatch, an absent stamp or a stamp with no "
             "commit — and the override is NAMED in the stamp")
    p.add_argument("--model", default=None)
    p.add_argument(
        "--tenants-root", type=Path, default=None,
        help="the tenants root the episode's tenant is resolved under (the tenant the source "
             "run's runs-base record names; the source's stamp must agree with it); "
             "default <this checkout>/knowledge/tenants. Handed to every sibling (#1106)")
    return p.parse_args(argv)


def main(  # noqa: PLR0913 — the launcher's inputs plus its eight injection seams
    argv: list[str],
    *,
    spawn: Callable[..., int] | None = None,
    door: Any = None,
    questioner: Any = None,
    adapters: Any = None,
    invoke: Any = None,
    preflight: Callable[[str | None], int] | None = None,
    judge: Any = None,
    lessons_dir: Path | None = None,
    live_tree: Callable[[], _provenance.RunProvenance] | None = None,
) -> int:
    """Launch one episode, reporting a refusal as an operator exit rather than a traceback.

    The delegated checks (source store, branch point, primer, family loader, staging guard,
    review) raise their own classes with operator-ready messages; they are converted here.
    `sqlite3.Error` is included because a corrupt source store raises it, not `BranchError`.

    One abort rule: anything else raised from `Step.QUESTIONER` through `Step.REVIEW` is also
    reported as a refusal (in `_launch`) — teardown has already run, no sibling has started,
    and the operator is told which step ended the episode.
    """
    # Deferred so `cli.py --help` works in an interpreter without the model runtime, which the
    # review's imports pull in.
    from defender.learning.branch.review import ReviewError

    try:
        return _launch(argv, spawn=spawn, door=door, questioner=questioner,
                       adapters=adapters, invoke=invoke, preflight=preflight, judge=judge,
                       lessons_dir=lessons_dir, live_tree=live_tree)
    except (branch.BranchError, LedgerError, EstateError, FamilyError,
            staging_mod.StagingRefused, ReviewError,
            session_store.StoreError, sqlite3.Error) as refusal:
        raise LauncherRefused(f"[branch] {refusal}") from refusal


def _launch(  # noqa: PLR0913 — see `main`
    argv: list[str], *, spawn: Any, door: Any, questioner: Any, adapters: Any, invoke: Any,
    preflight: Callable[[str | None], int] | None, judge: Any = None,
    lessons_dir: Path | None = None,
    live_tree: Callable[[], _provenance.RunProvenance] | None = None,
) -> int:
    from defender.run import preflight_role_models

    ns = parse_branch_args(argv)
    # Injected seams are resolved once here and threaded inward non-`None`, so no two frames can
    # disagree about which door, preflight or model an episode used.
    role_preflight = preflight_role_models if preflight is None else preflight
    # The episode's tenant first: the door, corpus patterns, review read side and siblings all
    # resolve through it.
    source = Path(ns.source_run_dir).resolve()
    tenants_root = (ns.tenants_root if ns.tenants_root is not None
                    else default_tenants_root(REPO_ROOT))
    tenant = _episode_tenant(source, tenants_root)
    # ...and the same tenant's tree under the data root (#1078 D4): the episodes root's
    # data-root refusal and the grade's runs base are handed this, never re-derive it.
    tenant_paths = _tenant.TenantPaths(_tenant.resolve_data_root(), tenant.tenant_id)
    runs_base = tenant_paths.runs
    write_door = (staging_mod.write_door_from_env(staging_mod.host_context(tenant.settings))
                  if door is None else door)
    questioner_lessons_dir = PATHS.lessons_questioner_dir if lessons_dir is None else lessons_dir
    # Injectable so end-to-end tests aren't compared against the suite's own HEAD.
    live_capture = ((lambda: _provenance.capture_tree(REPO_ROOT)) if live_tree is None
                    else live_tree)
    episode_id = episode_id_for(source.name, ns.branch_message_id)
    episode_dir = episode_dir_for(episode_id, tenant=tenant_paths)
    token, patterns, source_stamp = preflight_episode(
        source_run_dir=source, branch_message_id=ns.branch_message_id, episode_id=episode_id,
        episode_dir=episode_dir, door=write_door, preflight=role_preflight,
        model=ns.model, continuation_prompt=ns.continuation_prompt,
        allow_dirty=ns.allow_dirty, live_tree=live_capture, settings_dir=tenant.settings)

    # The model and adapter seams are built before the claim, so a deployment that cannot build
    # them (e.g. a gather-granted adapter missing from the tree) is refused before an episode
    # dir exists. `seams.model_seam` serves both the authoring fan-out and the comparator so
    # they cannot end up on different models.
    try:
        author = seams.model_seam(episode_dir) if questioner is None else questioner
        compare_with = seams.model_seam(episode_dir) if invoke is None else invoke
        read_side = (seams.adapter_seam(episode_dir, tenant, runs_base=runs_base)
                     if adapters is None else adapters)
    except Exception as unbuildable:  # noqa: BLE001 — every seam's own fault class, and the answer is the same refusal
        raise LauncherRefused(
            f"[branch] the launcher could not build its model and adapter seams "
            f"({unbuildable!r}) — the {Step.QUESTIONER} and {Step.REVIEW} steps drive a "
            "questioner and the estate's read side, and an episode that cannot reach either "
            "has nothing to measure") from unbuildable

    # From here on the episode spends, and after the first staging append there are live
    # cluster names only this process knows about, so everything runs inside the teardown guard.
    episode = prepare_episode(episode_id, source, tenant=tenant_paths)
    # The episode is held for the whole launch, teardown included: every write below goes
    # through this one handle.
    with episode:
        # Tells the `finally` whether an exception is already heading to the operator; only this
        # frame knows (see `_teardown_without_masking`).
        aborting = False
        # One-shot so the episode can release the cluster before the long judge pass (which never
        # reads the cluster), while the `finally` still covers every other path.
        teardown = _OneShotTeardown(episode, write_door)
        try:
            return _run_episode(
                ns, source=source, source_stamp=source_stamp, episode_id=episode_id,
                episode=episode, token=token, patterns=patterns, door=write_door,
                questioner=author, adapters=read_side, invoke=compare_with, spawn=spawn,
                judge=judge, lessons_dir=questioner_lessons_dir, teardown=teardown,
                tenant=tenant, tenants_root=tenants_root, runs_base=runs_base)
        except SystemExit:
            aborting = True
            raise
        except BaseException as failed:  # noqa: BLE001 — one abort rule, see `main`'s docstring
            aborting = True
            if teardown.done:
                # Re-raised unchanged: once the cluster has been handed back the siblings have run,
                # so the abort message below ("no sibling started…") would be false for anything
                # raised now, whatever its class.
                raise
            raise LauncherRefused(
                f"[branch] episode {episode_id} aborted: {failed!r} — no sibling started and every "
                "staged name is torn down") from failed
        finally:
            # On every exit not already torn down: a staged name left live is one the next
            # launch's sweep refuses to touch and nothing else removes.
            teardown(aborting=aborting)


class _OneShotTeardown:
    """`_teardown_without_masking`, called at most once however many callers ask.

    Both the episode (releasing the cluster before grading) and `_launch`'s `finally` call it,
    and `staging.teardown` is not safe to run twice."""

    def __init__(self, episode: Episode, door: Any) -> None:
        self._episode = episode
        self._door = door
        self._done = False

    @property
    def done(self) -> bool:
        """Has the cluster already been handed back?"""
        return self._done

    def __call__(self, *, aborting: bool) -> None:
        if self._done:
            return
        self._done = True
        _teardown_without_masking(self._episode, self._door, aborting=aborting)


def _teardown_without_masking(episode: Episode, door: Any, *, aborting: bool) -> None:
    """Tear the episode's staged names down without letting a failure displace an abort in flight.

    In a `finally` a second exception would replace the first, and the abort is what the
    operator must act on. So while aborting, a teardown failure is logged, saying where its
    unverified names are: the review record, or only this message when that record was
    refused (`TeardownUnrecorded`); otherwise it is re-raised.
    """
    # `aborting` is passed in, not read from `sys.exc_info()`, which is thread-global and would
    # report an in-flight exception from any caller up the stack.
    try:
        staging_mod.teardown(episode, door=door)
    except Exception as cleanup_failed:  # noqa: BLE001 — never mask an in-flight abort; re-raised otherwise
        if not aborting:
            raise
        where = ("only in this message: the review record was refused"
                 if isinstance(cleanup_failed, staging_mod.TeardownUnrecorded)
                 else "in the review record")
        _logger.error(f"teardown also failed ({cleanup_failed!r}); the names it could not "
                      f"verify gone are {where}. The failure that ended the episode is what "
                      "follows")


def _run_episode(  # noqa: PLR0913 — the episode's whole identity plus its seams
    ns: argparse.Namespace, *, source: Path, source_stamp: dict, episode_id: str,
    episode: Episode, token: str, patterns: Sequence[str], door: Any, questioner: Any,
    adapters: Any, invoke: Any, spawn: Any, lessons_dir: Path, judge: Any = None,
    teardown: Any = None, tenant: RunTenant, tenants_root: Path, runs_base: Path,
) -> int:
    """Every `Step`, `QUESTIONER` through `JUDGE`, inside the teardown guard.

    `teardown` is `_launch`'s one-shot guard, called here once the archive is written so the
    cluster is released before the grade spends its model calls; `_launch`'s `finally` covers
    every path that does not reach that call. `source_stamp` is the anchor the preflight read
    and judged, handed to `verify_family` unchanged."""
    # One clock for the episode; every step frame is drawn here, in launch order.
    clock = timing_mod.StageClock(episode)
    with clock.step(Step.QUESTIONER):
        family = _author(ns, source=source, episode_id=episode_id, episode=episode,
                         questioner=questioner, patterns=patterns, lessons_dir=lessons_dir)
    with clock.step(Step.STAGING):
        # The staging record exists from the moment staging begins, so its absence can only
        # mean "staging never started".
        # Exclusive: a record already there (a re-entered episode) is kept and appended to,
        # and anything not plain at the name is refused rather than followed or replaced.
        with contextlib.suppress(FileExistsError):
            # A comment, not `[]`: rows are appended as YAML list items, and appending after a
            # literal `[]` makes the record unparseable, which teardown refuses to act on.
            episode.staged.create(
                f"# staged names for episode {episode_id} — one row per name, appended BEFORE "
                "the name is created\n")
        for world in runnable_worlds(family):
            staging_mod.stage_world(world, episode=episode, episode_token=token,
                                    configured_patterns=patterns, door=door)
    from defender.learning.branch import review as review_mod

    with clock.step(Step.REVIEW):
        record = review_mod.review(family, episode=episode, adapters=adapters,
                                   door=door, invoke=invoke, settings_dir=tenant.settings,
                                   runs_base=runs_base)
    if record.get("episode", {}).get("decision") == REJECTED:
        # Any rejected world ends the whole episode: a family missing an arm measures nothing,
        # and running the rest would look like a completed comparison.
        _record_episode_outcome(episode, outcome=REJECTED, reason=str(
            record.get("episode", {}).get("reason") or "a world contradicted the capture"),
            decision=REJECTED)
        episode.worlds.ensure()
        _logger.info(f"episode {episode_id}: rejected before any sibling started")
        return 1

    labels = [w.world_id for w in runnable_worlds(family)]
    with clock.step(Step.RUNS):
        exits = start_family(episode, labels, spawn=spawn, model=ns.model,
                             tenant_id=tenant.tenant_id, tenants_root=tenants_root)
    runs = sibling_runs_base(episode.dir)
    with clock.step(Step.VERIFY):
        report = verify_family(
            episode, [runs / f"{episode_id}-{label}" for label in labels],
            source=source_stamp, allow_dirty=ns.allow_dirty)
    failed = sorted(label for label, code in exits.items() if code)
    for label in failed:
        _logger.warning(f"world {label} exited {exits[label]}")
    _logger.info(f"episode {episode_id}: outcome={report['outcome']} "
                 f"({len(report['scrub_verified'])}/{len(labels)} verified)")
    # Hand-back is the outer frame and the judge clock the inner one: the cluster is released
    # before the judge's clock starts, so teardown time isn't booked to the judge, and the
    # judge's entry is recorded before a held hand-back failure is raised.
    with _cluster_released(teardown, episode_id=episode_id):
        with clock.step(Step.JUDGE):
            _grade(episode.dir, episode_id=episode_id, judge=judge, runs_base=runs_base)
        # Rendered after the JUDGE frame closes so the page sees the judge's timing row;
        # non-fatal.
        _render_page(episode.dir, episode_id=episode_id)
    # The exit status is about the launch (did every sibling exit cleanly); an `incomplete`
    # family is a measurement, recorded in the episode outcome, not a launch failure.
    return 1 if failed else 0



@contextlib.contextmanager
def _cluster_released(teardown: Any, *, episode_id: str) -> Iterator[None]:
    """Hand the cluster back, then run the body; a hand-back failure is held until the body
    completes, and never masks a failure of the body's own.

    The cluster is released first because everything the judge reads is on disk and the grade
    is the longest step. A teardown failure must not preempt the grade (the episode would end
    with no `judge.yaml`), so it is held and raised after the body completes.

    The re-raise is in a `finally` so the held fault is not dropped when the body exits on a
    `BaseException` (`_OneShotTeardown` has already latched, so nothing else would report it).
    If the body did not complete, something is already heading to the operator, so the fault is
    logged instead (its unverified names are in the review record). `completed` is a
    frame-local flag rather than `sys.exc_info()`, which is thread-global.
    """
    held: BaseException | None = None
    if teardown is not None:
        try:
            teardown(aborting=False)
        except Exception as cleanup_failed:  # noqa: BLE001 — held: raised after a completed body, logged otherwise
            held = cleanup_failed
    completed = False
    try:
        yield
        completed = True
    finally:
        if held is not None:
            if completed:
                raise held
            _logger.error(f"episode {episode_id}: teardown also failed ({held!r}); "
                          "the names it could not verify gone are in the review record, and the failure "
                          "that ended the episode is what follows")


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

        judge_mod.grade_episode(episode_dir, judge=judge, runs_base=runs_base)
    # Imports are inside the `try` too, so an import or config fault is a judge failure
    # rather than reaching `_launch`'s abort arm with a false "no sibling started" message.
    except Exception as judge_failed:  # noqa: BLE001 — a judge failure is non-fatal, see below
        # Every class: the grade reads model-authored archives, a shared queue and an injected
        # model seam, any of which can raise anything. Logged in full so the launch's status
        # stays about the launch without hiding the failure.
        _logger.warning(f"episode {episode_id}: the judge pass failed ({judge_failed!r}); the "
                        "episode itself is otherwise unaffected", exc_info=True)


def write_questioner_samples(episode: Episode, samples: Any) -> Path:
    """Write `samples.yaml`, the questioner's reference document per staged pattern, into the
    episode archive, so the judge is shown the same bytes the questioner was (which makes a
    `shape-invention` claim decidable) even after the source run is pruned.

    Normalised to one `dict` before dumping, so the file never relies on a YAML loader's
    handling of repeated keys. Overwritten wholesale on a re-entered episode; a retried
    `Step.QUESTIONER` may therefore pair these samples with a world from an earlier attempt.
    """
    import yaml

    doc = dict(samples)
    record = episode.samples
    record.write(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True,
                                default_flow_style=False))
    return record.path


def _author(
    ns: argparse.Namespace, *, source: Path, episode_id: str, episode: Episode,
    questioner: Any, lessons_dir: Path, patterns: Sequence[str] = (),
) -> Family:
    """@owns configured_patterns — the one writer of the manifest's recorded tenant patterns;
    every later reader takes them from `family.yaml` via `_family.parse_family`.

    `Step.QUESTIONER`: the questioner authors the triplet, and it is validated before anything
    reads it. The launcher's derived fields (episode id, source run, branch point, T0,
    continuation prompt) overwrite whatever the model returned, so a family cannot name a
    different source than it was authored from. One identity gate runs over the whole manifest
    before anything is staged."""
    from defender._corpus import iter_lesson_paths
    from defender.learning.branch import questioner as questioner_mod
    from defender.learning.branch.estate.stagers.elastic import source_pattern  # noqa: E501 # lint-shippable: ok — the per-vendor stager owns which key of a call names its corpus; the join surface holds no vendor knowledge and takes this as its `pattern_of`
    from defender.learning.lead_repository import corpus_samples, joined, questioner_leads

    as_of = branch_point_clock(source, ns.branch_message_id)
    fences = _fence_count(source, ns.branch_message_id,
                          continuation_prompt=ns.continuation_prompt, as_of=as_of)
    # Joined once and projected twice (sampler and leads render), so both see the same leads.
    leads = _joined_leads(source, joined)
    # The sample keys are the capture's own FROM patterns, which `parse_family` judges overlay
    # keys against and the prompt names as stageable — one walk, so they cannot diverge.
    samples = _corpus_samples(leads, corpus_samples, source_pattern)
    # Archived before the model call, so the judge sees exactly what the questioner saw.
    write_questioner_samples(episode, samples)
    captured = tuple(samples)
    stageable = tuple(dict.fromkeys([*patterns, *captured]))
    # Paths only; `author_family` opens them and screens them against `stageable`.
    lessons = iter_lesson_paths(lessons_dir)
    document = questioner_mod.author_family(
        source_run_dir=source, episode_dir=episode.dir,
        invoke=questioner,
        leads=questioner_leads(leads),
        alert=_alert_document(source),
        frontier=questioner_mod.read_frontier(source, fences_at=fences),
        # The same set `parse_family` below judges the overlays against.
        stageable_patterns=stageable,
        corpus_samples=samples,
        lessons=lessons,
    )
    document.update({
        "episode_id": episode_id,
        "source_run_dir": str(source),
        "source_run_id": source.name,
        "branch_message_id": ns.branch_message_id,
        "fences_at": fences,
        "as_of": as_of.isoformat().replace("+00:00", "Z"),
        "continuation_prompt": ns.continuation_prompt,
        # Recorded in the manifest, not only passed to the check below: overlay keys may name a
        # captured FROM pattern (views match patterns by equality, so a world staged under a
        # wide configured key is invisible to narrower queries), and siblings re-parsing the
        # manifest via `load_family` have no capture to consult.
        "captured_patterns": list(captured),
        # Recorded so a sibling or judge re-reading the manifest needs no settings folder.
        "configured_patterns": list(patterns),
    })
    family = parse_family(document, captured_patterns=captured,
                          configured_patterns=lambda: tuple(patterns))
    check_identities(family)
    _family.write_family(episode, document)
    return family


def _corpus_samples(leads: Any, sampler: Any, pattern_of: Any) -> dict[str, Any]:
    """One document per corpus the capture queried.

    The sampler skips unreadable payloads itself; this catches host-level read faults. Samples
    are an orientation aid, so a fault yields a thinner prompt rather than no episode. The
    count is logged because an empty sample set otherwise looks like a capture that queried
    nothing.
    """
    try:
        samples = sampler(leads, pattern_of=lambda q: pattern_of(q.verb, q.params or {}))
    except Exception as unreadable:  # noqa: BLE001 — a fault at the read is a thinner prompt, not no episode
        _logger.warning(f"could not sample the source's corpora ({unreadable!r}); the questioner "
                        "is shown none")
        return {}
    shown = sum(1 for doc in samples.values() if doc)
    _logger.info(f"sampled {shown} corpus document(s) across {len(samples)} pattern(s) the "
                 "capture addressed")
    return samples

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
    document = path.read_text(encoding="utf-8")
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
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    loaded, unreadable = load_json_artifact(text)
    return loaded if unreadable is None and isinstance(loaded, dict) else {}


__all__ = [
    "ACCEPTED",
    "EPISODES_BASE_ENV",
    "INCOMPLETE",
    "Ledger",
    "LedgerError",
    "REJECTED",
    "episode_dir_for",
    "episode_id_for",
    "episodes_root",
    "main",
    "parse_branch_args",
    "prepare_episode",
    "refuse_bad_episode_id",
    "sibling_argv",
    "sibling_runs_base",
    "start_family",
    "verify_family",
]


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    raise SystemExit(main(sys.argv[1:]))
