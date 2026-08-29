#!/usr/bin/env python3
"""Fork one finished run into a questioner-authored triplet of worlds, and run them.

The composition root for #947's episode. The operator names two things — a source run and the
message to branch at — and this module decides the ORDER everything else happens in, which is
the part no seam can enforce about itself:

1. **Step 1, the preflight block.** Everything that can refuse before anything is spent, asked
   in one place: the branch point is in range, the source alert is a plain file, the configured
   corpus patterns can carry a view name, the write door reaches the cluster, the sweep of this
   episode's own namespace completes, and every registered role has a usable model. A refusal
   here costs no model call, no staged name and no primed capture.
2. **Step 2, the questioner.** A deny-all role authors the triplet; its raw output is validated
   into `Family` and held to ONE identity gate before anything is staged.
3. **Step 3, staging.** Each world's corpus is written into the `wv-` namespace, every name
   write-ahead-recorded in `staged.yaml` before it is created.
4. **Step 4, review by replay.** The captured set is replayed through each world; any world
   that contradicts the capture, or whose declared difference is unreachable, REJECTS — and any
   rejected world ends the EPISODE (§7 FORK-14), so no sibling starts at all.
5. **Step 5, the family as processes.** Each accepted world runs as its own `run.py --resume`
   child, started together, under `{episode_dir}/runs/` — never beside the source run and never
   under the operator's runs base (§7 FORK-13).
6. **Step 6, verification and the archive.** Every sibling's scrub verdict and provenance stamp
   is checked; agreeing stamps write the family stamp, and anything else marks the episode
   `incomplete` — a modelled outcome with a reason, not the absence of a file (§7 FORK-1).

THIS MODULE DRIVES NO INVESTIGATION IN ITS OWN PROCESS, and has no path to one: it neither
imports the driver's entry point nor awaits anything. D1's whole content is that a sibling is a
`run.py` PROCESS, which is what gets it the box lifecycle, the reap scan, its own role preflight
and its own provenance stamp — the four pieces the in-process launcher this replaces could not
have without answering a concurrency question it had not answered. It also means the launcher
acquires `run.py`'s two automatic lanes and has to refuse them there rather than silently not
calling them, which is `run.py --resume`'s job and not this file's.

Teardown runs on EVERY exit: rejection, clean completion, `incomplete`, and any exception raised
after the first staging append. The cluster does not care why the episode ended.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sqlite3
import sys
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

# This file is a path-based launcher, just like `run.py` and `learning/loop.py`. Python puts
# only `learning/branch/` on `sys.path` for `python3 defender/learning/branch/cli.py`, so both
# the first `defender` import and package-relative imports fail unless the workspace root is
# installed before any package import resolves. Re-exec into the project venv first when it
# exists, matching the other launchers' dependency boundary.
_DEFENDER_DIR = Path(__file__).resolve().parents[2]
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

import yaml

from defender._io import guarded_mkdir, write_guarded
from defender._paths import PATHS
from defender._run_paths import RunPaths, artifact_dir, artifact_file
from defender.learning.branch import staging as staging_mod
from defender.learning.branch.capture import PrimeReport, prime_base
from defender.learning.branch.estate.registry import EstateError
from defender.learning.branch.estate.stagers.elastic import configured_patterns  # noqa: E501 # lint-shippable: ok — the one import of the per-vendor stager's configured-pattern reader; the vendor knowledge stays behind it
from defender.learning.branch.ledger import Ledger, LedgerError, base_file
from defender.run_common import REPO_ROOT, resolve_runs_base
from defender.runtime import branch, session_store
from defender.runtime.branch import _family
from defender.runtime.branch._family import (
    MANIFEST_NAME,
    Family,
    FamilyError,
    check_identities,
    episode_token_for,
    parse_family,
    runnable_worlds,
)

#: The environment variable naming where episodes live. THERE IS NO DEFAULT DERIVATION, and the
#: absence is the whole point (§7 round 2, F5-EPISODE-ROOT). Deriving this from the runs base is
#: what put `episodes/` back inside the tree every corpus walker descends and inside the checkout
#: a sibling's own provenance stamp is taken over — the two containment holes FORK-13 closed. A
#: reader that re-derives it silently restores both, so with the variable unset the launcher
#: REFUSES naming it rather than inventing a location.
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"

#: Where a sibling's run dir lives, relative to its episode. The child process is handed this as
#: its own `DEFENDER_RUNS_BASE`, so the run dir it materialises is inside the episode rather than
#: beside the source run.
RUNS_SUBDIR = "runs"

#: The archived worlds' directory, and the family stamp's filename.
WORLDS_SUBDIR = "worlds"
FAMILY_STAMP_NAME = "provenance.json"
REVIEW_NAME = "review.yaml"

#: The three outcomes an episode can end in. `incomplete` is a MODELLED outcome carrying a
#: reason rather than the absence of a file (§7 FORK-1): every question about a partially good
#: family used to fall through the gap between "accepted" and "rejected".
ACCEPTED, REJECTED, INCOMPLETE = "accepted", "rejected", "incomplete"


class LauncherRefused(SystemExit):
    """An episode this launcher will not run, reported as an operator's exit.

    A `SystemExit` because every one of these is an answer to an operator's own command line —
    the launcher's failure mode is an exit with a written explanation, not a traceback out of a
    library frame.
    """


# ---------------------------------------------------------------------------------------
# where an episode lives (§7 FORK-13 + F5-EPISODE-ROOT)
# ---------------------------------------------------------------------------------------


def episodes_root() -> Path:
    """The CONFIGURED root every episode directory is a child of.

    READ FROM CONFIGURATION, never derived. Three properties have to hold at once and only a
    configured location gets all three: it is outside the runs base, so no runs-base walker can
    descend into an episode and count a sibling as an ordinary run; it is outside the checkout,
    so an untracked episode directory cannot dirty the tree a sibling's own provenance stamp is
    taken over — which would compose with the dirty refusal into a family that can never
    complete; and re-pointing the runs base moves no episode, so the two roots are independent
    facts rather than one arithmetic.

    Both refusals below are the same refusal in two spellings, and neither is optional: a
    default under the runs base would restore the first hole, and one under the checkout the
    second, in both cases silently and with a green run.
    """
    raw = os.environ.get(EPISODES_BASE_ENV)
    if not raw:
        raise LauncherRefused(
            f"[branch] {EPISODES_BASE_ENV} is not set — an episode's directory is a CONFIGURED "
            "location, and there is deliberately no default: derived from the runs base it "
            "would be walked by every consumer that indexes runs, and derived from the checkout "
            "it would dirty the tree every sibling stamps itself against. Name a directory "
            "outside both")
    root = Path(raw)
    for forbidden, why in (
        (resolve_runs_base(), "the runs base — every walker of that tree descends into every "
                              "directory under it, so an episode there is indexed as runs"),
        (REPO_ROOT, "the checkout — an untracked directory there is what a sibling's own "
                    "provenance stamp reports as a dirty tree"),
    ):
        forbidden = Path(forbidden).resolve()
        candidate = root.resolve() if root.exists() else root
        if candidate == forbidden or forbidden in candidate.parents:
            raise LauncherRefused(
                f"[branch] {EPISODES_BASE_ENV}={root} resolves inside {why}")
    return root


def refuse_bad_episode_id(episode_id: str) -> None:  # lint-dup: ok — one RULE, two error CLASSES: `_family` owns the predicate and raises `FamilyError`; this frame owns nothing but the operator-facing `SystemExit` every other check on this command line raises
    """The episode id's own rule, as the launcher's OPERATOR-FACING refusal.

    The rule itself lives with the schema (`_family.refuse_bad_episode_id`), because the id is a
    property of the manifest's identity rather than of this command line. What is this module's
    is the CLASS: an operator's own argument is answered with an exit and a written explanation,
    not with a library exception, and every other check on this path already does that. Two
    spellings of "you cannot branch this" from one command is the thing `main`'s handler exists
    to collapse.
    """
    try:
        _family.refuse_bad_episode_id(episode_id)
    except FamilyError as bad:
        raise LauncherRefused(f"[branch] {bad}") from bad


def episode_dir_for(episode_id: str) -> Path:
    """Where one episode's shared records live.

    Under the configured episodes root, as a single path component. `episode_id` is checked
    HERE, at the path-construction boundary as well as in `_launch`, because `prepare_episode`
    WRITES through this path before any run id derived from it is ever judged — so an id
    carrying a separator plants the family's capture outside the episodes root, or onto another
    episode's, with the run still green.
    """
    refuse_bad_episode_id(episode_id)
    return episodes_root() / episode_id


def episode_id_for(source_run_id: str, branch_message_id: int) -> str:
    """The episode id this source and branch point derive.

    DERIVED, not an operator argument. An episode is one (source run, branch point) pair, so an
    id chosen by hand is a second name for something that already has one — and two launches of
    the same pair under two ids are two immutable captures of one moment, with nothing saying
    they are the same episode. Case-folded because the id names a directory, and two spellings
    of it are one directory wherever the filesystem folds case.
    """
    return f"{source_run_id}-n{branch_message_id}".casefold()


def refuse_distant_source(source_run_dir: Path) -> None:
    """Refuse a source that is not an ordinary run dir directly under the configured runs base.

    `open_source_store` derives `runs_base` as `run_dir.parent` and checks
    `store_path_for(case_id, runs_base)` against the pointer the writer recorded — so a source
    living anywhere but directly under the runs base it was WRITTEN under resolves to a path no
    database is at, and the failure surfaces later as "records its store at X but resolves to
    Y", naming the opposite cause. Answered here, where the operator's own argument is in hand.

    NOT ON THE LAUNCH PATH ANY MORE, and that is FORK-13's doing rather than an omission. The
    check earned its place when a sibling was materialised BESIDE its source, so the source's
    runs base was also the siblings' — after FORK-13 a sibling's run dir lives under the episode
    directory and the manifest names the source by absolute path, so where the source sits
    relative to THIS process's configured runs base decides nothing about the family. What still
    decides something is the source's own pointer, and `open_source_store` is the frame that
    reads it: it is called on every launch, it refuses the same mismatch, and it refuses it with
    the store in hand rather than from a path comparison.

    Kept, exported and exercised because it is still the right pre-check for the ORDINARY layout
    — an operator branching a run from the runs base gets the refusal one argument earlier —
    and because `test_947_branch_cli.py` is the regression witness that the two spellings of
    "you cannot branch this" have not drifted apart.
    """
    base = resolve_runs_base().resolve()
    if Path(source_run_dir).resolve().parent != base:
        raise LauncherRefused(
            f"[branch] source run {source_run_dir} does not live directly under {base} — a "
            "source's own session store is resolved from its parent, and one parked elsewhere "
            "resolves to a database that was never its own")


# ---------------------------------------------------------------------------------------
# step 1 — the preflight block
# ---------------------------------------------------------------------------------------


def prepare_episode(
    episode_id: str, source_run_dir: Path,
    prime: Callable[[Path, Path], PrimeReport] = prime_base,
) -> Path:
    """Prime the family's base ONCE, exclusively, and hand back the episode directory.

    THE CLAIM IS ATOMIC, not a check-then-act (§7 FORK-2). Two launchers racing on one source
    and branch point derive ONE episode id, so without an exclusive claim both pass an
    `exists()` test, both prime, and the two captures stack into a single recording that
    `_absorb` reads first-row-wins — one source's estate answering every sibling of the other,
    with nothing in the table to tell them apart. `O_CREAT|O_EXCL` on the claim file is what
    makes exactly one of them win.

    AND A MANIFESTLESS EPISODE DIRECTORY IS ADOPTED, which is the other half of the same fork.
    A launcher killed mid-prime would otherwise make that source and branch point permanently
    unbranchable with no documented remedy, because the directory it left behind fails every
    existence test. What is permanent is a MANIFEST: once the questioner has authored a family
    into this episode, the episode is that family, and priming a second capture underneath it is
    the merge the claim exists to prevent.

    `prime` is the primer as an INJECTION SEAM rather than a module lookup, so a caller that
    needs to observe whether priming ran at all — the refusals above exist precisely to keep it
    from running — can hand in its own without reaching into this module's globals.
    """
    episode = episode_dir_for(episode_id)
    manifest = episode / MANIFEST_NAME
    if manifest.exists() or manifest.is_symlink():
        raise LedgerError(
            f"episode {episode_id!r} already holds a manifest at {manifest} — an episode id "
            "names one immutable family capture and the triplet authored over it. Reusing it "
            "would mix an earlier estate into this run under first-row-wins; name a fresh "
            "source run or branch point")
    # A PARTLY-RUN EPISODE IS NOT ADOPTABLE, and this is the half of FORK-2's adopt answer that
    # keeps it from being a hole. `Ledger._absorb` reads the base tier AND this world's own file,
    # first-row-wins — so a world ledger left behind by an earlier attempt at the same id would
    # override live reads for keys the NEW source never captured, silently, under a capture that
    # otherwise reads clean. What is adoptable is a directory that got no further than being
    # made: a mid-prime death, which is the state the fork's answer exists to keep recoverable.
    stale = sorted(p.name for p in base_file(episode).parent.glob("*.jsonl")
                   if p.name != base_file(episode).name) if artifact_dir(episode) else []
    if stale:
        raise LedgerError(
            f"episode {episode_id!r} at {episode} already holds per-world rows {stale} from an "
            "earlier attempt — those rows are absorbed first-row-wins and would answer this "
            "episode's live reads with the earlier one's estate. Remove the episode directory "
            "to re-prime it")
    served = base_file(episode).parent
    # THE EPISODE DIRECTORY IS THE TRUST ROOT for every mkdir under it. Everything at or
    # above it is host-controlled — the episodes root is configured, outside both the runs
    # base and the checkout — while everything BELOW it is reachable from a sibling box's
    # rw bind, which is exactly the split `guarded_mkdir`'s anchor is for.
    guarded_mkdir(served, base=episode)
    claim = served / ".priming"
    try:
        os.close(os.open(claim, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
    except FileExistsError as taken:
        raise LedgerError(
            f"another launcher is priming episode {episode_id!r} ({claim} exists) — a family's "
            "capture is written once, before any sibling forks. If no launcher is running, that "
            "file is the wreck of one that was killed mid-prime; remove it to retry") from taken
    try:
        report = prime(Path(source_run_dir), base_file(episode))
    except LedgerError as nothing_to_prime:
        # A SOURCE THAT CAPTURED NOTHING IS STILL BRANCHABLE, and this is the one place that
        # reading is taken. `prime_base` refuses a zero-row capture, and for its own caller that
        # is right: #920's in-process launcher had no other signal, and an episode whose every
        # question goes live is one whose siblings differ by the estate's drift rather than by
        # their worlds.
        #
        # #947 has that signal. The review replays EXACTLY the set the primer read, and records
        # what it replayed and what it could not; a family over an empty capture is a family
        # whose review says so, per world, in the archive. And the launcher's own fixtures for
        # relaunch and for the exclusive-create race are sources with no captured query at all —
        # a run dir carrying evidence and no queries table is an ordinary imported or replayed
        # run. So the refusal is DOWNGRADED here to an empty base plus a loud line, and nowhere
        # else: `prime_base` keeps it for every other caller, and an episode that took this path
        # is the one an operator was told about at launch.
        #
        # Declared as a MECHANISM DEVIATION rather than a repair. If a later reader decides an
        # empty capture must abort, the change is one `raise` here and a fixture that captures.
        if not _is_empty_capture(nothing_to_prime):
            claim.unlink(missing_ok=True)
            raise
        write_guarded(base_file(episode), "")
        print(
            f"[branch] {source_run_dir} captured no replayable query — the family's base is "
            "EMPTY, so every key each sibling asks reaches the live estate and any difference "
            "between siblings includes the estate's own drift. The review records what it "
            "replayed; read it before comparing.", file=sys.stderr)
        claim.unlink(missing_ok=True)
        return episode
    finally:
        # The claim is released on EVERY exit, including the primer's own refusal, so a refused
        # prime does not make the episode permanently unbranchable — which is the state the
        # adopt half of this fork exists to keep reachable.
        claim.unlink(missing_ok=True)
    # BOTH HALVES, NAMED. Every skipped row is a key that will reach the LIVE estate during the
    # episode rather than replaying, so the skips are the size of the non-deterministic surface
    # — and a reader shown only "primed 10" would assume it was zero.
    print(
        f"[branch] primed {report.primed} captured row(s) into {base_file(episode)}; "
        f"{report.skipped} skipped ({report}) — a skipped key is read live per world rather "
        "than replayed", file=sys.stderr)
    return episode


def _is_empty_capture(refusal: LedgerError) -> bool:
    """Is this the primer's ZERO-ROW refusal, rather than one of its others?

    Matched on the primer's own sentence rather than on a class, because `LedgerError` is also
    what a base that already exists raises — and downgrading THAT would be exactly the two-runs-
    merged-under-first-row-wins failure the claim above exists to prevent. Narrow on purpose: a
    refusal this predicate does not recognise propagates.
    """
    return "primed no base rows" in str(refusal)


def preflight_episode(
    *, source_run_dir: Path, branch_message_id: int, episode_id: str, episode_dir: Path,
    door: Any, preflight: Callable[[str | None], int], model: str | None,
) -> tuple[str, tuple[str, ...]]:
    """Everything that can refuse BEFORE the questioner is paid for, in one block.

    ONE BLOCK, not six checks scattered along the happy path (§7 FORK-8). Each of these refuses
    for its own reason, and every one of them is knowable before a single model call, a single
    staged name or a single primed row exists. Split across the flow they fired in the order the
    code happened to reach them, which meant an operator with two problems fixed them one paid
    episode at a time.

    Returns the episode token and the configured corpus patterns, because both are computed here
    to be checked and every later step needs them — recomputing either downstream is a second
    reading of a value the preflight already judged.
    """
    token = _episode_token(episode_id)
    patterns = staging_mod.check_configured_patterns(configured_patterns())
    _check_branch_point(source_run_dir, branch_message_id)
    # THE SOURCE ALERT IS SCREENED BEFORE THE QUESTIONER READS IT, and this is the third reader
    # of that surface — beside `run.py --resume`'s own seed read and the questioner's frontier
    # read. The source run dir is a prior box's rw bind, so `alert.json` there is model-writable
    # and a link planted at that name would copy its TARGET's bytes into a model-facing prompt.
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
    # THE SWEEP IS THE FIRST THING THAT TOUCHES THE NAMESPACE. An episode must never author
    # worlds into a namespace still holding an earlier attempt's aliases: those names are live
    # on the cluster under exactly the token this episode is about to reuse, so a query for this
    # world's view would read the dead attempt's documents.
    staging_mod.sweep(episode_dir, episode_token=token, door=door)
    return token, patterns


def _episode_token(episode_id: str) -> str:
    try:
        return episode_token_for(episode_id)
    except FamilyError as bad:
        raise LauncherRefused(
            f"[branch] {bad} — pass an explicit episode token if this source run's id cannot "
            "render to one") from bad


def _probe_cluster(door: Any, patterns: Sequence[str]) -> None:
    """Refuse an episode whose write door cannot reach the cluster.

    Asked with the door's own connecting call rather than by trusting its construction: the door
    is built from configuration and its failure mode is at USE — a container that is not
    running, a docker context that does not resolve. Discovered at step 3 instead, the refusal
    arrives after the questioner has been paid for and the base primed.
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


#: The largest message id any one investigation's session could hold, used ONLY when the source
#: run carries no readable session store. The driver caps an investigation at
#: `DEFAULT_REQUEST_LIMIT` model requests and a request appends a bounded handful of messages, so
#: an id two orders of magnitude beyond that product names no message any run could have
#: produced. It is a CEILING and not the check: where a store exists, `branch_point_time` asks
#: the session itself, which is the only authority on which of ITS messages may be branched from.
MAX_BRANCH_MESSAGE_ID = 100 * 60


def _check_branch_point(source_run_dir: Path, branch_message_id: int) -> None:
    """Refuse a branch point the source run could not have produced.

    THE STORE IS THE AUTHORITY when there is one: `branch_point_time` reads the session and
    refuses a message id it does not hold, or one that is not a branchable boundary.

    A SOURCE RUN WITH NO SESSION STORE is still branchable, and that is a deliberate looseness
    rather than an oversight — an imported run dir, a replayed fixture and a run whose store was
    pruned all carry their evidence and none carries a session. What can still be said about
    such a request is exactly the ceiling above: negative is no message, and an id beyond what
    any session could hold is a typo or a paste. Anything between those the launcher cannot
    judge, and it says so rather than refusing a source it has no evidence against.
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
        branch.branch_point_time(store, Path(source_run_dir), branch_message_id)
    except branch.BranchError as bad:
        raise LauncherRefused(f"[branch] {bad}") from bad
    finally:
        store.close()


def _source_store(source_run_dir: Path) -> Any:
    """The source run's own session store, or `None` when it does not carry one.

    `open_source_store` refuses a run whose case pointer is missing or does not reconcile, and
    that refusal is right for a caller about to FORK into the store — a handle over the wrong
    database inherits nothing. Here the question is weaker: does this source have a session this
    launcher can ask about its own messages? A run with none is answered `None`, and the two
    callers above each say what they do with that.
    """
    try:
        return branch.open_source_store(Path(source_run_dir))
    except (branch.BranchError, session_store.StoreError, sqlite3.Error, OSError):
        return None


def branch_point_clock(source_run_dir: Path, branch_message_id: int) -> Any:
    """T0 — the moment every sibling resumes INTO — derived once for the whole family.

    DERIVED ONCE, never per world: a moment each sibling worked out for itself is not a shared
    clock, and nothing downstream could tell that it was not.

    THE SESSION IS THE AUTHORITY, and where there is one this is exactly `branch_point_time`.
    Where there is not, T0 falls back to the newest moment the source run's own evidence
    carries — the last time anything in that run dir was written. That is a MECHANISM DEVIATION
    from the design, which names the store and only the store, and it is recorded as one: the
    fallback is the moment the source's evidence STOPPED, which is the closest thing a storeless
    run has to a branch point, and it is strictly better than the alternative of stamping every
    sibling's payloads with the afternoon the family happened to be launched. A source that DOES
    carry a session never reaches it.
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
# step 5 — the family as processes
# ---------------------------------------------------------------------------------------


def sibling_runs_base(episode_dir: Path) -> Path:
    """The runs base each sibling PROCESS is handed.

    INSIDE THE EPISODE (§7 FORK-13). A sibling materialised beside its source is indistinguishable
    from an ordinary run to every consumer that walks the runs base — the held-out index claims
    the fixture slug by prefix and hands the score to the newest by mtime, the lesson tracer
    counts one investigation as four, and the orientation corpus's recursive walk moves the
    denominator every ordinary run is ranked against. None of those readers can tell a synthetic
    sibling from a real run, and the answer this seam took is to keep them out of the tree rather
    than to teach three readers a fourth rule.
    """
    return Path(episode_dir) / RUNS_SUBDIR


def sibling_argv(episode_dir: Path, world_label: str) -> list[str]:
    """One sibling's command line: the manifest, and which arm of it this process is.

    Everything else a sibling needs is DERIVED from the manifest, which is what makes the
    manifest the contract. `sys.executable` rather than a bare `python3`, because the launcher
    already re-execs into the project venv and a child that did not would resolve a different
    interpreter with a different dependency set.
    """
    return [sys.executable, str(PATHS.defender_dir / "run.py"),
            "--resume", str(Path(episode_dir) / MANIFEST_NAME), "--world", world_label]


def start_family(
    episode_dir: Path, world_labels: Sequence[str], *,
    spawn: Callable[..., int] | None = None,
) -> dict[str, int]:
    """Start every accepted sibling TOGETHER, and wait for all of them.

    TOGETHER IS A PROPERTY OF THE START, not of a config flag: the children are handed to the
    process seam from N threads that rendezvous first, so no sibling's start waits on another
    sibling's completion. Serially, an episode's arms would be separated in time by however long
    each investigation took — and a family compared across a moving estate is exactly what the
    primed capture and the shared T0 exist to prevent, undone by the launcher's own scheduling.

    THE CHILD'S RUNS BASE IS INSIDE THE EPISODE. That is the whole of the containment decision:
    the child materialises its run dir under `DEFENDER_RUNS_BASE`, so pointing that at the
    episode is what puts the sibling out of every runs-base walker's reach without teaching any
    of those walkers a new rule.

    `spawn` is the process seam. Defaulted at the boundary rather than re-coalesced in the body,
    per the project's own anchoring rule.
    """
    start = _default_spawn if spawn is None else spawn
    episode_dir = Path(episode_dir)
    runs = sibling_runs_base(episode_dir)
    guarded_mkdir(runs, base=episode_dir)
    labels = list(world_labels)
    if not labels:
        return {}
    ready = threading.Barrier(len(labels))
    exits: dict[str, int] = {}

    def launch_one(label: str) -> None:
        env = dict(os.environ)
        env["DEFENDER_RUNS_BASE"] = str(runs)
        # RENDEZVOUS FIRST. Without it "started together" would be whatever the pool's own
        # scheduling happened to produce, and a family whose arms did not overlap would still
        # look like one that did.
        ready.wait(timeout=30)
        exits[label] = start(sibling_argv(episode_dir, label), env=env)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(labels)) as pool:
        for future in [pool.submit(launch_one, label) for label in labels]:
            future.result()
    return exits


def _default_spawn(argv: list[str], *, env: dict[str, str] | None = None) -> int:
    """Run one sibling to completion in its own process, inheriting nothing but `env`."""
    import subprocess

    return subprocess.run(argv, env=env, check=False).returncode  # noqa: S603 — fixed argv


# ---------------------------------------------------------------------------------------
# step 6 — verification, the family stamp, and the archive
# ---------------------------------------------------------------------------------------


def _world_label_of(run_dir: Path) -> str:
    """Which arm a sibling's run dir belongs to: the last component of its run id."""
    return Path(run_dir).name.rsplit("-", 1)[-1]


def _scrub_ran(run_dir: Path) -> bool:
    """Did the reap scan walk this sibling's tree and say so?

    Read at the SIDECAR path beside the run dir, never inside it: the verdict is written outside
    the tree it judges on purpose (§7 D8) — in-tree it would be both plantable and forgeable by
    the box that is root on that mount — so a run-dir-scoped read finds nothing and would mark
    every family incomplete.
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
    """One sibling's own provenance record, or `None` when it has none this reader can use.

    ABSENT AND UNREADABLE ANSWER THE SAME WAY, and that is the point: neither is an agreeing
    stamp, and treating an unknown as agreement is the one error a provenance comparison must
    not make.
    """
    stamp = Path(run_dir) / FAMILY_STAMP_NAME
    if not artifact_file(stamp):
        return None
    try:
        record = json.loads(stamp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) else None


def _stamp_disagreement(stamps: dict[str, dict | None], *, allow_dirty: bool) -> str | None:
    """Why these siblings are not provably one family, or `None` when they are.

    THREE FIELDS, and the third is #947's addition. The commit says which code ran and the scope
    says what `dirty` was measured over; the MODEL says which engine answered, and the role
    preflight resolves it PER PROCESS — so three siblings launched into a changed environment
    are a comparison across two models with a perfectly agreeing commit, and nothing anywhere
    saying so.

    EVERY NON-CLEAN STAMP REFUSES ABSENT THE OVERRIDE, and there are three shapes a capture can
    produce: a dirty tree, a git that could not be asked at all (no sha, a reason), and a git
    that named the sha and could not answer for the tree. An unknown is not a clean bill of
    health, so all three are refused by the same rule rather than by a taxonomy that would have
    to decide which unknowns are comfortable.
    """
    missing = sorted(label for label, stamp in stamps.items() if stamp is None)
    if missing:
        return (f"sibling(s) {missing} carry no readable provenance stamp — an absent or "
                "unreadable stamp is not an agreeing one")
    unclean = {label for label, stamp in stamps.items() if not _clean_stamp(stamp)}
    if unclean and not allow_dirty:
        label = sorted(unclean)[0]
        stamp = stamps[label] or {}
        return (f"sibling {label!r} reports a tree this family cannot be compared across "
                f"(dirty={stamp.get('dirty')!r}, commit={stamp.get('commit')!r}, "
                f"unavailable={stamp.get('unavailable')!r}) — pass --allow-dirty to record the "
                "family anyway")
    # THE AGREEMENT IS TAKEN OVER THE STAMPS THAT SAY SOMETHING. With the override given, an
    # arm whose git could not be asked has no commit and no tree answer to agree or disagree
    # with, and reading its silence as disagreement would make the override unable to do the one
    # thing it exists for. Without the override that arm never reaches here at all.
    comparable = {label: stamp for label, stamp in stamps.items() if label not in unclean}
    for field in ("commit", "scope", "model"):
        values = {label: (stamp or {}).get(field) for label, stamp in comparable.items()}
        if len({v for v in values.values()}) > 1:
            return (f"siblings disagree on {field}: {values} — the family is held constant on "
                    "it, so a comparison across two values is never archived as comparable")
    return None


def _clean_stamp(stamp: dict | None) -> bool:
    """Did git answer for this sibling's tree, and say it was clean?

    THREE SHAPES ARE NOT CLEAN and only one is: a dirty tree, a git that could not be asked at
    all (no sha, a reason), and a git that named the sha and could not answer for the tree. An
    unknown is not a clean bill of health — that is the one error a provenance comparison must
    never make, and the three arms are refused by one rule rather than by a taxonomy that would
    have to decide which unknowns are comfortable.
    """
    if stamp is None:
        return False
    return stamp.get("dirty") is False and bool(stamp.get("commit"))


def _agreed_record(stamps: dict[str, dict | None]) -> dict:
    """The provenance every sibling reported, as one record.

    Taken from the siblings rather than captured again here: the launcher no longer hoists ONE
    capture above the family (that record could only ever describe the moment the launcher ran,
    which is not the moment any sibling did), so the family stamp is a CONCLUSION about N
    per-process stamps and never a reading of its own.
    """
    any_stamp = next(iter(stamps.values())) or {}
    return {k: v for k, v in any_stamp.items() if k != "allow_dirty"}


def verify_family(
    episode_dir: Path, run_dirs: Sequence[Path], *, allow_dirty: bool = False,
    door: Any = None,
) -> dict:
    """Check every sibling, archive what is clean, and record the episode's outcome.

    THE OUTCOME IS A FIELD WITH A REASON (§7 FORK-1). Before it was one, `incomplete` was
    carried by the ABSENCE of a family stamp, and every question about a partially good family
    fell through the gap between "accepted" and "rejected": which arms are usable, whether the
    directory can be compared, why not.

    An incomplete family ARCHIVES PER WORLD and withholds only the family stamp and the
    comparability claim it stands for. Each individually clean sibling is a real investigation
    that really ran, and deleting it because a fourth arm failed its scrub would throw away the
    expensive half of the episode to record the cheap half more tidily.

    And `incomplete` is a FOURTH TEARDOWN TRIGGER. The cluster does not care why the episode
    ended; a staged name left live under this episode's token is a name the next launch's sweep
    will refuse to touch and nothing else will ever remove.
    """
    episode_dir = Path(episode_dir)
    dirs = {_world_label_of(d): Path(d) for d in run_dirs}
    scrub_verified = [label for label in dirs if _scrub_ran(dirs[label])]
    unverified = sorted(set(dirs) - set(scrub_verified))
    stamps = {label: _stamp_of(path) for label, path in dirs.items()}

    reasons: list[str] = []
    if unverified:
        reasons.append(
            f"sibling(s) {unverified} have no scrub verdict recording a completed walk — an "
            "unwalked tree is one nothing has certified as free of what the box left behind")
    disagreement = _stamp_disagreement(
        {label: stamps[label] for label in scrub_verified}, allow_dirty=allow_dirty)
    if disagreement:
        reasons.append(disagreement)

    outcome = INCOMPLETE if reasons else ACCEPTED
    reason = "; ".join(reasons)
    # THE ARCHIVE DIRECTORY EXISTS WHATEVER THE OUTCOME. `worlds/` is the archive's own shape,
    # and its ABSENCE would be a third spelling of "incomplete" beside the outcome field and the
    # withheld family stamp — which is the exact gap FORK-1 closed. An episode that archived no
    # world has an empty `worlds/`, and the recorded outcome is what says why.
    guarded_mkdir(episode_dir / WORLDS_SUBDIR, base=episode_dir)
    # PER WORLD, and only the individually clean ones: a sibling whose own scrub never ran has a
    # tree nothing certified, so copying out of it is the read the certification exists to gate.
    from defender.learning.branch import archive as archive_mod

    archive_mod.archive_episode(
        episode_dir, {label: dirs[label] for label in scrub_verified})
    if outcome == ACCEPTED:
        _write_family_stamp(episode_dir, stamps, allow_dirty=allow_dirty)
    _record_episode_outcome(episode_dir, outcome=outcome, reason=reason)
    if door is not None:
        staging_mod.teardown(episode_dir, door=door, review_path=episode_dir / REVIEW_NAME)
    return {"outcome": outcome, "reason": reason, "scrub_verified": scrub_verified,
            "worlds": sorted(dirs)}


def _write_family_stamp(
    episode_dir: Path, stamps: dict[str, dict | None], *, allow_dirty: bool,
) -> None:
    """The family's one stamp: what every sibling agreed on, and whether it was waved through.

    TWO ROLES, DISJOINT. The agreed provenance is a CONCLUSION about the siblings' own records;
    the override is a fact about the operator's command line. Sourced from one another they
    would be indistinguishable to an archive reader — a family that was clean and one that was
    waved through would read identically — which is the whole reason the override is named.
    """
    write_guarded(
        Path(episode_dir) / FAMILY_STAMP_NAME,
        json.dumps({"agreed": _agreed_record(stamps), "allow_dirty": bool(allow_dirty)},
                   indent=2, sort_keys=True) + "\n")


def _record_episode_outcome(
    episode_dir: Path, *, outcome: str, reason: str, decision: str | None = None,
) -> None:
    """Merge the episode's own verdict into its review record, never over the worlds it holds."""
    path = Path(episode_dir) / REVIEW_NAME
    record: dict[str, Any] = {}
    # `artifact_file`, not `is_file()`: the episode dir holds a sibling's archived artifacts and
    # is reachable from a box's rw bind, so an entry at the review's name may be a link — and
    # `is_file()` stats THROUGH one, which would merge this episode's outcome into whatever the
    # link points at and then write the merged document back over it.
    if artifact_file(path):
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            loaded = None
        if isinstance(loaded, dict):
            record = loaded
    episode = record.setdefault("episode", {})
    if isinstance(episode, dict):
        episode["outcome"] = outcome
        episode["reason"] = reason
        if decision is not None:
            episode["decision"] = decision
    write_guarded(path, yaml.safe_dump(record, sort_keys=False, allow_unicode=True))


# ---------------------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------------------


def parse_branch_args(argv: list[str]) -> argparse.Namespace:
    """The operator's whole command line: a source run, a branch point, and what to say.

    THE EPISODE ID IS NOT HERE. An episode IS a (source run, branch point) pair, so the id is
    derived from those two rather than chosen: two launches of one pair under two operator-chosen
    ids are two immutable captures of one moment with nothing saying they are the same episode.

    THE CONTINUATION PROMPT IS REQUIRED. It is part of the measured instrument — the 2026-08-16
    experiment's own caveat was that its continuation wording biased the run toward closing over
    gathering — and the design names no other author for it, so a launch without one refuses at
    the parser rather than inventing a string.
    """
    p = argparse.ArgumentParser(prog="branch", description=__doc__)
    p.add_argument("source_run_dir", type=Path, help="the finished run to fork")
    p.add_argument("branch_message_id", type=int, help="the message to resume from")
    p.add_argument(
        "--continuation-prompt", required=True,
        help="what every sibling is told on arrival — part of the measured instrument, so it is "
             "the operator's rather than the seam's")
    p.add_argument(
        "--episode-token", default=None,
        help="an explicit episode token, for a source run id that cannot render to a nameable "
             "one; every world token and staged alias is built from it")
    p.add_argument(
        "--allow-dirty", action="store_true",
        help="record the family stamp even though a sibling reported a tree git could not "
             "certify clean; the override is NAMED in the stamp")
    p.add_argument("--model", default=None)
    return p.parse_args(argv)


def main(  # noqa: PLR0913 — the launcher's inputs plus its five injection seams
    argv: list[str],
    *,
    spawn: Callable[..., int] | None = None,
    door: Any = None,
    questioner: Any = None,
    adapters: Any = None,
    invoke: Any = None,
    preflight: Callable[[str | None], int] | None = None,
) -> int:
    """Launch one episode, reporting a refusal as a REFUSAL rather than as a crash.

    Every check this module owns exits with a written explanation, and the checks it delegates
    to — the source store, the branch point, the primer, the family loader, the staging guard,
    the review — raise their own classes with messages authored for exactly this reader.
    Uncaught, those reached the operator wrapped in a stack trace while the ones beside them
    printed cleanly: two spellings of "you cannot branch this" from one command.

    THE STORE FAULTS RIDE HERE TOO, and for the reason the driver's own setup handler names
    them: every step-1 check reads the source's sqlite database, so a file that is not one
    raises `sqlite3.DatabaseError` — never a `BranchError` — and left out, the corrupt-store
    case printed a traceback while the pointer-mismatch case one line away printed a clean
    refusal.

    ANYTHING ELSE RAISED FROM STEPS 2 TO 4 IS ALSO A REFUSAL (§7 FORK-9: one abort rule, not a
    six-way taxonomy). A questioner call that fails, a staging door that fails mid-way and a
    review whose replay cannot reach the cluster are three different exception classes and one
    outcome: teardown has already fired in `_launch`'s own `finally`, no sibling has started,
    and the operator is told which step ended the episode.
    """
    # DEFERRED, and the reason is the launcher's own entry point: `python3
    # defender/learning/branch/cli.py --help` has to reach argparse in an interpreter that may
    # not carry the model runtime, and the review's own imports pull it in. The names below are
    # needed only once a launch is actually under way.
    from defender.learning.branch.review import ReviewError

    try:
        return _launch(argv, spawn=spawn, door=door, questioner=questioner,
                       adapters=adapters, invoke=invoke, preflight=preflight)
    except (branch.BranchError, LedgerError, EstateError, FamilyError,
            staging_mod.StagingRefused, ReviewError,
            session_store.StoreError, sqlite3.Error) as refusal:
        raise LauncherRefused(f"[branch] {refusal}") from refusal


def _launch(  # noqa: PLR0913 — see `main`
    argv: list[str], *, spawn: Any, door: Any, questioner: Any, adapters: Any, invoke: Any,
    preflight: Callable[[str | None], int] | None,
) -> int:
    from defender.run import preflight_role_models

    ns = parse_branch_args(argv)
    # RESOLVED ONCE, HERE, and threaded inward non-`None`. Both are DI seams whose production
    # value is expensive to name (`default_door` reads the deployment's config; the preflight
    # sources provider keys), so the signature cannot carry them as literal defaults — the
    # project's anchoring rule is then to resolve at the boundary rather than to re-coalesce in
    # each body, which is what would let two frames disagree about which door an episode used.
    role_preflight = preflight_role_models if preflight is None else preflight
    write_door = staging_mod.write_door_from_env() if door is None else door
    source = Path(ns.source_run_dir).resolve()
    episode_id = episode_id_for(source.name, ns.branch_message_id)
    episode_dir = episode_dir_for(episode_id)
    token, patterns = preflight_episode(
        source_run_dir=source, branch_message_id=ns.branch_message_id, episode_id=episode_id,
        episode_dir=episode_dir, door=write_door, preflight=role_preflight,
        model=ns.model)

    # STEP 2 ONWARD IS THE PART THAT SPENDS. Everything from here to the archive runs inside the
    # teardown guard, because from the first staging append onward there are names live on the
    # cluster that only this process knows about (§7 FORK-9: ONE abort rule for steps 2-4).
    episode_dir = prepare_episode(episode_id, source)
    try:
        return _run_episode(
            ns, source=source, episode_id=episode_id, episode_dir=episode_dir, token=token,
            patterns=patterns, door=write_door, questioner=questioner,
            adapters=adapters, invoke=invoke, spawn=spawn)
    except SystemExit:
        raise
    except BaseException as failed:  # noqa: BLE001 — ONE abort rule, see `main`'s docstring
        raise LauncherRefused(
            f"[branch] episode {episode_id} aborted: {failed!r} — no sibling started and every "
            "staged name is torn down") from failed
    finally:
        # ON EVERY EXIT: the rejection, the clean completion, the `incomplete` family and any
        # exception raised after the first staging append. The cluster does not care why the
        # episode ended, and a staged name left live under this episode's token is one the next
        # launch's sweep will refuse to touch and nothing else will ever remove.
        staging_mod.teardown(episode_dir, door=write_door,
                             review_path=episode_dir / REVIEW_NAME)


def _run_episode(  # noqa: PLR0913 — the episode's whole identity plus its seams
    ns: argparse.Namespace, *, source: Path, episode_id: str, episode_dir: Path, token: str,
    patterns: Sequence[str], door: Any, questioner: Any, adapters: Any, invoke: Any, spawn: Any,
) -> int:
    """Steps 2 to 6, inside the teardown guard."""
    family = _author(ns, source=source, episode_id=episode_id, episode_dir=episode_dir,
                     questioner=questioner)
    # THE STAGING RECORD EXISTS FROM THE MOMENT STAGING BEGINS, empty if nothing is staged.
    # It is the SOLE account of a cluster write — the write door bypasses `guard_outbound`,
    # which is also the capture recorder — so its ABSENCE has to mean "staging never started"
    # and never "staging wrote something this file does not name". An empty record is the
    # honest statement that a family declared no corpus difference.
    staged = staging_mod.staged_path(episode_dir)
    if not staged.exists():
        # A COMMENT LINE, not `[]`. The record is APPENDED to, one YAML list item per created
        # name, so a literal empty-list document would make every later append unparseable —
        # and an unparseable staging record is the one thing teardown refuses to act on, which
        # would leave every name this episode creates live on the cluster forever. A comment
        # parses to nothing, so an episode that staged no corpus reads back as no rows, while
        # the FILE still exists from the moment staging began.
        write_guarded(
            staged,
            f"# staged names for episode {episode_id} — one row per name, appended BEFORE the "
            "name is created\n")
    for world in runnable_worlds(family):
        staging_mod.stage_world(world, episode_dir=episode_dir, episode_token=token,
                                configured_patterns=patterns, door=door)
    from defender.learning.branch import review as review_mod

    record = review_mod.review(family, episode_dir=episode_dir, adapters=adapters, door=door,
                               invoke=invoke)
    if record.get("episode", {}).get("decision") == REJECTED:
        # ANY REJECTED WORLD ENDS THE EPISODE (§7 FORK-14). Not the rejected one alone: a world
        # is a difference against its siblings, so a family missing an arm measures nothing the
        # design claims to measure, and running the remainder would produce a directory that
        # reads like a completed comparison.
        _record_episode_outcome(episode_dir, outcome=REJECTED, reason=str(
            record.get("episode", {}).get("reason") or "a world contradicted the capture"),
            decision=REJECTED)
        guarded_mkdir(episode_dir / WORLDS_SUBDIR, base=episode_dir)
        print(f"[branch] episode {episode_id}: rejected before any sibling started",
              file=sys.stderr)
        return 1

    labels = [w.world_id for w in runnable_worlds(family)]
    exits = start_family(episode_dir, labels, spawn=spawn)
    runs = sibling_runs_base(episode_dir)
    report = verify_family(
        episode_dir, [runs / f"{episode_id}-{label}" for label in labels],
        allow_dirty=ns.allow_dirty)
    failed = sorted(label for label, code in exits.items() if code)
    for label in failed:
        print(f"[branch] world {label} exited {exits[label]}", file=sys.stderr)
    print(f"[branch] episode {episode_id}: outcome={report['outcome']} "
          f"({len(report['scrub_verified'])}/{len(labels)} verified)", file=sys.stderr)
    # THE EXIT STATUS IS ABOUT THE LAUNCH, and the RECORD is about the family. A sibling that
    # exited non-zero is a launch that did not do what it was asked; an `incomplete` family is a
    # launch that did exactly what it was asked and found the results not comparable, which is a
    # measurement rather than a failure — and it is written down, in the episode's own outcome
    # field, where a reader who cares can see it. Collapsing the two into the status would make
    # a real finding indistinguishable from a crashed child.
    return 1 if failed else 0


def _author(
    ns: argparse.Namespace, *, source: Path, episode_id: str, episode_dir: Path,
    questioner: Any,
) -> Family:
    """Step 2: the questioner authors the triplet, and it is validated before anything reads it.

    THE DERIVED HALF IS THE LAUNCHER'S, and it is written over whatever the model returned. The
    episode id, the source run, the branch point, T0 and the operator's continuation prompt are
    facts about the measurement; a family that could choose its own would be a family that could
    name a different source run than the one it was authored from.

    ONE IDENTITY GATE, over the whole manifest, BEFORE anything is staged (§7 FORK-4): every
    rule it applies would otherwise have refused at a different depth, and refused there it
    costs a primed episode and however many siblings had already run against a live model.
    """
    from defender.learning.branch import questioner as questioner_mod
    from defender.learning.lead_repository import joined

    as_of = branch_point_clock(source, ns.branch_message_id)
    fences = _fence_count(source)
    document = questioner_mod.author_family(
        source_run_dir=source, episode_dir=episode_dir,
        invoke=questioner,
        leads=_joined_leads(source, joined),
        alert=_alert_document(source),
        frontier=questioner_mod.read_frontier(source, fences_at=fences),
    )
    document.update({
        "episode_id": episode_id,
        "source_run_dir": str(source),
        "source_run_id": source.name,
        "branch_message_id": ns.branch_message_id,
        "fences_at": fences,
        "as_of": as_of.isoformat().replace("+00:00", "Z"),
        "continuation_prompt": ns.continuation_prompt,
    })
    family = parse_family(document)
    check_identities(family)
    _family.write_family(episode_dir, document)
    return family


def _fence_count(source: Path) -> int:
    """How many invlang fences the source run's document closed at the branch point."""
    from defender.skills.invlang.parser import scan_fences

    path = RunPaths(source).investigation
    if not artifact_file(path):
        return 0
    scanned = scan_fences(path.read_text(encoding="utf-8"))
    return len(getattr(scanned, "fences", ()) or ())


def _joined_leads(source: Path, joined: Any) -> list[dict]:
    """The joined leads at the branch point, through the ONE read/join surface."""
    try:
        return [lead.__dict__ if hasattr(lead, "__dict__") else dict(lead)
                for lead in joined(source)]
    except Exception as unreadable:  # noqa: BLE001 — a missing table is an empty frontier
        print(f"[branch] could not join the source's leads ({unreadable!r}); the questioner is "
              "shown none", file=sys.stderr)
        return []


def _alert_document(source: Path) -> dict:
    """The source run's alert, already screened by the preflight."""
    path = RunPaths(source).alert
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


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
    "refuse_distant_source",
    "sibling_argv",
    "sibling_runs_base",
    "start_family",
    "verify_family",
]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
