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
import traceback
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

from defender import _provenance
from defender._io import guarded_mkdir, write_guarded
from defender._paths import PATHS
from defender._run_paths import RunPaths, artifact_dir, artifact_file
from defender.learning.branch import seams
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
    # RESOLVED UNCONDITIONALLY. `Path.resolve()` is non-strict and answers for a path that does
    # not exist yet, which is EVERY first launch — nothing creates the episodes root ahead of
    # `guarded_mkdir`. Resolved only when it existed, a relative `DEFENDER_EPISODES_BASE=episodes`
    # compared as `Path("episodes")`, whose `.parents` is `(Path("."),)`, so neither refusal
    # fired and the episode landed inside the checkout — untracked, which is exactly what every
    # sibling's own provenance stamp then reports as a dirty tree.
    root = Path(raw)
    candidate = root.resolve()
    for forbidden, why in (
        (resolve_runs_base(), "the runs base — every walker of that tree descends into every "
                              "directory under it, so an episode there is indexed as runs"),
        (REPO_ROOT, "the checkout — an untracked directory there is what a sibling's own "
                    "provenance stamp reports as a dirty tree"),
    ):
        forbidden = Path(forbidden).resolve()
        if candidate == forbidden or forbidden in candidate.parents:
            raise LauncherRefused(
                f"[branch] {EPISODES_BASE_ENV}={root} resolves inside {why}")
    # THE RESOLVED PATH, which is what "RESOLVED UNCONDITIONALLY" above is about. Returned
    # unresolved, a relative `DEFENDER_EPISODES_BASE` made every path built from it relative:
    # `sibling_runs_base` reached a child process as `DEFENDER_RUNS_BASE`, and the manifest
    # reached it as `--resume`, both re-resolved against whatever cwd that child happened to
    # have. The refusals judged `candidate`; every consumer has to get the same value.
    return candidate


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
    refuse_claimed_episode(episode, episode_id)
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
        # whose review says so, per world, in the archive. So the refusal is DOWNGRADED here to
        # an empty base plus a loud line, and nowhere else: `prime_base` keeps it for every
        # other caller, and an episode that took this path is the one an operator was told
        # about at launch.
        #
        # ONE SOURCE SHAPE REACHES IT, and naming it is the point: a run with NO SESSION STORE.
        # `_check_branch_point` asks `branch.validate` — which refuses a capture that reached no
        # system — but only where there is a store to ask it of, and it returns early where
        # there is none. An imported run dir, a replayed fixture and a pruned store are exactly
        # the sources that arrive with evidence, no session and no queries table. A source that
        # DOES carry a session was already refused at the preflight, before the claim above and
        # before a model call, which is where an unbranchable source should be refused.
        #
        # Declared as a MECHANISM DEVIATION rather than a repair. If a later reader decides an
        # empty capture must abort, the change is one `raise` here and a fixture that captures.
        if not _is_empty_capture(nothing_to_prime):
            raise
        write_guarded(base_file(episode), "")
        print(
            f"[branch] {source_run_dir} captured no replayable query — the family's base is "
            "EMPTY, so every key each sibling asks reaches the live estate and any difference "
            "between siblings includes the estate's own drift. The review records what it "
            "replayed; read it before comparing.", file=sys.stderr)
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


def preflight_episode(  # noqa: PLR0913 — ONE BLOCK is the point (§7 FORK-8): every refusal that is knowable before a model call is asked here, so an operator with two problems is not told about them one paid episode at a time. Splitting it to satisfy an argument count would restore exactly the shape it exists to replace.
    *, source_run_dir: Path, branch_message_id: int, episode_id: str, episode_dir: Path,
    door: Any, preflight: Callable[[str | None], int], model: str | None,
    continuation_prompt: str, episode_token: str | None = None,
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
    token = _episode_token(episode_id, episode_token)
    patterns = staging_mod.check_configured_patterns(configured_patterns())
    _check_branch_point(source_run_dir, branch_message_id,
                        continuation_prompt=continuation_prompt)
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
    # ASKED BEFORE THE SWEEP, not left to `prepare_episode` twenty lines later. The sweep
    # DELETES every `wv-<token>.*` name this episode's own `staged.yaml` records — and a second
    # launcher on the same (source, branch point) pair derives the SAME episode id and the SAME
    # token, so it reads the FIRST launcher's record, finds every live alias "recorded", and
    # removes the running family's whole staged corpus before `prepare_episode` refuses it. The
    # first launcher's siblings then read views that no longer exist, which `_search` answers
    # 200-with-zero-hits (`ignore_unavailable=true`) while every ledger row still says `staged`.
    # A manifest is what says the episode has been authored, and staged names exist only after
    # one — so refusing here closes the window entirely.
    refuse_claimed_episode(episode_dir, episode_id)
    # THE SWEEP IS THE FIRST THING THAT TOUCHES THE NAMESPACE. An episode must never author
    # worlds into a namespace still holding an earlier attempt's aliases: those names are live
    # on the cluster under exactly the token this episode is about to reuse, so a query for this
    # world's view would read the dead attempt's documents.
    staging_mod.sweep(episode_dir, episode_token=token, door=door)
    return token, patterns


def refuse_claimed_episode(episode_dir: Path, episode_id: str) -> None:
    """Refuse an episode id whose family has already been authored.

    ONE RULE, TWO DOORS. `prepare_episode` asks it because priming a second capture under an
    existing family is the merge its exclusive claim exists to prevent; `preflight_episode`
    asks it because the sweep it runs one line later would delete that family's live staged
    names first. Spelled once so the two cannot come to disagree about what "already claimed"
    is — the second door was added after the first, and the failure it closes is destructive.
    """
    manifest = Path(episode_dir) / MANIFEST_NAME
    if manifest.exists() or manifest.is_symlink():
        raise LedgerError(
            f"episode {episode_id!r} already holds a manifest at {manifest} — an episode id "
            "names one immutable family capture and the triplet authored over it. Reusing it "
            "would mix an earlier estate into this run under first-row-wins; name a fresh "
            "source run or branch point")


def _episode_token(episode_id: str, override: str | None = None) -> str:
    """The episode's token, or the operator-facing refusal that names the escape.

    `override` IS THAT ESCAPE, and it has to reach `episode_token_for` or the refusal below
    names a remedy that does nothing: the operator re-runs with `--episode-token`, the flag is
    parsed and dropped, the identical message prints again, and that source run and branch
    point are permanently unbranchable. The override is held to exactly the same nameability
    rule as a derived token (`_nameable_token`), so naming one buys no laxity.
    """
    try:
        return episode_token_for(episode_id, override=override)
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


def _check_branch_point(source_run_dir: Path, branch_message_id: int, *,
                        continuation_prompt: str) -> None:
    """Refuse a branch point the source run could not have produced.

    THE STORE IS THE AUTHORITY when there is one, and `branch.validate` is what it is asked
    THROUGH. That call is the seam's own set of preconditions and it is asked HERE, before the
    questioner is paid, rather than only inside each sibling: a branch point at a dangling tool
    call, over a capture that reached no system, at the tip of a finished investigation, or over
    a frontier whose fence mapping was snapped is refused by every one of the three children —
    identically, with the same message, after three model calls, a primed base, a staged corpus
    and a full review have already been spent on it. Two of those preconditions govern what the
    questioner is SHOWN (`read_frontier(source, fences_at=...)` slices the same document
    `validate` judges), so a triplet authored past them was authored against material the seam
    exists to refuse.

    `branch_point_time` first, and its answer is what the spec carries: `validate` cross-checks
    `as_of` against its own derivation, so a launcher that invented one would be refused on a
    value it had just computed. One store handle does both, and the sibling that later opens the
    same store re-asks the same rule — one home, two askings, no second spelling.

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

    `open_source_store` refuses a run whose case pointer is missing or does not reconcile, and
    that refusal is right for a caller about to FORK into the store — a handle over the wrong
    database inherits nothing. Here the question is weaker: does this source have a session this
    launcher can ask about its own messages? A run with none is answered `None`, and the two
    callers above each say what they do with that.

    ONLY THE ABSENT POINTER IS "NO SESSION", and the distinction is the whole of this frame.
    `open_source_store` raises ONE class for two facts — a run dir that carries no pointer at
    all (an imported run, a replayed fixture, a pruned store) and a pointer that does not
    reconcile with the store it names. Catching the class swallowed the second as if it were
    the first: a source parked off its own runs base then reported "no session store", every
    caller took its fallback, T0 became the moment the launcher ran and the questioner was shown
    the FINISHED document's frontier instead of the branch point's — a whole episode paid for
    against a source both `refuse_distant_source` and this handle existed to refuse. The
    presence of the pointer is asked HERE, so anything `open_source_store` says about a pointer
    that IS there propagates as the refusal it is.
    """
    run_dir = Path(source_run_dir)
    if not artifact_file(run_dir / session_store.POINTER_FILENAME):
        return None
    return branch.open_source_store(run_dir)


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


def sibling_argv(episode_dir: Path, world_label: str, *, model: str | None = None) -> list[str]:
    """One sibling's command line: the manifest, which arm of it this process is, and the model.

    Everything else a sibling needs is DERIVED from the manifest, which is what makes the
    manifest the contract. `sys.executable` rather than a bare `python3`, because the launcher
    already re-execs into the project venv and a child that did not would resolve a different
    interpreter with a different dependency set.

    THE MODEL IS NOT DERIVABLE FROM THE MANIFEST, so it rides here. The launcher preflights
    `--model` at family level (`preflight_episode`), and dropped from the child's argv that
    check certified a model no sibling then ran: every arm resolved `$DEFENDER_MODEL` or the
    built-in default instead. The failure is invisible without this line, because all N arms
    resolve the SAME wrong model — so `_stamp_disagreement`'s `model` comparison finds perfect
    agreement and the family is archived as comparable on a model nobody asked for.
    """
    argv = [sys.executable, str(PATHS.defender_dir / "run.py"),
            "--resume", str(Path(episode_dir) / MANIFEST_NAME), "--world", world_label]
    if model is not None:
        argv += ["--model", model]
    return argv


#: The exit code recorded for an arm whose PROCESS never started — the spawn seam raised, or the
#: rendezvous broke. Not any code a sibling can itself exit with (`run.py` returns 0, 1 or 2), so
#: "we could not start it" stays distinguishable in the launcher's own report from "it ran and
#: failed"; both are non-zero, which is what the launch status is about.
SPAWN_FAILED_EXIT = 70


def start_family(
    episode_dir: Path, world_labels: Sequence[str], *,
    spawn: Callable[..., int] | None = None, model: str | None = None,
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
        exits[label] = start(sibling_argv(episode_dir, label, model=model), env=env)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(labels)) as pool:
        futures = {label: pool.submit(launch_one, label) for label in labels}
    # A THREAD THAT DIED IS A RESULT, not a reason to abandon its siblings — the contract the
    # `return_exceptions=True` fan-in this replaced spelled out loud. Re-raised here it left
    # `_run_episode` through `_launch`'s abort arm, so `verify_family` never ran:
    # the siblings that DID complete a whole investigation were never archived, no episode
    # outcome was recorded, and the operator was told "no sibling started" — which is false of
    # every arm the pool had already run to completion. It also fires for all N at once, since
    # one late arrival breaks the shared barrier for every party.
    #
    # Recorded as a NON-ZERO exit rather than as a missing key: `_run_episode` reads a label's
    # absence from this map as nothing to report, so a swallowed failure would have exited 0.
    for label, future in futures.items():
        try:
            future.result()
        except Exception as never_started:  # noqa: BLE001 — one arm's failure, not the family's
            exits[label] = SPAWN_FAILED_EXIT
            print(f"[branch] world {label} was never started: {never_started!r}",
                  file=sys.stderr)
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

    THROUGH `_provenance.read`, NOT a hand-rolled `artifact_file`-then-`read_text` pair. The
    class owns what a provenance record IS, and this file lives in the sibling BOX's rw bind —
    so the bytes at that name are whatever the box last wrote there. Read raw, a forged
    `"commit": ["x"]` was truthy to `_clean_stamp`, `_stamp_speaks` admitted the arm, and
    `_stamp_disagreement`'s set build then raised `TypeError: unhashable type: 'list'` out of
    `verify_family` — before a single world was archived, destroying the expensive half of the
    episode over one arm's file. `from_obj` refuses a non-`str` commit and a non-`bool` dirty,
    and `read_guarded` is the alias-refusing read this frame was spelling by hand.

    Re-serialised back to the record's own wire shape so every reader below keeps asking a
    mapping — `_agreed_record` publishes it verbatim, and a field the class gains reaches the
    family stamp without a second census here.
    """
    record = _provenance.read(Path(run_dir) / FAMILY_STAMP_NAME)
    if record is None:
        return None
    # lint-parse: ok — `as_json` is the class's OWN wire shape, narrowed field by field by
    # `RunProvenance.as_json`; this is a round-trip of a typed record, not a read of untyped input.
    return json.loads(record.as_json())


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
    # THE AGREEMENT IS TAKEN OVER THE STAMPS THAT SAY SOMETHING, and a DIRTY tree says
    # something. `_clean_stamp` answers one question for three shapes, and only one of them —
    # git could not be asked, so there is no commit, no scope and no model to compare — is a
    # silence. Dropping every non-clean arm made `--allow-dirty` waive the whole agreement:
    # the three siblings run from ONE checkout, so a dirty tree makes all three unclean at once,
    # `comparable` was empty, the loop below compared nothing, and a family that ran across two
    # commits or two MODELS was archived as comparable — which is the exact fact `_provenance`
    # grew its `model` field to catch. Kept here, a dirty arm is compared on the fields it does
    # carry; the tree's dirtiness itself is what the override waives, and only that.
    comparable = {label: stamp for label, stamp in stamps.items() if _stamp_speaks(stamp)}
    for field in ("commit", "scope", "model"):
        # NO `or {}`: `comparable` is built from `_stamp_speaks`, which is False for `None`,
        # and the `missing` arm above already returned for every absent stamp. Re-coalescing
        # here made the dead case answer `None` for every field, which compares EQUAL across
        # siblings — so a relaxed boundary would silently archive a split family as comparable.
        values = {label: stamp.get(field) for label, stamp in comparable.items() if stamp}
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


def _stamp_speaks(stamp: dict | None) -> bool:
    """Did git answer AT ALL for this sibling — whatever it said about the tree?

    The weaker half of `_clean_stamp`, and the one the AGREEMENT is taken over. A stamp with a
    commit names a commit, a scope and a model that can agree or disagree with a sibling's; a
    stamp without one is a silence, and reading a silence as disagreement would make
    `--allow-dirty` unable to do the one thing it exists for.
    """
    return stamp is not None and bool(stamp.get("commit"))


def _agreed_record(stamps: dict[str, dict | None]) -> dict:
    """The provenance every sibling reported, as one record.

    Taken from the siblings rather than captured again here: the launcher no longer hoists ONE
    capture above the family (that record could only ever describe the moment the launcher ran,
    which is not the moment any sibling did), so the family stamp is a CONCLUSION about N
    per-process stamps and never a reading of its own.

    READ OFF A STAMP THAT SPOKE, and only after `_stamp_disagreement` has found the speakers to
    agree. Taken from an arbitrary entry of the whole mapping it could publish the commit and
    the model of an arm that was excluded from the very comparison this record stands for.
    """
    speaking = [stamp for stamp in stamps.values() if stamp and _stamp_speaks(stamp)]
    if speaking:
        any_stamp: dict = speaking[0]
    else:
        any_stamp = next((stamp for stamp in stamps.values() if stamp), {})
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

    try:
        archive_mod.archive_episode(
            episode_dir, {label: dirs[label] for label in scrub_verified})
    except Exception as archive_refused:  # noqa: BLE001 — recorded, then re-raised unchanged
        # A HALF-ARCHIVE IS RECORDED BEFORE THE EXCEPTION LEAVES, which is the whole of FORK-1
        # applied to this frame. `archive_episode` screens per world and raises on the first
        # world whose run dir has an artifact's name occupied by something that is not the
        # artifact — so an episode with three clean scrubs could leave `worlds/a/` behind, no
        # `episode.outcome` written at all, and a `review.yaml` still saying "3 worlds
        # reviewed, none rejected". `episode._refuse_incomplete` gates on a RECORDED
        # `incomplete`, so both derived readers then answered a one-arm question for a
        # three-arm family with nothing on disk marking it partial — the absence-means-
        # incomplete gap the outcome field exists to close.
        _record_episode_outcome(
            episode_dir, outcome=INCOMPLETE,
            reason="; ".join([*reasons, f"the archive refused: {archive_refused}"]))
        raise
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
    """Merge the episode's own verdict into its review record, never over the worlds it holds.

    THROUGH `staging.merge_review`, which is the ONE merger of this file. Spelled here as well,
    the two writers had drifted on key ordering, unicode escaping and whether the parent
    directory was made — and both run against the same document in one episode, so which of them
    wrote last decided its whole shape.
    """
    block: dict[str, Any] = {"outcome": outcome, "reason": reason}
    if decision is not None:
        block["decision"] = decision
    staging_mod.merge_review(Path(episode_dir) / REVIEW_NAME, "episode", block)


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


def main(  # noqa: PLR0913 — the launcher's inputs plus its six injection seams
    argv: list[str],
    *,
    spawn: Callable[..., int] | None = None,
    door: Any = None,
    questioner: Any = None,
    adapters: Any = None,
    invoke: Any = None,
    preflight: Callable[[str | None], int] | None = None,
    judge: Any = None,
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
                       adapters=adapters, invoke=invoke, preflight=preflight, judge=judge)
    except (branch.BranchError, LedgerError, EstateError, FamilyError,
            staging_mod.StagingRefused, ReviewError,
            session_store.StoreError, sqlite3.Error) as refusal:
        raise LauncherRefused(f"[branch] {refusal}") from refusal


def _launch(  # noqa: PLR0913 — see `main`
    argv: list[str], *, spawn: Any, door: Any, questioner: Any, adapters: Any, invoke: Any,
    preflight: Callable[[str | None], int] | None, judge: Any = None,
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
        model=ns.model, continuation_prompt=ns.continuation_prompt,
        episode_token=ns.episode_token)

    # THE REMAINING SEAMS ARE ANSWERED FOR HERE, at the same boundary `door` and `preflight`
    # are resolved at, and threaded inward non-`None`. Left to their `None` defaults they
    # reached `author_family`'s `invoke(...)` and `review(adapters=None)` as a bare `TypeError`,
    # AFTER `prepare_episode` had primed an immutable episode directory that cannot be reused —
    # so the shipped `__main__` path burned an episode id per attempt and reported it as a crash.
    #
    # RESOLVED BEFORE THE CLAIM, so a deployment that cannot build them is refused while
    # nothing has been spent and no episode directory exists. The adapter seam is the one that
    # can answer that here: building its registry reads and parses every system the gather
    # grant names, so a tree missing an adapter the grant declares refuses now rather than
    # inside the review. The questioner's own model config was already asked for by the role
    # preflight above, which sweeps every registered role including this one.
    #
    # `seams.model_seam` answers BOTH model calls, because the authoring fan-out and the
    # comparator make the same call on the same role and differ only by the `agent_id` their
    # traces partition on — see that module for why a second builder here would be a second
    # place for them to acquire different models.
    try:
        author = seams.model_seam(episode_dir) if questioner is None else questioner
        compare_with = seams.model_seam(episode_dir) if invoke is None else invoke
        read_side = seams.adapter_seam(episode_dir) if adapters is None else adapters
    except Exception as unbuildable:  # noqa: BLE001 — every seam's own fault class, and the answer is the same refusal
        raise LauncherRefused(
            f"[branch] the launcher could not build its model and adapter seams "
            f"({unbuildable!r}) — steps 2 and 4 drive a questioner and the estate's read side, "
            "and an episode that cannot reach either has nothing to measure") from unbuildable

    # STEP 2 ONWARD IS THE PART THAT SPENDS. Everything from here to the archive runs inside the
    # teardown guard, because from the first staging append onward there are names live on the
    # cluster that only this process knows about (§7 FORK-9: ONE abort rule for steps 2-4).
    episode_dir = prepare_episode(episode_id, source)
    # SET ON THE WAY OUT OF EVERY ABORT ARM, and read by the `finally`. The one thing the
    # teardown frame has to know is whether an exception is already on its way to the operator,
    # and the only frame that can say so is this one — see `_teardown_without_masking`.
    aborting = False
    # ONE SHOT, so the episode can hand the cluster back EARLY and the `finally` still covers
    # every path that did not. The grade at the tail of `_run_episode` makes worlds x draws
    # model calls, each bounded only by the subagent timeout, and it reads the ARCHIVE and the
    # runs base — never the cluster. Holding every staged alias live across that is minutes to
    # hours of namespace nobody is using, and any hang there delays teardown of names the next
    # launch's sweep will refuse to touch.
    teardown = _OneShotTeardown(episode_dir, write_door)
    try:
        return _run_episode(
            ns, source=source, episode_id=episode_id, episode_dir=episode_dir, token=token,
            patterns=patterns, door=write_door, questioner=author,
            adapters=read_side, invoke=compare_with, spawn=spawn, judge=judge,
            teardown=teardown)
    except SystemExit:
        aborting = True
        raise
    except BaseException as failed:  # noqa: BLE001 — ONE abort rule, see `main`'s docstring
        aborting = True
        if teardown.done:
            # UNCHANGED, not wrapped — and the condition is WHAT HAPPENED, not one exception
            # class. Once the episode has handed the cluster back, every sibling has started,
            # archived and been reviewed, so both halves of the abort sentence below ("no
            # sibling started and every staged name is torn down") are false of anything raised
            # from here on: the teardown's own refusal, whichever class `staging.teardown`
            # leaked on the way to raising it (`read_staged`'s `UnicodeDecodeError`,
            # `merge_review`'s `OSError`), or an interrupt during the grade. Named on the class
            # instead, exactly one of those was reported honestly and every other one was
            # reported as an episode that never ran. BEFORE the teardown, a `StagingRefused` out
            # of `stage_world` IS the one-abort case and keeps the wrap.
            raise
        raise LauncherRefused(
            f"[branch] episode {episode_id} aborted: {failed!r} — no sibling started and every "
            "staged name is torn down") from failed
    finally:
        # ON EVERY EXIT that has not already torn down: the rejection, the clean completion, the
        # `incomplete` family and any exception raised after the first staging append. The
        # cluster does not care why the episode ended, and a staged name left live under this
        # episode's token is one the next launch's sweep will refuse to touch and nothing else
        # will ever remove.
        teardown(aborting=aborting)


class _OneShotTeardown:
    """`_teardown_without_masking`, called at most once however many callers ask.

    Two frames want it now — the episode itself, which releases the cluster before it spends
    minutes grading, and `_launch`'s `finally`, which covers every path the episode did not
    reach. `staging.teardown` is not safe to run twice (it re-deletes a name already gone and
    files the adapter's complaint as a verification failure), so the second call is the one that
    must do nothing rather than the first being conditional on a flag someone has to thread."""

    def __init__(self, episode_dir: Path, door: Any) -> None:
        self._episode_dir = episode_dir
        self._door = door
        self._done = False

    @property
    def done(self) -> bool:
        """Has the cluster already been handed back? Read by `_launch`'s abort arm, which must
        not tell an operator "no sibling started" about an episode that ran to completion."""
        return self._done

    def __call__(self, *, aborting: bool) -> None:
        if self._done:
            return
        self._done = True
        _teardown_without_masking(self._episode_dir, self._door, aborting=aborting)


def _teardown_without_masking(episode_dir: Path, door: Any, *, aborting: bool) -> None:
    """Tear the episode's staged names down, and NEVER let that displace the abort in flight.

    A `finally` is the one frame where a second exception silently replaces the first, and the
    two are not interchangeable here: the abort says why the episode ended and is what the
    operator has to act on, while a teardown failure says the cleanup also went wrong. Reported
    the other way round, "the door died on its third connection" is what an operator sees for an
    episode that was actually rejected in review.

    NOT SWALLOWED, though — `teardown` has already written the unverified names into the review
    record before it raises, which is the obligation, and this frame adds the stderr line. With
    nothing else propagating, the failure is the answer and it is re-raised.
    """
    # PASSED IN, never inferred. `sys.exc_info()` is THREAD-global, not frame-local: read here
    # it answers for whatever exception is being handled anywhere up this thread's stack, so a
    # `cli.main` called from inside someone else's `except` block reported an in-flight abort
    # for a perfectly clean episode — and a teardown that could not verify its names gone was
    # then swallowed into an exit 0 with live aliases on the cluster. Only `_launch` knows, and
    # it says so.
    try:
        staging_mod.teardown(episode_dir, door=door, review_path=episode_dir / REVIEW_NAME)
    except Exception as cleanup_failed:  # noqa: BLE001 — see the docstring: never mask
        if not aborting:
            raise
        print(f"[branch] teardown also failed ({cleanup_failed!r}); the names it could not "
              "verify gone are in the review record, and the failure that ended the episode "
              "is what follows", file=sys.stderr)


def _run_episode(  # noqa: PLR0913 — the episode's whole identity plus its seams
    ns: argparse.Namespace, *, source: Path, episode_id: str, episode_dir: Path, token: str,
    patterns: Sequence[str], door: Any, questioner: Any, adapters: Any, invoke: Any, spawn: Any,
    judge: Any = None, teardown: Any = None,
) -> int:
    """Steps 2 to 6, inside the teardown guard.

    `teardown` is `_launch`'s one-shot guard, called here once the archive is written so the
    cluster is released before the grade spends its model calls; `_launch`'s `finally` covers
    every path that does not reach that call."""
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
    exits = start_family(episode_dir, labels, spawn=spawn, model=ns.model)
    runs = sibling_runs_base(episode_dir)
    report = verify_family(
        episode_dir, [runs / f"{episode_id}-{label}" for label in labels],
        allow_dirty=ns.allow_dirty)
    failed = sorted(label for label, code in exits.items() if code)
    for label in failed:
        print(f"[branch] world {label} exited {exits[label]}", file=sys.stderr)
    print(f"[branch] episode {episode_id}: outcome={report['outcome']} "
          f"({len(report['scrub_verified'])}/{len(labels)} verified)", file=sys.stderr)
    # J10: the judge runs at the TAIL of the step runner, after the archive step and before the
    # return — never in `_launch`'s post-teardown path, which is production-dead on this route.
    # Its own frame, so the tear-down/grade/re-raise rule is one readable unit and this function
    # keeps the branch count the shared complexity gate allows it.
    _release_and_grade(episode_dir, episode_id=episode_id, judge=judge, teardown=teardown)
    # THE EXIT STATUS IS ABOUT THE LAUNCH, and the RECORD is about the family. A sibling that
    # exited non-zero is a launch that did not do what it was asked; an `incomplete` family is a
    # launch that did exactly what it was asked and found the results not comparable, which is a
    # measurement rather than a failure — and it is written down, in the episode's own outcome
    # field, where a reader who cares can see it. Collapsing the two into the status would make
    # a real finding indistinguishable from a crashed child.
    return 1 if failed else 0



def _release_and_grade(
    episode_dir: Path, *, episode_id: str, judge: Any, teardown: Any,
) -> None:
    """Hand the cluster back, then grade — J10's tail of the step runner.

    A judge failure is NON-FATAL to the episode (F-5): the launcher's own exit status stays
    about the LAUNCH, never about the grade, so a malformed reply or an unreachable model does
    not turn an otherwise-clean episode into a `LauncherRefused`.

    THE CLUSTER IS HANDED BACK BEFORE THE GRADE. Everything the judge reads is on disk — the
    archived episode and the operator's runs base — so there is nothing left for the staged
    names to serve, and the grade is the longest-running thing in the episode.

    HELD, NOT RAISED THROUGH. `_teardown_without_masking` re-raises when `aborting` is False,
    and calling it ahead of the grade therefore made a CLEANUP failure preempt the grade
    entirely: a fully archived, fully reviewed episode ended with no draws, no queue rows and no
    `judge.yaml` — the file whose presence certifies the pass — and the operator saw only the
    staging refusal, indistinguishable from an episode that was never graded for any other
    reason. The refusal is still this episode's answer; it is raised AFTER the grade it has
    nothing to do with (nothing the judge reads is on the cluster).
    """
    teardown_failed: BaseException | None = None
    graded = False
    if teardown is not None:
        try:
            teardown(aborting=False)
        except Exception as cleanup_failed:  # noqa: BLE001 — re-raised below, unchanged
            teardown_failed = cleanup_failed

    try:
        from defender.learning import judge as judge_mod
        from defender.run_common import resolve_runs_base

        judge_mod.grade_episode(episode_dir, judge=judge, runs_base=resolve_runs_base())
    # INSIDE THE `try`, imports included: an import fault in the judge package, or a
    # `FatalConfigError` out of `resolve_runs_base`, is a judge failure like any other, and
    # raised from outside this boundary it reached `_launch`'s `except BaseException` and was
    # reported as "no sibling started and every staged name is torn down" — both halves false of
    # an episode that has already run, archived and torn down.
    except Exception as judge_failed:  # noqa: BLE001 — F-5 IS the broad catch, see below
        # EVERY class, not `JudgeRefused` alone. "A judge failure is non-fatal to the episode"
        # is a property of this boundary, and a boundary that lists the failures it will
        # tolerate does not have it: the grade reads model-authored archives, a shared queue and
        # an injected model seam, and each of those produced a live escape (a decode error, a
        # corrupt draw file, a lock timeout, whatever the seam raises) that reached here as a
        # traceback and cost an otherwise-clean episode its own exit status. The failure is
        # printed in full rather than swallowed — the point is that the LAUNCH's status stays
        # about the launch, not that the failure goes unreported.
        print(f"[branch] episode {episode_id}: the judge pass failed ({judge_failed!r}); the "
              "episode itself is otherwise unaffected", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        graded = True
    else:
        graded = True
    finally:
        # IN A `finally`, so the held cleanup fault survives a class the arm above does not
        # catch. Raised only after the block, it was DROPPED whenever the grade exited on a
        # `BaseException` — an operator's interrupt during minutes of model calls, a `SystemExit`
        # out of an import — and because `_OneShotTeardown` latches `_done` BEFORE it calls,
        # `_launch`'s `finally` was already a no-op: nothing retried, nothing reported, and the
        # names stayed live under a token the next launch's sweep will refuse to touch.
        if teardown_failed is not None:
            # NEVER MASKING, which is `_teardown_without_masking`'s own rule at the frame that
            # first had to make this choice — and answered from a FRAME-LOCAL flag, never
            # `sys.exc_info()`, which is thread-global and answers for whatever is being handled
            # anywhere up this thread's stack. `graded` is set on both paths that leave this
            # block normally, so it is False exactly when something is still on its way to the
            # operator: then the cleanup fault is printed (its unverified names are already in
            # the review record, which is the obligation), and otherwise it is the answer.
            if graded:
                raise teardown_failed
            print(f"[branch] episode {episode_id}: teardown also failed ({teardown_failed!r}); "
                  "the names it could not verify gone are in the review record, and the failure "
                  "that ended the episode is what follows", file=sys.stderr)


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
    fences = _fence_count(source, ns.branch_message_id,
                          continuation_prompt=ns.continuation_prompt, as_of=as_of)
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


def _fence_count(source: Path, branch_message_id: int, *,
                 continuation_prompt: str, as_of: Any) -> int:
    """How many invlang fences the source run's document closed at the branch point.

    THROUGH `branch.fence_count_at`, which is the frame that owns this arithmetic and the only
    one that can answer it AT a branch point — the document alone says how many fences the run
    ever wrote, and the session says which of them had landed by the message being branched
    from. Spelled here as `len(scan_fences(...).fences)` it answered 0 for every document:
    `FenceScan` carries `bodies`/`spans`/`orphaned_headers`/`open_tail` and no `fences`, and the
    `getattr` default swallowed the mistake — so `fences_at: 0` went into every manifest and the
    questioner was shown an EMPTY frontier for every episode it authored.

    A source with NO session store falls back to the document's own total, the same shape and
    for the same reason `branch_point_clock` falls back to the moment its evidence stopped: an
    imported or replayed run has no session to say when, and its whole document is the prefix.
    """
    from defender.runtime.branch import BranchSpec, fence_count_at, source_session
    from defender.skills.invlang.parser import scan_fences

    path = RunPaths(source).investigation
    if not artifact_file(path):
        return 0
    document = path.read_text(encoding="utf-8")
    # `bodies` is the fence content; the complement (`orphaned_headers`) is not dropped
    # silently — it is what `fence_count_at` is asked for instead whenever a session exists,
    # and this arm is only reached for a run that carries none.
    total = len(scan_fences(document).bodies)  # lint-row-drop: ok — a COUNT of fences, not a read of their content; the orphan complement is not addressable by an index into `bodies` and `fence_count_at` below is what answers when a session can say  # noqa: E501
    store = _source_store(source)
    if store is None:
        return total
    try:
        spec = BranchSpec(source_run_dir=Path(source), branch_message_id=branch_message_id,
                          continuation_prompt=continuation_prompt, as_of=as_of)
        return fence_count_at(store, source_session(store, spec), branch_message_id, document)
    finally:
        store.close()


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
