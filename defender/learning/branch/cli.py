#!/usr/bin/env python3
"""Fork one finished run into a family of sibling worlds, and run them.

The composition root for the turn-N branch. Everything it wires already exists as a seam —
`run_investigation(resume=…, verbs=…)` takes the branch spec and the estate registry, `fork`
opens the child session, the applier holds the world's difference — and this is the one place
that decides the ORDER those seams have to be touched in, which is the part no seam can enforce
about itself:

1. Derive T0 from the source store, so every sibling resumes into the same moment.
2. Prime the family's base from the source run's capture, ONCE, before any world exists.
3. Materialise one run dir per world beside the source.
4. Run the worlds in parallel, each with its own ledger over that shared base.

Steps 1 and 2 are what a per-sibling entry point cannot get right on its own: the first because
a moment derived independently by each world is not a shared clock at all, the second because
the base must be written while there is provably no reader.

NOT YET WIRED FOR A LIVE RUN, and that is a scope boundary rather than an oversight. This is
the composition root for ORDERING — the four steps above, which no seam can enforce about
itself — and it deliberately does not reproduce `run.py`'s per-run lifecycle. Three pieces are
missing and each fails loudly rather than quietly if you try:

- no `start_box`/`stop_and_scrub`, so `AgentDeps` falls back to an unattached `BoxExecutor`
  and every `deps.box.run_parsed` raises `BoxFault`; a sibling would burn its budget retrying
  and never get a shell;
- no reap-scan, so `scrub.tree_verified` is False for every sibling run dir and
  `run_common.learning_refusal_gate` refuses it;
- no `preflight_role_models`, the one in-process pass that sources the billable key — so a
  missing key surfaces per sibling, after the base is primed and N forks have committed into
  the SOURCE store.

Wiring them means deciding whether N sandboxes may run concurrently, which is a design
question this batch has not answered. Until it is, drive a branched run through the e2e replay
harness (`tests/e2e/test_920_branch_resume.py`) rather than through this entry point.

WHAT THIS DOES NOT DO, and it is deliberate rather than unfinished: it does not author the
worlds. A `World` here carries an id and the systems it touches, and its overlay is whatever the
caller hands it. The questioner that writes a triplet, the review that replays it against the
estate, and the archive are #947's.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sqlite3
import sys
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

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

from defender._paths import PATHS
from defender._run_id import (
    CASE_STABLE_REQUIRED,
    RUN_ID_ALLOWED,
    is_case_stable_id,
    is_valid_run_id,
)
from defender._run_paths import RunPaths, artifact_file
from defender.learning.branch.capture import PrimeReport, prime_base
from defender.learning.branch.estate.registry import (
    EstateError,
    WorldRegistry,
    validate_world_touches,
)
from defender.learning.branch.ledger import Ledger, LedgerError, base_file
from defender.run_common import materialize_run_dir, resolve_runs_base
from defender.runtime import branch, driver, session_store


@dataclass(frozen=True)
class World:
    """One sibling's identity: which world it is, and which systems its difference touches.

    `touches` decides cost as much as semantics — a system no world declares is never staged,
    never patched and never costs a model call — so it is the world's own declaration rather
    than something inferred from an overlay that may be empty for honest reasons.

    THE ID IS CHECKED AT THE MINT, here, because everything downstream checks a DIFFERENT rule
    at a later depth: the registry wants a non-empty string, a stager wants a name its corpus
    can carry, `Ledger.for_world` wants a filename component, and `materialize_run_dir` wants
    `{episode_id}-{world_id}` to be a legal run id. Refused only there, an operator's typo cost
    a primed episode directory and however many siblings had already run to completion against
    a live model — and `materialize_run_dir` refuses with `sys.exit`, which is a
    `BaseException`, so it aborts the family rather than landing in the result list.
    """

    world_id: str
    touches: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.world_id:
            raise SystemExit(
                "a world needs an id: `--world ID[:sys,sys]`. `None`/empty is how the family "
                "tier spells 'the shared base', and a world claiming it would overwrite the "
                "recording its siblings replay")
        if not is_valid_run_id(self.world_id):
            raise SystemExit(
                f"world id {self.world_id!r} is not usable (allowed: {RUN_ID_ALLOWED}) — it "
                "names this sibling's run dir, its ledger file and its staged corpus, and each "
                "of those refuses a different subset at a different depth")
        if not is_case_stable_id(self.world_id):
            raise SystemExit(
                f"world id {self.world_id!r} is not usable ({CASE_STABLE_REQUIRED}) — it names "
                f"a file beside its siblings and beside the family's capture, and on a "
                f"case-insensitive filesystem {self.world_id.casefold()!r} is the same file. "
                f"Every guard between a world and that capture is an exact string compare, so "
                f"the collision is invisible to all of them. Use "
                f"{self.world_id.casefold()!r}")


def episode_dir_for(episode_id: str) -> Path:
    """Where one episode's shared records live.

    Beside the runs rather than inside any of them: the base ledger is the FAMILY's, and parking
    it in one sibling's run dir would make that sibling's tree the thing every other sibling
    reads through — a coupling nothing later could untangle, and one that reads as ordinary
    until someone deletes a run dir.

    `episode_id` is checked as a run-id-shaped token by `parse_branch_args`, for the reason the
    world id is: it is joined straight into a path here, and `prepare_episode` writes through
    that path BEFORE `materialize_run_dir` ever gets to judge the run id derived from it — so
    an id carrying a separator planted the family's capture outside the runs base entirely.
    """
    # Validate at the path-construction boundary as well as in `_launch`: callers such as tests
    # and future orchestration code invoke `prepare_episode` directly, and none may write before
    # the same single-component rule has run.
    refuse_bad_episode_id(episode_id)
    return resolve_runs_base() / "episodes" / episode_id


def refuse_distant_source(source_run_dir: Path) -> None:
    """Refuse a source that a sibling cannot be materialised beside.

    `open_source_store` derives `runs_base` as `run_dir.parent` and checks
    `store_path_for(case_id, runs_base)` against the pointer the writer recorded — so a
    sibling's own pointer reconciles only if the sibling and its source share a parent.
    `materialize_run_dir` always builds under `resolve_runs_base()`, so a source living anywhere
    else yields siblings whose pointers resolve to a path no database is at, and the failure
    surfaces later as "records its store at X but resolves to Y", naming the opposite cause.

    Refused HERE, where the cause is still visible, rather than by widening
    `open_source_store` — that check is what stops a pointer naming a database this run has no
    business in, and it earns its keep.
    """
    base = resolve_runs_base().resolve()
    if Path(source_run_dir).resolve().parent != base:
        raise SystemExit(
            f"source run {source_run_dir} does not live directly under {base} — a sibling is "
            "materialised beside its source so their case pointers resolve to the same store, "
            "and one parked elsewhere cannot be branched from")


def prepare_episode(
    source_run_dir: Path, episode_id: str,
    prime: Callable[[Path, Path], PrimeReport] = prime_base,
) -> Path:
    """Prime the family's base and hand back the episode directory.

    ONCE, AND BEFORE ANY WORLD. `Ledger.__post_init__` refuses a missing base precisely so a
    sibling built out of order fails loudly instead of reading the live estate for every key,
    and this is the call that makes the ordering true rather than merely checked.

    `prime` is the primer as an INJECTION SEAM rather than a module lookup, so a caller that
    needs to observe whether priming ran at all — the refusals above exist precisely to keep it
    from running — can hand in its own without reaching into this module's globals. The default
    is the real one, so no production caller has to know the seam is there.
    """
    episode = episode_dir_for(episode_id)
    if episode.exists() or episode.is_symlink():
        raise LedgerError(
            f"episode {episode_id!r} already exists at {episode} — an episode id names one "
            "immutable family capture and its per-world live-base rows. Reusing it would mix "
            "the earlier estate into this run under first-row-wins; name a fresh episode id")
    report = prime(source_run_dir, base_file(episode))
    # BOTH HALVES, NAMED. Every skipped row is a key that will reach the LIVE estate during the
    # episode rather than replaying, so the skips are the size of the non-deterministic surface
    # — and a reader shown only "primed 10" would assume it was zero.
    skipped = report.skipped
    print(
        f"[branch] primed {report.primed} captured row(s) into "
        f"{base_file(episode)}; {skipped} skipped ({report}) — a skipped "
        "key is read live per world rather than replayed",
        file=sys.stderr)
    return episode


def materialize_worlds(
    worlds: list[World], *, spec: branch.BranchSpec, episode_dir: Path, episode_id: str,
) -> list[tuple[World, str, Path, WorldRegistry]]:
    """Step 3, whole and SERIALLY, before any sibling starts spending.

    This is where the module docstring's ordering says it belongs, and doing it inside the
    parallel step instead cost two things. `materialize_run_dir` refuses with `sys.exit`, and
    `SystemExit` is a `BaseException` that CPython's `Task.__step` re-raises past
    `asyncio.gather(return_exceptions=True)` and out of `asyncio.run` — so a run dir that
    already existed (the ordinary state after a partly-failed episode, which the CLI's own exit
    code invites you to retry) aborted the whole family instead of landing in the result list,
    cancelling siblings mid-flight and skipping the "N/M ran" report entirely. And
    `Ledger.for_world`'s refusals — an id that is not a filename component, or one that names
    the family's own capture — fired per world, after N-1 siblings had already run a real model
    against a real estate.

    THE REGISTRY IS BUILT HERE for the same reason: every one of `WorldRegistry.__init__`'s
    four refusals — an empty id, an unreadable `touches`, an id no stager can name a corpus in,
    a patch table the applier could never apply — is a property of the WORLD alone, knowable
    before the family starts. Left inside the gathered task they fired per sibling, so an
    authoring typo in world 3 was reported as "2/3 ran": a family with a missing arm, which
    reads like a run that failed rather than like a launch that should never have happened.

    Both are properties of the family that are knowable before it starts, so they are answered
    before it starts: every failure here is a raise out of `main` with nothing spent.
    """
    # THE SOURCE ALERT IS SCREENED BEFORE THE FIRST COPY, and this is the only frame that can.
    # `materialize_run_dir` admits it with `alert.is_file()` and copies it with `shutil.copy` —
    # both of which FOLLOW a link — and every other caller hands it an operator-supplied path.
    # This one hands it a path INSIDE the source run dir, which is the box's rw bind, so
    # `alert.json` there is model-writable and a link planted at that name copies its TARGET's
    # bytes into all N sibling run dirs under the case input's own name, where the visualizer
    # and the archive read them as the alert. `branch._inherit_evidence` already refuses that
    # link with the same `artifact_file` — but only per sibling, inside `run_investigation`,
    # long after the copies exist and after `store.fork` has committed. Asked once, here,
    # before anything is written.
    alert = RunPaths(Path(spec.source_run_dir)).alert
    if not artifact_file(alert):
        raise SystemExit(
            f"source alert {alert} is not a plain file — the alert is the case input every "
            "sibling investigates, and a link wearing its name would copy bytes from outside "
            "the source run into every run dir this launcher creates")
    prepared = []
    for world in worlds:
        run_id = f"{episode_id}-{world.world_id}"
        registry = WorldRegistry(
            PATHS.adapters_dir, driver.GATHER_DEF.verb_grant,
            world=world, ledger=Ledger.for_world(episode_dir, world.world_id),
            as_of=spec.as_of,
        )
        run_dir = materialize_run_dir(RunPaths(Path(spec.source_run_dir)).alert, run_id)
        prepared.append((world, run_id, run_dir, registry))
    return prepared


async def run_world(
    *, spec: branch.BranchSpec, run_id: str, run_dir: Path, registry: WorldRegistry,
    defender_dir: Path, model_name: str | None, model_override: str | None,
) -> dict:
    """One sibling, in its own run dir, against its own ledger over the family's base.

    `model_override` is the operator's RAW `--model`, and so is `model_name` — this launcher
    resolves NEITHER, because `run_investigation` calls `resolve_main_model(model_name)` itself.
    Both slots are kept rather than collapsed because they part company one frame in:
    `model_override` is what reaches the review bundle, whose roles pin their OWN defaults, and
    dropping it ran MAIN on `X` and every review stage on its pinned default — a family not
    comparable with a `run.py --model X` baseline, with nothing anywhere saying the two review
    configurations differed. (`run.py` resolves `model_name` before the call because it also
    PRINTS it and runs `preflight_role_models`; this launcher does neither — see the module
    docstring's third missing piece.)
    """
    return await driver.run_investigation(
        alert_path=RunPaths(run_dir).alert, run_dir=run_dir, run_id=run_id,
        defender_dir=defender_dir, model_name=model_name, model_override=model_override,
        verbs=registry, resume=spec,
    )


async def run_family(
    prepared: list[tuple[World, str, Path, WorldRegistry]], *, spec: branch.BranchSpec,
    defender_dir: Path, model_name: str | None, model_override: str | None,
) -> list:
    """Every sibling, concurrently.

    PARALLEL IS SAFE HERE ONLY BECAUSE THE TIERS ARE SPLIT: the base is primed and read-only for
    the whole run, and each world writes its own file, so no two processes or threads ever
    append to one path. Run against a shared ledger file this would tear a multi-hundred-KB row
    in half and `read_jsonl_rows` would drop it silently.

    `return_exceptions`, because one world failing is a result rather than a reason to abandon
    its siblings: the ones that completed are still a family, and the caller can see which arm
    is missing instead of losing all three to whichever failed first. That promise is only kept
    because `materialize_worlds` already took the setup failures — a `BaseException` raised in
    a gathered task is re-raised past `return_exceptions` and there is nothing this call can do
    about it.
    """
    return await asyncio.gather(*(
        run_world(
            spec=spec, run_id=run_id, run_dir=run_dir, registry=registry,
            defender_dir=defender_dir, model_name=model_name, model_override=model_override)
        for _world, run_id, run_dir, registry in prepared
    ), return_exceptions=True)


def parse_branch_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="branch", description=__doc__)
    p.add_argument("source_run_dir", type=Path, help="the finished run to fork")
    p.add_argument("branch_message_id", type=int, help="the message to resume from")
    p.add_argument("--episode-id", required=True, help="names this family's shared records")
    p.add_argument(
        "--world", action="append", default=[], metavar="ID[:sys,sys]",
        help="a sibling and the systems its difference touches; repeat per world")
    p.add_argument(
        "--continuation-prompt", required=True,
        help="what the sibling is told on arrival — part of the measured instrument, so it is "
             "the operator's rather than the seam's")
    p.add_argument("--model", default=None)
    return p.parse_args(argv)


def refuse_bad_episode_id(episode_id: str) -> None:
    """Refuse an episode id that cannot name a directory beside the runs.

    `episode_dir_for` joins this straight into a path, and `prepare_episode` WRITES through it
    before `materialize_run_dir` ever judges the run id derived from it — so `--episode-id
    ../..` planted the family's capture outside the runs base, or onto another episode's, with
    the run still green. The same rule the world id is held to, because the two are joined into
    one run id and a token that fails there fails here.
    """
    if not is_valid_run_id(episode_id):
        raise SystemExit(
            f"--episode-id {episode_id!r} is not usable (allowed: {RUN_ID_ALLOWED}) — it names "
            "a directory beside the runs and half of every sibling's run id")
    if not is_case_stable_id(episode_id):
        # The same rule the world id is held to, and for the reason `prepare_episode` refuses a
        # reused id: an episode id names one immutable family capture, and two spellings of it
        # are one directory wherever the filesystem folds case — which would mix an earlier
        # estate into this run under first-row-wins while every check here read them as
        # distinct.
        raise SystemExit(
            f"--episode-id {episode_id!r} is not usable ({CASE_STABLE_REQUIRED}) — use "
            f"{episode_id.casefold()!r}")


def parse_world(spec: str) -> World:
    world_id, _, touches = spec.partition(":")
    world = World(
        world_id=world_id,
        touches=tuple(s for s in touches.split(",") if s))
    # BEFORE THE SOURCE STORE OR EPISODE. A typo otherwise survives as a world that touches
    # nothing: every real system records `passthrough`, the run stays green, and the declared
    # difference was never applied. The registry repeats this same helper for programmatic
    # worlds; calling it here keeps a bad CLI declaration from priming an immutable episode.
    validate_world_touches(world, driver.GATHER_DEF.verb_grant)
    return world


def main(argv: list[str]) -> int:
    """Launch one episode, reporting a refusal as a REFUSAL rather than as a crash.

    Every check this module owns exits with a written explanation, and the checks it delegates
    to — `open_source_store`, `branch_point_time`, `validate`, `prime_base`, `Ledger.for_world`
    — raise `BranchError`/`LedgerError`/`EstateError` with messages authored for exactly this
    reader. Uncaught, those reached the operator wrapped in a stack trace while the four beside
    them printed cleanly: two spellings of "you cannot branch this" from one command.

    THE STORE FAULTS RIDE HERE TOO, and they are the same set `driver.run_investigation`'s own
    setup handler names for the same reason. `open_source_store`, `branch_point_time` and
    `validate` all read the source's sqlite database, so a file that is not one, or one written
    under a schema version this build does not know, raises `sqlite3.DatabaseError` or a
    `StoreError` — never a `BranchError`. Left out, the corrupt-store case printed a traceback
    naming `PRAGMA user_version` while the pointer-mismatch case one line away printed a clean
    refusal: exactly the two spellings this handler exists to collapse, from the two inputs an
    operator is most likely to get wrong together.
    """
    try:
        return _launch(argv)
    except (branch.BranchError, LedgerError, EstateError,
            session_store.StoreError, sqlite3.Error) as refusal:
        raise SystemExit(f"[branch] {refusal}") from refusal


def _launch(argv: list[str]) -> int:
    ns = parse_branch_args(argv)
    source = Path(ns.source_run_dir).resolve()
    refuse_distant_source(source)
    refuse_bad_episode_id(ns.episode_id)
    worlds = [parse_world(w) for w in ns.world]
    if not worlds:
        raise SystemExit("name at least one --world; a family with no sibling measures nothing")
    # DISTINCT, and refused here rather than discovered as a collision. Two `--world a` entries
    # is an ordinary copy-paste, and it hands two siblings ONE run id and ONE ledger path — two
    # `Ledger` objects, so two `threading.Lock`s, appending to one file. `run_family`'s parallel
    # design rests on "each world writes its own file"; a repeated id is the one way to make
    # that premise false from outside.
    # CASE-FOLDED, because the thing being kept distinct is a FILENAME. `is_valid_run_id`
    # admits upper case, so `--world a --world A` is two ids by string and ONE run dir and ONE
    # ledger file on a case-insensitive filesystem — which macOS is, and which is where the
    # default runs base lives for every developer on one (`_io.guarded_mkdir` names the same
    # platform for the same reason). Refusing the pair on a case-SENSITIVE host too is the safe
    # direction: a family whose arms are told apart only by capitalisation is unreadable in a
    # report either way.
    repeated = sorted(
        world_id for world_id, seen
        in Counter(w.world_id.casefold() for w in worlds).items() if seen > 1)
    if repeated:
        raise SystemExit(
            f"--world named {repeated} more than once (ignoring case) — a family is a set of "
            "DIFFERENT worlds, and two siblings sharing an id share a run dir and a ledger "
            "file, which on a case-insensitive filesystem includes two spellings of one id")

    store = branch.open_source_store(source)
    try:
        # T0 BEFORE THE SPEC, because the spec carries it — and derived once for the family
        # rather than per world, since a moment each sibling worked out for itself is not a
        # shared clock and nothing downstream could tell that it was not.
        spec = branch.BranchSpec(
            source_run_dir=source, branch_message_id=ns.branch_message_id,
            continuation_prompt=ns.continuation_prompt,
            as_of=branch.branch_point_time(store, source, ns.branch_message_id),
        )
        branch.validate(store, spec)
    finally:
        store.close()

    episode_dir = prepare_episode(source, ns.episode_id)
    prepared = materialize_worlds(
        worlds, spec=spec, episode_dir=episode_dir, episode_id=ns.episode_id)
    results = asyncio.run(run_family(
        prepared, spec=spec, defender_dir=PATHS.defender_dir,
        model_name=ns.model, model_override=ns.model))
    # PAIRED WITH `prepared`, not with `worlds`. `run_family` gathers over `prepared` and
    # `asyncio.gather` answers in ARGUMENT order, so the results line up with the list that was
    # gathered — and re-zipping the separate input list is correct only while
    # `materialize_worlds` happens to preserve it one-for-one. The world is already in the
    # tuple; reading it from there makes the attribution structural rather than incidental, so
    # a future skip or reorder there cannot silently name the wrong sibling as the broken arm.
    failed = [(world.world_id, r) for (world, *_), r in zip(prepared, results, strict=True)
              if isinstance(r, BaseException)]
    for world_id, err in failed:
        print(f"[branch] world {world_id} failed: {err!r}", file=sys.stderr)
    print(f"[branch] episode {ns.episode_id}: {len(worlds) - len(failed)}/{len(worlds)} ran",
          file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
