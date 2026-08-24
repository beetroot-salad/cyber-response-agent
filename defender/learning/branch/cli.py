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

WHAT THIS DOES NOT DO, and it is deliberate rather than unfinished: it does not author the
worlds. A `World` here carries an id and the systems it touches, and its overlay is whatever the
caller hands it. The questioner that writes a triplet, the review that replays it against the
estate, and the archive are #947's.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path

from defender._paths import PATHS
from defender._run_paths import RunPaths
from defender.run_common import materialize_run_dir, resolve_runs_base
from defender.runtime import branch, driver

from .capture import prime_base
from .estate.registry import WorldRegistry
from .ledger import BASE_FILENAME, SERVED_DIRNAME, Ledger


@dataclass(frozen=True)
class World:
    """One sibling's identity: which world it is, and which systems its difference touches.

    `touches` decides cost as much as semantics — a system no world declares is never staged,
    never patched and never costs a model call — so it is the world's own declaration rather
    than something inferred from an overlay that may be empty for honest reasons.
    """

    world_id: str
    touches: tuple[str, ...] = ()


def episode_dir_for(source_run_dir: Path, episode_id: str) -> Path:
    """Where one episode's shared records live.

    Beside the runs rather than inside any of them: the base ledger is the FAMILY's, and parking
    it in one sibling's run dir would make that sibling's tree the thing every other sibling
    reads through — a coupling nothing later could untangle, and one that reads as ordinary
    until someone deletes a run dir.
    """
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


def prepare_episode(source_run_dir: Path, episode_id: str) -> Path:
    """Prime the family's base and hand back the episode directory.

    ONCE, AND BEFORE ANY WORLD. `Ledger.__post_init__` refuses a missing base precisely so a
    sibling built out of order fails loudly instead of reading the live estate for every key,
    and this is the call that makes the ordering true rather than merely checked.
    """
    episode = episode_dir_for(source_run_dir, episode_id)
    report = prime_base(source_run_dir, episode / SERVED_DIRNAME / BASE_FILENAME)
    # BOTH HALVES, NAMED. Every skipped row is a key that will reach the LIVE estate during the
    # episode rather than replaying, so the skips are the size of the non-deterministic surface
    # — and a reader shown only "primed 10" would assume it was zero.
    skipped = report.duplicates + report.failed + report.sentinels + report.unreadable
    print(
        f"[branch] primed {report.primed} captured row(s) into "
        f"{episode / SERVED_DIRNAME / BASE_FILENAME}; {skipped} skipped ({report}) — a skipped "
        "key is read live per world rather than replayed",
        file=sys.stderr)
    return episode


async def run_world(
    world: World, *, spec: branch.BranchSpec, episode_dir: Path, run_id: str,
    defender_dir: Path, model_name: str | None,
) -> dict:
    """One sibling, in its own run dir, against its own ledger over the family's base."""
    run_dir = materialize_run_dir(RunPaths(Path(spec.source_run_dir)).alert, run_id)
    registry = WorldRegistry(
        PATHS.adapters_dir, driver.GATHER_DEF.verb_grant,
        world=world, ledger=Ledger.for_world(episode_dir, world.world_id), as_of=spec.as_of,
    )
    return await driver.run_investigation(
        alert_path=RunPaths(run_dir).alert, run_dir=run_dir, run_id=run_id,
        defender_dir=defender_dir, model_name=model_name, verbs=registry, resume=spec,
    )


async def run_family(
    worlds: list[World], *, spec: branch.BranchSpec, episode_dir: Path, episode_id: str,
    defender_dir: Path, model_name: str | None,
) -> list:
    """Every sibling, concurrently.

    PARALLEL IS SAFE HERE ONLY BECAUSE THE TIERS ARE SPLIT: the base is primed and read-only for
    the whole run, and each world writes its own file, so no two processes or threads ever
    append to one path. Run against a shared ledger file this would tear a multi-hundred-KB row
    in half and `read_jsonl_rows` would drop it silently.

    `return_exceptions`, because one world failing is a result rather than a reason to abandon
    its siblings: the ones that completed are still a family, and the caller can see which arm
    is missing instead of losing all three to whichever failed first.
    """
    return await asyncio.gather(*(
        run_world(
            world, spec=spec, episode_dir=episode_dir,
            run_id=f"{episode_id}-{world.world_id}",
            defender_dir=defender_dir, model_name=model_name)
        for world in worlds
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


def parse_world(spec: str) -> World:
    world_id, _, touches = spec.partition(":")
    return World(
        world_id=world_id,
        touches=tuple(s for s in touches.split(",") if s))


def main(argv: list[str]) -> int:
    ns = parse_branch_args(argv)
    source = Path(ns.source_run_dir).resolve()
    refuse_distant_source(source)
    worlds = [parse_world(w) for w in ns.world]
    if not worlds:
        raise SystemExit("name at least one --world; a family with no sibling measures nothing")

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
    results = asyncio.run(run_family(
        worlds, spec=spec, episode_dir=episode_dir, episode_id=ns.episode_id,
        defender_dir=PATHS.defender_dir, model_name=ns.model))
    failed = [(w.world_id, r) for w, r in zip(worlds, results, strict=True)
              if isinstance(r, BaseException)]
    for world_id, err in failed:
        print(f"[branch] world {world_id} failed: {err!r}", file=sys.stderr)
    print(f"[branch] episode {ns.episode_id}: {len(worlds) - len(failed)}/{len(worlds)} ran",
          file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
