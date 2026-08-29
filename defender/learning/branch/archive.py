"""The archive: one directory per world, holding everything a later reader may ask about.

#947's M8. When a family has run, the episode dir becomes the object #921 grades and a human
reads — and D3's claim about it is not "the episode dir is where we happened to put things"
but **self-containment**: after the archive, `delta_o` and `verdicts` answer from
`episodes/<id>/` alone, with no re-run and no path outside it. That is only true if the copy
here is complete, which is why the archived world carries SIX roles rather than a report and a
pointer: the report, the investigation document, the two tables, the run's own provenance
stamp, the scrub verdict, and a text pointer naming the run dir the bytes came from.

**None of the six is sourced from another.** The pointer is informational: it is a text file,
never a symlink, and nothing in this design follows it. A reader that resolved it would make
the episode self-contained only for as long as the runs base happens to still hold the run,
which is the property the archive exists to stop depending on — the sibling run dirs are
disposable, and one test deletes all three and asks both readers the same questions again.

**The scrub verdict is a SIDECAR, and reaching for it inside the run dir finds nothing.**
`scrub.verdict_path(tree)` is `tree.parent / f"{tree.name}.scrub-verdict.json"` (#771 §7 D8,
re-probed here as G17): the verdict is written OUTSIDE the tree it judges precisely because a
verdict inside a box-writable tree is both plantable and forgeable. So the archive reads a
RUNS-BASE path, and a copy written against the design's "inside the run dir" sentence would
copy a file that is never there and archive a world with no verdict at all — silently, since
absence and "the scan did not run" are the same bytes on disk.

**Every read out of the run dir goes through the lstat screens, and the screening happens
BEFORE anything lands.** The run dir is the box's rw bind, so an entry there may be a symlink
the model planted at an artifact's name; `shutil.copy2` follows it and writes the TARGET's
bytes into the archive, where every later reader — the derived readers here, #921's grader, a
human — takes them for a legitimate in-run artifact and no later gate can tell. The two tables
go through `lead_repository.stage_tables`, the repository's own screened staging path (it
`artifact_file`s the queries table, `artifact_dir`s `gather_raw`, and walks the tree with
`symlinks=True` plus a per-entry ignore hook); the four single files go through
`_run_paths.artifact_file` directly. The whole world is screened first and copied second, so a
world carrying one planted link archives NOTHING rather than a half-world whose missing file
reads as a run that did not produce one.

**Absent and planted are different answers.** A path that is simply not there is skipped and
reported (a sibling that died before writing its report has no report, and refusing the whole
archive would throw away the artifacts it DID produce — the launcher's `incomplete` outcome is
where that fact is recorded, not here). A path that EXISTS and is not a regular file (or, for
`gather_raw`, not a real directory) is a refusal: nothing about the tree it was found in can
be trusted after that, and the launcher's own verification is what should have caught it.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from defender._io import guarded_mkdir, write_guarded
from defender._run_paths import RunPaths, artifact_dir, artifact_file
from defender.learning.lead_repository import stage_tables
from defender.runtime.scrub import verdict_path

#: The archived world's directory, under the episode. One level, keyed by the SHORT label X —
#: the manifest's `world_id`, not the composed world token: the token is what the estate and
#: the ledger compare on, and the archive is what a human opens.
WORLDS_DIRNAME = "worlds"

#: The scrub verdict's name INSIDE the archive. Deliberately not the sidecar's own spelling
#: (`<run>.scrub-verdict.json`): inside `worlds/<X>/` the world is the directory, so the name
#: that carried the run id outside it would carry a run id here that nothing may resolve.
SCRUB_VERDICT_NAME = "scrub_verdict.json"

#: The run-dir pointer's name. A TEXT file, never a link — see the module docstring.
RUN_DIR_POINTER = "run_dir"


class ArchiveRefused(ValueError):
    """A world that cannot be archived honestly.

    Raised for exactly one thing: an artifact's name in the source run dir is occupied by
    something that is not the artifact (a symlink, a FIFO, a device, a link where a directory
    belongs). A `ValueError`, so a caller that already funnels this design's refusals through
    one boundary catch keeps them all; named, so the launcher can say which world and which
    name rather than reporting "the archive failed".
    """


def _single_files(run_dir: Path) -> tuple[tuple[Path, str], ...]:
    """The four single-file roles, as `(source, archived name)`.

    Spelled once, in the order the archived-world row declares them, because two readers of
    this list exist — the screen and the copy — and a name in one and not the other is an
    artifact that is checked and not copied, or copied and not checked.
    """
    paths = RunPaths(run_dir)
    return (
        (paths.report, "report.md"),
        (paths.investigation, "investigation.md"),
        (paths.provenance, "provenance.json"),
        # The SIDECAR beside the run dir, not a path inside it (G17).
        (verdict_path(run_dir), SCRUB_VERDICT_NAME),
    )


def _screen(source: Path, *, world: str, is_dir: bool = False) -> bool:
    """Is `source` an artifact this archive may copy?

    Three answers, not two. `True` — a regular file (or a real directory) that may be copied.
    `False` — nothing is there at all, so there is nothing to copy and nothing to refuse. A
    RAISE — something IS there under the artifact's name and it is not the artifact.

    `exists() or is_symlink()` rather than `exists()` alone: a link pointing at a path that
    does not exist is invisible to `exists()`, and a broken link at an artifact's name is
    exactly as much of a signal as a working one.
    """
    if artifact_dir(source) if is_dir else artifact_file(source):
        return True
    if source.exists() or source.is_symlink():
        raise ArchiveRefused(
            f"world {world!r}: {source} is not a "
            f"{'directory' if is_dir else 'regular file'} — the run dir is the box's writable "
            "bind, so a link (or a FIFO, or a device) wearing an artifact's name is something "
            "the model planted, and copying it would write the target's bytes into the archive "
            "under a name every later reader takes for an in-run artifact")
    return False


def _screened_sources(world: str, run_dir: Path) -> list[tuple[Path, str]]:
    """Every source that will be copied for one world, or the refusal — nothing copied yet.

    The whole point of running this before the first `copy2`: an archive that refused halfway
    would leave a world directory holding some of its six roles, and a MISSING artifact is how
    this design records "the run did not produce one". A half-archive is therefore not a
    partial answer but a wrong one.
    """
    present = [(src, name) for src, name in _single_files(run_dir)
               if _screen(src, world=world)]
    paths = RunPaths(run_dir)
    _screen(paths.executed_queries, world=world)
    _screen(paths.gather_raw, world=world, is_dir=True)
    return present


def archive_episode(episode_dir: Path, run_dirs: dict[str, Path]) -> dict[str, Path]:
    """Archive each world's run dir into `episode_dir/worlds/<label>/`; return what was written.

    `run_dirs` is keyed by the SHORT world label, and the caller chooses its members: an
    episode the launcher marked `incomplete` archives the siblings that were individually
    clean and omits the one that was not, so this function is handed the set to archive rather
    than deriving it from the manifest.

    Screening is per world and copying is per world, in that order (see `_screened_sources`),
    and the worlds are processed in a stable sorted order so a partial failure leaves the same
    prefix on every run rather than whichever order a dict was built in.
    """
    episode_dir = Path(episode_dir)
    archived: dict[str, Path] = {}
    for world in sorted(run_dirs):
        run_dir = Path(run_dirs[world])
        sources = _screened_sources(world, run_dir)
        world_dir = episode_dir / WORLDS_DIRNAME / world
        guarded_mkdir(world_dir, base=episode_dir)
        for source, name in sources:
            # Screened by `_screen` above, before this loop began: a link at any of these
            # names has already raised, so nothing here can follow one.
            shutil.copy2(  # lint-tree-read-follows-link: ok — every source screened in `_screened_sources`
                source, world_dir / name)
        # The two tables, through the repository's own screened staging path — which refuses a
        # non-artifact ENTRY at any depth of `gather_raw` as well as at its root, a walk this
        # module has no business writing a second copy of. It REFUSES rather than aborting (a
        # dangling link deep in the gather tree must not cost a world its whole archive) and
        # returns what it dropped, so the drop is said out loud instead of read later as a
        # payload the run never wrote.
        refused = stage_tables(run_dir, world_dir)
        if refused:
            print(f"[archive] world {world}: {len(refused)} non-artifact entr"
                  f"{'y was' if len(refused) == 1 else 'ies were'} refused rather than copied: "
                  f"{', '.join(str(p) for p in refused)}", file=sys.stderr)
        # The pointer, LAST and as TEXT: informational only, so it is written after the bytes
        # it names have landed, and it is written through the guarded seam like every other
        # write into a tree a box can reach.
        write_guarded(world_dir / RUN_DIR_POINTER, f"{run_dir}\n")
        archived[world] = world_dir
    return archived


__all__ = [
    "RUN_DIR_POINTER",
    "SCRUB_VERDICT_NAME",
    "WORLDS_DIRNAME",
    "ArchiveRefused",
    "archive_episode",
]
