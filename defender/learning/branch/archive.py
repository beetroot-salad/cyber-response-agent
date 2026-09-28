"""The archive: one directory per world, holding everything a later reader may ask about.

After archiving, `delta_o`, `verdicts` and the grader answer from `episodes/<id>/` alone, with no
re-run and no path outside it. That self-containment requires a complete copy: the report, the
investigation document, the two tables, the run's provenance stamp, the scrub verdict, the
run-end record, the lessons-loaded table, the alert, the gather summaries, and a text pointer
naming the source run dir.

None is sourced from another. The pointer is a text file, never a symlink, and nothing follows
it: sibling run dirs are disposable, and resolving it would make the episode self-contained only
while the runs base still holds the run.

The scrub verdict and run-end record are sidecars beside the run dir (`scrub.verdict_path`,
`run_end.sidecar_path`), written outside the tree they describe because a file inside a
box-writable tree is plantable and forgeable. Looking for them inside the run dir would silently
archive a world with no verdict.

Every read out of the run dir is lstat-screened before anything lands. The run dir is the box's
rw bind, so an artifact's name may be a planted symlink, and `shutil.copy2` would copy the
target's bytes into the archive as if they were in-run artifacts. The tables go through
`lead_repository.stage_tables` (its own screened staging); single files through
`_run_paths.artifact_file`. The whole world is screened before anything is copied, so a world
carrying one planted link archives NOTHING rather than a half-world whose missing file reads as a
run that did not produce one.

Absent and planted are different answers. A missing path is skipped and reported (a sibling
that died before writing its report still has other artifacts; the launcher's `incomplete`
outcome records that). A path that exists but is not a regular file (or, for `gather_raw`, a
real directory) is a refusal.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from defender._io import Bound, entry_present, guarded_mkdir, write_guarded
from defender._episode_paths import LAYOUT, EpisodePaths, WorldPaths
from defender._run_paths import (
    RunPaths,
    artifact_dir,
    artifact_file,
    plain_file,
)
from defender.learning.lead_repository import (
    refuse_non_artifacts,
    refusing_copy2,
    stage_tables,
)
from defender.runtime.run_end import sidecar_path as run_end_sidecar_path
from defender.runtime.scrub import verdict_path

_logger = logging.getLogger(__name__)

# This module binds no record names of its own: sources and destinations are both reached
# through the owners' accessors (`RunPaths`, `EpisodePaths`), so a rename in the owner cannot
# strand a re-binding here.


def read_family_stamp(bound: Bound) -> dict[str, Any] | None:
    """The episode-root family stamp — `{agreed: {...}, allow_dirty}` — or `None` when nothing
    is at the name.

    Unlike the tolerant per-world stamp reader (`family.json_mapping`), this knows the family
    stamp's shape and refuses anything else, through the bound reader's screen: the episode dir
    is reachable from a sibling box's rw bind. The refusal names the relative name only.
    """
    stamp = LAYOUT.family_stamp
    rec = bound.read(stamp)
    if rec.absent:
        return None
    # A directory at the name is refused by the bound walk; a separate `is_dir()` would be an
    # unscreened read of the same entry.
    if rec.text is None:
        raise ValueError(f"{stamp} could not be read: {rec.reason}")
    try:
        doc = json.loads(rec.text)
    except (ValueError, RecursionError) as bad:
        raise ValueError(f"{stamp} is not the family stamp: {bad}") from bad
    if not (isinstance(doc, dict) and isinstance(doc.get("agreed"), dict)
            and "allow_dirty" in doc):
        raise ValueError(f"{stamp} is not the family stamp")
    return doc


class ArchiveRefused(ValueError):
    """A world that cannot be archived honestly.

    Raised when an artifact's name (in the source run dir or the destination) is occupied by
    something that is not the artifact: a symlink, FIFO, device, or a link where a directory
    belongs. A `ValueError` so callers can catch this design's refusals at one boundary.
    """


def _single_files(run_dir: Path, world: WorldPaths) -> tuple[tuple[Path, Path], ...]:
    """The single-file roles, as `(source, destination)` accessor pairs.

    Shared by the screen and the copy so no role can be checked without being copied or vice
    versa. The gather summaries are a directory and are handled in `archive_episode`. The judge,
    not the archive, decides what the sidecars' bytes mean.
    """
    paths = RunPaths(run_dir)
    return (
        (paths.report, world.report),
        (paths.investigation, world.investigation),
        (paths.provenance, world.provenance),
        # The two sidecars beside the run dir. Inside `worlds/<X>/` they take the episode
        # owner's names, dropping the run-id-keyed spelling nothing here may resolve.
        (verdict_path(run_dir), world.scrub_verdict),
        (run_end_sidecar_path(run_dir), world.run_end),
        (paths.lessons_loaded, world.lessons_loaded),
        (paths.alert, world.alert),
    )


def _screen(source: Path, *, world: str, is_dir: bool = False) -> bool:
    """Is `source` an artifact this archive may copy?

    `True`: a regular file (or real directory). `False`: nothing there. Raises: something is
    there and it is not the artifact. `exists() or is_symlink()` so a broken link counts too.
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


def _screened_sources(world: str, run_dir: Path,
                      dest: WorldPaths) -> list[tuple[Path, Path]]:
    """Every source that will be copied for one world, or the refusal — nothing copied yet.

    Runs before the first copy because a half-archived world is wrong, not partial: a missing
    artifact is how this design records "the run did not produce one".
    """
    paths = RunPaths(run_dir)
    present = [(src, to) for src, to in _single_files(run_dir, dest)
               if _screen(src, world=world)]
    _screen(paths.executed_queries, world=world)
    _screen(paths.gather_raw, world=world, is_dir=True)
    _screen(paths.gather_summaries, world=world, is_dir=True)
    return present


def _screen_destinations(world: str, dest: WorldPaths, run_dir: Path,
                         present: set[Path]) -> None:
    """Judge every name this lane will write under the world dir, before the first copy — or
    raise `ArchiveRefused`. `present` is the single-file destinations that have a source this
    time."""
    # The episode dir is reachable from a sibling box's rw bind, and `copy2` opens the
    # destination for writing, following a link planted there. `guarded_mkdir` only judges
    # directory components, so each leaf is checked here. `plain_file`, not `artifact_file`,
    # so a hard link is refused too.
    #
    # Every single-file name is judged, not only those with a source. A plain file left at a
    # name whose source is now absent (a re-archive) would be read as this run's own, so it is
    # removed. An alias is refused, never removed: deleting it would hide it from any scan.
    for _source, target in _single_files(run_dir, dest):
        if not entry_present(target):
            continue
        if not plain_file(target):
            raise ArchiveRefused(
                f"world {world!r}: {target} is occupied by something that is not a plain "
                "regular file — the archive is written into a tree a box can reach, and "
                "copying onto a link would put this world's artifact wherever it points")
        if target not in present:
            target.unlink()
    # The directory and table destinations too: `copytree(dirs_exist_ok=True)` (here and in
    # `stage_tables`) resolves a link planted at the destination, and `stage_tables` screens
    # only its sources. The tables land in the run-dir layout rooted at the world dir.
    staged_dests = RunPaths(dest.dir)
    for target, is_dir in ((dest.gather_summaries, True), (staged_dests.gather_raw, True),
                           (staged_dests.executed_queries, False)):
        if not entry_present(target):
            continue
        if artifact_dir(target) if is_dir else plain_file(target):
            continue
        raise ArchiveRefused(
            f"world {world!r}: {target} is occupied by something that is not a "
            f"{'real directory' if is_dir else 'plain regular file'} — copying onto it "
            "would write this world's archived artifact wherever it points")


def archive_episode(episode_dir: Path, run_dirs: dict[str, Path]) -> dict[str, Path]:
    """Archive each world's run dir into `episode_dir/worlds/<label>/`; return what was written.

    `run_dirs` is keyed by short world label and chosen by the caller: an `incomplete` episode
    archives only its clean siblings, so the set is not derived from the manifest.

    Each world is screened, then copied. Worlds go in sorted order so a partial failure always
    leaves the same prefix.
    """
    episode_dir = Path(episode_dir)
    episode = EpisodePaths(episode_dir)
    archived: dict[str, Path] = {}
    for world in sorted(run_dirs):
        run_dir = Path(run_dirs[world])
        dest = episode.world(world)
        sources = _screened_sources(world, run_dir, dest)
        world_dir = dest.dir
        guarded_mkdir(world_dir, base=episode_dir)
        _screen_destinations(world, dest, run_dir, {to for _s, to in sources})
        for source, target in sources:
            shutil.copy2(  # lint-tree-read-follows-link: ok — every source screened in `_screened_sources`
                source, target)
        # `stage_tables` refuses non-artifact entries at any depth of `gather_raw` without
        # aborting, and returns what it dropped so the drop is reported.
        refused = stage_tables(run_dir, world_dir)
        # `gather_summaries/` through the same per-entry-screened walk as `gather_raw`.
        summaries_src = RunPaths(run_dir).gather_summaries
        summaries_dest = dest.gather_summaries
        if artifact_dir(summaries_src):
            summaries_refused: list[Path] = []
            shutil.copytree(  # lint-tree-read-follows-link: ok — source root screened by `_screen`, destination root screened above and every entry by `refusing_copy2`
                summaries_src, summaries_dest, symlinks=True,
                ignore=refuse_non_artifacts(summaries_refused), dirs_exist_ok=True,
                # Screens each leaf destination too: `dirs_exist_ok=True` walks into the
                # existing directory, where a planted link at a leaf would be followed.
                copy_function=refusing_copy2(summaries_refused))
            refused = [*refused, *summaries_refused]
        if refused:
            _logger.warning(f"world {world}: {len(refused)} non-artifact entr"
                            f"{'y was' if len(refused) == 1 else 'ies were'} refused rather than copied: "
                            f"{', '.join(str(p) for p in refused)}")
        # The pointer last, as text, through the guarded seam.
        write_guarded(dest.run_dir_pointer, f"{run_dir}\n")
        archived[world] = world_dir
    return archived


__all__ = [
    # No record names are re-exported: readers use the owner's accessors directly.
    "ArchiveRefused",
    "archive_episode",
    "read_family_stamp",
]
