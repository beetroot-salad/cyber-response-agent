"""The archive: one directory per world, holding everything a later reader may ask about.

#947's M8. When a family has run, the episode dir becomes the object #921 grades and a human
reads — and D3's claim about it is not "the episode dir is where we happened to put things"
but **self-containment**: after the archive, `delta_o` and `verdicts` answer from
`episodes/<id>/` alone, with no re-run and no path outside it. That is only true if the copy
here is complete, which is why the archived world carries SEVEN roles rather than a report and
a pointer: the report, the investigation document, the two tables, the run's own provenance
stamp, the scrub verdict, the run-end record (#1047 — how the run ended, and whether the model
had closed before it did), and a text pointer naming the run dir the bytes came from.

**None of the seven is sourced from another.** The pointer is informational: it is a text file,
never a symlink, and nothing in this design follows it. A reader that resolved it would make
the episode self-contained only for as long as the runs base happens to still hold the run,
which is the property the archive exists to stop depending on — the sibling run dirs are
disposable, and one test deletes all three and asks both readers the same questions again.

**The scrub verdict and the run-end record are SIDECARS, and reaching for either inside the
run dir finds nothing.** `scrub.verdict_path(tree)` is `tree.parent /
f"{tree.name}.scrub-verdict.json"` (#771 §7 D8, re-probed here as G17) and
`run_end.sidecar_path` has the same shape: both are written OUTSIDE the tree they describe
precisely because such a file inside a box-writable tree is both plantable and forgeable. So
the archive reads two RUNS-BASE paths, and a copy written against the design's "inside the run
dir" sentence would copy a file that is never there and archive a world with no verdict at all
— silently, since absence and "the scan did not run" are the same bytes on disk.

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

import json
import shutil
import sys
from pathlib import Path
from typing import Any

from defender._io import Bound, entry_present, guarded_mkdir, write_guarded
from defender._episode_paths import (
    ARCHIVED_RUN_END_NAME,
    ARCHIVED_SCRUB_VERDICT_NAME,
    JUDGE_DRAWS_DIRNAME,
    JUDGE_NAME,
    REVIEW_NAME,
    RUN_DIR_POINTER_NAME,
    SAMPLES_NAME,
    WORLDS_DIRNAME,
)
from defender._run_paths import (
    ALERT,
    GATHER_SUMMARIES_DIRNAME,
    INVESTIGATION,
    LESSONS_LOADED,
    PROVENANCE,
    REPORT,
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

#: The archived world's directory, under the episode. One level, keyed by the SHORT label X —
#: the manifest's `world_id`, not the composed world token: the token is what the estate and
#: the ledger compare on, and the archive is what a human opens.
# `WORLDS_DIRNAME` — the owner's (`_episode_paths`, #1077 D1), imported above.

#: Where a sibling's run dir lives, relative to its episode. The child process is handed this as
#: its own `DEFENDER_RUNS_BASE`, so the run dir it materialises is inside the episode rather than
#: beside the source run. Owned here, beside the other episode-layout names, so the launcher
#: that writes the tree and the page that reads it spell the segment once.
RUNS_SUBDIR = "runs"

#: The scrub verdict's name INSIDE the archive. Deliberately not the sidecar's own spelling
#: (`<run>.scrub-verdict.json`): inside `worlds/<X>/` the world is the directory, so the name
#: that carried the run id outside it would carry a run id here that nothing may resolve.
SCRUB_VERDICT_NAME = ARCHIVED_SCRUB_VERDICT_NAME

#: The run-dir pointer's name. A TEXT file, never a link — see the module docstring.
RUN_DIR_POINTER = RUN_DIR_POINTER_NAME

#: The three episode-level records, spelled ONCE (#1025 O8). The review's own record, beside
#: the manifest it reviewed (kept on a rejection too — the measurement of a family that did not
#: run is what O4's drift obligation is observed by); the questioner's reference document per
#: staged pattern, moved into the archive at step 2 so it survives a pruned source run; and the
#: judge's family record, written last. Every writer and reader imports these — a second
#: spelling is a reader that opens a file nobody writes the day one of them is renamed.
# `REVIEW_NAME`/`SAMPLES_NAME`/`JUDGE_NAME` — the owner's (`_episode_paths`, #1077 D1),
# imported above and re-exported here for the writers and readers that bind them off this
# module.

#: The judge's per-draw documents, `worlds/<X>/judge/<n>.yaml` (and `worlds/family/judge/` for
#: the family-level call) — the directory the pass creates under each archived world, spelled
#: once for the same reason as the three records above: the writer (`judge/__init__.py`), the
#: enqueue's re-read and the episode page all address it.
DRAWS_DIRNAME = JUDGE_DRAWS_DIRNAME

#: The episode-root family stamp's name — same spelling as a WORLD's own flat run stamp
#: (`_run_paths.PROVENANCE`), a DIFFERENT shape at the same file name (#1025 fk-8/J12). Moved
#: here from `branch/cli.py` (its previous sole owner) so the reader below and the writer share
#: one spelling; bound nowhere else.
FAMILY_STAMP_NAME = PROVENANCE


def read_family_stamp(bound: Bound) -> dict[str, Any] | None:
    """The episode-root family stamp — `{agreed: {...}, allow_dirty}` — or `None` when nothing
    is at the name (#1025 J12).

    A public accessor distinct from the per-world run-stamp reader (`family.json_mapping`,
    tolerant and shape-agnostic): this one KNOWS the family stamp's own shape and refuses a
    directory or a document that is not it, through the bound reader's own screen (#1049) —
    the episode dir is reachable from a sibling box's rw bind, exactly like every other
    episode-root record, and the refusal names the relative name, never the operator's tree.
    """
    rec = bound.read(FAMILY_STAMP_NAME)
    if rec.absent:
        return None
    # A directory squatting the name is refused by the walk itself — no separate `is_dir()`
    # check, which would be an unscreened read of the same box-writable entry the walk judges.
    if rec.text is None:
        raise ValueError(f"{FAMILY_STAMP_NAME} could not be read: {rec.reason}")
    try:
        doc = json.loads(rec.text)
    except (ValueError, RecursionError) as bad:
        raise ValueError(f"{FAMILY_STAMP_NAME} is not the family stamp: {bad}") from bad
    if not (isinstance(doc, dict) and isinstance(doc.get("agreed"), dict)
            and "allow_dirty" in doc):
        raise ValueError(f"{FAMILY_STAMP_NAME} is not the family stamp")
    return doc


class ArchiveRefused(ValueError):
    """A world that cannot be archived honestly.

    Raised for exactly one thing: an artifact's name in the source run dir is occupied by
    something that is not the artifact (a symlink, a FIFO, a device, a link where a directory
    belongs). A `ValueError`, so a caller that already funnels this design's refusals through
    one boundary catch keeps them all; named, so the launcher can say which world and which
    name rather than reporting "the archive failed".
    """


#: The run-end record's archived name (#1047). Its SOURCE is the host-side sidecar beside the
#: run dir (`run_end.sidecar_path`, outside every box's rw bind), exactly the scrub verdict's
#: shape — a file wearing this name INSIDE the run dir is never an input to anything.
RUN_END_NAME = ARCHIVED_RUN_END_NAME

#: The judge's directory-of-summaries role's name, both in a sibling's run dir and archived.
# `GATHER_SUMMARIES_DIRNAME` — the owner's (`_run_paths`), imported above.
#: The judge's two single-file additions' archived names — the same as their run-dir names.
LESSONS_LOADED_NAME = LESSONS_LOADED
ALERT_NAME = ALERT


def _single_files(run_dir: Path) -> tuple[tuple[Path, str], ...]:
    """The seven single-file roles, as `(source, archived name)`.

    Spelled once, in the order the archived-world row declares them, because two readers of
    this list exist — the screen and the copy — and a name in one and not the other is an
    artifact that is checked and not copied, or copied and not checked.

    D7 (#921) adds the last two: `lessons_loaded.jsonl` and `alert.json`, the two of the
    judge's three new inputs that are single files. `gather_summaries/` is the third and is a
    DIRECTORY, so it takes the per-entry-screened walk beside `stage_tables`' own two tables
    rather than a slot in this tuple — see `_gather_summaries_source`/`archive_episode`.

    #1047 adds the seventh: the run-end record, the second host-side sidecar. Like the scrub
    verdict it is read from BESIDE the run dir and takes the same screen, the same copy and
    the same absent/planted split as the other six — the judge, not the archive, decides what
    its bytes mean (`run_end.parse_record`), exactly as it does for the verdict.
    """
    paths = RunPaths(run_dir)
    return (
        (paths.report, REPORT),
        (paths.investigation, INVESTIGATION),
        (paths.provenance, PROVENANCE),
        # The two SIDECARS beside the run dir, not paths inside it (G17).
        (verdict_path(run_dir), SCRUB_VERDICT_NAME),
        (run_end_sidecar_path(run_dir), RUN_END_NAME),
        (run_dir / LESSONS_LOADED_NAME, LESSONS_LOADED_NAME),
        (paths.alert, ALERT_NAME),
    )


def _gather_summaries_source(run_dir: Path) -> Path:
    """The sibling's own directory of per-lead gather summaries, D7's directory-shaped input."""
    return run_dir / GATHER_SUMMARIES_DIRNAME


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
    would leave a world directory holding some of its seven roles, and a MISSING artifact is how
    this design records "the run did not produce one". A half-archive is therefore not a
    partial answer but a wrong one.
    """
    present = [(src, name) for src, name in _single_files(run_dir)
               if _screen(src, world=world)]
    paths = RunPaths(run_dir)
    _screen(paths.executed_queries, world=world)
    _screen(paths.gather_raw, world=world, is_dir=True)
    _screen(_gather_summaries_source(run_dir), world=world, is_dir=True)
    return present


def _screen_destinations(world: str, world_dir: Path, run_dir: Path,
                         present: set[str]) -> None:
    """Judge every name this lane will write under `world_dir`, BEFORE the first copy — or
    raise `ArchiveRefused`. `present` is the single-file names that have a source this time."""
    # THE DESTINATION IS SCREENED TOO, and before the first copy for the same reason the
    # sources are. `guarded_mkdir` judges the DIRECTORY components; nothing judged the leaf,
    # and `shutil.copy2` opens the destination for writing, which resolves a link planted
    # there — the episode dir is reachable from a sibling box's rw bind (it is why
    # `merge_review` and the run-dir pointer both go through the guarded seam), so an entry
    # at `worlds/<label>/report.md` would redirect an artifact copy out of the archive.
    # `plain_file`, not `artifact_file`: a HARD link at the leaf is a regular file to
    # `lstat`, and `copy2` opens it for writing all the same — the same rule
    # `write_guarded` applies to every other write into this tree (#1047 F-F), applied to
    # EVERY destination this lane writes: the seven single files here, the two tables and
    # the summaries directory below, and each leaf `refusing_copy2` lands inside them.
    #
    # EVERY single-file NAME is judged, not only the ones with a source. A MISSING artifact
    # is how this design records "the run did not produce one", and that has to be true of
    # the destination too: a plain file left at a name whose source is now absent (a
    # re-archive after the sidecar or the report was lost) would be read by every later
    # reader as this run's own, so it is removed — a plain regular file is exactly what the
    # copy would have replaced. An ALIAS at such a name is refused, never removed (D1:
    # removal is sanitizing, and an entry the archive deletes is one no scan can report).
    for _source, name in _single_files(run_dir):
        dest = world_dir / name
        if not entry_present(dest):
            continue
        if not plain_file(dest):
            raise ArchiveRefused(
                f"world {world!r}: {dest} is occupied by something that is not a plain "
                "regular file — the archive is written into a tree a box can reach, and "
                "copying onto a link would put this world's artifact wherever it points")
        if name not in present:
            dest.unlink()
    # The DIRECTORY destination is screened by the same rule and for the same reason. It is
    # not covered by the loop above (which judges the single files) and `copytree` will not
    # refuse it for us: under `dirs_exist_ok=True` its own `makedirs(dst, exist_ok=True)`
    # RESOLVES a link planted at this name, writing the world's summaries wherever it
    # points — the exact escape this screen exists to stop, one directory over.
    # ALL THREE OF THEM, not only the one this design added. `stage_tables` runs the same
    # `copytree(dirs_exist_ok=True)` onto `worlds/<label>/gather_raw` and a `copy2` onto
    # `worlds/<label>/executed_queries.jsonl`, and it screens only its SOURCES — so the
    # destination escape screened here for `gather_summaries/` was still open one directory
    # over, on artifacts that predate it. The screen belongs to the destination tree, which
    # is this function's, so it is applied to every name written into that tree.
    summaries_dest = world_dir / GATHER_SUMMARIES_DIRNAME
    staged_dests = RunPaths(world_dir)
    for dest, is_dir in ((summaries_dest, True), (staged_dests.gather_raw, True),
                         (staged_dests.executed_queries, False)):
        if not entry_present(dest):
            continue
        if artifact_dir(dest) if is_dir else plain_file(dest):
            continue
        raise ArchiveRefused(
            f"world {world!r}: {dest} is occupied by something that is not a "
            f"{'real directory' if is_dir else 'plain regular file'} — copying onto it "
            "would write this world's archived artifact wherever it points")


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
        _screen_destinations(world, world_dir, run_dir, {name for _s, name in sources})
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
        # `gather_summaries/`, D7's directory-shaped input, through the SAME per-entry-screened
        # walk as `gather_raw` — a non-artifact entry at any depth is refused and reported, and
        # the rest of the directory (and the rest of the world) still archives.
        summaries_src = _gather_summaries_source(run_dir)
        summaries_dest = world_dir / GATHER_SUMMARIES_DIRNAME
        if artifact_dir(summaries_src):
            summaries_refused: list[Path] = []
            shutil.copytree(  # lint-tree-read-follows-link: ok — source root screened by `_screen`, destination root screened above and every entry by `refusing_copy2`
                summaries_src, summaries_dest, symlinks=True,
                ignore=refuse_non_artifacts(summaries_refused), dirs_exist_ok=True,
                # THE DESTINATION AT EVERY DEPTH, not only at the root. The screen above judges
                # `worlds/<label>/gather_summaries` itself; `dirs_exist_ok=True` then walks INTO
                # it, and `copy2` opens each leaf destination for writing — so a link planted at
                # `gather_summaries/<lead>.md` by a box whose rw bind reaches the episode dir was
                # still followed and this world's summary written wherever it pointed.
                copy_function=refusing_copy2(summaries_refused))
            refused = [*refused, *summaries_refused]
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
    # The three D7 names, the three #1025 O8 record names, the #1047 run-end record's name and
    # the draws directory are EXPORTED, not private constants: the judge reads every one of them back out of the
    # archive this module writes, and a name spelled here and re-spelled there is a rename that
    # leaves the writer and the reader looking at two different files with no error anywhere —
    # an absent `gather_summaries/` is a note on the record, not a refusal.
    "ALERT_NAME",
    "DRAWS_DIRNAME",
    "FAMILY_STAMP_NAME",
    "GATHER_SUMMARIES_DIRNAME",
    "JUDGE_NAME",
    "LESSONS_LOADED_NAME",
    "REVIEW_NAME",
    "RUN_DIR_POINTER",
    "RUN_END_NAME",
    "SAMPLES_NAME",
    "SCRUB_VERDICT_NAME",
    "WORLDS_DIRNAME",
    "ArchiveRefused",
    "archive_episode",
    "read_family_stamp",
]
