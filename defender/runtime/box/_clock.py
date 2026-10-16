"""The run clock inside the box (#1255, design rev 4 "Time / Into the box").

The SQL engine and every other program in the box evaluate time themselves, and shadowing one
spelling of `now()` misses the rest (U3). So the box image preloads a time-faking library for
every run (libfaketime, from the `box` extra's `libfaketime` wheel; `LD_PRELOAD` and its
settings on the create command, `CLOCK_ENV`), which reads the run clock from a small
file in its own read-only mount, `CLOCK_TARGET`. The mount lands outside the model view's trees,
so no read shape of the permission gate reaches it; only the preload reads it.

The file holds the run clock's OFFSET from the wall clock, in whole seconds, in libfaketime's
relative spelling (`+N` / `-N`): a natural run reads an offset of (about) zero, an arm the gap
between its run clock and the wall — the same shape for both. The host rewrites it before every
command the box runs (`BoxExecutor.run_parsed`), because the run clock moves against the wall
(an oracle turn pauses it; an injected source moves on its own).

The host side of the mount is a per-run directory in a sibling of the runs base (`clock_dir`),
never under any of the run's trees.
"""
from __future__ import annotations

import shutil
from datetime import UTC, datetime
from pathlib import Path

from defender._io import guarded_mkdir, write_guarded

#: Where the clock's directory lands in the box: outside `/runs/current`, `/defender`, `/agent`.
CLOCK_TARGET = Path("/clock")
#: The file the preload reads (`FAKETIME_TIMESTAMP_FILE` in `CLOCK_ENV`).
CLOCK_FILE_NAME = "clock"
#: The runs base's sibling holding every run's clock directory (as `sessions` holds stores).
CLOCKS_DIRNAME = "clocks"

#: The time-faking library every box process preloads: libfaketime as the `libfaketime` wheel
#: (the `box` extra, pinned `==3.0.1`) vendors it, at the path `uv sync` installs it to in the
#: image (`UV_PROJECT_ENVIRONMENT=/usr/local`, python3.11 — `box.Dockerfile`). Verified by
#: running the image's own sync into a scratch prefix, not guessed.
#:
#: !!! x86_64 ONLY !!! The wheel is tagged `py3-none-any` but its `libfaketime.so.1` is an
#: x86_64 ELF. On an arm64 host the dynamic loader cannot preload it and the box's programs would
#: read the wall clock instead of the run clock — so the box start refuses (`_probe_clock` in
#: `_lifecycle.py` fails loud on the loader's preload error), rather than run on the wrong time.
PRELOAD_LIBRARY = Path(
    "/usr/local/lib/python3.11/site-packages/libfaketime/vendor/libfaketime/src/libfaketime.so.1")

#: The box's create-command environment for the run clock: the same for every run, natural or
#: arm — only the clock FILE's content differs. `NO_CACHE`: the file is re-read on every call,
#: since the host rewrites it between commands. `DONT_FAKE_MONOTONIC`: monotonic clocks stay real
#: (they time the box's own work, never a time the model is shown).
CLOCK_ENV: dict[str, str] = {
    "LD_PRELOAD": str(PRELOAD_LIBRARY),
    "FAKETIME_TIMESTAMP_FILE": str(CLOCK_TARGET / CLOCK_FILE_NAME),
    "FAKETIME_NO_CACHE": "1",
    "FAKETIME_DONT_FAKE_MONOTONIC": "1",
}


def clock_dir(run_dir: Path) -> Path:
    """The host directory bound at `CLOCK_TARGET` for the run on `run_dir`:
    `<runs base>/../clocks/<run folder name>`. A sibling of the runs base, never a child: the
    runs folder admits only runs and their sidecar files."""
    run_dir = Path(run_dir)
    return run_dir.parent.parent / CLOCKS_DIRNAME / run_dir.name


def offset_text(reading: datetime, wall: datetime) -> str:
    """The clock file's content for a run clock at `reading` when the wall clock reads `wall`:
    libfaketime's relative offset, whole seconds, signed."""
    seconds = round((reading - wall).total_seconds())
    return f"{seconds:+d}\n"


def write_clock(clock_file: Path, reading: datetime) -> None:
    """Rewrite `clock_file` for a run clock now at `reading` (aware UTC)."""
    write_guarded(clock_file, offset_text(reading, datetime.now(UTC)))


def prepare_clock(run_dir: Path) -> Path:
    """Make the run's clock directory with a zero offset in its file (a run's clock starts at
    the wall clock until the run binds its own, `BoxExecutor.follow_clock`). Returns the file."""
    where = clock_dir(run_dir)
    guarded_mkdir(where, base=where.parent.parent)
    clock_file = where / CLOCK_FILE_NAME
    write_guarded(clock_file, "+0\n")
    return clock_file


def remove_clock(clock_file: Path) -> None:
    """Remove a run's clock directory once its box is gone (best-effort host housekeeping)."""
    shutil.rmtree(clock_file.parent, ignore_errors=True)
