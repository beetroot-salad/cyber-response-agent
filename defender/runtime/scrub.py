
from __future__ import annotations

import os
import stat
from pathlib import Path


class RunTainted(Exception):
    pass


_PERMITTED = (stat.S_ISREG, stat.S_ISDIR)


def _check_entry(entry: Path) -> None:
    st = entry.lstat()
    if not any(pred(st.st_mode) for pred in _PERMITTED):
        raise RunTainted(
            f"{entry.name}: the run dir holds a {stat.filemode(st.st_mode)[0]!r}-type entry "
            f"({entry}) — only regular files and directories may survive a boxed run"
        )
    if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        raise RunTainted(
            f"{entry.name}: {entry} is a hard link with {st.st_nlink} names — a within-bind "
            "hard link aliases another path in the run dir and survives the box's death"
        )


def scrub(run_dir: Path) -> None:
    for parent, dirs, files in os.walk(run_dir):
        for name in (*dirs, *files):
            _check_entry(Path(parent) / name)
