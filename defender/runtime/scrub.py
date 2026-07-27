
from __future__ import annotations

import os
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    """One entry the walk refused, carrying what triage actually runs on.

    `target` is the whole point (#747). For a symlink the planted payload IS the target
    string — there are no bytes to inspect, the entry's size is 0 — so a report naming the
    path without `readlink`'s answer has recorded the fact of a link and dropped its
    meaning: the difference between build tooling leaving a relative link and something
    reaching for `/root/.ssh/id_rsa` is exactly the field that was missing. `None` for every
    other refused shape (FIFO, socket, device, hard link) — none of them has a target to read.
    """

    path: Path
    kind: str            # "type" (allowlist violation) | "hardlink" (second name for one
                         # inode) | "unreadable" (the walk could not judge it at all)
    filemode: str        # the mode character — 'l', 'p', 's', 'c', ... ('?' when unreadable)
    nlink: int
    target: str | None
    detail: str | None = None   # the OS error, for the "unreadable" kind only

    def describe(self) -> str:
        if self.kind == "hardlink":
            return f"{self.path}: hard link with {self.nlink} names"
        if self.kind == "unreadable":
            return f"{self.path}: could not be read ({self.detail})"
        link = f", symlink -> {self.target!r}" if self.target is not None else ""
        return f"{self.path}: {self.filemode!r}-type entry{link}"


class RunTainted(Exception):
    """A boxed run's tree holds something that may not survive it.

    Carries `findings` — EVERY offending entry, not the first one the walk reached. The
    message renders them for the operator; the attribute is what a caller that wants to
    record them (#747's quarantine manifest) reads without re-parsing prose.
    """

    def __init__(self, message: str, findings: Sequence[Finding] = ()) -> None:
        super().__init__(message)
        self.findings: tuple[Finding, ...] = tuple(findings)


_PERMITTED = (stat.S_ISREG, stat.S_ISDIR)

# The message is operator-facing (it reaches stderr and `[loop] FATAL:`), and an in-box RCE
# can plant an unbounded number of entries. Cap what is RENDERED, never what is COLLECTED —
# `findings` always holds the full set, and the tail is announced rather than dropped silently.
_MESSAGE_CAP = 20


def _check_entry(entry: Path) -> Finding | None:
    """Judge one entry. Returns a finding rather than raising: the walk has to reach every
    entry before anything propagates, or a tree with five planted things reports one."""
    st = entry.lstat()
    if not any(pred(st.st_mode) for pred in _PERMITTED):
        target = None
        if stat.S_ISLNK(st.st_mode):
            # Never dereferences: `readlink` reads the link's OWN contents, and the walk
            # below runs with followlinks=False. The scrub stays a pure reader that also
            # never follows what it is in the middle of refusing.
            try:
                target = os.readlink(entry)
            except OSError:  # raced away between lstat and readlink — the type still damns it
                target = None
        return Finding(
            path=entry, kind="type", filemode=stat.filemode(st.st_mode)[0],
            nlink=st.st_nlink, target=target,
        )
    if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
        return Finding(
            path=entry, kind="hardlink", filemode=stat.filemode(st.st_mode)[0],
            nlink=st.st_nlink, target=None,
        )
    return None


def _unreadable(path: Path, err: OSError) -> Finding:
    """An entry the walk could not judge is REFUSED, never skipped.

    The scrub's claim is that everything under the tree is a regular file or a directory; an
    entry it failed to `lstat`, or a directory it failed to list, is precisely the entry it
    cannot make that claim about. Failing closed here also keeps the walk's own errors from
    becoming the two silences this module exists to retire: `os.walk`'s default `onerror`
    DROPS an unlistable directory (the scrub would then certify a subtree it never read), and
    letting an `OSError` propagate out of `scrub` would discard every finding already
    collected and deny the caller the `RunTainted` its quarantine handler keys on (#747).
    """
    return Finding(
        path=path, kind="unreadable", filemode="?", nlink=0, target=None,
        detail=f"{type(err).__name__}: {err.strerror or err}",
    )


def _render_findings(run_dir: Path, findings: Sequence[Finding]) -> str:
    shown = findings[:_MESSAGE_CAP]
    lines = [
        f"{len(findings)} offending entr{'y' if len(findings) == 1 else 'ies'} under "
        f"{run_dir} — only regular files and directories may survive a boxed run, and a "
        "within-bind hard link aliases another path in the tree",
        *(f"  {f.describe()}" for f in shown),
    ]
    if len(findings) > len(shown):
        lines.append(
            f"  ... and {len(findings) - len(shown)} more "
            f"(all {len(findings)} on RunTainted.findings)"
        )
    return "\n".join(lines)


def scrub(run_dir: Path) -> None:
    findings: list[Finding] = []

    def refuse_unwalkable(err: OSError) -> None:
        findings.append(_unreadable(Path(err.filename or run_dir), err))

    for parent, dirs, files in os.walk(run_dir, onerror=refuse_unwalkable):
        for name in (*dirs, *files):
            entry = Path(parent) / name
            try:
                finding = _check_entry(entry)
            except OSError as e:
                finding = _unreadable(entry, e)
            if finding is not None:
                findings.append(finding)
    if not findings:
        return
    # os.walk yields in the filesystem's order, so sort: the same tainted tree has to produce
    # the same message twice, or the report is not something an operator can diff or cite.
    # Sorted by PATH, not by `str(path)` — the two disagree wherever a separator meets a
    # character below '/' (`a/b` vs `a-c/x`), and path order is what a reader compares against.
    findings.sort(key=lambda f: f.path)
    raise RunTainted(_render_findings(run_dir, findings), findings)
