
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
    kind: str            # "type" (allowlist violation) | "hardlink" (second name for one inode)
    filemode: str        # the mode character — 'l', 'p', 's', 'c', ...
    nlink: int
    target: str | None

    def describe(self) -> str:
        if self.kind == "hardlink":
            return f"{self.path}: hard link with {self.nlink} names"
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


def _render(run_dir: Path, findings: Sequence[Finding]) -> str:
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
    for parent, dirs, files in os.walk(run_dir):
        for name in (*dirs, *files):
            finding = _check_entry(Path(parent) / name)
            if finding is not None:
                findings.append(finding)
    if not findings:
        return
    # os.walk yields in the filesystem's order, so sort: the same tainted tree has to produce
    # the same message twice, or the report is not something an operator can diff or cite.
    findings.sort(key=lambda f: str(f.path))
    raise RunTainted(_render(run_dir, findings), findings)
