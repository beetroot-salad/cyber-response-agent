
from __future__ import annotations

import json
import logging
import os
import stat
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from defender._io import write_guarded
from defender.run_repository import RunPaths

_logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Finding:
    """One entry the walk refused, with what triage needs.

    For a symlink the `target` string is the planted payload, and distinguishes a harmless
    relative link from one reaching for e.g. `/root/.ssh/id_rsa`. `None` for other shapes.
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

    `findings` holds every offending entry, for the quarantine manifest; the message renders
    them for the operator.
    """

    def __init__(self, message: str, findings: Sequence[Finding] = ()) -> None:
        super().__init__(message)
        self.findings: tuple[Finding, ...] = tuple(findings)


_PERMITTED = (stat.S_ISREG, stat.S_ISDIR)

# The box can plant unboundedly many entries: cap what is rendered (announcing the tail), never
# what is collected.
_MESSAGE_CAP = 20


def _check_entry(entry: Path) -> Finding | None:
    """Judge one entry. Returns rather than raises so the walk reports every finding."""
    st = entry.lstat()
    if not any(pred(st.st_mode) for pred in _PERMITTED):
        target = None
        if stat.S_ISLNK(st.st_mode):
            # `readlink` reads the link itself; the scrub never follows what it refuses.
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
    """An entry the walk could not judge is refused, never skipped.

    `os.walk`'s default `onerror` silently drops an unlistable directory, and a propagating
    `OSError` would discard the findings collected and the `RunTainted` the caller keys on.
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


# The scan's verdict lives beside the tree it judges, keyed by the tree's name. In-tree the box
# (root on that mount) could plant or forge it.


def verdict_path(tree: Path) -> Path:
    tree = Path(tree)
    return RunPaths(tree).scrub_verdict(tree.parent)


def _write_verdict(tree: Path, doc: dict) -> None:
    """Write the verdict sidecar, best-effort: a missing verdict already reads as unverified,
    and a write failure must not replace the signal the caller is holding."""
    try:
        write_guarded(verdict_path(tree), json.dumps(doc))
    except OSError as e:
        _logger.error(f"could not write the scan verdict for {tree}: {e!r}")


def write_did_not_run(tree: Path, reason: str) -> None:
    """Record that the walk was skipped (the box was not provably dead), so the tree is
    distinguishable from one never judged. Used on teardown and startup faults, per run dir or
    writable mount source. Best-effort."""
    _write_verdict(tree, {"ran": False, "reason": reason})


def tree_verified(tree: Path) -> bool:
    """Whether the verdict records `ran: true`; absent or anything else reads as unverified.

    This only says the walk completed (no redirection); it is not a contents-intact claim,
    since the scan permits any regular file the box may have rewritten."""
    p = verdict_path(tree)
    if not p.is_file():
        return False
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))  # lint-whole-read: ok — scrub verdict sidecar: host-written tiny JSON outside every box mount
    except (OSError, json.JSONDecodeError):
        return False
    return doc.get("ran") is True


Lister = Callable[..., Iterator[tuple[str, list[str], list[str]]]]


def scrub(run_dir: Path, *, lister: Lister = os.walk) -> None:
    """Walk `run_dir` and refuse anything that is not a plain regular file or directory.

    `lister` is the walk seam, for producing partial walks in tests. Every walk writes a
    verdict outside the tree before returning or raising: `ran: true` if every entry reached
    was classified (findings may still exist), `ran: false` if any became unreadable."""
    findings: list[Finding] = []

    def refuse_unwalkable(err: OSError) -> None:
        findings.append(_unreadable(Path(err.filename or run_dir), err))

    for parent, dirs, files in lister(run_dir, onerror=refuse_unwalkable):
        for name in (*dirs, *files):
            entry = Path(parent) / name
            try:
                finding = _check_entry(entry)
            except OSError as e:
                finding = _unreadable(entry, e)
            if finding is not None:
                findings.append(finding)

    partial = any(f.kind == "unreadable" for f in findings)
    if partial:
        _write_verdict(run_dir, {
            "ran": False,
            "reason": "the walk could not finish reliably: an entry became unreadable",
        })
    else:
        _write_verdict(run_dir, {"ran": True, "reason": "walk completed"})

    if not findings:
        return
    # Sort for a deterministic report. By `Path`, not `str`: they disagree where a separator
    # meets a character below '/' (`a/b` vs `a-c/x`).
    findings.sort(key=lambda f: f.path)
    raise RunTainted(_render_findings(run_dir, findings), findings)
