
from __future__ import annotations

import json
import os
import stat
import sys
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from defender._io import write_guarded


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


#: §7 D8 — the scan's verdict lives BESIDE the tree it judges, keyed by the tree's own name,
#: exactly where D7 sites the alias-refusal record and for the identical reason: in-tree it is
#: a host-side write into an attacker-owned tree — no census row, no lint gate, and it is both
#: PLANTABLE (an alias at the verdict's own name) and FORGEABLE (the box is root on that mount,
#: and the consumer rule below fails closed on absence and on nothing else).
_VERDICT_SUFFIX = ".scrub-verdict.json"


def verdict_path(tree: Path) -> Path:
    tree = Path(tree)
    return tree.parent / f"{tree.name}{_VERDICT_SUFFIX}"


def _write_verdict(tree: Path, doc: dict) -> None:
    """Write the verdict sidecar, BEST-EFFORT on every arm.

    The marker is a fail-closed signal, never a carrier of one: an unwritten verdict leaves the
    tree with no verdict at all, and `tree_verified` already reads absence as unverified. What
    must not happen is the marker's own write failure REPLACING the signal its caller is
    holding — the `RunTainted` a completed walk collected (which `scrub` raises immediately
    after this call, and which is the whole reason the scan exists), or the fault
    `write_did_not_run`'s call site is already unwinding through. Both would be swapped for a
    write-side `OSError` from a sidecar nobody has read yet."""
    try:
        write_guarded(verdict_path(tree), json.dumps(doc))
    except OSError as e:
        print(f"[scrub] could not write the scan verdict for {tree}: {e!r}", file=sys.stderr)


def write_did_not_run(tree: Path, reason: str) -> None:
    """§7 D2 — a caller that SKIPPED the walk (the box was not provably dead) records that
    explicitly, rather than leaving the tree indistinguishable from one nobody has judged yet.
    Called by `box.stop_and_scrub` on a teardown fault, and by both of `start_box`'s lanes on a
    startup fault that leaves a host-touched tree behind — the investigation lane keyed on its
    run dir, the request lane on each of its WRITABLE mount sources (a lane with none, the
    read-only run-cycle box, has no tree to judge and writes no marker). Best-effort, for the
    reason `_write_verdict` carries."""
    _write_verdict(tree, {"ran": False, "reason": reason})


def tree_verified(tree: Path) -> bool:
    """§7 D2/D6 — a tree whose verdict is absent, or does not record `ran: true`, reads as
    UNVERIFIED. `ran: true` says only that the walk COMPLETED: the scan permits any regular
    file, so an artifact the box emptied, rewrote or removed is indistinguishable from an
    untouched one and is not what this predicate claims (§7 D6 — the audit obligation is
    discharged against redirection only, deliberately, and a consumer must not read this as a
    contents-intact claim)."""
    p = verdict_path(tree)
    if not p.is_file():
        return False
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return doc.get("ran") is True


Lister = Callable[..., Iterator[tuple[str, list[str], list[str]]]]


def scrub(run_dir: Path, *, lister: Lister = os.walk) -> None:
    """Walk `run_dir` and refuse anything that is not a plain regular file or directory.

    `lister` is the walk seam (§7 H10.3/H10.4's provisional pins are driven through it — a
    partial or malformed walk cannot be produced deterministically any other way). Every
    completed walk writes a verdict OUTSIDE the tree (§7 D8) before returning or raising:
    `ran: true` when every entry the walk reached was fully classified (findings may still be
    non-empty — the walk COMPLETED and found taint, which is not the same as not completing at
    all); `ran: false` when the walk itself could not finish reliably (an entry vanished or
    became unreadable between listing and inspection — §7 H10.3's fail-closed pin: a
    partially-walked tree is an unverified tree, whatever it found)."""
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
    # os.walk yields in the filesystem's order, so sort: the same tainted tree has to produce
    # the same message twice, or the report is not something an operator can diff or cite.
    # Sorted by PATH, not by `str(path)` — the two disagree wherever a separator meets a
    # character below '/' (`a/b` vs `a-c/x`), and path order is what a reader compares against.
    findings.sort(key=lambda f: f.path)
    raise RunTainted(_render_findings(run_dir, findings), findings)
