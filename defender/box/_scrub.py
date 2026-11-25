
from __future__ import annotations

import json
import logging
import os
import stat
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from defender._io import read_text_utf8, write_guarded
from defender.records import RunPaths

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


def classify_entry(entry: Path) -> Finding | None:
    """The one classifier: judge one entry, `None` when it may survive a boxed run (a lone
    regular file or a directory), else the `Finding` the scrub raises on and the bundle packer
    lists and leaves out (`defender.evidence.bundle`). An entry that cannot be judged is an
    `unreadable` finding, never a pass. Returns rather than raises so a walk reports every
    finding."""
    try:
        return _check_entry(entry)
    except OSError as e:
        return unreadable_finding(entry, e)


def _check_entry(entry: Path) -> Finding | None:
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


def unreadable_finding(path: Path, err: OSError) -> Finding:
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
#
# Three states, one reader (`verdict_state`): `clean` (the walk completed and found nothing),
# `tainted` (it found something, or could not judge an entry), `not_run` (no walk was made). The
# file keeps the `ran` key readers of the earlier spelling look for, and `ran` is true only for
# `clean`: a reader that knows nothing of the states can never take a tainted tree for verified.

CLEAN = "clean"
TAINTED = "tainted"
NOT_RUN = "not_run"

_CLEAN_DOC = {"ran": True, "reason": "walk completed"}


def verdict_path(tree: Path) -> Path:
    tree = Path(tree)
    return RunPaths(tree).scrub_verdict()


def _write_verdict(tree: Path, doc: dict, *, write_verdict: Callable[[dict], None] | None = None,
                   replaces_clean: bool = False) -> None:
    """Write the verdict sidecar, best-effort: a missing verdict already reads as unverified,
    and a write failure must not replace the signal the caller is holding.

    `replaces_clean`: the verdict is not `clean`, so when the write fails an earlier `clean`
    one must not stay standing for a tree that just failed its walk; the file is removed (on
    the default path only: an injected writer is its caller's to keep honest)."""
    try:
        if write_verdict is not None:
            write_verdict(doc)
        else:
            write_guarded(verdict_path(tree), json.dumps(doc))
    except OSError as e:
        _logger.error(f"could not write the scan verdict for {tree}: {e!r}")
        if replaces_clean and write_verdict is None:
            try:
                verdict_path(tree).unlink(missing_ok=True)
            except OSError as gone:
                _logger.error(f"could not remove the stale scan verdict for {tree}: {gone!r}")


def write_did_not_run(tree: Path, reason: str, *, write_verdict: Callable[[dict], None] | None = None) -> None:
    """Record that the walk was skipped (the box was not provably dead), so the tree is
    distinguishable from one never judged. Used on teardown and startup faults, per run dir or
    writable mount source. Best-effort."""
    _write_verdict(tree, {"ran": False, "reason": reason}, write_verdict=write_verdict, replaces_clean=True)


def mark_unsandboxed(tree: Path, *, read_verdict: Callable[[], str | None] | None = None, write_verdict: Callable[[dict], None] | None = None) -> None:
    """Add `"sandboxed": false` to the tree's verdict: the run had no box, so the read-only
    input directory was never mounted and the alert's bytes are unbound — the learning gate
    reads this and refuses the run (#1222). Best-effort, like every write of the verdict."""
    p = verdict_path(tree)
    try:
        text = read_verdict() if read_verdict is not None else read_text_utf8(p)
        doc = json.loads(text) if text is not None else {}
    except (OSError, json.JSONDecodeError):
        doc = {}
    if not isinstance(doc, dict):
        doc = {}
    _write_verdict(tree, {**doc, "sandboxed": False}, write_verdict=write_verdict)


def tree_unsandboxed(tree: Path) -> bool:
    """Whether the verdict marks the run as having had no box (`mark_unsandboxed`)."""
    try:
        doc = json.loads(read_text_utf8(verdict_path(tree)))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(doc, dict) and doc.get("sandboxed") is False


def state_of_verdict(text: str | None) -> str | None:
    """The state a verdict file's text records: `clean`, `tainted` or `not_run`; `None` for no
    text, text that is not a verdict, or a verdict naming no state. The one parse of the file."""
    if text is None:
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    named = doc.get("state")
    if named == TAINTED:
        return TAINTED
    if named is not None and named not in (CLEAN, NOT_RUN):
        return None
    ran = doc.get("ran")
    if ran is True:
        return CLEAN
    if ran is False:
        return NOT_RUN
    return None


def verdict_state(tree: Path) -> str | None:
    """The scan verdict of `tree`: `clean`, `tainted`, `not_run`, or `None` when it has none
    (never judged, or the file is unreadable). The one reader of the verdict file."""
    p = verdict_path(tree)
    if not p.is_file():
        return None
    try:
        return state_of_verdict(read_text_utf8(p))
    except OSError:
        return None


def tree_verified(tree: Path) -> bool:
    """Whether the verdict is `clean`; anything else reads as unverified.

    This only says the walk completed and found nothing; it is not a contents-intact claim,
    since the scan permits any regular file the box may have rewritten."""
    return verdict_state(tree) == CLEAN


Lister = Callable[..., Iterator[tuple[str, list[str], list[str]]]]


def scrub(run_dir: Path, *, lister: Lister = os.walk, write_verdict: Callable[[dict], None] | None = None) -> str:
    """Walk `run_dir` and refuse anything that is not a plain regular file or directory.

    Returns `"clean"` when the walk completed and found nothing. Anything found, and any entry
    the walk could not judge, writes the `tainted` verdict and raises `RunTainted`. `lister` is
    the walk seam, for producing partial walks in tests. Every walk writes its verdict outside
    the tree before returning or raising, replacing an earlier one."""
    findings: list[Finding] = []

    def refuse_unwalkable(err: OSError) -> None:
        findings.append(unreadable_finding(Path(err.filename or run_dir), err))

    try:
        for parent, dirs, files in lister(run_dir, onerror=refuse_unwalkable):
            for name in (*dirs, *files):
                finding = classify_entry(Path(parent) / name)
                if finding is not None:
                    findings.append(finding)
    except OSError as e:
        findings.append(unreadable_finding(run_dir, e))
    except BaseException as e:
        # The walk itself failed: no verdict on the tree, and an earlier one must not stand.
        write_did_not_run(run_dir, f"the walk failed: {e!r}", write_verdict=write_verdict)
        raise

    if not findings:
        _write_verdict(run_dir, _CLEAN_DOC, write_verdict=write_verdict)
        return CLEAN
    # Sort for a deterministic report. By `Path`, not `str`: they disagree where a separator
    # meets a character below '/' (`a/b` vs `a-c/x`).
    findings.sort(key=lambda f: f.path)
    unreadable = sum(f.kind == "unreadable" for f in findings)
    reason = (f"the walk found {len(findings)} offending entr{'y' if len(findings) == 1 else 'ies'}"
              + (f", {unreadable} it could not read" if unreadable else ""))
    _write_verdict(run_dir, {"ran": False, "state": TAINTED, "reason": reason},
                   write_verdict=write_verdict, replaces_clean=True)
    raise RunTainted(_render_findings(run_dir, findings), findings)
