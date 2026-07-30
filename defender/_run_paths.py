from __future__ import annotations

import re
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunPaths:
    """One run's directories and named artifacts.

    ``run_dir`` is the source root (the finished investigation, read); the five
    artifact accessors (``alert``/``report``/``investigation``/``executed_queries``/
    ``gather_raw``) resolve relative to it. ``learning_run_dir`` is the
    optional per-case leg-output dir (under ``LoopPaths.runs_dir``); the learning
    loop copies the artifacts into it, so reads off that root use ``.learning`` (a
    ``RunPaths`` rooted there). Construct ``RunPaths(some_dir)`` on whichever root
    you hold — the accessors are root-relative by design.
    """

    run_dir: Path
    learning_run_dir: Path | None = None

    @property
    def alert(self) -> Path:
        return self.run_dir / "alert.json"

    @property
    def report(self) -> Path:
        return self.run_dir / "report.md"

    @property
    def investigation(self) -> Path:
        return self.run_dir / "investigation.md"

    @property
    def executed_queries(self) -> Path:
        return self.run_dir / "executed_queries.jsonl"

    @property
    def gather_raw(self) -> Path:
        return self.run_dir / "gather_raw"

    @property
    def learning(self) -> RunPaths:
        if self.learning_run_dir is None:
            raise ValueError("RunPaths has no learning_run_dir")
        return RunPaths(self.learning_run_dir)


# A run bundle is ALWAYS `runs_dir / <run_id>` (`LoopPaths.runs_dir` is the only place the
# learning loop creates one), so a recorded `source_run_dir` contributes a NAME and nothing
# else. A degenerate input (`"/"`, `"."`, `".."`, `""`) names no run: it maps to a child that
# cannot exist, so a caller's `is_dir()` check reads it as a missing bundle rather than
# admitting the runs root — or its parent — as one.
_NO_BUNDLE = "_unresolvable_source_run_dir"
_NAMELESS = {"", ".", ".."}

# The two by-ref payload families a run writes, as literal shapes: the gather lane's
# `gather_raw/{lead_id}/{seq}.json` (lead ids are claim-gated to this same alphabet) and the
# judge's ticket-read capture `ticket_reads/{seq}.json`. Anything else recorded in the queries
# table is not an artifact this system produces.
#
# `[0-9]`, not `\d`: a str pattern's `\d` matches every Unicode decimal (`٣.json` passes), which
# would widen the whitelist past anything a writer produces and past the ASCII-only lead-id
# alphabet standing next to it. Both seqs are `f"{int}"`, so ASCII is the exact shape.
_PAYLOAD_SHAPES = (
    re.compile(r"gather_raw/l-[A-Za-z0-9]+/[0-9]+\.json"),
    re.compile(r"ticket_reads/[0-9]+\.json"),
)

# `resolve()` on a hostile operand — a symlink cycle, an embedded NUL, a name past PATH_MAX.
_RESOLVE_ERRORS = (OSError, RuntimeError, ValueError)


def _lstat_is(path: Path, kind) -> bool:
    """`kind` of the entry ITSELF — never of what it points at. Fails closed: an entry the
    caller cannot judge is not one it may copy."""
    try:
        return bool(kind(path.lstat().st_mode))
    except (OSError, ValueError):
        return False


def artifact_file(path: Path) -> bool:
    """True when ``path`` is a REGULAR FILE, not a link (or FIFO, or device) wearing its name.

    Nothing this system writes into a run dir is ever a link: a boxed run's exit scrub taints
    any tree holding a non-regular entry (#747), and the run dir is the box's rw bind, so a
    link at an artifact's name is something the model planted. The distinction matters at the
    COPY, not at the read — ``is_file()`` answers about the link's target, so a `copy2` of it
    writes the TARGET's bytes into learning state under an artifact's name, where the actor and
    the judge then read them as a legitimate in-run file and no later gate can tell.
    """
    return _lstat_is(path, stat.S_ISREG)


def artifact_dir(path: Path) -> bool:
    """True when ``path`` is a REAL directory rather than a link to one — see ``artifact_file``.

    Separate from the per-entry rule inside a tree: `copytree`'s ``symlinks=True`` governs what
    it finds while walking and says nothing about the root it was handed, so a symlinked
    ``gather_raw`` copies the target directory's whole contents in.
    """
    return _lstat_is(path, stat.S_ISDIR)


def resolve_run_bundle(runs_dir: Path, source_run_dir: object) -> Path:
    """The run bundle a recorded ``source_run_dir`` names, always under ``runs_dir``.

    The recorded string is a label, never an address: only its last segment is honored, so
    neither a traversal nor an absolute path can move the read off the runs root.

    Typed ``object`` for the same reason ``contained_payload`` is: the value comes off a queued
    JSONL row, so a non-string there must read as a missing bundle rather than raise out of a
    drain batch mid-flight."""
    if not isinstance(source_run_dir, str):
        return runs_dir / _NO_BUNDLE
    name = Path(source_run_dir.rstrip("/")).name
    return runs_dir / (_NO_BUNDLE if name in _NAMELESS else name)


def contained_payload(run_dir: Path, payload_path: object) -> Path | None:
    """The by-ref payload ``payload_path`` names under ``run_dir``, or ``None`` if it names
    anything else. Two gates, because they answer different questions (#648):

    1. **the shape** — the value must spell one of the payload families a run actually writes.
       This is what makes the read an artifact lookup rather than an open of a path an
       attacker chose: `..`, an absolute path and a stray filename all fail it outright.
    2. **containment after resolution** — a well-formed name can still be a symlink, and
       model-written bash writes into the run dir (it is the box's rw bind), so the shape
       gate alone would happily open a link planted at exactly the expected name. The
       resolved target must land inside the resolved ``run_dir``, which is the rule on
       whichever root the caller holds — the SOURCE run dir, where a planted link is still
       sitting, and the learning copy, which ``stage_tables`` refuses to carry one into.

    A `resolve()` fault FAILS CLOSED, the same posture the runtime read gate takes."""
    if not isinstance(payload_path, str) or not any(
        shape.fullmatch(payload_path) for shape in _PAYLOAD_SHAPES
    ):
        return None
    run_root = Path(run_dir)
    candidate = run_root / payload_path
    try:
        root, target = run_root.resolve(), candidate.resolve()
    except _RESOLVE_ERRORS:
        return None
    if root not in target.parents:
        return None
    # The UNresolved path: callers re-derive `relative_to(run_dir)` off it, and resolving
    # would break that wherever the run root itself sits behind a symlink.
    return candidate
