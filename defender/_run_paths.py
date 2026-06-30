"""``RunPaths`` — one run's on-disk layout, as a value object.

Top-level (not under ``learning/``) so the runtime, hooks, scripts, and the
learning loop can all name the run artifacts from one place without coupling to
the learning package — the runtime/learning decoupling of #317. Pure pathlib; no
imports beyond the stdlib.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RunPaths:
    """One run's directories and named artifacts.

    ``run_dir`` is the source root (the finished investigation, read); the six
    artifact accessors (``alert``/``report``/``investigation``/``executed_queries``/
    ``gather_raw``/``meta``) resolve relative to it. ``learning_run_dir`` is the
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
    def meta(self) -> Path:
        return self.run_dir / "meta.json"

    @property
    def learning(self) -> RunPaths:
        """The same layout rooted at ``learning_run_dir`` (where the learning loop
        copies the artifacts). Fails loud if this run has no learning leg."""
        if self.learning_run_dir is None:
            raise ValueError("RunPaths has no learning_run_dir")
        return RunPaths(self.learning_run_dir)


def resolve_run_bundle(runs_dir: Path, source_run_dir: str) -> Path:
    """Resolve a recorded ``source_run_dir`` to its on-disk bundle dir.

    The canonical consumer side of ``persist._source_run_dir``. An **absolute**
    ``source_run_dir`` (out-of-repo, under ``DEFENDER_LEARNING_STATE_DIR``) is used
    as-is; a **repo-relative** one (in-repo) resolves as ``runs_dir / <run_id>`` (its
    last path component). ``runs_dir`` must be the shared-state ``LoopPaths.runs_dir``,
    NOT ``repo_root / source_run_dir`` — under a batch author worktree (#420/#423) the
    latter resolves into the worktree's empty ``runs/`` and the bundle goes missing,
    breaking the forward-check and the held-out double-check (#425).

    Lives here (pure pathlib, stdlib-only) rather than in ``core.persist`` so the lean
    forward-check verifiers (``verify_forward/actor.py`` / ``env.py``) can import it
    without dragging in ``persist``'s module-level ``yaml`` — they are spawned as
    short-lived Bash subprocesses and stay import-light by design (cf. ``forward.py``,
    which regex-parses YAML to avoid the dependency).
    """
    src = Path(source_run_dir.rstrip("/"))
    return src if src.is_absolute() else runs_dir / src.name
