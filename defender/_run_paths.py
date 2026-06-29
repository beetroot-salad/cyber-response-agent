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
