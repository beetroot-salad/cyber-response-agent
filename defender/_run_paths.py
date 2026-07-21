from __future__ import annotations

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


def resolve_run_bundle(runs_dir: Path, source_run_dir: str) -> Path:
    src = Path(source_run_dir.rstrip("/"))
    return src if src.is_absolute() else runs_dir / src.name
