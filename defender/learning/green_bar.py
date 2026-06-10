"""The author green bar (platform-design §4.4): the no-regression checks that gate
an ``auto_on_green`` merge. A PR is always opened; this decides whether it
auto-merges or waits for human review.

Schema/validator + forward-check are **author-time** gates that revert a bad edit
*before* commit, so anything committed to the lessons branch passed them by
construction — the green bar's net-new work is the held-out + secondary quality
checks over runs produced under the candidate corpus.

Both checks are **floors**, not pr-vs-base diffs: producing a base run-set means a
second expensive live sweep, deferred (a strict regression gate is a follow-up). The
floors come from env and the bar **fails closed** — an unset or unmet floor, or a
provider that errors (e.g. no live stack), means *not green* and the PR falls through
to human review.

The metric providers are injected so the decision logic is unit-testable without the
live stack; the defaults lazily wire ``eval_held_out.score`` and
``eval_secondary.run_secondary`` (lazy because eval_secondary re-execs into the venv
at import — only safe on the live path).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from _loop_config import DEFAULT_PATHS, LoopPaths


def _env_float(name: str) -> float | None:
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _default_runs_dir() -> Path:
    return Path(os.environ.get("DEFENDER_RUNS_BASE", "/tmp/defender-runs"))


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class GreenBarResult:
    passed: bool
    checks: list[Check] = field(default_factory=list)
    backlog: dict = field(default_factory=dict)

    def summary(self) -> str:
        verdict = "GREEN" if self.passed else "NOT GREEN"
        lines = [f"green bar: {verdict}"]
        for c in self.checks:
            lines.append(f"  [{'ok' if c.passed else 'FAIL'}] {c.name}: {c.detail}")
        if self.backlog:
            lines.append(f"  backlog: {self.backlog}")
        return "\n".join(lines)


# --- default (live) metric providers ---------------------------------------


def _default_held_out_score(runs_dir: Path) -> tuple[int, int, float]:
    import eval_held_out  # lazy: cheap module, but keep green_bar import side-effect-free
    return eval_held_out.score(runs_dir)


def _default_secondary_catch_rate() -> float | None:
    # Lazy import: eval_secondary re-execs into defender/.venv at import time, so it
    # must only be imported on the live auto_on_green path (in the venv), never at
    # green_bar import (which the unit tests do with a stubbed provider).
    import eval_secondary
    summary = eval_secondary.run_secondary(
        k=int(os.environ.get("LEARNING_SECONDARY_K", "3")),
        out_dir=Path(os.environ.get(
            "LEARNING_SECONDARY_OUT",
            str(DEFAULT_PATHS.learning_dir / "eval" / "secondary"),
        )),
        runs_base=_default_runs_dir(),
        fixtures_dir=DEFAULT_PATHS.repo_root / "defender" / "fixtures",
        repo_root=DEFAULT_PATHS.repo_root,
    )
    caught, denom = summary.catch_rate()
    return (caught / denom) if denom else None


# --- backlog signal ---------------------------------------------------------


def _backlog_signal(paths: LoopPaths) -> dict:
    """Queue depth across the three pending queues + a pending-file mtime age proxy.

    §4.3 asks for oldest-queued finding age + depth; the queue rows carry no
    timestamp, so age is the pending file's mtime here (a follow-up adds a per-row
    enqueue ts for true oldest-finding age)."""
    import time
    depth = 0
    oldest_mtime: float | None = None
    for f in (paths.pending_file, paths.actor_observations_file,
              paths.environment_observations_file):
        if f.is_file():
            depth += sum(1 for line in f.read_text().splitlines() if line.strip())
            m = f.stat().st_mtime
            oldest_mtime = m if oldest_mtime is None else min(oldest_mtime, m)
    age_s = int(time.time() - oldest_mtime) if oldest_mtime is not None else None
    return {"queue_depth": depth, "oldest_pending_age_s": age_s}


# --- the gate ---------------------------------------------------------------


def _check_held_out(
    runs_dir: Path, floor: float | None,
    provider: Callable[[Path], tuple[int, int, float]],
) -> Check:
    if floor is None:
        return Check("held_out", False, "no floor configured (LEARNING_GREEN_HELDOUT_FLOOR)")
    try:
        correct, total, acc = provider(runs_dir)
    except Exception as e:  # noqa: BLE001 — fail closed on any provider error
        return Check("held_out", False, f"eval errored: {e!r}")
    if total == 0:
        return Check("held_out", False, f"no held-out runs under {runs_dir}")
    return Check(
        "held_out", acc >= floor,
        f"accuracy {correct}/{total}={acc:.1%} vs floor {floor:.1%}",
    )


def _check_secondary(floor: float | None, provider: Callable[[], float | None]) -> Check:
    if floor is None:
        return Check("secondary", False, "no floor configured (LEARNING_GREEN_SECONDARY_FLOOR)")
    try:
        rate = provider()
    except Exception as e:  # noqa: BLE001 — fail closed on any provider error
        return Check("secondary", False, f"eval errored: {e!r}")
    if rate is None:
        return Check("secondary", False, "catch-rate unavailable (0 executed / replay-incompatible)")
    return Check("secondary", rate >= floor, f"catch_rate {rate:.1%} vs floor {floor:.1%}")


def evaluate(
    *,
    paths: LoopPaths = DEFAULT_PATHS,
    runs_dir: Path | None = None,
    held_out_floor: float | None = None,
    secondary_floor: float | None = None,
    held_out_score: Callable[[Path], tuple[int, int, float]] | None = None,
    secondary_catch_rate: Callable[[], float | None] | None = None,
) -> GreenBarResult:
    """Compute the green bar. Floors default to env
    (``LEARNING_GREEN_HELDOUT_FLOOR`` / ``LEARNING_GREEN_SECONDARY_FLOOR``);
    providers default to the live evals. Fails closed — see module docstring."""
    if runs_dir is None:
        runs_dir = _default_runs_dir()
    if held_out_floor is None:
        held_out_floor = _env_float("LEARNING_GREEN_HELDOUT_FLOOR")
    if secondary_floor is None:
        secondary_floor = _env_float("LEARNING_GREEN_SECONDARY_FLOOR")
    if held_out_score is None:
        held_out_score = _default_held_out_score
    if secondary_catch_rate is None:
        secondary_catch_rate = _default_secondary_catch_rate

    checks = [
        _check_held_out(runs_dir, held_out_floor, held_out_score),
        _check_secondary(secondary_floor, secondary_catch_rate),
    ]
    return GreenBarResult(
        passed=all(c.passed for c in checks),
        checks=checks,
        backlog=_backlog_signal(paths),
    )
