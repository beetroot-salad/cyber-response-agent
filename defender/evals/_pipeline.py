"""Per-alert pipeline for the secondary-metric harness."""
from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# Ensure evals/ is on sys.path so _secondary_config / _generation are importable
# regardless of how this module is loaded.
_EVALS_DIR = Path(__file__).resolve().parent
if str(_EVALS_DIR) not in sys.path:
    sys.path.insert(0, str(_EVALS_DIR))

from _secondary_config import (  # noqa: E402
    REPO_ROOT,
    SKIP_OUTCOME,
    SecondaryError,
)
from _generation import GenerationPin, replay_script_path  # noqa: E402

from defender._run_paths import RunPaths  # noqa: E402


# DI seam for the real `subprocess.run` (the test injects a fake). Forward-ref the
# return so the alias never subscripts CompletedProcess at runtime.
_RunFn = Callable[..., "subprocess.CompletedProcess[Any]"]


# ---------------------------------------------------------------------------
# Per-alert pipeline
# ---------------------------------------------------------------------------

@dataclass
class AlertResult:
    slug: str
    ground_truth: str
    status: str               # executed | not_executed | failed
    head_disposition: str | None = None
    judge_outcome: str | None = None  # caught/survived/incoherent/undecidable/skip-passthrough
    error: str | None = None
    head_run_dir: str | None = None
    replay_run_dir: str | None = None

    def to_dict(self) -> dict:
        return {
            "slug": self.slug,
            "ground_truth": self.ground_truth,
            "status": self.status,
            "head_disposition": self.head_disposition,
            "judge_outcome": self.judge_outcome,
            "error": self.error,
            "head_run_dir": self.head_run_dir,
            "replay_run_dir": self.replay_run_dir,
        }


def run_head_defender(
    alert,
    run_id: str,
    runs_base: Path,
    *,
    runner: _RunFn = subprocess.run,
) -> Path:
    """Invoke ``defender/run.py --no-learn`` and return the run dir.

    The run dir is created by ``run.py`` under ``$DEFENDER_RUNS_BASE``;
    we return the expected path so the caller can read its artifacts.
    """
    run_dir = runs_base / run_id
    env = os.environ.copy()
    env["DEFENDER_RUNS_BASE"] = str(runs_base)
    proc = runner(
        [
            sys.executable,
            str(REPO_ROOT / "defender" / "run.py"),
            str(alert.alert_path),
            "--run-id", run_id,
            "--no-learn",
        ],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SecondaryError(
            f"defender/run.py failed (rc={proc.returncode}):\n{proc.stderr[-2000:]}"
        )
    if not run_dir.is_dir():
        raise SecondaryError(f"defender/run.py did not create {run_dir}")
    return run_dir


def run_frozen_actor(
    head_run_dir: Path,
    staging_dir: Path,
    worktree: Path,
    pin: GenerationPin,
    case_id: str,
    loop_mod,
    *,
    runner: _RunFn = subprocess.run,
) -> Path:
    """Invoke replay_actor.py in the gen-{N-K} worktree. Returns staging.

    ``case_id`` is the *stable* identifier (no attempt suffix) used to
    seed the actor menu/archetype, so reruns of the same
    (generation, alert) sample identically. The staging dir name is
    allowed to carry a per-attempt suffix for filesystem uniqueness.
    """
    import shutil
    staging_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(RunPaths(head_run_dir).alert, RunPaths(staging_dir).alert)
    # Stage the two tables (the actor replays off them via lead_repository),
    # through the single shared staging helper so this and the persist stage
    # share one definition of the on-disk table set.
    loop_mod.lead_repository.stage_tables(head_run_dir, staging_dir)
    venv_python = worktree / "defender" / ".venv" / "bin" / "python3"
    # Walk-up the parent worktrees in case the pinned tree shares the
    # repo's venv with the main checkout (saves a `uv venv` per worktree).
    python = venv_python if venv_python.is_file() else Path(sys.executable)

    env = os.environ.copy()
    env["ACTOR_MODEL"] = pin.actor_model

    proc = runner(
        [
            str(python),
            str(replay_script_path(worktree)),
            str(staging_dir),
            "--case-id", case_id,
        ],
        cwd=str(worktree),
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SecondaryError(
            f"replay_actor.py failed (rc={proc.returncode}):\n"
            f"stderr: {proc.stderr[-2000:]}"
        )
    if not (staging_dir / "actor_story.md").is_file():
        raise SecondaryError(f"replay_actor.py did not write actor_story.md in {staging_dir}")
    return staging_dir


def run_head_oracle_and_judge(
    head_run_dir: Path,
    staging_dir: Path,
    loop_mod,
) -> str:
    """Run HEAD oracle + judge against the frozen actor's story.

    Returns the judge outcome keyword. Raises ``SecondaryError`` on
    invalid oracle/judge output.
    """
    actor_story_path = staging_dir / "actor_story.md"
    actor_story = actor_story_path.read_text(encoding="utf-8")
    if loop_mod.is_skip_story(actor_story):
        return SKIP_OUTCOME

    # Source the in-process stages' metered keys UP FRONT — before the oracle's per-lead fan-out
    # AND the judge, the way the learning loop does. _prepare_engines_for sources the oracle +
    # judge (both run here, both in-process on the metered key); include_actor=False skips only the
    # actor, which already ran frozen in its own subprocess, so requiring its provider key here
    # would be a phantom dependency (a Sonnet-judge secondary run must not fail loud for the actor's
    # Fireworks key, which this actor-frozen path never uses).
    loop_mod._prepare_engines_for(["adversarial"], include_actor=False)

    # Dispatch the oracle + judge through the SAME InProcessSubagents adapter the learning loop
    # uses (the composition root that names the in-process engines), then wrap their RunUnprocessable
    # — raised on timeout / model error — which would otherwise escape the per-alert handler in
    # run_secondary() and abort the harness mid-loop with no summary written. The oracle fans one
    # in-process PydanticAI call per lead and reassembles; a per-lead failure surfaces the same way
    # (run_stage maps a per-lead timeout/model error to RunUnprocessable — no subprocess to raise
    # TimeoutExpired).
    try:
        oracle_yaml = loop_mod.InProcessSubagents().oracle(
            head_run_dir, actor_story_path, staging_dir
        )
    except loop_mod.RunUnprocessable as e:
        raise SecondaryError(f"oracle invocation failed: {e}") from e
    # The oracle doc is assembled by our own code (one projection per lead, lead_ids
    # from the join); the only model-authored content is each lead's events list, read
    # by the LLM judge as text. No structural validation gate — just strip + write.
    projected_path = staging_dir / "projected_telemetry.yaml"
    projected_path.write_text(loop_mod.strip_yaml_fence(oracle_yaml), encoding="utf-8")

    try:
        judge_yaml = loop_mod.InProcessSubagents().judge(
            loop_mod.ADVERSARIAL_WIRING,
            head_run_dir,
            actor_story_path,
            projected_path,
            staging_dir,
        )
    except (loop_mod.RunUnprocessable, subprocess.TimeoutExpired) as e:
        raise SecondaryError(f"judge invocation failed: {e}") from e
    # Funnel through the SAME shared normalizer as the live loop + A/B harness
    # (fence/envelope + prose-preamble strip) so a preamble'd judge verdict is not
    # dead-lettered here while the other two consumers parse it — the #492 drift.
    judge_stripped = loop_mod.normalize_judge_yaml(judge_yaml)
    (staging_dir / "judge_findings.yaml").write_text(judge_stripped, encoding="utf-8")
    try:
        judge_doc = yaml.safe_load(judge_stripped)
        loop_mod.validate_judge_doc(judge_doc)
    except (yaml.YAMLError, loop_mod.RunUnprocessable) as e:
        raise SecondaryError(f"judge YAML invalid: {e}") from e
    outcome = loop_mod._outcome_keyword(judge_doc["outcome"])
    return outcome
