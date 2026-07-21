from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_EVALS_DIR = Path(__file__).resolve().parent
if str(_EVALS_DIR) not in sys.path:
    sys.path.insert(0, str(_EVALS_DIR))

from _secondary_config import (  # noqa: E402
    REPO_ROOT,
    SKIP_OUTCOME,
    SecondaryError,
)
from _generation import GenerationPin, replay_script_path  # noqa: E402

from defender._yaml import safe_load
from defender._run_paths import RunPaths  # noqa: E402


_RunFn = Callable[..., "subprocess.CompletedProcess[Any]"]



@dataclass
class AlertResult:
    slug: str
    ground_truth: str
    status: str
    head_disposition: str | None = None
    judge_outcome: str | None = None
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
    import shutil
    staging_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(RunPaths(head_run_dir).alert, RunPaths(staging_dir).alert)
    loop_mod.lead_repository.stage_tables(head_run_dir, staging_dir)
    venv_python = worktree / "defender" / ".venv" / "bin" / "python3"
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
    actor_story_path = staging_dir / "actor_story.md"
    actor_story = actor_story_path.read_text(encoding="utf-8")
    if loop_mod.is_skip_story(actor_story):
        return SKIP_OUTCOME

    loop_mod._prepare_engines_for(["adversarial"], include_actor=False)

    try:
        oracle_yaml = loop_mod.InProcessSubagents().oracle(
            head_run_dir, actor_story_path, staging_dir
        )
    except loop_mod.RunUnprocessable as e:
        raise SecondaryError(f"oracle invocation failed: {e}") from e
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
    judge_stripped = loop_mod.normalize_judge_yaml(judge_yaml)
    (staging_dir / "judge_findings.yaml").write_text(judge_stripped, encoding="utf-8")
    try:
        judge_doc = safe_load(judge_stripped)
        loop_mod.validate_judge_doc(judge_doc)
    except (yaml.YAMLError, loop_mod.RunUnprocessable) as e:
        raise SecondaryError(f"judge YAML invalid: {e}") from e
    outcome = loop_mod._outcome_keyword(judge_doc["outcome"])
    return outcome
