from __future__ import annotations

from pathlib import Path
from typing import Protocol

from defender.learning import lead_repository
from defender._run_paths import RunPaths
from defender.learning.core.config import JudgeWiring
from defender.learning.core.prologue import extract_case_entities
from defender.learning.pipeline.benign_actor.run import invoke_actor_benign
from defender.learning.pipeline.judge.run import invoke_judge
from defender.learning.pipeline.malicious_actor.run import invoke_actor, is_skip_story
from defender.learning.pipeline.oracle.run import invoke_oracle

__all__ = ["InProcessSubagents", "Subagents", "is_skip_story"]


class Subagents(Protocol):
    def actor(self, run_dir: Path, learning_run_dir: Path) -> str: ...
    def actor_benign(self, run_dir: Path, learning_run_dir: Path,
                     alert_rule_key: str) -> str: ...
    def oracle(self, run_dir: Path, actor_story_path: Path,
               learning_run_dir: Path) -> str: ...
    def judge(self, wiring: JudgeWiring, run_dir: Path, actor_story_path: Path,
              projected_telemetry_path: Path, learning_run_dir: Path) -> str: ...


class InProcessSubagents:

    def actor(self, run_dir: Path, learning_run_dir: Path) -> str:
        from defender.learning.pipeline.actor_engine import _run_actor_pydantic
        actor_input_path = learning_run_dir / "actor_input.yaml"
        actor_input_path.write_text(lead_repository.render_actor_view_yaml(run_dir), encoding="utf-8")
        return invoke_actor(RunPaths(run_dir).alert, actor_input_path, learning_run_dir,
                            actor_fn=_run_actor_pydantic)

    def actor_benign(self, run_dir: Path, learning_run_dir: Path,
                     alert_rule_key: str) -> str:
        from defender.learning.pipeline.actor_engine import _run_actor_pydantic
        case_entities = extract_case_entities(RunPaths(run_dir).investigation)
        return invoke_actor_benign(
            RunPaths(run_dir).alert, case_entities, alert_rule_key, learning_run_dir,
            actor_fn=_run_actor_pydantic,
        )

    def oracle(self, run_dir: Path, actor_story_path: Path,
               learning_run_dir: Path) -> str:
        from defender.learning.pipeline.oracle_engine import _run_oracle_pydantic
        return invoke_oracle(run_dir, actor_story_path, learning_run_dir,
                             oracle_fn=_run_oracle_pydantic)

    def judge(self, wiring: JudgeWiring, run_dir: Path, actor_story_path: Path,
              projected_telemetry_path: Path, learning_run_dir: Path) -> str:
        from defender.learning.pipeline.judge.engine_pydantic import _run_judge_pydantic
        return invoke_judge(
            wiring, run_dir, actor_story_path, projected_telemetry_path,
            learning_run_dir, judge_fn=_run_judge_pydantic,
        )
