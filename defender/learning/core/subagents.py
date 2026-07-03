"""Subagent seam: ``claude -p`` invocation today, Claude Agent SDK tomorrow.

``Subagents`` is the port — orchestration depends only on it ("give me the actor's
story", "project the telemetry", "judge the encounter"). ``ClaudePrintSubagents`` is the
adapter that assembles each step's inputs and delegates to the per-stage ``invoke_*``
free functions under ``pipeline/``. A future ``SdkSubagents`` swaps the adapter without
touching orchestration, validators, persistence, or the test fakes.

``is_skip_story`` is re-exported here so orchestration imports both the seam and the
SKIP predicate from one place.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from defender.learning import lead_repository
from defender._run_paths import RunPaths
from defender.learning.core.config import FatalConfigError, JudgeWiring, judge_engine
from defender.learning.core.prologue import extract_case_entities
from defender.learning.pipeline.benign_actor.run import invoke_actor_benign
from defender.learning.pipeline.judge.run import invoke_judge
from defender.learning.pipeline.malicious_actor.run import invoke_actor, is_skip_story
from defender.learning.pipeline.oracle.run import invoke_oracle

__all__ = ["ClaudePrintSubagents", "Subagents", "is_skip_story"]


class Subagents(Protocol):
    def actor(self, run_dir: Path, learning_run_dir: Path) -> str: ...
    def actor_benign(self, run_dir: Path, learning_run_dir: Path,
                     alert_rule_key: str) -> str: ...
    def oracle(self, run_dir: Path, actor_story_path: Path) -> str: ...
    def judge(self, wiring: JudgeWiring, run_dir: Path, actor_story_path: Path,
              projected_telemetry_path: Path, learning_run_dir: Path) -> str: ...


class ClaudePrintSubagents:
    """Default adapter — assembles each step's inputs and shells out to ``claude -p``."""

    def actor(self, run_dir: Path, learning_run_dir: Path) -> str:
        # The actor-facing view is queries-only (no goal / what_to_summarize) —
        # written as a real side-artifact for transcripts/visualizers.
        actor_input_path = learning_run_dir / "actor_input.yaml"
        actor_input_path.write_text(lead_repository.render_actor_view_yaml(run_dir))
        return invoke_actor(RunPaths(run_dir).alert, actor_input_path, learning_run_dir)

    def actor_benign(self, run_dir: Path, learning_run_dir: Path,
                     alert_rule_key: str) -> str:
        case_entities = extract_case_entities(RunPaths(run_dir).investigation)
        return invoke_actor_benign(
            RunPaths(run_dir).alert, case_entities, alert_rule_key, learning_run_dir
        )

    def oracle(self, run_dir: Path, actor_story_path: Path) -> str:
        return invoke_oracle(run_dir, actor_story_path)

    def judge(self, wiring: JudgeWiring, run_dir: Path, actor_story_path: Path,
              projected_telemetry_path: Path, learning_run_dir: Path) -> str:
        # Engine selection: default `pydantic_ai` runs the judge in-process on the
        # metered key; `claude_print` runs the legacy shared claude -p transport
        # (invoke_judge's default judge_fn). The pydantic-ai import is lazy +
        # branch-local. Only the judge moves engine; actor/oracle above stay on claude -p.
        if judge_engine() == "pydantic_ai":
            from defender.learning.pipeline.judge.engine_pydantic import _run_judge_pydantic
            return invoke_judge(
                wiring, run_dir, actor_story_path, projected_telemetry_path,
                learning_run_dir, judge_fn=_run_judge_pydantic,
            )
        # claude_print serves Anthropic models only. The default JUDGE_MODEL is now a
        # Fireworks model (glm-5.2), so a claude_print run that didn't also re-pin a
        # claude-* model would shell `claude -p --model glm-5.2` into an opaque CLI
        # error — fail loud here instead. (declarative routing, no backend import.)
        from defender.runtime import providers

        try:
            is_anthropic = providers.provider_id_for(wiring.model) == "anthropic"
        except ValueError:
            is_anthropic = False  # unroutable name — claude -p can't serve it either
        if not is_anthropic:
            raise FatalConfigError(
                f"LEARNING_JUDGE_ENGINE=claude_print serves Anthropic models only, but the "
                f"{wiring.label} judge model is {wiring.model!r} — set a claude-* "
                f"JUDGE_MODEL/BENIGN_JUDGE_MODEL, or use the pydantic_ai engine (the default)."
            )
        return invoke_judge(
            wiring, run_dir, actor_story_path, projected_telemetry_path, learning_run_dir,
        )
