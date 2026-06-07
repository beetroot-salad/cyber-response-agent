"""Static config, injectable paths, and shared primitives for the learning loop.

`LoopPaths` is the injection seam for the run/queue filesystem layout: production
uses `DEFAULT_PATHS`; tests construct `LoopPaths(repo_root=tmp_path)` and thread it
through `run_one` / the persist + queue functions instead of monkeypatching module
globals. Everything else here is static deployment config (prompt files, models,
enums) that tests never need to override.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class LoopPaths:
    """Run-dir + _pending queue layout, derived from a repo root."""

    repo_root: Path

    @property
    def learning_dir(self) -> Path:
        return self.repo_root / "defender" / "learning"

    @property
    def runs_dir(self) -> Path:
        return self.learning_dir / "runs"

    @property
    def pending_dir(self) -> Path:
        return self.learning_dir / "_pending"

    @property
    def pending_file(self) -> Path:
        return self.pending_dir / "findings.jsonl"

    @property
    def findings_lock_file(self) -> Path:
        return self.pending_dir / ".findings.lock"

    @property
    def actor_observations_file(self) -> Path:
        return self.pending_dir / "actor_observations.jsonl"

    @property
    def actor_observations_consumed_file(self) -> Path:
        return self.pending_dir / "actor_observations.consumed.jsonl"

    @property
    def actor_observations_lock_file(self) -> Path:
        return self.pending_dir / ".actor.lock"

    @property
    def environment_observations_file(self) -> Path:
        return self.pending_dir / "environment_observations.jsonl"

    @property
    def environment_observations_consumed_file(self) -> Path:
        return self.pending_dir / "environment_observations.consumed.jsonl"

    @property
    def environment_observations_lock_file(self) -> Path:
        return self.pending_dir / ".environment.lock"


DEFAULT_PATHS = LoopPaths(repo_root=REPO_ROOT)

LEARNING_DIR = DEFAULT_PATHS.learning_dir

ACTOR_PROMPT = LEARNING_DIR / "actor.md"
ACTOR_BENIGN_PROMPT = LEARNING_DIR / "actor_benign.md"
ORACLE_PROMPT = LEARNING_DIR / "oracle.md"
JUDGE_PROMPT = LEARNING_DIR / "judge.md"
JUDGE_BENIGN_PROMPT = LEARNING_DIR / "judge_benign.md"
PROJECT_SCRIPT = REPO_ROOT / "defender" / "scripts" / "project_lead_sequence.py"

ACTOR_SETTINGS = LEARNING_DIR / "actor-settings.json"
BENIGN_ACTOR_SETTINGS = LEARNING_DIR / "benign-actor-settings.json"
LESSONS_ACTOR_DIR = REPO_ROOT / "defender" / "lessons-actor"
LESSONS_ENVIRONMENT_DIR = REPO_ROOT / "defender" / "lessons-environment"

GROUND_TRUTH_FILE = "ground_truth.yaml"

DISPOSITION_ENUM = {"benign", "inconclusive", "malicious"}
# Direction dispatch: the adversarial actor hunts false negatives on
# closed/uncertain dispositions; the benign actor hunts false positives on
# escalated/uncertain ones. ``inconclusive`` runs both.
ADVERSARIAL_DISPOSITIONS = {"benign", "inconclusive"}
BENIGN_DISPOSITIONS = {"malicious", "inconclusive"}

OUTCOME_ENUM = {"caught", "survived", "undecidable", "incoherent", "skip-passthrough"}
# Benign judge outcomes mirror the adversarial enum: ``survived`` always means
# "the defender failed to handle the story" — FN-risk adversarially, FP-risk here.
BENIGN_OUTCOME_ENUM = {
    "survived",
    "refuted",
    "undecidable",
    "incoherent",
    "skip-passthrough",
}

QUEUEABLE_FINDING_TYPES = {
    "lead-set",
    "lead-quality",
    "analyze-discipline",
    "observability",
}
ALL_FINDING_TYPES = QUEUEABLE_FINDING_TYPES | {"detection-confirmed"}
# Benign defender findings share the queueable types; ``disposition-confirmed``
# is the FP-direction audit-only type (the adversarial ``detection-confirmed``
# analog — a justified escalation, filtered out of the queued lessons).
BENIGN_ALL_FINDING_TYPES = QUEUEABLE_FINDING_TYPES | {"disposition-confirmed"}
ACTOR_OBSERVATION_TYPES = {"misprediction", "framing-choice", "discarded-class"}

ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "claude-sonnet-4-6")
BENIGN_ACTOR_MODEL = os.environ.get("BENIGN_ACTOR_MODEL", "claude-sonnet-4-6")
# Story construction was never pinned, so the actor ran at the inherited global
# `high` default. An effort A/B on a falco-nettool case (n=1/cell) found the
# response bimodal: medium (~194s) ≈ high (~216s) in wall + thinking, while low
# (~37s) sharply curtails reasoning. high was *dominated* by medium — medium was
# both faster and better-grounded (it recovered the real jump-box IP + the
# monitoring-probe fingerprint that high invented), so high buys nothing. Pinned
# medium. low stays a 5x-cheaper fallback that still yields coherent (if blunter)
# stories. Effort drives sophistication, not fact fidelity — that's corpus work.
# Override via ACTOR_EFFORT.
ACTOR_EFFORT = os.environ.get("ACTOR_EFFORT", "medium")
BENIGN_ACTOR_EFFORT = os.environ.get("BENIGN_ACTOR_EFFORT", "medium")
ORACLE_MODEL = os.environ.get("ORACLE_MODEL", "claude-sonnet-4-6")
# Per-lead generative oracle. Generative work — sonnet for content fidelity (per the
# d2d72ab model decision); effort pinned low since each call sees only its own lead and
# projects a signed baseline-diff (no cross-lead matching to reason about). Override via
# ORACLE_*. ORACLE_MAX_CONCURRENCY bounds the per-direction fan-out of per-lead calls.
ORACLE_EFFORT = os.environ.get("ORACLE_EFFORT", "low")
_oracle_concurrency_raw = os.environ.get("ORACLE_MAX_CONCURRENCY", "8")
try:
    ORACLE_MAX_CONCURRENCY = int(_oracle_concurrency_raw)
except ValueError:
    raise ValueError(
        f"ORACLE_MAX_CONCURRENCY must be an integer; got {_oracle_concurrency_raw!r}"
    ) from None
JUDGE_MODEL = os.environ.get("JUDGE_MODEL", "claude-sonnet-4-6")
BENIGN_JUDGE_MODEL = os.environ.get("BENIGN_JUDGE_MODEL", "claude-sonnet-4-6")
# The judges do 0 tool calls and follow a heavily-scaffolded prompt that already
# walks every analytic step, so high-effort reasoning over-thinks: ~90% of judge
# output tokens were extended thinking at the inherited global `high` default.
# Pin a low budget explicitly; override per-direction via env for A/B.
JUDGE_EFFORT = os.environ.get("JUDGE_EFFORT", "low")
BENIGN_JUDGE_EFFORT = os.environ.get("BENIGN_JUDGE_EFFORT", "low")
SUBAGENT_TIMEOUT = int(os.environ.get("LEARNING_SUBAGENT_TIMEOUT_SECONDS", "450"))


class LoopError(Exception):
    """Fatal orchestrator error — caller should stop processing this run."""


def _log(msg: str) -> None:
    print(f"[loop] {msg}", file=sys.stderr)
