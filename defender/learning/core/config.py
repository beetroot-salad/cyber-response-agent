"""Static config, injectable paths, and shared primitives for the learning loop.

`LoopPaths` is the injection seam for the run/queue filesystem layout: production
uses `DEFAULT_PATHS`; tests construct `LoopPaths(repo_root=tmp_path)` and thread it
through `run_one` / the persist + queue functions instead of monkeypatching module
globals. Everything else here is static deployment config (prompt files, models,
enums) that tests never need to override.
"""
from __future__ import annotations

import datetime as _dt
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class RunDirs:
    """The two directories a direction leg threads together: the source ``run_dir``
    (the finished investigation, read) and the per-case ``learning_run_dir`` (this
    leg's artifacts, written)."""

    run_dir: Path
    learning_run_dir: Path


@dataclass(frozen=True)
class LoopPaths:
    """Run-dir + _pending queue layout.

    Two roots: ``repo_root`` resolves the in-repo prompts/code (read-only at
    runtime); ``state_dir`` resolves the mutable learning *state* (the findings
    queue, per-run learning dirs, the author lock + work queue). When
    ``state_dir`` is None the state lives under ``learning_dir`` — today's
    in-repo behavior, so tests that pass only ``repo_root`` are unaffected.
    Concurrent live runs set ``DEFENDER_LEARNING_STATE_DIR`` so the queue lives
    out-of-repo and every process resolves the same single location.
    """

    repo_root: Path
    state_dir: Path | None = None

    @property
    def learning_dir(self) -> Path:
        return self.repo_root / "defender" / "learning"

    # Repo-relative corpora + catalog roots (read-only at runtime; never
    # relocate with DEFENDER_LEARNING_STATE_DIR). The author family reads these
    # off ``paths`` instead of import-time module globals so a test rooted at a
    # tmp tree resolves them with one ``LoopPaths(repo_root=tmp)``.
    @property
    def lessons_dir(self) -> Path:
        return self.repo_root / "defender" / "lessons"

    @property
    def lessons_actor_dir(self) -> Path:
        return self.repo_root / "defender" / "lessons-actor"

    @property
    def lessons_environment_dir(self) -> Path:
        return self.repo_root / "defender" / "lessons-environment"

    @property
    def catalog_dir(self) -> Path:
        return self.repo_root / "defender" / "skills" / "gather" / "queries"

    @property
    def skills_dir(self) -> Path:
        return self.repo_root / "defender" / "skills"

    @property
    def worktree_base(self) -> Path:
        # Repo-local scratch where each author drain creates its throwaway batch
        # worktree (one leaf dir per batch; see author/branch.py). Repo-relative
        # so a tmp-tree test resolves it under its own root.
        return self.repo_root / ".worktrees"

    @property
    def _state_root(self) -> Path:
        return self.state_dir if self.state_dir is not None else self.learning_dir

    def with_repo_root(self, repo_root: Path) -> LoopPaths:
        """A copy rooted at a different ``repo_root`` (e.g. an author batch worktree)
        that keeps this layout's *resolved* state dir. So the corpus/catalog dirs move
        to the worktree (where the curator edits + the loop commits) while the queues,
        locks, and pending files stay at the shared original location — the markers
        being drained live there, not in the throwaway worktree."""
        return LoopPaths(repo_root=repo_root, state_dir=self._state_root)

    @property
    def runs_dir(self) -> Path:
        return self._state_root / "runs"

    @property
    def pending_dir(self) -> Path:
        return self._state_root / "_pending"

    @property
    def lead_pending_dir(self) -> Path:
        return self._state_root / "_pending_leads"

    # --- general-failure pitfalls queue (cross-run; feeds the lead-author's
    # execution.md curation mode). Lives under the shared state root so an append
    # from inside a drain worktree lands centrally, like the other pending queues. ---
    @property
    def pitfalls_pending_dir(self) -> Path:
        return self._state_root / "_pending_pitfalls"

    @property
    def pitfalls_pending_file(self) -> Path:
        return self.pitfalls_pending_dir / "pitfalls.jsonl"

    @property
    def pitfalls_consumed_file(self) -> Path:
        return self.pitfalls_pending_dir / "pitfalls.consumed.jsonl"

    @property
    def pitfalls_lock_file(self) -> Path:
        return self.pitfalls_pending_dir / ".pitfalls.lock"

    @property
    def author_lock_file(self) -> Path:
        return self._state_root / "_author.lock"

    @property
    def learn_queue_dir(self) -> Path:
        # run.py drops a marker here per finished run; the off-process learn
        # worker (loop.py --learn-drain) claims + drains it. Mirror of
        # author_queue_dir, one stage upstream. No drain lock: learning is
        # concurrent (§4.3), so cross-worker safety is the per-marker
        # rename-claim into learn-queue/inflight/, not a one-at-a-time lock.
        return self._state_root / "learn-queue"

    @property
    def author_queue_dir(self) -> Path:
        return self._state_root / "author-queue"

    @property
    def author_drain_lock_file(self) -> Path:
        # Distinct from author_lock_file (the curators' repo lock): the drainer
        # holds this so a second drainer exits, while the curators it calls can
        # still take author_lock_file without a same-process deadlock.
        return self._state_root / ".author-drain.lock"

    @property
    def lead_author_drain_lock_file(self) -> Path:
        # The lead-author drain's own one-drainer-at-a-time lock, distinct from
        # author_drain_lock_file so the lessons drain and the lead-author drain
        # are independently scheduled. Each drain runs in its own git worktree,
        # so they need no cross-drain lock — this only serializes same-type ticks.
        return self._state_root / ".lead-author-drain.lock"

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

    # Adversarial env-fact stream — a second source for the SHARED
    # lessons-environment/ corpus (issue #298). Separate queue from the benign
    # environment_observations so each drains in its own single-direction batch
    # (clean per-commit trailers + per-direction outcome policy); both authors
    # commit into defender/lessons-environment/.
    @property
    def actor_environment_observations_file(self) -> Path:
        return self.pending_dir / "actor_environment_observations.jsonl"

    @property
    def actor_environment_observations_consumed_file(self) -> Path:
        return self.pending_dir / "actor_environment_observations.consumed.jsonl"

    @property
    def actor_environment_observations_lock_file(self) -> Path:
        return self.pending_dir / ".actor_environment.lock"


def _env_state_dir() -> Path | None:
    """Out-of-repo learning-state dir from ``DEFENDER_LEARNING_STATE_DIR``.

    Returns None when unset (state stays in-repo). When set, the dir is
    *resolved* so producer (run/learn) and consumer (author) processes agree on
    one identical location — no silent fallback that would split-brain the queue
    across concurrent runs. It is **not** created here: importing this module
    must have no filesystem side effect, and a typo'd/unwritable path should fail
    at first use (where each writer mkdirs the specific subdir it needs), not
    crash the import of the whole learning subsystem.
    """
    raw = os.environ.get("DEFENDER_LEARNING_STATE_DIR")
    if not raw:
        return None
    return Path(raw).resolve()


DEFAULT_PATHS = LoopPaths(repo_root=REPO_ROOT, state_dir=_env_state_dir())

LEARNING_DIR = DEFAULT_PATHS.learning_dir

_PIPELINE_DIR = LEARNING_DIR / "pipeline"
ACTOR_PROMPT = _PIPELINE_DIR / "malicious_actor" / "prompt.md"
ACTOR_BENIGN_PROMPT = _PIPELINE_DIR / "benign_actor" / "prompt.md"
# Per-lead generative telemetry oracle: one call per lead, fanned out concurrently
# (see pipeline/oracle/run.py + pipeline/oracle/sample.py).
ORACLE_PROMPT = _PIPELINE_DIR / "oracle" / "prompt.md"
JUDGE_PROMPT = _PIPELINE_DIR / "judge" / "malicious.md"
JUDGE_BENIGN_PROMPT = _PIPELINE_DIR / "judge" / "benign.md"

ACTOR_SETTINGS = _PIPELINE_DIR / "malicious_actor" / "actor-settings.json"
BENIGN_ACTOR_SETTINGS = _PIPELINE_DIR / "benign_actor" / "benign-actor-settings.json"
LESSONS_ACTOR_DIR = DEFAULT_PATHS.lessons_actor_dir
LESSONS_ENVIRONMENT_DIR = DEFAULT_PATHS.lessons_environment_dir

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
# Audit-only adversarial types: validated + emitted for analysis, but never
# queued as lessons (filtered in ``_loop_persist.append_findings``), so the
# author / lesson schema / verify_forward need not route them.
#   detection-confirmed — a justified detection worth preserving.
ADVERSARIAL_AUDIT_ONLY_FINDING_TYPES = {"detection-confirmed"}
ALL_FINDING_TYPES = QUEUEABLE_FINDING_TYPES | ADVERSARIAL_AUDIT_ONLY_FINDING_TYPES
# Benign defender findings share the queueable types; ``disposition-confirmed``
# is the FP-direction audit-only type (the adversarial ``detection-confirmed``
# analog — a justified escalation, filtered out of the queued lessons).
BENIGN_AUDIT_ONLY_FINDING_TYPES = {"disposition-confirmed"}
BENIGN_ALL_FINDING_TYPES = QUEUEABLE_FINDING_TYPES | BENIGN_AUDIT_ONLY_FINDING_TYPES
ACTOR_OBSERVATION_TYPES = {"misprediction", "framing-choice", "discarded-class"}

ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "claude-sonnet-4-6")
BENIGN_ACTOR_MODEL = os.environ.get("BENIGN_ACTOR_MODEL", "claude-sonnet-4-6")
# Story construction was never pinned, so the actor ran at the inherited global
# `high` default. An effort A/B on a network-tool detection case (n=1/cell) found the
# response bimodal: medium (~194s) ≈ high (~216s) in wall + thinking, while low
# (~37s) sharply curtails reasoning. high was *dominated* by medium — medium was
# both faster and better-grounded (it recovered the real jump-box IP + the
# monitoring-probe fingerprint that high invented), so high buys nothing. Pinned
# medium. low stays a 5x-cheaper fallback that still yields coherent (if blunter)
# stories. Effort drives sophistication, not fact fidelity — that's corpus work.
# Override via ACTOR_EFFORT.
ACTOR_EFFORT = os.environ.get("ACTOR_EFFORT", "medium")
BENIGN_ACTOR_EFFORT = os.environ.get("BENIGN_ACTOR_EFFORT", "medium")
# Per-lead generative oracle. Generative work — sonnet for content fidelity (per the
# d2d72ab model decision); effort pinned low since each call sees only its own lead and
# projects a signed baseline-diff (no cross-lead matching to reason about). Override via
# ORACLE_*. ORACLE_MAX_CONCURRENCY bounds the per-direction fan-out of per-lead calls.
ORACLE_MODEL = os.environ.get("ORACLE_MODEL", "claude-sonnet-4-6")
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


@dataclass(frozen=True)
class JudgeWiring:
    """Per-direction judge knobs — the only things that differ between the adversarial
    and benign grounded-judge calls (the projection itself rides
    ``projected_telemetry_path``). Bundled beside the ``JUDGE_*`` constants they wrap so
    the per-direction config lives in one place instead of being threaded as loose kwargs
    through every call layer. ``comparison_dirname`` / ``settings_name`` are distinct per
    direction so concurrent legs on an ``inconclusive`` case don't clobber each other's
    grounding files (see ``build_judge_invocation`` in ``_loop_subagents.py``). The two
    instances live on the ``Direction`` specs in ``_loop_directions.py``."""

    prompt_path: Path
    model: str
    effort: str
    trace_name: str
    label: str
    comparison_dirname: str
    settings_name: str
    # When True, the judge's settings surface grants a scoped, closed-only ticket read
    # (issue #338) so it can confirm a cited closed case from the case-history store —
    # the benign (FP) direction only; the adversarial judge never reads the store.
    closed_ticket_read: bool = False


SUBAGENT_TIMEOUT = int(os.environ.get("LEARNING_SUBAGENT_TIMEOUT_SECONDS", "450"))

# Author merge gating (platform-design §4.4). The serial author always opens a PR
# (audit trail); this knob decides whether it auto-merges on a green bar or waits
# for human review. Default `human_review` until the revert + lesson→outcome
# traceability surface lands (PR D) — see docs/decisions/ephemeral-run-worktree-isolation.md.
# Validated lazily at the author stage (see _loop_orchestrate.author_drain), NOT
# here: this module is imported by every learning stage (LEARN, run_one, run.py's
# post-step), and a typo'd author-only knob must not crash stages that never merge.
VALID_MERGE_MODES = ("auto_on_green", "human_review")
MERGE_MODE = os.environ.get("LEARNING_MERGE_MODE", "human_review")


class LoopError(Exception):
    """Fatal orchestrator error — caller should stop processing this run."""


def env_int(name: str, default: int) -> int:
    """Read an integer env override, failing loud on a non-numeric value.

    The drain wake gates read their trigger thresholds at call time (so tests
    override via ``monkeypatch.setenv``). A bad operator value (``=high``, ``=""``)
    must surface as a ``LoopError`` — which the drain's ``_run_stage`` maps to the
    contracted exit 2 — rather than an uncaught ``ValueError`` that crashes the
    stage with a traceback and an uncontracted exit 1. Mirrors the fail-loud reads
    for ``LEARNING_MERGE_MODE`` and ``ORACLE_MAX_CONCURRENCY``.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise LoopError(f"{name} must be an integer; got {raw!r}") from None


def pitfalls_threshold() -> int:
    """Min count of queued general-failure pitfalls before the curation mode fires.

    Lives in ``core`` (not ``leads.lead_author``) because BOTH the lead-author drain's
    wake gate (``core.orchestrate._has_lead_author_work``) and the curator itself
    (``leads.lead_author.run_pitfalls``) read it. Keeping the env name + default in one
    core place stops the gate and the curator from disagreeing about the threshold — and
    lets the gate read it without ``core`` reaching up into the ``leads`` package. Read at
    call time so tests can monkeypatch via ``monkeypatch.setenv``.
    """
    return env_int("LEARNING_PITFALLS_THRESHOLD", 5)


def make_logger(prefix: str, *, flush: bool = False) -> Callable[[str], None]:
    """Build a stderr logger that prefixes every line with ``[prefix]``."""
    def _log(msg: str) -> None:
        print(f"[{prefix}] {msg}", file=sys.stderr, flush=flush)
    return _log


def now_iso() -> str:
    """UTC timestamp, seconds precision (the loop's canonical clock string)."""
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


_log = make_logger("loop")  # this module's own logger


def subscription_env() -> dict[str, str]:
    """Env for a ``claude -p`` call: strip ``ANTHROPIC_API_KEY`` so the call
    bills against the subscription, never the metered first-party key
    (reserved for the PydanticAI engine — see defender/run.py)."""
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)
    return env
