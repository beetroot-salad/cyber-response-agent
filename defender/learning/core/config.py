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
from collections.abc import Callable
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

# The env-coercion + clock primitives live at the ``defender.`` namespace root so
# every layer (runtime/, scripts/, learning/) shares one source instead of each
# re-deriving a crash-prone ``int(os.environ.get(...))`` with its own default.
# Re-exported below (``env_int``, ``now_iso``, ``FatalConfigError``) so existing
# ``core.config`` importers are unchanged; the import-time constants in this module
# call ``env_int`` directly. ``FatalConfigError`` (the layer-neutral *condition*)
# is enrolled into this loop's ``StageAbort``/exit-2 *response* at the drain catch
# sites in ``orchestrate`` — see that module and ``StageAbort`` below.
from defender._clock import now_iso  # noqa: F401 — re-export: core.config stays the loop's import surface
from defender._env import env_int, env_str
from defender._env import FatalConfigError  # noqa: F401 — re-export; enrolled as stage-fatal in orchestrate
# RunPaths is a neutral top-level value object (no learning dependency, so the
# runtime/hooks/scripts can import it without coupling to the loop — #317).
# Re-exported here so learning-side code keeps importing it off core.config.
from defender._run_paths import RunPaths  # noqa: F401 — re-export
# DefenderPaths is the repo-relative layout primitive (defender/_paths.py, another
# neutral top-level value object): the single owner of every ``<repo>/defender/...``
# offset. LoopPaths composes it below (its repo-relative properties delegate), and it
# is re-exported here so learning-side code imports it off core.config like RunPaths.
from defender._paths import DefenderPaths  # noqa: F401 — used by LoopPaths + re-export


REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class QueueChannel:
    """One _pending observation stream as a unit: its queue ``file``, the
    ``consumed`` sink rows rotate into, and the ``lock`` serializing both. Always
    consumed together, so callers take the channel instead of rebuilding the
    triple by hand. (The ``findings`` stream is deliberately *not* a channel — it
    has a queue + lock but no consumed sink.)"""

    file: Path
    consumed: Path
    lock: Path


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

    @cached_property
    def defender(self) -> DefenderPaths:
        """The repo-relative layout, composed. The offset strings live in
        ``DefenderPaths`` (``defender/_paths.py``); the repo-relative properties
        below delegate here so there is one owner per offset. ``LoopPaths`` keeps
        ``repo_root`` as its field, so every caller constructs it unchanged.

        ``cached_property``: ``repo_root`` is frozen, so the composed value never
        changes — resolve it once instead of allocating a fresh ``DefenderPaths`` on
        every delegated property read."""
        return DefenderPaths(self.repo_root)

    # Repo-relative corpora + catalog + skills roots (read-only at runtime; never
    # relocate with DEFENDER_LEARNING_STATE_DIR). Delegated to ``self.defender`` so
    # the author family + scope-gate share one layout owner; a test rooted at a tmp
    # tree still resolves them with one ``LoopPaths(repo_root=tmp)``.
    @property
    def learning_dir(self) -> Path:
        return self.defender.learning_dir

    @property
    def lessons_dir(self) -> Path:
        return self.defender.lessons_dir

    @property
    def lessons_actor_dir(self) -> Path:
        return self.defender.lessons_actor_dir

    @property
    def lessons_environment_dir(self) -> Path:
        return self.defender.lessons_environment_dir

    # Repo-relative twins of the three corpus dirs, used as git pathspec prefixes
    # by the author commit/scope-gate. Trailing slash significant; repo-root-
    # independent class constants on ``DefenderPaths``.
    @property
    def lessons_dir_rel(self) -> str:
        return DefenderPaths.lessons_dir_rel

    @property
    def lessons_actor_dir_rel(self) -> str:
        return DefenderPaths.lessons_actor_dir_rel

    @property
    def lessons_environment_dir_rel(self) -> str:
        return DefenderPaths.lessons_environment_dir_rel

    @property
    def catalog_dir(self) -> Path:
        return self.defender.catalog_dir

    @property
    def skills_dir(self) -> Path:
        return self.defender.skills_dir

    @property
    def worktree_base(self) -> Path:
        return self.defender.worktree_base

    @property
    def state_root(self) -> Path:
        """The resolved mutable-state root: out-of-repo ``state_dir`` when set, else the
        in-repo ``learning_dir``. The authoritative source for ``runs_dir`` / the queues
        AND for the ``DEFENDER_LEARNING_STATE_DIR`` value pinned into curator-agent
        subprocesses (#425) — derive the state root from this, never by inverting
        ``runs_dir`` (e.g. ``runs_dir.parent``), which silently breaks if the runs layout
        ever gains a level."""
        return self.state_dir if self.state_dir is not None else self.learning_dir

    def with_repo_root(self, repo_root: Path) -> LoopPaths:
        """A copy rooted at a different ``repo_root`` (e.g. an author batch worktree)
        that keeps this layout's *resolved* state dir. So the corpus/catalog dirs move
        to the worktree (where the curator edits + the loop commits) while the queues,
        locks, and pending files stay at the shared original location — the markers
        being drained live there, not in the throwaway worktree."""
        return LoopPaths(repo_root=repo_root, state_dir=self.state_root)

    @property
    def runs_dir(self) -> Path:
        return self.state_root / "runs"

    @property
    def pending_dir(self) -> Path:
        return self.state_root / "_pending"

    @property
    def lead_pending_dir(self) -> Path:
        return self.state_root / "_pending_leads"

    # --- general-failure pitfalls queue (cross-run; feeds the lead-author's
    # execution.md curation mode). Lives under the shared state root so an append
    # from inside a drain worktree lands centrally, like the other pending queues. ---
    @property
    def pitfalls_pending_dir(self) -> Path:
        return self.state_root / "_pending_pitfalls"

    @property
    def pitfalls(self) -> QueueChannel:
        return QueueChannel(
            file=self.pitfalls_pending_dir / "pitfalls.jsonl",
            consumed=self.pitfalls_pending_dir / "pitfalls.consumed.jsonl",
            lock=self.pitfalls_pending_dir / ".pitfalls.lock",
        )

    @property
    def author_lock_file(self) -> Path:
        return self.state_root / "_author.lock"

    @property
    def learn_queue_dir(self) -> Path:
        # run.py drops a marker here per finished run; the off-process learn
        # worker (loop.py --learn-drain) claims + drains it. Mirror of
        # author_queue_dir, one stage upstream. No drain lock: learning is
        # concurrent (§4.3), so cross-worker safety is the per-marker
        # rename-claim into learn-queue/inflight/, not a one-at-a-time lock.
        return self.state_root / "learn-queue"

    @property
    def author_queue_dir(self) -> Path:
        return self.state_root / "author-queue"

    @property
    def author_drain_lock_file(self) -> Path:
        # Distinct from author_lock_file (the curators' repo lock): the drainer
        # holds this so a second drainer exits, while the curators it calls can
        # still take author_lock_file without a same-process deadlock.
        return self.state_root / ".author-drain.lock"

    @property
    def lead_author_drain_lock_file(self) -> Path:
        # The lead-author drain's own one-drainer-at-a-time lock, distinct from
        # author_drain_lock_file so the lessons drain and the lead-author drain
        # are independently scheduled. Each drain runs in its own git worktree,
        # so they need no cross-drain lock — this only serializes same-type ticks.
        return self.state_root / ".lead-author-drain.lock"

    @property
    def pending_file(self) -> Path:
        return self.pending_dir / "findings.jsonl"

    @property
    def findings_lock_file(self) -> Path:
        return self.pending_dir / ".findings.lock"

    @property
    def actor_observations(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_dir / "actor_observations.jsonl",
            consumed=self.pending_dir / "actor_observations.consumed.jsonl",
            lock=self.pending_dir / ".actor.lock",
        )

    @property
    def environment_observations(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_dir / "environment_observations.jsonl",
            consumed=self.pending_dir / "environment_observations.consumed.jsonl",
            lock=self.pending_dir / ".environment.lock",
        )

    # Adversarial env-fact stream — a second source for the SHARED
    # lessons-environment/ corpus (issue #298). Separate queue from the benign
    # environment_observations so each drains in its own single-direction batch
    # (clean per-commit trailers + per-direction outcome policy); both authors
    # commit into defender/lessons-environment/.
    @property
    def actor_environment_observations(self) -> QueueChannel:
        return QueueChannel(
            file=self.pending_dir / "actor_environment_observations.jsonl",
            consumed=self.pending_dir / "actor_environment_observations.consumed.jsonl",
            lock=self.pending_dir / ".actor_environment.lock",
        )


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


def learning_state_root() -> Path:
    """The learning-state root resolved **at call time** from the live environment:
    the out-of-repo ``DEFENDER_LEARNING_STATE_DIR`` when set, else the in-repo
    ``defender/learning``. ``DEFAULT_PATHS`` below freezes this at import time for the
    loop; renderers that run in a separately-spawned process (e.g. the visualizer,
    which the off-process worker invokes after setting the env) call this so they
    mirror ``LoopPaths.runs_dir`` from one source instead of re-reading the env."""
    return _env_state_dir() or (REPO_ROOT / "defender" / "learning")


def learning_run_paths(run_id: str) -> RunPaths:
    """A learning-leg ``RunPaths`` for ``run_id``, deriving ``learning_run_dir`` from
    the call-time ``learning_state_root()`` so a separately-spawned renderer honors
    ``DEFENDER_LEARNING_STATE_DIR``. The single source for the
    ``<state_root>/runs/<run_id>`` path that ``orchestrate`` and the visualizers both
    need — no parallel re-derivation (the latent "renders an empty judge page" bug).
    Rooted at ``learning_run_dir`` so the copied artifact accessors resolve there."""
    learning_run_dir = learning_state_root() / "runs" / run_id
    return RunPaths(run_dir=learning_run_dir, learning_run_dir=learning_run_dir)


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

LESSONS_ACTOR_DIR = DEFAULT_PATHS.lessons_actor_dir
LESSONS_ENVIRONMENT_DIR = DEFAULT_PATHS.lessons_environment_dir

# The two read-only lesson-retrieval scripts the in-process actor may run, pinned by the
# actor's AgentPolicy bash_allow patterns (pipeline/actor_engine._script_pattern). The single
# home for these offsets — verify_forward/env.py reuses LESSONS_ENV_RETRIEVE_SCRIPT.
_LESSONS_SCRIPTS_DIR = REPO_ROOT / "defender" / "scripts" / "lessons"
LESSONS_ENV_RETRIEVE_SCRIPT = _LESSONS_SCRIPTS_DIR / "lessons_env_retrieve.py"
LESSONS_ACTOR_INDEX_SCRIPT = _LESSONS_SCRIPTS_DIR / "lessons_actor_index.py"

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

# The actor runs IN-PROCESS on PydanticAI (GLM 5.2, Fireworks) — the metered first-party path,
# the mirror of the judge migration (both actors share the metered key; oracle/curators stay on
# claude -p). GLM reasons by default and bills that thinking as output tokens, capped by
# `reasoning_effort`; `low` is the shipped default (the cheapest coherent tier). NB a prior
# Sonnet effort A/B found `low` sharply curtails story sophistication (effort drives
# sophistication, not fact fidelity — that's corpus work), so revisit `medium` if the secondary
# catch-rate / story quality regresses. Override via ACTOR_MODEL / ACTOR_EFFORT (any provider
# providers.provider_for routes — e.g. claude-sonnet-4-6 for an A/B).
ACTOR_MODEL = os.environ.get("ACTOR_MODEL", "glm-5.2")
BENIGN_ACTOR_MODEL = os.environ.get("BENIGN_ACTOR_MODEL", "glm-5.2")
ACTOR_EFFORT = os.environ.get("ACTOR_EFFORT", "low")
BENIGN_ACTOR_EFFORT = os.environ.get("BENIGN_ACTOR_EFFORT", "low")
# The oracle runs IN-PROCESS on PydanticAI (GLM 5.2, Fireworks) — the metered first-party path,
# the mirror of the actor/judge migrations (all three in-process stages share the metered key;
# the curators stay on claude -p). Each call is a MECHANICAL per-lead projection: it sees only its
# own lead — sanitized what_to_summarize + queries + one scrubbed sample — and emits a signed
# baseline-diff, with no cross-lead matching to reason about. So reasoning is DISABLED: `none` is
# the explicit string that forwards reasoning_effort="none" (NOT Python None, which OMITS the knob
# and leaves GLM reasoning on) — the same lever the equally-mechanical gather subagent uses. Effort
# maps through `providers.build_for_effort` (Fireworks `reasoning_effort` / Anthropic
# `anthropic_effort`). Override via ORACLE_MODEL / ORACLE_EFFORT (any provider
# providers.provider_for routes). NB `none` is a Fireworks-only effort: an Anthropic A/B
# (e.g. ORACLE_MODEL=claude-sonnet-4-6) MUST also set ORACLE_EFFORT to a Claude-valid effort
# (low/medium/high/…), else build_for_effort raises → FatalConfigError (exit 2) on every lead.
# ORACLE_MAX_CONCURRENCY bounds the per-direction fan-out of per-lead calls.
ORACLE_MODEL = os.environ.get("ORACLE_MODEL", "glm-5.2")
ORACLE_EFFORT = os.environ.get("ORACLE_EFFORT", "none")
ORACLE_MAX_CONCURRENCY = env_int("ORACLE_MAX_CONCURRENCY", 8)
# The judge runs in-process (PydanticAI) on GLM 5.2 (Fireworks) by default. Override
# per-direction via env for the A/B (any provider `providers.provider_for` can route).
JUDGE_MODEL = os.environ.get("JUDGE_MODEL", "glm-5.2")
BENIGN_JUDGE_MODEL = os.environ.get("BENIGN_JUDGE_MODEL", "glm-5.2")
# GLM 5.2 reasons by default and bills that thinking as output tokens, capped by
# `reasoning_effort`; the judge follows a heavily-scaffolded prompt and does only a
# bounded handful of read-only verification tool calls, so `medium` is the ported
# default (per the Step-2 model A/B — see evals/judge_equivalence.py), with `low` a
# cheaper fallback. Effort maps through `providers.build_for_effort` (Fireworks
# `reasoning_effort` / Anthropic `anthropic_effort`), so `medium` is valid on either.
# Override per-direction via env for A/B.
JUDGE_EFFORT = os.environ.get("JUDGE_EFFORT", "medium")
BENIGN_JUDGE_EFFORT = os.environ.get("BENIGN_JUDGE_EFFORT", "medium")


@dataclass(frozen=True)
class JudgeWiring:
    """Per-direction judge knobs — the only things that differ between the adversarial
    and benign grounded-judge calls (the projection itself rides
    ``projected_telemetry_path``). Bundled beside the ``JUDGE_*`` constants they wrap so
    the per-direction config lives in one place instead of being threaded as loose kwargs
    through every call layer. ``comparison_dirname`` is distinct per direction so
    concurrent legs on an ``inconclusive`` case don't clobber each other's grounding
    files (see ``build_judge_invocation`` in ``_loop_subagents.py``). The two instances
    live on the ``Direction`` specs in ``_loop_directions.py``."""

    prompt_path: Path
    model: str
    effort: str
    trace_name: str
    label: str
    comparison_dirname: str
    # When True, the judge is granted a scoped, closed-only ticket read (issue #338) so it
    # can confirm a cited closed case from the case-history store — the benign (FP)
    # direction only; the adversarial judge never reads the store.
    closed_ticket_read: bool = False


SUBAGENT_TIMEOUT = env_int("LEARNING_SUBAGENT_TIMEOUT_SECONDS", 450)

# --- Author / verifier / lead-author wiring -------------------------------------
# The curator-AGENT model/effort/timeout per author direction (distinct from the
# ACTOR/ORACLE/JUDGE *stage* models above), plus the forward-check verifier and the
# repo lock. Centralized here so each module reads ONE source instead of re-deriving
# the same env var + default from os.environ — the duplicated-default divergence #449
# fixed for the actor model, generalized to every stage knob.

# Forward-check gate — shared by both LLM verify_forward entry points
# (verify_forward/actor.py and forward.py; verify_forward/env.py is deterministic and
# has no model). Runs IN-PROCESS on PydanticAI (GLM 5.2, Fireworks) — the metered
# first-party path, the mirror of the judge/actor/oracle migrations. Two reasons the
# forward-check runs GLM rather than the old subscription Haiku: (1) it is the FOURTH
# in-process stage, so it shares the `_pydantic_stage` transport + billing invariant with
# the rest of the loop, and (2) the check is a same-case regression PROXY — it predicts
# what the *defender* (`runtime/driver.DEFAULT_MODEL = "glm-5.2"`) would conclude with the
# candidate lesson loaded — so predicting with the defender's own model tightens the proxy.
# GLM reasons by default and bills that thinking as output tokens, capped by
# `reasoning_effort`; `low` is the default — it matches the defender's OWN MAIN effort
# (`providers.FIREWORKS.main_effort`), so the proxy reasons at the SAME tier the defender it
# predicts does (and it mirrors the actor). `medium` is the fallback if a verifier TNR/TPR
# re-measure under GLM (experiments/defender-author-verification/) shows the counterfactual
# judgment regressing at `low`. Both knobs override via env (any provider
# `providers.provider_for` routes — e.g. claude-haiku-4-5 to A/B against the pre-migration gate).
VERIFIER_MODEL = os.environ.get("LEARNING_VERIFIER_MODEL", "glm-5.2")
VERIFIER_EFFORT = os.environ.get("LEARNING_VERIFIER_EFFORT", "low")
# Per-check wall-clock ceiling for the in-process forward-check (threaded into
# `_pydantic_stage.run_stage` as its `wall_clock_timeout`, the in-process twin of the old
# `claude -p` subprocess timeout). Kept BELOW the batch child ceiling so a batched check
# reports its own BAD/ERROR before verify_forward/batch.py kills it.
VERIFIER_TIMEOUT = env_int("LEARNING_VERIFIER_TIMEOUT_SECONDS", 180)
# Batch forward-check fan-out (verify_forward/batch.py). CHILD timeout sits above the
# single-check VERIFIER_TIMEOUT so a child reports BAD/ERROR rather than being killed.
VERIFY_BATCH_WORKERS = env_int("LEARNING_VERIFY_BATCH_WORKERS", 8)
VERIFY_BATCH_TIMEOUT = env_int("LEARNING_VERIFY_BATCH_TIMEOUT_SECONDS", 240)

# Findings (lessons/) curator agent. AUTHOR_EFFORT has no default (None = inherit the
# global effort) — preserved exactly from the prior lessons/run.py behavior.
AUTHOR_MODEL = os.environ.get("LEARNING_AUTHOR_MODEL", "claude-sonnet-4-6")
AUTHOR_TIMEOUT = env_int("LEARNING_AUTHOR_TIMEOUT_SECONDS", 1800)
AUTHOR_EFFORT = os.environ.get("LEARNING_AUTHOR_EFFORT")  # low|medium|high|xhigh|max
# Actor-tradecraft (lessons-actor/) curator agent.
AUTHOR_ACTOR_MODEL = os.environ.get("LEARNING_AUTHOR_ACTOR_MODEL", "claude-sonnet-4-6")
AUTHOR_ACTOR_TIMEOUT = env_int("LEARNING_AUTHOR_ACTOR_TIMEOUT_SECONDS", 1800)
AUTHOR_ACTOR_EFFORT = os.environ.get("LEARNING_AUTHOR_ACTOR_EFFORT", "low")
# Environment-lessons (lessons-environment/) curator agent — both env directions share it.
AUTHOR_ENV_MODEL = os.environ.get("LEARNING_AUTHOR_ENV_MODEL", "claude-sonnet-4-6")
AUTHOR_ENV_TIMEOUT = env_int("LEARNING_AUTHOR_ENV_TIMEOUT_SECONDS", 1800)
AUTHOR_ENV_EFFORT = os.environ.get("LEARNING_AUTHOR_ENV_EFFORT", "low")
# Offline lead-author (skills/ catalog) agent.
LEAD_AUTHOR_MODEL = os.environ.get("LEAD_AUTHOR_MODEL", "claude-sonnet-4-6")
LEAD_AUTHOR_TIMEOUT = env_int("LEAD_AUTHOR_TIMEOUT_SECONDS", 1800)

# Repo lock wait ceiling — the single location every curator serializes on. Lives here
# (not author/shared.py) so the value has one home; shared.py re-exports it.
REPO_LOCK_WAIT_SECONDS = env_int("LEARNING_REPO_LOCK_WAIT_SECONDS", 1800)

# Author merge gating (platform-design §4.4). The serial author always opens a PR
# (audit trail); this knob decides whether it auto-merges on a green bar or waits
# for human review. Default `human_review` until the revert + lesson→outcome
# traceability surface lands (PR D) — see docs/decisions/ephemeral-run-worktree-isolation.md.
VALID_MERGE_MODES = ("auto_on_green", "human_review")


def merge_mode() -> str:
    """The author merge gate, read + validated at **call time** (not import).

    A function, not a module constant, so the ``choices`` validation runs lazily at
    the author stage (``orchestrate.author_drain``) — this module is imported by
    every learning stage (LEARN, run_one, run.py's post-step), and a typo'd
    author-only knob must not crash stages that never merge. ``env_str`` raises
    ``FatalConfigError`` on an out-of-set value, which the drain maps to exit 2.
    Call-time read also lets tests override via ``monkeypatch.setenv`` (the env_int
    threshold pattern)."""
    return env_str("LEARNING_MERGE_MODE", "human_review", choices=VALID_MERGE_MODES)


class StageAbort(Exception):
    """A systemic failure — the whole stage must abort with the contracted
    ``exit 2``. This is the type ``_run_stage`` maps to exit 2 on every stage
    (drains and the direct single-run path alike), and the type the drains
    re-raise *before* their broad per-item quarantine guard so a deployment-wide
    fault dooms the stage rather than being mislabeled as one corrupt item.

    The layer-neutral ``FatalConfigError`` (imported from ``defender._env``, a
    misconfig *condition* runtime/ shares) is **enrolled alongside** ``StageAbort``
    at those two catch sites — it is no longer a subclass, since the exit-2
    *response* is learning-only while the *condition* is universal. See the
    ``except (StageAbort, FatalConfigError)`` seams in ``orchestrate``.

    Distinct from ``RunUnprocessable``: ``StageAbort`` is "the deployment is
    broken, stop everything"; ``RunUnprocessable`` is "this one run's data is
    bad, skip it." Keeping them disjoint (not one subclassing the other) is the
    point of #443 — the disposition is now carried by the *type*, not by which
    ``except`` happens to catch it.
    """


class RunUnprocessable(Exception):
    """This run's data/content is unprocessable — stop processing THIS run.

    The per-run data failures the loop overwhelmingly raises: a malformed
    ``report.md`` / judge YAML, a missing artifact, a ``claude -p`` non-zero rc.
    Raised only inside ``run_one``'s call graph (the per-run pipeline + its
    validators). Its disposition depends on the unit of work:

    * On the **queue path** (``learn_drain`` → ``_process_marker``) a drain's
      broad ``except Exception`` quarantines this one run and keeps draining.
    * On the **direct single-run path** (``loop.py <run_dir>``) there is no
      queue, so ``_run_stage`` (called with ``allow_run_error=True``) maps it to
      the contracted ``exit 2``.

    It is **not** a ``StageAbort`` and is never raised on an author-drain path —
    those use ``AuthorError`` / ``LeadAuthorError`` (quarantine) or
    ``StageAbort`` (abort). A ``RunUnprocessable`` reaching a *drain's*
    ``_run_stage`` is therefore a bug: it propagates uncaught (a loud
    exit-1 + traceback) rather than masquerading as a clean exit 2. See #443.
    """


def pitfalls_threshold() -> int:
    """Min count of queued general-failure pitfalls before the curation mode fires.

    Lives in ``core`` (not ``leads.pitfalls_curator``) because BOTH the lead-author drain's
    wake gate (``core.orchestrate._has_lead_author_work``) and the curator itself
    (``leads.pitfalls_curator.run_pitfalls``) read it. Keeping the env name + default in one
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


_log = make_logger("loop")  # this module's own logger


def subscription_env() -> dict[str, str]:
    """Env for a ``claude -p`` call: strip every billable provider key
    (``providers.api_key_vars()`` — ``ANTHROPIC_API_KEY``, ``FIREWORKS_API_KEY``, …) so
    the call bills against the subscription, never a metered first-party key (reserved
    for the in-process PydanticAI stages — see defender/run.py). Stripping ALL of them
    (not just Anthropic's, matching ``run_common.run_env``) keeps ``source_first_party_key``'s
    mixed-billing invariant true for every provider: a metered key sourced into
    ``os.environ`` can never reach a sibling ``claude -p``, whatever provider the in-process
    stage runs on."""
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    return env


def source_first_party_key(model: str, *, label: str = "judge") -> None:
    """Source an in-process PydanticAI stage's metered first-party key into ``os.environ``
    (idempotent) so the stage can authenticate against the first-party API. The provider is
    derived from the model name (``claude-*`` → ANTHROPIC_API_KEY, ``glm-5.2`` →
    FIREWORKS_API_KEY). ``label`` names the stage in the log/error text (``judge`` / ``actor``
    / ``engine`` for a mixed prep).

    Mixed billing within one run is SAFE: the in-process stages (the actor, oracle, and judge)
    run on the metered key, but every OTHER stage (the curators) shells out to ``claude -p``
    under ``subscription_env``, which COPIES ``os.environ`` and pops every provider key — so
    setting it here can never reach a subscription sibling, and they keep billing the
    subscription. A ``.env`` key takes precedence over the ambient value (for Anthropic the
    ambient is the subscription credential, which 401s against the first-party REST API). Fail
    loud (``FatalConfigError`` → the orchestrator's exit 2) when no key is available at all,
    rather than 401-ing mid-stage."""
    # provider_for imports no pydantic-ai backend (declarative routing), so this is
    # safe in the SIEM-free learn worker; _first_party_key is neutral (no run.py).
    from defender.runtime import providers
    from defender._first_party_key import resolve_first_party_key

    try:
        var = providers.provider_for(model).api_key_var
    except ValueError as e:
        # A typo'd model (JUDGE_MODEL / ACTOR_MODEL / …) is unroutable in provider_for; surface
        # it as the FatalConfigError → exit-2 this function documents (matching run.py's
        # _source_provider_keys) rather than a bare ValueError the drain would dead-letter
        # per-run for a run-independent config fault.
        raise FatalConfigError(str(e)) from e
    key, src = resolve_first_party_key(var=var, root=REPO_ROOT)
    if key:
        os.environ[var] = key
        _log(f"{label}_key: {var} sourced from {src} (overrides ambient)")
        return
    if os.environ.get(var):
        _log(f"{label}_key: no .env key; using the ambient {var}")
        return
    raise FatalConfigError(
        f"the in-process PydanticAI {label} (model {model!r}) needs {var} — set it in "
        "<repo>/.env or $DEFENDER_ENV_FILE (the in-process stage bills the first-party API)."
    )


def curator_agent_env(state_root: Path) -> dict[str, str]:
    """``subscription_env`` with ``DEFENDER_LEARNING_STATE_DIR`` pinned to the
    drain's resolved state root, for spawning a curator ``claude -p`` agent.

    The author drains run in a throwaway ``git worktree`` off ``origin/main``
    (#420/#423), which has no ``runs/``/``_pending/`` (gitignored). The curator
    agent's forward-check verifiers (``verify_forward/*.py``) run as Bash
    subprocesses that re-derive their paths from ``DEFAULT_PATHS`` — i.e. from
    their own worktree ``__file__`` — so under the default in-repo state they
    resolve the (empty) worktree bundle and fail. Pinning the env var here hands
    them the shared state root the same way the off-process worker hands it to a
    separately-spawned renderer (see ``learning_state_root``); a freshly-imported
    verifier then honors it via ``_env_state_dir``. Idempotent under out-of-repo
    state, where ``state_root`` is already the value the parent inherited (#425).
    """
    env = subscription_env()
    env["DEFENDER_LEARNING_STATE_DIR"] = str(state_root)
    return env
