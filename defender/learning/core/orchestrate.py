"""Learning-loop orchestration: dispatch a finished run dir through the actor →
oracle → judge → persist → queue pipeline, per direction, and trigger the curators.

`run_one` takes injectable `paths` (filesystem layout) and `agents` (the subagent
seam), so tests drive it with a `LoopPaths(repo_root=tmp_path)` and a fake `Subagents`
instead of monkeypatching module globals.
"""
from __future__ import annotations

import contextlib
import functools
import importlib
import json
import os
import subprocess
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from collections.abc import Callable

import yaml

from defender._yaml import safe_load
from defender.learning.core.config import (
    ADVERSARIAL_DISPOSITIONS,
    BENIGN_DISPOSITIONS,
    DEFAULT_PATHS,
    ORACLE_MODEL,
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    LoopPaths,
    RunPaths,
    _log,
    env_int,
    merge_mode,
    pitfalls_threshold,
    source_first_party_key,
)
from defender import _git
from defender._git import GitError
from defender._io import write_atomic
from defender.learning.author import shared as _author_shared
from defender.learning.core.directions import BY_NAME, Direction
from defender.learning.author.branch import AuthorBranch, BranchError
from defender.learning.core.persist import (
    DirectionArtifacts,
    append_findings,
    derive_alert_rule_key,
    persist_run,
    read_pitfalls,
)
from defender.learning.tickets.ticket_enrichment import enrich_case_ticket
from defender.learning.core.subagents import InProcessSubagents, Subagents, is_skip_story
from defender.learning.core.validate import (
    normalize_disposition,
    normalize_judge_yaml,
    strip_yaml_fence,
)


# The layer-neutral systemic-fault set: a fault that dooms the whole stage and maps to the
# contracted exit 2, never a per-item dead-letter. Named once so enrolling a future type is
# one edit, not N — both the in-drain dead-letter guard (``_run_or_dead_letter``) and the
# stage boundary (``_run_stage``) must reraise the *same* set, or a fault re-raised past the
# quarantine would still fall through to a bare exit-1 traceback at the boundary.
# ``FatalConfigError``/``GitError`` are enrolled (not subclassed) because the exit-2 response
# is learning-only; see ``_run_or_dead_letter`` for the rationale.
_SYSTEMIC_FAULTS: tuple[type[BaseException], ...] = (StageAbort, FatalConfigError, GitError)


# ---------------------------------------------------------------------------
# Per-step output handling (oracle: strip + write; judge: strip + validate;
# a *.raw.txt companion is written on mutation, or on a judge validation failure)
# ---------------------------------------------------------------------------


def _write_oracle_telemetry(
    oracle_raw: str, learning_run_dir: Path, out_name: str
) -> Path:
    """Strip the oracle YAML envelope and write it for the judge to read.

    There is no validation gate: the doc is assembled by our own code (one projection
    per lead, lead_ids from the join) and the only model-authored content — each lead's
    ``events`` list — is read solely by the LLM judge as text. ``strip_yaml_fence`` is a
    no-op on our own serialized output, kept only to normalize a fenced reply from an
    alternative ``Subagents`` adapter; the ``.raw.txt`` companion records the original if
    stripping ever changes anything.
    """
    stripped = strip_yaml_fence(oracle_raw)
    out_path = learning_run_dir / out_name
    out_path.write_text(stripped, encoding="utf-8")
    if stripped != oracle_raw:
        (learning_run_dir / (Path(out_name).stem + ".raw.txt")).write_text(oracle_raw, encoding="utf-8")
    return out_path


def _validate_judge_yaml(
    judge_raw: str, validate: Callable, raw_path: Path
) -> tuple[dict, str]:
    """Strip + validate judge YAML; on failure/mutation dump the raw to ``raw_path``."""
    stripped = normalize_judge_yaml(judge_raw)
    try:
        doc = validate(safe_load(stripped))
    except (yaml.YAMLError, RunUnprocessable) as e:
        # A nesting flood arrives as YAMLError via the shared seam (#613); dead-letter it
        # like any invalid verdict rather than crash the worker.
        raw_path.write_text(judge_raw, encoding="utf-8")
        raise RunUnprocessable(f"judge YAML invalid: {e}") from e
    if stripped != judge_raw:
        raw_path.write_text(judge_raw, encoding="utf-8")
    return doc, stripped


# ---------------------------------------------------------------------------
# Direction leg
# ---------------------------------------------------------------------------


def run_direction(
    spec: Direction,
    dirs: RunPaths,
    disposition: str,
    alert_rule_key: str,
    run_id: str,
    *,
    paths: LoopPaths,
    agents: Subagents,
) -> bool:
    """One direction: actor → oracle → judge → persist → append.

    Returns True if queue rows were appended (i.e. worth triggering the curators).
    """
    run_dir, learning_run_dir = dirs.run_dir, dirs.learning_run_dir
    assert learning_run_dir is not None, "run_direction requires a learning leg dir"
    _log(f"step=actor ({spec.name})")
    actor_story = spec.invoke_actor(agents, run_dir, learning_run_dir, alert_rule_key)
    # Write the story now so oracle + judge can read it from disk downstream; the
    # later persist_run re-archives the same path (idempotent) and is the only writer
    # on the SKIP short-circuit below.
    actor_story_path = learning_run_dir / spec.story_name
    actor_story_path.write_text(actor_story, encoding="utf-8")

    if is_skip_story(actor_story):
        _log(f"actor emitted SKIP ({spec.name}) — persisting, no findings")
        persist_run(
            dirs,
            artifacts=DirectionArtifacts(
                actor_story=actor_story, story_name=spec.story_name,
                judge_yaml=None, judge_name=spec.judge_name,
                telemetry_yaml=None, telemetry_name=spec.telemetry_name,
            ),
            disposition=disposition, alert_rule_key=alert_rule_key,
        )
        return False

    _log(f"step=oracle ({spec.name})")
    oracle_raw = agents.oracle(run_dir, actor_story_path, learning_run_dir)
    telemetry_path = _write_oracle_telemetry(
        oracle_raw, learning_run_dir, spec.telemetry_name
    )

    judge_raw = agents.judge(
        spec.judge_wiring, run_dir, actor_story_path, telemetry_path, learning_run_dir
    )
    judge_doc, judge_stripped = _validate_judge_yaml(
        judge_raw, spec.validate, learning_run_dir / spec.judge_raw_name
    )

    _log(f"step=persist ({spec.name})")
    persist_run(
        dirs,
        artifacts=DirectionArtifacts(
            actor_story=actor_story, story_name=spec.story_name,
            judge_yaml=judge_stripped, judge_name=spec.judge_name,
            telemetry_yaml=telemetry_path.read_text(encoding="utf-8"), telemetry_name=spec.telemetry_name,
        ),
        disposition=disposition, alert_rule_key=alert_rule_key,
    )

    n_f = append_findings(
        judge_doc, run_id, alert_rule_key, learning_run_dir,
        direction=spec.name, paths=paths,
    )
    n_o = spec.append_observations(
        judge_doc, run_id, alert_rule_key, learning_run_dir, paths=paths
    )
    n_env = 0
    if spec.append_env_observations is not None:
        n_env = spec.append_env_observations(
            judge_doc, run_id, alert_rule_key, learning_run_dir, paths=paths
        )
    _log(
        f"appended {n_f} finding(s), {n_o} observation(s), "
        f"{n_env} env-observation(s) ({spec.name})"
    )
    return True


def _directions_for(disposition: str) -> list[str]:
    """Which learning directions a disposition triggers, in run order.

    ``benign`` → adversarial only (hunt the missed attack); ``malicious`` → benign
    only (hunt the over-escalation); ``inconclusive`` → both.
    """
    directions: list[str] = []
    if disposition in ADVERSARIAL_DISPOSITIONS:
        directions.append("adversarial")
    if disposition in BENIGN_DISPOSITIONS:
        directions.append("benign")
    return directions


# ---------------------------------------------------------------------------
# Curators
# ---------------------------------------------------------------------------


class _LeadAuthorRetry(Exception):
    """A transient, retryable lead-author failure (a swallowed ``SubprocessError``/
    ``OSError`` surfaced by ``_run_curator_module`` as ``rc=None``): the run did not
    complete, so the drain leaves the marker queued for a bounded number of retries
    rather than unlinking it (success) or quarantining it (a hard failure)."""


def _invoke_lead_author(paths: LoopPaths, run_dir: Path) -> None:
    """Catalog/template refinement. Independent of disposition + actor/judge.

    ``paths`` is the batch worktree's layout (``LoopPaths(repo_root=<worktree>)``), so
    the lead author edits + the loop commits in the worktree, not the dev checkout.

    Three per-marker outcomes, signalled to ``_drain_lead_author_markers``:
      * ``rc == 0`` — success; returns normally and the drain unlinks the marker.
      * ``rc not in (0, None)`` (the agent crashed / timed out) — raises ``LeadAuthorError``
        so the drain quarantines the marker to ``failed/``, the same surfacing the scope-gate
        path gets. It is deliberately ``LeadAuthorError`` (a plain ``Exception``, *not* a
        ``StageAbort``): an agent crash dooms only *this* marker, so it must keep quarantining
        even if a future audit adds an ``except StageAbort: raise`` to this drain. The systemic
        ``FatalConfigError`` (a ``ValueError``, **not** a ``StageAbort`` since #468) re-raises to
        exit 2 only because it is named explicitly alongside ``StageAbort`` in
        ``_run_or_dead_letter``'s reraise tuple — a hand-rolled ``except StageAbort`` here would
        *miss* it.
      * ``rc is None`` (a swallowed-transient ``SubprocessError``/``OSError`` from
        ``_run_curator_module`` — the run did not complete) — raises ``_LeadAuthorRetry``
        so the drain leaves the marker queued for a bounded number of retries, then
        quarantines (a persistent pseudo-transient can't retry forever unsurfaced)."""
    from defender.learning.leads.lead_extraction import LeadAuthorError

    _log("step=lead-author")
    rc = _run_curator_module("lead_author", lambda mod: mod.run(run_dir, paths=paths))
    if rc not in (0, None):
        raise LeadAuthorError(f"lead-author for {run_dir.name} returned rc={rc}")
    if rc is None:
        raise _LeadAuthorRetry("lead-author hit a swallowed transient (rc=None)")


def _maybe_trigger_author(
    paths: LoopPaths,
    pending_file: Path,
    threshold_env: str,
    module_name: str,
    pending_label: str,
) -> None:
    """Run the named curator if its pending queue meets the threshold.

    ``paths`` is the batch worktree's layout, so ``run_batch`` resolves its corpus dir
    (and the loop commits) under the worktree while the pending/lock files stay shared."""
    threshold = env_int(threshold_env, 5)
    pending_count = _pending_queue_count(pending_file)
    if pending_count < threshold:
        _log(f"{pending_label}={pending_count} threshold={threshold} — {module_name} not invoked")
        return
    _log(f"step={module_name} {pending_label}={pending_count} threshold={threshold}")
    # hold_committed: the drain commits onto an unmerged PR branch, so curators
    # keep committed findings queued (re-authored if the PR is rejected, filtered
    # by existing_*_ids once merged) rather than rotating them out. See author.py.
    # Thread the drain's own paths so the curator builds its config from the same
    # layout the threshold check above read (no import-time/injected split-brain).
    rc = _run_curator_module(
        module_name, lambda mod: mod.run_batch(hold_committed=True, paths=paths)
    )
    if rc not in (0, None):
        _log(f"{module_name} returned rc={rc} (queue intact, retry next tick)")


# Logical curator name (carried by Direction.module_name + the lead_author trigger,
# kept for log lines) -> its dotted module path after the package reorg.
_CURATOR_MODULES = {
    "lead_author": "defender.learning.leads.lead_author",
    "pitfalls_curator": "defender.learning.leads.pitfalls_curator",
    "author": "defender.learning.author.lessons.run",
    "author_actor": "defender.learning.author.malicious_actor.run",
    "author_actor_benign": "defender.learning.author.benign_actor.run",
    # The adversarial env direction (#298): drains the actor_environment_observations queue into
    # the shared lessons-environment/ corpus via the benign_actor.env entry point. Absent this
    # entry, the _CURATOR_MODULES[module_name] subscript (outside the SubprocessError/OSError try)
    # raised KeyError and wedged the whole drain when the adversarial-env queue hit threshold.
    "author_actor_env": "defender.learning.author.benign_actor.env",
}


def _run_curator_module(module_name: str, call: Callable[[Any], int]):
    """Import a curator from the ``defender.learning`` package by name and run it.

    Narrow swallow for ``lead_author``-style child-process / filesystem hiccups; real
    regressions (ImportError, TypeError, …) propagate so they fail loudly.
    """
    mod = importlib.import_module(_CURATOR_MODULES[module_name])
    try:
        return call(mod)
    except (subprocess.SubprocessError, OSError) as e:
        _log(f"{module_name} crashed: {e!r} (continuing)")
        return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _enqueue_marker(run_dir: Path, queue_dir: Path, label: str) -> None:
    """Drop a ``{run_id}.json`` marker carrying the run dir into ``queue_dir``,
    written atomically (tmp + replace). The marker carries the resolved run dir so
    a drainer running elsewhere (no SIEM creds, ``/tmp`` possibly cleared) can find
    the artifacts or detect a vanished one instead of silently dropping it. Shared
    by the author and learn queues so the two stages can't drift in marker shape."""
    queue_dir.mkdir(parents=True, exist_ok=True)
    marker = queue_dir / f"{run_dir.name}.json"
    write_atomic(
        marker,
        json.dumps({"run_id": run_dir.name, "run_dir": str(run_dir.resolve())}) + "\n",
    )
    _log(f"enqueued for {label}: {marker}")


def _enqueue_for_authoring(run_dir: Path, paths: LoopPaths) -> None:
    """Record this run for the serial author-drainer (lead-author per run dir)."""
    _enqueue_marker(run_dir, paths.author_queue_dir, "authoring")


def enqueue_for_learning(run_dir: Path, paths: LoopPaths = DEFAULT_PATHS) -> None:
    """Record a finished run for the off-process LEARN worker (``loop.py
    --learn-drain``). The worker holds no SIEM creds and may run elsewhere; the
    marker carries the run dir so it can find the artifacts to learn from. Mirror
    of ``_enqueue_for_authoring`` one stage upstream."""
    _enqueue_marker(run_dir, paths.learn_queue_dir, "learning")


def _prepare_engines_for(directions: list[str], *, include_actor: bool = True) -> None:
    """Ready the in-process stages (oracle + judge, and the actor unless excluded) for the
    directions that will run: source their metered keys UP FRONT in the main thread — before the
    direction fan-out AND before the oracle's per-lead fan-out, so there is no ``os.environ`` race
    — and only for the models the directions that will run actually use (the union of each leg's
    oracle + judge + actor model, deduped; sourcing one provider twice is idempotent). Fails loud
    here (→ exit 2) rather than 401-ing mid-stage; the curators run in-process too and source
    their own metered key (see ``source_first_party_key``).

    The oracle + judge are ALWAYS sourced — both run for every non-skip direction, in the learning
    loop and the secondary harness alike. ``include_actor=False`` skips only the actor model, for
    an ACTOR-FROZEN consumer (the secondary harness, whose story is generated in its own frozen
    subprocess). Requiring the actor provider's key there would be a phantom dependency: a
    Sonnet-judge secondary run would fail loud for a Fireworks key the actor never uses in that
    process."""
    models: set[str] = {ORACLE_MODEL} if directions else set()
    for name in directions:
        d = BY_NAME[name]
        models.add(d.judge_wiring.model)
        if include_actor:
            models.add(d.actor_model)
    for model in models:
        source_first_party_key(model, label="engine")


def run_one(
    run_dir: Path,
    *,
    paths: LoopPaths = DEFAULT_PATHS,
    agents: Subagents | None = None,
) -> int:
    """LEARN stage: produce findings/observations into the queue + enqueue the
    run for authoring. Does **not** author or commit — that is ``author_drain``.
    Safe to run concurrently across processes (each direction leg serializes its
    shared queue writes on a flock)."""
    if agents is None:
        agents = InProcessSubagents()

    run_id = run_dir.name
    _log(f"run_id={run_id} step=normalize")
    src = RunPaths(run_dir)
    disposition = normalize_disposition(src.report)
    directions = _directions_for(disposition)
    _prepare_engines_for(directions)

    alert = json.loads(src.alert.read_text(encoding="utf-8"))
    alert_rule_key = derive_alert_rule_key(alert)
    learning_run_dir = paths.runs_dir / run_id
    learning_run_dir.mkdir(parents=True, exist_ok=True)
    _log(
        f"step=dispatch disposition={disposition} directions={directions} "
        f"alert_rule_key={alert_rule_key}"
    )

    # The direction legs are mutually independent: each writes disjoint
    # per-direction files (story/telemetry/judge outputs by `spec.*_name`, and the
    # judge's comparison dir under the wiring's per-direction name — see
    # `_loop_subagents.build_judge_invocation`) and serializes shared
    # findings/observation writes on a flock (cross-process safe). subprocess.run
    # releases the GIL while the claude child runs, so threads give real wall-time
    # overlap. Within a leg, actor→oracle→judge stays serial.
    dirs = RunPaths(run_dir, learning_run_dir)
    errors: list[tuple[str, BaseException]] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures: dict[Any, str] = {}
        for name in directions:
            futures[pool.submit(
                run_direction, BY_NAME[name], dirs,
                disposition, alert_rule_key, run_id,
                paths=paths, agents=agents,
            )] = name
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                fut.result()
            except Exception as e:  # re-raised after all legs settle (fail loud)
                errors.append((name, e))

    # Stamp the case-history ticket's seed-eligibility flag from the adversarial
    # verdict (issue #317 read path). Benign-disposed cases only — they are the
    # benign seed sampler's only candidates — and only when the adversarial leg
    # actually produced a verdict (it always runs for `benign`). Non-fatal: the
    # enricher swallows its own failures, never converting a clean learn into a
    # failed one. Runs once per case (the legs have all settled here).
    adversarial_ok = "adversarial" in directions and not any(
        name == "adversarial" for name, _ in errors
    )
    if disposition == "benign" and adversarial_ok:
        enrich_case_ticket(run_dir, learning_run_dir)

    # Hand the run to the serial author-drainer regardless of leg outcome —
    # lead-author refines the query catalog (independent of the legs) and any
    # findings a surviving leg already appended still need draining. Commits
    # happen there, never here. Enqueue *before* failing loud so a single failed
    # leg doesn't strand the run with no author-work marker.
    _enqueue_for_authoring(run_dir, paths)

    if errors:
        for name, exc in errors:
            _log(f"{name} leg failed: {exc!r}")
        raise errors[0][1]

    if not directions:
        _log(f"disposition={disposition} — no learning direction; findings queue untouched")
    return 0


# ---------------------------------------------------------------------------
# Author stage — serial drainer (the only stage that commits)
# ---------------------------------------------------------------------------


def _rewrite_marker(marker: Path, spec: dict) -> None:
    """Rewrite a queue marker in place, atomically (tmp + replace) — same write shape as
    ``_enqueue_marker`` — so bumping the transient-retry counter never leaves a window
    where the marker is missing (a concurrent drainer would otherwise see it vanish)."""
    write_atomic(marker, json.dumps(spec) + "\n")


def _quarantine_marker(spec: dict, marker: Path, queue_dir: Path, reason: str) -> None:
    """Move a marker we can't process to ``<queue_dir>/failed/`` — surfaced for a
    human, not silently dropped, and (crucially) not left to re-poison the queue
    on every subsequent drain tick. ``queue_dir`` is the queue the marker came
    from (author-queue or learn-queue), so each stage quarantines under its own."""
    failed_dir = queue_dir / "failed"
    failed_dir.mkdir(parents=True, exist_ok=True)
    rec = dict(spec)
    rec["failed"] = reason
    (failed_dir / marker.name).write_text(json.dumps(rec) + "\n", encoding="utf-8")
    with contextlib.suppress(OSError):
        marker.unlink()
    _log(f"quarantined {spec.get('run_id')} — {reason}")


def _run_or_dead_letter(
    fn: Callable[[], object],
    on_dead_letter: Callable[[Exception], None],
    *,
    propagate: tuple[type[BaseException], ...] = (),
) -> bool:
    """Run ``fn`` under the author drains' dead-letter contract; return ``True`` on
    success, ``False`` if it was dead-lettered.

    This is the **one** place the systemic-vs-quarantine invariant lives, so a drain
    can't hand-roll a broad ``except Exception`` that silently swallows a systemic
    fault (the #438 regression):

      * ``StageAbort`` is **always re-raised** — a systemic fault must reach
        ``_run_stage`` as the contracted ``exit 2`` rather than being mislabeled as
        a per-item failure. (It can't be caught in an outer wrapper instead: the
        broad guard below is *inside* the drain, so an outer ``except`` can never
        recatch what this one already swallowed.) Catching the ``StageAbort`` base
        keeps any future learning-internal systemic-fault type re-raising here for
        free (#443/#445).
      * ``FatalConfigError`` and ``GitError`` are re-raised **alongside** ``StageAbort``.
        Both are layer-neutral *conditions* shared with other layers (``defender._env`` /
        ``defender._git``), enrolled here rather than subclassed because the exit-2
        *response* is learning-only — so they must be named explicitly, not inherited via
        ``StageAbort``. ``GitError`` is a failed local-state git op (status/commit/worktree)
        — a broken tree that dooms the whole batch, not one marker — so it fails loud (exit
        2), not a silent dead-letter quarantine. The remote/forge retry lane
        (``branch.py`` push + ``Forge`` → ``BranchError``) is caught separately and is *not*
        in this set.
      * any type in ``propagate`` is re-raised too — drain-specific control flow
        (e.g. ``_LeadAuthorRetry``'s bounded retry) that the caller handles itself;
        it is *not* a dead-letter and must escape this guard.
      * every other ``Exception`` is dead-lettered: ``on_dead_letter(e)`` is invoked
        (quarantine the marker, or just log for a marker-less phase) and the drain
        keeps going. ``RunUnprocessable`` per-run *data* failures land here and
        quarantine, exactly as before — only the systemic family is special.

    A new drain that routes its swallow site through this helper is systemic-fault-safe
    for free; one that hand-rolls ``except Exception`` is the visible odd-one-out.
    """
    reraise: tuple[type[BaseException], ...] = (*_SYSTEMIC_FAULTS, *propagate)
    try:
        fn()
    except reraise:
        raise
    except Exception as e:  # noqa: BLE001 — the sole dead-letter guard for the drains
        on_dead_letter(e)
        return False
    return True


def _curator_queue_checks(paths: LoopPaths) -> list[tuple[Path, str]]:
    """The (pending_file, threshold_env) pairs the three curators drain."""
    checks = [(paths.pending_file, "LEARNING_AUTHOR_THRESHOLD")]
    for direction in BY_NAME.values():
        for t in (direction.obs_trigger, *direction.extra_obs_triggers):
            checks.append((t.pending_file(paths), t.threshold_env))
    return checks


def _pending_queue_count(pending_file: Path) -> int:
    """Count of non-blank lines in a pending-queue file (0 if it doesn't exist).

    The shared 'how full is this queue' primitive for the line-oriented curator
    queues — the wake gate (``_has_curator_work``) and the per-queue trigger
    (``_maybe_trigger_author``) read the same count against the same
    ``env_int(<ENV>, 5)`` threshold, so they can't disagree about whether a queue
    is at threshold."""
    if not pending_file.is_file():
        return 0
    return sum(1 for line in pending_file.read_text(encoding="utf-8").splitlines() if line.strip())


def _has_curator_work(paths: LoopPaths) -> bool:
    """Whether the lessons drain would do anything — any findings/observation curator
    queue at threshold. Lets the drain skip creating a worktree on empty ticks."""
    return any(
        _pending_queue_count(pending_file) >= env_int(env, 5)
        for pending_file, env in _curator_queue_checks(paths)
    )


def _has_lead_author_work(paths: LoopPaths) -> bool:
    """Whether the lead-author drain would do anything: a run dir queued for
    catalog/skill curation, OR the cross-run pitfalls queue at its curation
    threshold. Lets the drain skip creating a worktree on empty ticks — but still
    fire on a markers-empty tick once enough general failures have accumulated."""
    # Read the pitfalls threshold up front (before the markers short-circuit) so a
    # non-numeric override fails loud here — outside any try/except — as the contracted
    # exit 2. Deferring it to the markers-empty branch would let a bad value surface only
    # deep inside run_pitfalls, where _drain_pitfalls's `except Exception` swallows it
    # (exit 0, not exit 2). See #435.
    threshold = pitfalls_threshold()
    qdir = paths.author_queue_dir
    if qdir.is_dir() and any(qdir.glob("*.json")):
        return True
    # Count parsed rows (not raw lines) against the curator's own threshold, so the
    # wake gate can't disagree with run_pitfalls — a malformed/partial line that
    # read_pitfalls drops must not wake the drain to a no-op (worktree churn).
    return len(read_pitfalls(paths)) >= threshold


def _drain_curators(
    paths: LoopPaths,
    trigger_author: Callable[[LoopPaths, Path, str, str, str], None],
) -> None:
    """The lessons drain's work: the threshold-gated findings/observation curators,
    committing in ``paths.repo_root`` (a batch worktree). The lead author is NOT here
    — it has its own drain (``lead_author_drain``)."""
    trigger_author(paths, paths.pending_file, "LEARNING_AUTHOR_THRESHOLD", "author", "pending")
    for direction in BY_NAME.values():
        for t in (direction.obs_trigger, *direction.extra_obs_triggers):
            trigger_author(
                paths, t.pending_file(paths), t.threshold_env, t.module_name, t.pending_label
            )


def _discard_worktree_changes(repo_root: Path) -> None:
    """Discard every uncommitted change in the batch worktree so one marker's leftover
    edits can't leak into the next (the lead-author batch shares a single worktree across
    all its markers). A marker that succeeded already committed its corpus delta, so this
    is a no-op for it; a marker that failed the scope gate (quarantined) or exited
    non-zero leaves uncommitted edits that — left in place — would either be swept into
    the next marker's pathspec commit or falsely trip its scope gate. Safe because the
    worktree is throwaway and committed markers persist in HEAD; ``clean -fd`` (no ``-x``)
    leaves gitignored state (e.g. ``runs/``) untouched. Best-effort: a missing worktree
    (the fake-branch test path has no real checkout) or a git error is suppressed."""
    if not (repo_root / ".git").exists():
        return  # no real worktree here (e.g. the _FakeBranch test path) — nothing to reset
    for args in (["reset", "--hard", "--quiet"], ["clean", "-fdq"]):
        _git.git(args, cwd=repo_root, check=False)


def _quarantine_lead_author_failure(
    spec: dict, marker: Path, queue_dir: Path, e: Exception
) -> None:
    """The lead-author drain's dead-letter action: quarantine the marker with a
    lead-author-error reason. Bound (via ``functools.partial``) to the per-marker
    spec/marker so it satisfies ``_run_or_dead_letter``'s ``Callable[[Exception], None]``."""
    _quarantine_marker(spec, marker, queue_dir, f"lead-author-error: {e!r}")


def _drain_lead_author_markers(
    paths: LoopPaths,
    run_lead_author: Callable[[LoopPaths, Path], None],
) -> None:
    """The lead-author drain's work: lead-author each queued run dir, committing in
    ``paths.repo_root`` (a batch worktree). The queue + quarantine dir resolve off the
    shared state root, so markers are drained from (and quarantined to) the original
    location, not the throwaway worktree.

    The batch worktree is shared across markers, so after each marker we discard any
    uncommitted leftovers (``_discard_worktree_changes``) — a failed/quarantined marker
    must not contaminate the next one's commit or gate.

    Three per-marker outcomes (see ``_invoke_lead_author``): success unlinks the marker; a
    hard failure quarantines it; a transient (``_LeadAuthorRetry``) leaves it queued with a
    bumped attempt count, and is quarantined only once it has burned ``LEAD_AUTHOR_MAX_RETRIES``
    attempts — so a genuine blip self-heals but a persistent pseudo-transient still surfaces."""
    qdir = paths.author_queue_dir
    markers = sorted(qdir.glob("*.json")) if qdir.is_dir() else []
    max_retries = env_int("LEAD_AUTHOR_MAX_RETRIES", 3)
    _log(f"lead_author_drain: {len(markers)} run(s) queued for lead-author")
    for marker in markers:
        try:
            spec = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            _log(f"lead_author_drain: unreadable marker {marker.name}: {e!r}; skipping")
            continue
        run_dir = Path(spec.get("run_dir", ""))
        if not run_dir.is_dir():
            _quarantine_marker(spec, marker, paths.author_queue_dir, "artifact-missing")
            continue
        try:
            # The dead-letter contract (re-raise StageAbort -> exit 2; quarantine any
            # other poison run dir so it can't wedge the serial drain or re-crash every
            # tick) lives in _run_or_dead_letter. A systemic fault here — e.g. a non-numeric
            # LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD read deep inside run() -> _prepare_handoffs,
            # surfaced as FatalConfigError (the layer-neutral misconfig condition — a ValueError,
            # enrolled alongside StageAbort in _run_or_dead_letter's reraise tuple, not a subclass
            # of it since #468) — dooms every marker, so the
            # primitive propagates it past the broad quarantine guard to the contracted
            # exit 2. _LeadAuthorRetry is drain-specific control flow, not a dead-letter, so
            # it's propagated out and handled below. (functools.partial binds run_dir/spec/marker
            # eagerly, so each call closes over *this* iteration's values, not the loop's last.)
            drained = _run_or_dead_letter(
                functools.partial(run_lead_author, paths, run_dir),
                functools.partial(
                    _quarantine_lead_author_failure, spec, marker, paths.author_queue_dir
                ),
                propagate=(_LeadAuthorRetry,),
            )
        except _LeadAuthorRetry as e:
            # Transient (rc=None): the run did not complete. Leave the marker queued for a
            # bounded number of retries — the attempt count rides in the marker, so it
            # survives ticks and process restarts — then quarantine, so a persistent
            # pseudo-transient can't retry forever unsurfaced.
            attempts = int(spec.get("attempts", 0)) + 1
            if attempts >= max_retries:
                _quarantine_marker(
                    spec, marker, paths.author_queue_dir,
                    f"transient-exhausted after {attempts} attempt(s): {e!r}",
                )
            else:
                spec["attempts"] = attempts
                _rewrite_marker(marker, spec)
                _log(
                    f"lead_author_drain: transient on {spec.get('run_id')} "
                    f"(attempt {attempts}/{max_retries}) — left queued for retry"
                )
            continue
        finally:
            # Always leave the shared worktree clean for the next marker — committed work
            # survives, uncommitted leftovers (a quarantined or rc!=0 marker) are dropped.
            _discard_worktree_changes(paths.repo_root)
        if drained:
            with contextlib.suppress(OSError):
                marker.unlink()


def _invoke_pitfalls(paths: LoopPaths) -> int:
    """Run the cross-run execution.md pitfalls curation mode (pitfalls_curator.run_pitfalls),
    committing in the batch worktree (``paths.repo_root``). The pitfalls queue resolves
    off the shared state root, so it is drained from the original location."""
    _log("step=pitfalls-curation")
    rc = _run_curator_module("pitfalls_curator", lambda mod: mod.run_pitfalls(paths=paths))
    return rc if rc is not None else 0


def _drain_pitfalls(
    paths: LoopPaths,
    run_pitfalls: Callable[[LoopPaths], int],
) -> None:
    """The pitfalls curation phase of the lead-author drain: fold queued general
    failures into per-system ``execution.md`` (once per drain; ``run_pitfalls`` is
    cross-run + threshold-gated internally). A curation hiccup must not wedge the
    drain, so a curation error is logged and swallowed (a systemic ``StageAbort`` still
    propagates to the contracted exit 2 — see the body); the shared worktree is then left
    clean (a successful run already committed, so this is a no-op for it; a mid-edit
    failure has its uncommitted edits discarded) and the queue stays intact for retry."""
    try:
        # Dead-letter contract via the shared primitive (re-raise StageAbort -> exit 2,
        # swallow the rest). There's no marker here — pitfalls is a queue-file curation — so
        # the dead-letter action just logs; the finally discards any mid-edit leftovers.
        # The StageAbort re-raise is defense-in-depth, no current trigger: the only fatal
        # config run_pitfalls reads (the pitfalls threshold) is already validated up front at
        # the _has_lead_author_work wake gate (#437), so a bad value aborts before this runs.
        # It guards any *future* systemic fault added inside run_pitfalls from being swallowed
        # (exit 0).
        _run_or_dead_letter(
            lambda: run_pitfalls(paths),
            lambda e: _log(f"lead_author_drain: pitfalls curation error: {e!r}; discarding edits"),
        )
    finally:
        _discard_worktree_changes(paths.repo_root)


def _drain_lead_author(
    paths: LoopPaths,
    run_lead_author: Callable[[LoopPaths, Path], None],
    run_pitfalls: Callable[[LoopPaths], int],
) -> None:
    """The lead-author drain's full work: per-run catalog/skill curation for each
    queued marker, then the cross-run ``execution.md`` pitfalls curation. Both commit
    into the same shared worktree and ride the one ``lead-author/`` PR."""
    _drain_lead_author_markers(paths, run_lead_author)
    _drain_pitfalls(paths, run_pitfalls)


def _validate_merge_mode() -> None:
    """Fail fast on a bad ``LEARNING_MERGE_MODE`` at drain entry, before any curation
    work. ``merge_mode()`` reads + validates against ``VALID_MERGE_MODES`` at call
    time (not config import) so an author-only misconfig fails loud for the drains
    without crashing the LEARN / run_one importers that never merge; the raised
    ``FatalConfigError`` is enrolled alongside ``StageAbort``, so main() maps it→rc 2."""
    merge_mode()


def _run_worktree_batch(
    paths: LoopPaths,
    branch: AuthorBranch,
    *,
    label: str,
    has_work: Callable[[LoopPaths], bool],
    do_work: Callable[[LoopPaths], None],
) -> int:
    """Shared worktree-batch envelope for an author drain.

    Writer lease → ``start_batch`` (fresh worktree off ``origin/main``) → run the
    drain's work rooted at the worktree → ``finish_batch`` (push + one PR) → always
    ``cleanup`` the worktree. The dev checkout is never touched, so two drains never
    race on a shared HEAD and a failed cleanup can't strand anyone."""
    if not has_work(paths):
        _log(f"{label}: nothing queued and no curator at threshold — skipping")
        return 0

    # Writer lease (§4.4): at most one open PR per branch-prefix, so we never form a
    # second divergent branch. Under human_review the lease spans the whole review window.
    try:
        if branch.open_pr_exists():
            _log(f"{label}: an open {branch.branch_prefix} PR holds the writer lease — skipping")
            return 0
        batch_id = uuid.uuid4().hex[:12]
        wt = branch.start_batch(batch_id)
    except BranchError as e:
        _log(f"{label}: cannot start batch worktree: {e} — skipping")
        return 0

    # Re-root the layout at the worktree: corpus/catalog dirs move there (where the
    # curator edits + the loop commits) while queues/locks/pending stay shared.
    wt_paths = paths.with_repo_root(wt)
    pr = None
    try:
        do_work(wt_paths)
        try:
            pr = branch.finish_batch(batch_id, wt)
        except BranchError as e:
            # push / `gh pr create` failed (auth, network, branch already on origin).
            # Work was held (hold_committed) / re-authored next tick — don't crash the
            # drainer (BranchError is not a StageAbort, so main() would not catch it).
            _log(f"{label}: finish_batch failed: {e} — work stays queued, retry next tick")
    finally:
        # Always remove the batch worktree. Unlike the old in-place restore, a failed
        # cleanup is harmless: the dev checkout was never moved, and the next batch's
        # `worktree prune` clears a stale registration.
        with contextlib.suppress(Exception):
            branch.cleanup(wt)

    if pr is None:
        _log(f"{label}: batch produced no commits — no PR opened")
        return 0
    _log(f"{label}: opened PR {pr}")
    if merge_mode() == "auto_on_green":
        # PR C wires the green bar + `gh pr merge --auto` here; until then the PR
        # falls through to human review even under auto_on_green.
        _log(f"{label}: merge_mode=auto_on_green — green-bar auto-merge not yet "
             "wired (PR C); leaving PR for review")
    return 0


def _lead_author_pr_title(batch_id: str) -> str:
    return f"learning: lead-author catalog/skill batch {batch_id}"


def _lead_author_pr_body(branch: str) -> str:
    return (
        "Automated gather-catalog / system-skill curation from the lead-author drain "
        f"(branch `{branch}`, off freshly-fetched `origin/main`). May also fold "
        "agent-fixable execution failures into per-system `execution.md` "
        "`## Common pitfalls`. Touches `defender/skills/` only — distinct from the "
        "lessons PR."
    )


def author_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    trigger_author: Callable[[LoopPaths, Path, str, str, str], None] | None = None,
    branch: AuthorBranch | None = None,
) -> int:
    """Lessons AUTHOR stage: in a fresh ``lessons/<id>`` worktree off freshly-fetched
    ``origin/main``, drain the threshold-gated findings/observation curators (committing
    in the worktree), then push and open one ``lessons/`` PR. The lead author is no
    longer part of this drain — it has its own (``lead_author_drain``).

    The **per-prefix writer lease** (one open ``lessons/`` PR at a time) plus the
    per-batch worktree keep batches non-conflicting; ``merge_mode`` (default
    ``human_review``) decides whether the PR auto-merges on a green bar (PR C).

    One live drainer at a time, guarded by a non-blocking flock on a dedicated lock
    (``author_drain_lock_file``). A second drainer that can't grab it exits.
    ``trigger_author`` / ``branch`` are injectable for tests."""
    _validate_merge_mode()
    if trigger_author is None:
        trigger_author = _maybe_trigger_author
    if branch is None:
        branch = AuthorBranch(repo_root=paths.repo_root)

    with _author_shared.flock_or_skip(paths.author_drain_lock_file) as locked:
        if not locked:
            _log("author_drain: another drainer holds the lock — exiting")
            return 0
        return _run_worktree_batch(
            paths, branch, label="author_drain",
            has_work=_has_curator_work,
            do_work=lambda wt_paths: _drain_curators(wt_paths, trigger_author),
        )


def lead_author_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    run_lead_author: Callable[[LoopPaths, Path], None] | None = None,
    run_pitfalls: Callable[[LoopPaths], int] | None = None,
    branch: AuthorBranch | None = None,
) -> int:
    """Lead-author AUTHOR stage: in a fresh ``lead-author/<id>`` worktree off
    freshly-fetched ``origin/main``, curate the gather query-template catalog +
    system-skill surface for each queued run dir (the loop commits each in the
    worktree), then push and open one ``lead-author/`` PR — separate from the lessons
    PR (different dirs `defender/skills/` vs `defender/lessons/`, different merge
    concerns).

    Its own non-blocking lock (``lead_author_drain_lock_file``) makes it independently
    schedulable from the lessons ``author_drain``; per-author worktrees mean the two
    never share a HEAD, so no cross-drain lock is needed. ``run_lead_author`` /
    ``branch`` are injectable for tests."""
    _validate_merge_mode()
    if run_lead_author is None:
        run_lead_author = _invoke_lead_author
    if run_pitfalls is None:
        run_pitfalls = _invoke_pitfalls
    if branch is None:
        branch = AuthorBranch(
            repo_root=paths.repo_root,
            branch_prefix="lead-author/",
            pr_title=_lead_author_pr_title,
            pr_body=_lead_author_pr_body,
        )

    with _author_shared.flock_or_skip(paths.lead_author_drain_lock_file) as locked:
        if not locked:
            _log("lead_author_drain: another drainer holds the lock — exiting")
            return 0
        return _run_worktree_batch(
            paths, branch, label="lead_author_drain",
            has_work=_has_lead_author_work,
            do_work=lambda wt_paths: _drain_lead_author(
                wt_paths, run_lead_author, run_pitfalls
            ),
        )


# ---------------------------------------------------------------------------
# Learn stage — off-process worker (concurrent; SIEM-free)
# ---------------------------------------------------------------------------


def _render_transcript(run_dir: Path) -> None:
    """Re-render run_dir's transcript.html (+ run-visualizations mirror) now that
    the judge artifacts exist, by calling ``visualize_run.render_and_mirror`` in
    process — no per-run interpreter spawn, and a render error surfaces as a
    catchable exception. Any failure propagates to ``learn_drain``, which logs it
    and drains on (the render is best-effort, never fatal)."""
    from defender.scripts.visualize.visualize_run import render_and_mirror

    render_and_mirror(run_dir)


def _process_marker(
    marker: Path,
    inflight_dir: Path,
    qdir: Path,
    run_one_fn: Callable[[Path], int],
    render: Callable[[Path], None],
) -> bool:
    """Claim and process one learn-queue marker. Returns True if the run was
    drained (counts toward the drained total), False if it was skipped (lost the
    claim race) or quarantined. Each marker is claimed by an atomic rename into
    ``inflight/`` before processing, so two workers never run the same run dir
    (the loser's ``os.replace`` raises ``FileNotFoundError`` and it moves on)."""
    claimed = inflight_dir / marker.name
    try:
        os.replace(marker, claimed)
    except FileNotFoundError:
        return False  # another worker claimed it first
    try:
        spec = json.loads(claimed.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _quarantine_marker({"run_id": marker.stem}, claimed, qdir, f"unreadable: {e!r}")
        return False
    run_dir = Path(spec.get("run_dir", ""))
    if not run_dir.is_dir():
        _quarantine_marker(spec, claimed, qdir, "artifact-missing")
        return False
    try:
        run_one_fn(run_dir)
    except Exception as e:  # noqa: BLE001 — one poison run must not wedge the worker
        # NB asymmetry vs. the lead-author drain: this guard is deliberately hand-rolled and
        # does NOT route through _run_or_dead_letter — i.e. it has no `except StageAbort: raise`.
        # run_one reads no operator config, so nothing systemic (no FatalConfigError, no
        # StageAbort) reaches here; its failures are RunUnprocessable — per-run *data* failures
        # (malformed report.md / judge YAML, missing keys — ~30 sites in core/validate.py) that
        # MUST keep quarantining. Routing through the primitive would be behavior-neutral *today*
        # (the StageAbort re-raise it adds would fire on a fault that never arrives), but the
        # absence is the point: this is the one swallow site whose disposition is "quarantine
        # everything," and a future audit must not "fix" a StageAbort/RunUnprocessable re-raise
        # in — a RunUnprocessable re-raise would turn every corrupt-data run into a worker-killing
        # exit 2. See #442/#443.
        _quarantine_marker(spec, claimed, qdir, f"run-one-error: {e!r}")
        return False
    try:
        render(run_dir)
    except Exception as e:  # noqa: BLE001 — render is best-effort
        _log(f"learn_drain: render failed for {run_dir.name}: {e!r} (continuing)")
    with contextlib.suppress(OSError):
        claimed.unlink()
    return True


def learn_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    run_one_fn: Callable[[Path], int] | None = None,
    render: Callable[[Path], None] | None = None,
) -> int:
    """Off-process LEARN worker: drain the learn-queue, running actor → oracle →
    judge (``run_one``) per finished run and re-rendering its transcript so the
    judge page lands. SIEM-free — holds none of the creds the investigation
    carried.

    Concurrency-safe across workers **without** a one-at-a-time lock: each marker
    is claimed by an atomic rename into ``learn-queue/inflight/`` before
    processing, so two workers never run the same run dir (the loser's
    ``os.replace`` raises ``FileNotFoundError`` and it moves on). Learning stays
    concurrent (§4.3); the author drain is the only serial stage. A worker that
    dies mid-``run_one`` leaves its marker in ``inflight/`` — surfaced, not lost
    (a stale-inflight reaper is a follow-up, not MVP). ``run_one_fn`` / ``render``
    are injectable for tests."""
    if run_one_fn is None:
        # Thread the drain's own paths into the default LEARN stage, so the queue
        # and the findings/runs/author-queue it writes resolve to one state dir.
        def run_one_fn(rd: Path) -> int:
            return run_one(rd, paths=paths)
    if render is None:
        render = _render_transcript

    qdir = paths.learn_queue_dir
    markers = sorted(qdir.glob("*.json")) if qdir.is_dir() else []
    _log(f"learn_drain: {len(markers)} run(s) queued for learning")
    inflight_dir = qdir / "inflight"
    if markers:
        inflight_dir.mkdir(parents=True, exist_ok=True)
    drained = 0
    for marker in markers:
        if _process_marker(marker, inflight_dir, qdir, run_one_fn, render):
            drained += 1
    _log(f"learn_drain: drained {drained} run(s)")
    return 0


_HELP_EPILOG = """\
Direction dispatch (by the defender's normalized disposition):
  benign        → adversarial direction only (hunt the missed attack / FN)
  malicious     → benign direction only      (hunt the over-escalation / FP)
  inconclusive  → both directions
A disposition that maps to no direction is skipped.

Inputs (must exist in <run_dir>):
  alert.json                 verbatim alert input
  report.md                  YAML frontmatter with disposition ∈ {benign, inconclusive, malicious}
  investigation.md           defender's invlang audit log
  executed_queries.jsonl     the queries table (FK lead_id) — written live by record_query.py
  gather_raw/{lead_id}.lead.json   the leads table — written live by record_lead.py
  gather_raw/{lead_id}/{seq}.json  raw query payloads (by-ref)
  (joined via defender/learning/lead_repository.py)

Outputs:
  defender/learning/runs/<run_id>/
    actor_input.yaml               adversarial actor-facing projection (queries only)
    actor_story.md / *_benign.md   per-direction story (or "SKIP: ...")
    projected_telemetry[_benign].yaml  per-lead oracle output: projections (one per lead)
    projected_telemetry[_benign].raw.txt  assembled oracle doc, pre-strip (only on mutation)
    judge_findings[_benign].yaml   judge classification + queueable findings
  defender/learning/_pending/findings.jsonl
    appended queueable defender findings (both directions, tagged `direction`);
    when count >= LEARNING_AUTHOR_THRESHOLD the lessons curator (author.py) runs.
  defender/learning/_pending/actor_observations.jsonl   (adversarial direction)
    when count >= LEARNING_AUTHOR_ACTOR_THRESHOLD, author_actor.py runs.
  defender/learning/_pending/environment_observations.jsonl   (benign/FP direction)
    when count >= LEARNING_AUTHOR_ENV_THRESHOLD, author_actor_benign.py runs.
  defender/learning/_pending/actor_environment_observations.jsonl  (adversarial direction, #298)
    adversarial env facts → the SHARED lessons-environment/ corpus; when count >=
    LEARNING_AUTHOR_ACTOR_ENV_THRESHOLD, author_actor_env.py runs.

Environment:
  ACTOR_MODEL / BENIGN_ACTOR_MODEL     claude model for the adversarial / benign actor
  ORACLE_MODEL                         per-lead telemetry oracle model (default: glm-5.2;
                                       needs FIREWORKS_API_KEY — the oracle runs in-process)
  ORACLE_EFFORT                        oracle reasoning effort (default: none — reasoning
                                       DISABLED; the mechanical per-lead projection needs none)
  ORACLE_MAX_CONCURRENCY               max concurrent per-lead oracle calls (default: 8)
  JUDGE_EFFORT / BENIGN_JUDGE_EFFORT   judge reasoning effort (default: medium)
  JUDGE_MODEL / BENIGN_JUDGE_MODEL     adversarial / benign judge model (default: glm-5.2;
                                       needs FIREWORKS_API_KEY — the judge runs in-process)
  LEARNING_SUBAGENT_TIMEOUT_SECONDS    per-subagent timeout (default: 450)
  LEARNING_AUTHOR_THRESHOLD            pending findings before author runs (default: 5)
  LEARNING_AUTHOR_ACTOR_THRESHOLD      pending actor observations before author_actor runs
  LEARNING_AUTHOR_ENV_THRESHOLD        pending FP env observations before author_actor_benign runs
  LEARNING_AUTHOR_ACTOR_ENV_THRESHOLD  pending adversarial env observations before author_actor_env runs (#298)

Typical use (off-process): `defender/run.py` enqueues a learn-queue marker per finished
run; a SIEM-free worker drains it with `python3 defender/learning/loop.py --learn-drain`
(running this LEARN stage + re-rendering each transcript). `python3
defender/learning/loop.py <run_dir>` runs LEARN directly for a single run (re-processing).

Exit codes: 0 success / 0 skipped (no direction, or actor SKIP) / 2 StageAbort (systemic
fault — fix the deployment) / 2 RunUnprocessable on a direct single run (bad run data) /
1 usage. On a drain, a RunUnprocessable is a bug (the per-item guards should have caught
it), so it propagates uncaught rather than masquerading as a clean exit 2.
"""


def _run_stage(stage: Callable[[], int], *, allow_run_error: bool = False) -> int:
    """Run one stage entrypoint, mapping a systemic fault to the FATAL exit-2 contract.

    A ``StageAbort`` (the learning systemic-fault base) or a ``FatalConfigError`` (the
    layer-neutral misconfig condition from ``defender._env``, enrolled alongside it)
    always maps to exit 2 — the whole stage is doomed. A ``RunUnprocessable``
    (this-run's-data-is-bad) is handled by ``allow_run_error``:

    * The **direct single-run** path (``loop.py <run_dir>``) passes ``allow_run_error=True``:
      there is no queue to quarantine into, so a bad run maps to the contracted exit 2.
    * The **drain** paths pass it as False (the default). A ``RunUnprocessable`` reaching a
      drain's boundary did *not* pass the per-item quarantine guard — it is a bug, not a
      clean abort — so it propagates uncaught (a loud exit-1 + traceback) rather than
      masquerading as exit 2. This is the #443 structural guard: the per-run type can no
      longer be silently read as a stage-kill.
    """
    try:
        return stage()
    except _SYSTEMIC_FAULTS as e:
        print(f"[loop] FATAL: {e}", file=sys.stderr)
        return 2
    except RunUnprocessable as e:
        if not allow_run_error:
            raise
        print(f"[loop] FATAL: unprocessable run: {e}", file=sys.stderr)
        return 2


def main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="defender/learning/loop.py",
        description=(
            "Defender learning-loop orchestrator. Given a finished defender run dir, "
            "runs actor → oracle → judge, persists artifacts under "
            "defender/learning/runs/<run_id>/, and queues findings for the curators."
        ),
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "run_dir", type=Path, nargs="?",
        help="Defender run dir (LEARN stage: produce findings + enqueue for authoring)",
    )
    parser.add_argument(
        "--author-drain", action="store_true",
        help="LESSONS AUTHOR stage: in a fresh lessons/ worktree, drain the "
             "findings/observation curator queues and open one lessons PR "
             "(takes no run_dir; one drainer at a time).",
    )
    parser.add_argument(
        "--lead-author-drain", action="store_true",
        help="LEAD-AUTHOR stage: in a fresh lead-author/ worktree, curate the gather "
             "catalog + system skills for each queued run dir and open one lead-author "
             "PR (separate from the lessons PR; takes no run_dir; one drainer at a time).",
    )
    parser.add_argument(
        "--learn-drain", action="store_true",
        help="LEARN stage (off-process worker): drain the learn-queue, running "
             "actor → oracle → judge per finished run + re-rendering its transcript "
             "(takes no run_dir; SIEM-free, safe to run concurrently).",
    )
    ns = parser.parse_args(argv[1:])

    drain_flags = sum((ns.author_drain, ns.lead_author_drain, ns.learn_drain))
    if drain_flags > 1:
        print("--author-drain, --lead-author-drain, and --learn-drain are mutually "
              "exclusive", file=sys.stderr)
        return 1

    if ns.author_drain:
        if ns.run_dir is not None:
            print("--author-drain takes no run_dir", file=sys.stderr)
            return 1
        return _run_stage(author_drain)

    if ns.lead_author_drain:
        if ns.run_dir is not None:
            print("--lead-author-drain takes no run_dir", file=sys.stderr)
            return 1
        return _run_stage(lead_author_drain)

    if ns.learn_drain:
        if ns.run_dir is not None:
            print("--learn-drain takes no run_dir", file=sys.stderr)
            return 1
        return _run_stage(learn_drain)

    if ns.run_dir is None:
        print("run_dir required (or pass --author-drain / --lead-author-drain)", file=sys.stderr)
        return 1
    run_dir = ns.run_dir.resolve()
    if not run_dir.is_dir():
        print(f"not a directory: {run_dir}", file=sys.stderr)
        return 1
    # Direct single-run: no queue to quarantine into, so a RunUnprocessable (bad run data)
    # maps to the contracted exit 2 rather than propagating.
    return _run_stage(lambda: run_one(run_dir), allow_run_error=True)
