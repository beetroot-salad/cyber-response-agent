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
from defender._paths import PATHS
from defender.runtime import box as box_mod
from defender.run_common import is_held_out_alert_copy
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


_SYSTEMIC_FAULTS: tuple[type[BaseException], ...] = (
    StageAbort, FatalConfigError, GitError, box_mod.BoxFault,
)




def _write_oracle_telemetry(
    oracle_raw: str, learning_run_dir: Path, out_name: str
) -> Path:
    stripped = strip_yaml_fence(oracle_raw)
    out_path = learning_run_dir / out_name
    out_path.write_text(stripped, encoding="utf-8")
    if stripped != oracle_raw:
        (learning_run_dir / (Path(out_name).stem + ".raw.txt")).write_text(oracle_raw, encoding="utf-8")
    return out_path


def _validate_judge_yaml(
    judge_raw: str, validate: Callable, raw_path: Path
) -> tuple[dict, str]:
    stripped = normalize_judge_yaml(judge_raw)
    try:
        doc = validate(safe_load(stripped))
    except (yaml.YAMLError, RunUnprocessable) as e:
        raw_path.write_text(judge_raw, encoding="utf-8")
        raise RunUnprocessable(f"judge YAML invalid: {e}") from e
    if stripped != judge_raw:
        raw_path.write_text(judge_raw, encoding="utf-8")
    return doc, stripped




def run_direction(
    spec: Direction,
    dirs: RunPaths,
    disposition: str,
    alert_rule_key: str,
    run_id: str,
    *,
    paths: LoopPaths,
    agents: Subagents,
    box: Any,
) -> bool:
    run_dir, learning_run_dir = dirs.run_dir, dirs.learning_run_dir
    assert learning_run_dir is not None, "run_direction requires a learning leg dir"
    _log(f"step=actor ({spec.name})")
    actor_story = spec.invoke_actor(agents, run_dir, learning_run_dir, alert_rule_key, box=box)
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
        spec.judge_wiring, run_dir, actor_story_path, telemetry_path, learning_run_dir,
        box=box,
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
    directions: list[str] = []
    if disposition in ADVERSARIAL_DISPOSITIONS:
        directions.append("adversarial")
    if disposition in BENIGN_DISPOSITIONS:
        directions.append("benign")
    return directions




class _LeadAuthorRetry(Exception):
    pass


def _invoke_lead_author(paths: LoopPaths, run_dir: Path, *, box: Any = None) -> None:
    from defender.learning.leads.lead_extraction import LeadAuthorError

    _log("step=lead-author")
    rc = _run_curator_module("lead_author", lambda mod: mod.run(run_dir, paths=paths, box=box))
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
    *,
    box: Any = None,
) -> None:
    threshold = env_int(threshold_env, 5)
    pending_count = _pending_queue_count(pending_file)
    if pending_count < threshold:
        _log(f"{pending_label}={pending_count} threshold={threshold} — {module_name} not invoked")
        return
    _log(f"step={module_name} {pending_label}={pending_count} threshold={threshold}")
    rc = _run_curator_module(
        module_name, lambda mod: mod.run_batch(hold_committed=True, paths=paths, box=box)
    )
    if rc not in (0, None):
        _log(f"{module_name} returned rc={rc} (queue intact, retry next tick)")


_CURATOR_MODULES = {
    "lead_author": "defender.learning.leads.lead_author",
    "pitfalls_curator": "defender.learning.leads.pitfalls_curator",
    "author": "defender.learning.author.lessons.run",
    "author_actor": "defender.learning.author.malicious_actor.run",
    "author_actor_benign": "defender.learning.author.benign_actor.run",
    "author_actor_env": "defender.learning.author.benign_actor.env",
}


def _run_curator_module(module_name: str, call: Callable[[Any], int]):
    mod = importlib.import_module(_CURATOR_MODULES[module_name])
    try:
        return call(mod)
    except (subprocess.SubprocessError, OSError) as e:
        _log(f"{module_name} crashed: {e!r} (continuing)")
        return None




def _enqueue_marker(run_dir: Path, queue_dir: Path, label: str) -> None:
    queue_dir.mkdir(parents=True, exist_ok=True)
    marker = queue_dir / f"{run_dir.name}.json"
    write_atomic(
        marker,
        json.dumps({"run_id": run_dir.name, "run_dir": str(run_dir.resolve())}) + "\n",
    )
    _log(f"enqueued for {label}: {marker}")


def _enqueue_for_authoring(run_dir: Path, paths: LoopPaths) -> None:
    _enqueue_marker(run_dir, paths.author_queue_dir, "authoring")


def enqueue_for_learning(run_dir: Path, paths: LoopPaths = DEFAULT_PATHS) -> None:
    _enqueue_marker(run_dir, paths.learn_queue_dir, "learning")


def _prepare_engines_for(directions: list[str], *, include_actor: bool = True) -> None:
    models: set[str] = {ORACLE_MODEL} if directions else set()
    for name in directions:
        d = BY_NAME[name]
        models.add(d.judge_wiring.model)
        if include_actor:
            models.add(d.actor_model)
    for model in models:
        source_first_party_key(model, label="engine")


_RUN_CYCLE_NAME_PREFIX = "defender-runcycle-"


def _run_cycle_box_request(
    run_dir: Path, learning_run_dir: Path, defender_dir: Path,
) -> box_mod.BoxRequest:
    """The run-cycle box's geography (M2/M3/DC2): mounts the UNION of the actor's and the
    judge's gate scopes — learning_run_dir (R4: ro, no in-box writer) + the defender infra
    tree (also a judge gate root, M3b overlap) + the judged run's gather_raw (ro, S1),
    snapshotted at box-creation time (R10, decision 9's absent-vs-empty split) — plus the
    actor's cwd_anchor, covered as the ro parent of the defender mount (DC2)."""
    gather_raw = RunPaths(run_dir).gather_raw
    mounts = [
        box_mod.Mount(source=learning_run_dir, target=learning_run_dir, writable=False),
        box_mod.Mount(source=defender_dir, target=defender_dir, writable=False),
    ]
    if gather_raw.is_dir():
        mounts.append(box_mod.Mount(source=gather_raw, target=gather_raw, writable=False))
    return box_mod.BoxRequest(
        name=f"{_RUN_CYCLE_NAME_PREFIX}{learning_run_dir.name}",
        mounts=tuple(mounts),
        workdir=defender_dir.parent,
        # M2/RF1: the shared infra helper, so the box carries DEFENDER_RUN_DIR/RUNS_BASE too —
        # box.py re-derives DEFENDER_DIR/PATH/PYTHONPATH off the workdir to the same values.
        env=box_mod.infra_env(defender_dir, learning_run_dir),
    )


def _dispatch_directions(
    directions: list[str],
    dirs: RunPaths,
    disposition: str,
    alert_rule_key: str,
    run_id: str,
    *,
    paths: LoopPaths,
    agents: Subagents,
    box: Any,
) -> list[tuple[str, BaseException]]:
    errors: list[tuple[str, BaseException]] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures: dict[Any, str] = {}
        for name in directions:
            futures[pool.submit(
                run_direction, BY_NAME[name], dirs,
                disposition, alert_rule_key, run_id,
                paths=paths, agents=agents, box=box,
            )] = name
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                fut.result()
            except Exception as e:
                errors.append((name, e))
    return errors


def _stop_and_hold(stop_box: Callable[..., None], box: Any) -> BaseException | None:
    """Tear the run-cycle box down and HOLD any fault instead of raising it here (O7): the
    fault still propagates, but only after the run has reached the author queue — a box fault
    must not silently drop the case from authoring, the same invariant a failed LEG keeps."""
    if box is None:
        return None
    try:
        stop_box(box)
    except Exception as e:  # noqa: BLE001 — held, re-raised by the caller after the enqueue
        return e
    return None


def run_one(
    run_dir: Path,
    *,
    paths: LoopPaths = DEFAULT_PATHS,
    agents: Subagents | None = None,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
) -> int:
    if agents is None:
        agents = InProcessSubagents()

    run_id = run_dir.name
    src = RunPaths(run_dir)
    if is_held_out_alert_copy(src.alert, paths.held_out_fixtures):
        _log(f"run_id={run_id} alert is a held-out eval fixture — REFUSING to learn "
             f"(its findings must never feed a corpus it is scored against)")
        return 0
    _log(f"run_id={run_id} step=normalize")
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

    dirs = RunPaths(run_dir, learning_run_dir)

    box: Any = None
    if directions:
        # O1/M1: one run-cycle box, created before the legs dispatch (decision 2 — actor and
        # judge share it), torn down exactly once at run end (O7) — including on an
        # exceptional exit, since neither leg's own error handling may leak it.
        box = start_box(_run_cycle_box_request(
            run_dir, learning_run_dir, PATHS.defender_dir,
        ))
    teardown_fault: BaseException | None = None
    try:
        errors = _dispatch_directions(
            directions, dirs, disposition, alert_rule_key, run_id,
            paths=paths, agents=agents, box=box,
        )
    finally:
        teardown_fault = _stop_and_hold(stop_box, box)

    adversarial_ok = "adversarial" in directions and not any(
        name == "adversarial" for name, _ in errors
    )
    if disposition == "benign" and adversarial_ok:
        enrich_case_ticket(run_dir, learning_run_dir)

    _enqueue_for_authoring(run_dir, paths)

    if teardown_fault is not None:
        _log(f"run-cycle box teardown failed: {teardown_fault!r}")
        raise teardown_fault

    if errors:
        for name, exc in errors:
            _log(f"{name} leg failed: {exc!r}")
        raise errors[0][1]

    if not directions:
        _log(f"disposition={disposition} — no learning direction; findings queue untouched")
    return 0




def _rewrite_marker(marker: Path, spec: dict) -> None:
    write_atomic(marker, json.dumps(spec) + "\n")


def _quarantine_marker(spec: dict, marker: Path, queue_dir: Path, reason: str) -> None:
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
    checks = [(paths.pending_file, "LEARNING_AUTHOR_THRESHOLD")]
    for direction in BY_NAME.values():
        for t in (direction.obs_trigger, *direction.extra_obs_triggers):
            checks.append((t.pending_file(paths), t.threshold_env))
    return checks


def _pending_queue_count(pending_file: Path) -> int:
    if not pending_file.is_file():
        return 0
    return sum(1 for line in pending_file.read_text(encoding="utf-8").splitlines() if line.strip())


def _has_curator_work(paths: LoopPaths) -> bool:
    return any(
        _pending_queue_count(pending_file) >= env_int(env, 5)
        for pending_file, env in _curator_queue_checks(paths)
    )


def _has_lead_author_work(paths: LoopPaths) -> bool:
    threshold = pitfalls_threshold()
    qdir = paths.author_queue_dir
    if qdir.is_dir() and any(qdir.glob("*.json")):
        return True
    return len(read_pitfalls(paths)) >= threshold


def _drain_curators(
    paths: LoopPaths,
    trigger_author: Callable[..., None],
    *,
    box: Any = None,
) -> None:
    trigger_author(
        paths, paths.pending_file, "LEARNING_AUTHOR_THRESHOLD", "author", "pending", box=box,
    )
    for direction in BY_NAME.values():
        for t in (direction.obs_trigger, *direction.extra_obs_triggers):
            trigger_author(
                paths, t.pending_file(paths), t.threshold_env, t.module_name, t.pending_label,
                box=box,
            )


def _discard_worktree_changes(repo_root: Path) -> None:
    if not (repo_root / ".git").exists():
        return
    for args in (["reset", "--hard", "--quiet"], ["clean", "-fdq"]):
        _git.git(args, cwd=repo_root, check=False)


def _quarantine_lead_author_failure(
    spec: dict, marker: Path, queue_dir: Path, e: Exception
) -> None:
    _quarantine_marker(spec, marker, queue_dir, f"lead-author-error: {e!r}")


def _drain_lead_author_markers(
    paths: LoopPaths,
    run_lead_author: Callable[..., None],
    *,
    box: Any = None,
) -> None:
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
            drained = _run_or_dead_letter(
                functools.partial(run_lead_author, paths, run_dir, box=box),
                functools.partial(
                    _quarantine_lead_author_failure, spec, marker, paths.author_queue_dir
                ),
                propagate=(_LeadAuthorRetry,),
            )
        except _LeadAuthorRetry as e:
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
            _discard_worktree_changes(paths.repo_root)
        if drained:
            with contextlib.suppress(OSError):
                marker.unlink()


def _invoke_pitfalls(paths: LoopPaths, *, box: Any = None) -> int:
    _log("step=pitfalls-curation")
    rc = _run_curator_module(
        "pitfalls_curator", lambda mod: mod.run_pitfalls(paths=paths, box=box)
    )
    return rc if rc is not None else 0


def _drain_pitfalls(
    paths: LoopPaths,
    run_pitfalls: Callable[..., int],
    *,
    box: Any = None,
) -> None:
    try:
        _run_or_dead_letter(
            lambda: run_pitfalls(paths, box=box),
            lambda e: _log(f"lead_author_drain: pitfalls curation error: {e!r}; discarding edits"),
        )
    finally:
        _discard_worktree_changes(paths.repo_root)


def _drain_lead_author(
    paths: LoopPaths,
    run_lead_author: Callable[..., None],
    run_pitfalls: Callable[..., int],
    *,
    box: Any = None,
) -> None:
    _drain_lead_author_markers(paths, run_lead_author, box=box)
    _drain_pitfalls(paths, run_pitfalls, box=box)


def _validate_merge_mode() -> None:
    merge_mode()


# Trigger module → the LoopPaths attribute that already owns that curator's corpus dir. The
# directory NAMES live in `DefenderPaths` alone (`_paths.py`); re-spelling them here would let
# a rename there turn every drain box into an absent-bind-source create failure.
_CORPUS_ATTR_FOR_TRIGGER_MODULE = {
    "author_actor": "lessons_actor_dir",
    "author_actor_benign": "lessons_environment_dir",
    "author_actor_env": "lessons_environment_dir",
}


def _drain_triggered_corpora(paths: LoopPaths) -> tuple[Path, ...]:
    """R6 — decide-all-triggered before the box is created: the base lessons corpus is the
    one `author_drain`'s has_work gate always answers for (`_has_curator_work`'s primary
    check); the actor/environment siblings join only when THEIR own threshold independently
    fires. Evaluated once, before `_run_worktree_batch` composes the drain box's mount set —
    never a static union of all three (M1).

    Corpus dirs come off `paths`, so pass the WORKTREE-rooted LoopPaths: `with_repo_root`
    preserves `state_root`, so the queue counts are the same files either way."""
    triggered = [paths.lessons_dir]
    for direction in BY_NAME.values():
        for t in (direction.obs_trigger, *direction.extra_obs_triggers):
            threshold = env_int(t.threshold_env, 5)
            if _pending_queue_count(t.pending_file(paths)) >= threshold:
                attr = _CORPUS_ATTR_FOR_TRIGGER_MODULE.get(t.module_name)
                if attr is None:
                    continue
                corpus_dir = getattr(paths, attr)
                if corpus_dir not in triggered:
                    triggered.append(corpus_dir)
    return tuple(triggered)


def _drain_box_request(
    wt: Path, batch_id: str, label: str, paths: LoopPaths,
) -> box_mod.BoxRequest:
    """The drain box's geography (M1/S3/S4): infra ro over the whole worktree leaf (it carries
    `<wt>/defender` and is both drain roles' cwd_anchor), rw ONLY over what this batch actually
    needs — the triggered lesson corpora for `author_drain`, `<wt>/defender/skills` for
    `lead_author_drain` — never a static union (M1), never anything outside the leaf (S3)."""
    wt_paths = paths.with_repo_root(wt)
    mounts = [box_mod.Mount(source=wt, target=wt, writable=False)]
    if label == "lead_author_drain":
        rw_dirs: tuple[Path, ...] = (wt_paths.skills_dir,)
    else:
        rw_dirs = _drain_triggered_corpora(wt_paths)
    for d in rw_dirs:
        mounts.append(box_mod.Mount(source=d, target=d, writable=True))
    return box_mod.BoxRequest(
        name=f"defender-drain-{batch_id}", mounts=tuple(mounts), workdir=wt, env={},
    )


def _run_worktree_batch(
    paths: LoopPaths,
    branch: AuthorBranch,
    *,
    label: str,
    has_work: Callable[[LoopPaths], bool],
    do_work: Callable[..., None],
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> int:
    if not has_work(paths):
        _log(f"{label}: nothing queued and no curator at threshold — skipping")
        return 0

    try:
        if branch.open_pr_exists():
            _log(f"{label}: an open {branch.branch_prefix} PR holds the writer lease — skipping")
            return 0
        batch_id = uuid.uuid4().hex[:12]
        wt = branch.start_batch(batch_id)
    except BranchError as e:
        _log(f"{label}: cannot start batch worktree: {e} — skipping")
        return 0

    # M1: the box is created after the worktree exists AND after the threshold checks that
    # decide which curators wake, over exactly this batch's needs — never a static union. A
    # startup fault here unwinds the worktree/branch resources already minted (M1 consequence).
    try:
        box = start_box(_drain_box_request(wt, batch_id, label, paths))
    except BaseException:
        with contextlib.suppress(Exception):
            branch.cleanup(wt)
        raise

    wt_paths = paths.with_repo_root(wt)
    pr = None
    try:
        # O7: the box is torn down on ANY exit from do_work, ordinary or exceptional — never
        # leaked, and never skipped by a do_work failure.
        try:
            do_work(wt_paths, box=box)
        finally:
            stop_box(box)
        # O7/S7: the box (holding the rw bind) is already released here, then the written
        # tree is scanned for a tainting entry, BEFORE finish_batch's commit+push+PR
        # supply-chain step ever reads it (decision 8) — a failed teardown (above) blocks
        # both scrub and finish_batch (R2).
        scrub(wt)
        try:
            pr = branch.finish_batch(batch_id, wt)
        except BranchError as e:
            _log(f"{label}: finish_batch failed: {e} — work stays queued, retry next tick")
    finally:
        with contextlib.suppress(Exception):
            branch.cleanup(wt)

    if pr is None:
        _log(f"{label}: batch produced no commits — no PR opened")
        return 0
    _log(f"{label}: opened PR {pr}")
    if merge_mode() == "auto_on_green":
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
    # `(paths, pending_file, threshold_env, module_name, pending_label, *, box)` — `box=` is
    # threaded per call (R1), so the seam is not the old fixed 5-positional signature.
    trigger_author: Callable[..., None] | None = None,
    branch: AuthorBranch | None = None,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> int:
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
            do_work=lambda wt_paths, *, box=None: _drain_curators(
                wt_paths, trigger_author, box=box
            ),
            start_box=start_box, stop_box=stop_box, scrub=scrub,
        )


def lead_author_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    run_lead_author: Callable[..., None] | None = None,
    run_pitfalls: Callable[..., int] | None = None,
    branch: AuthorBranch | None = None,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> int:
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
            do_work=lambda wt_paths, *, box=None: _drain_lead_author(
                wt_paths, run_lead_author, run_pitfalls, box=box
            ),
            start_box=start_box, stop_box=stop_box, scrub=scrub,
        )




def _render_transcript(run_dir: Path) -> None:
    from defender.scripts.visualize.visualize_run import render_and_mirror

    render_and_mirror(run_dir)


def _process_marker(
    marker: Path,
    inflight_dir: Path,
    qdir: Path,
    run_one_fn: Callable[[Path], int],
    render: Callable[[Path], None],
) -> bool:
    claimed = inflight_dir / marker.name
    try:
        os.replace(marker, claimed)
    except FileNotFoundError:
        return False
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
    if run_one_fn is None:
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
    return _run_stage(lambda: run_one(run_dir), allow_run_error=True)
