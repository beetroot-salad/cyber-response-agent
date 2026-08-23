from __future__ import annotations

import contextlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from collections.abc import Callable

import yaml

from defender._yaml import safe_load
from defender.learning.core.config import (
    DEFAULT_PATHS,
    LegDirs,
    RunUnprocessable,
    LoopPaths,
    RunPaths,
    _log,
    source_first_party_key,
)
from defender._paths import PATHS
from defender._run_id import is_valid_run_id
from defender.runtime import box as box_mod
from defender.run_common import is_held_out_alert_copy
from defender.learning.core.directions import (
    BY_NAME,
    Direction,
    directions_for,
    raw_fallback_name,
)
from defender.learning.core.markers import (
    ClaimedMarker,
    claim_markers,
    quarantine_marker,
)
from defender.learning.core.persist import (
    DirectionArtifacts,
    append_findings,
    derive_alert_rule_key,
    persist_run,
)
from defender.learning.tickets.ticket_enrichment import enrich_case_ticket
from defender.learning.core.subagents import InProcessSubagents, Subagents, is_skip_story
from defender.learning.core.validate import (
    normalize_disposition,
    normalize_judge_yaml,
)


LEG_STATUS_STARTED = "started"
LEG_STATUS_COMPLETED = "completed"


def _leg_status_path(learning_run_dir: Path, spec: Direction) -> Path:
    return learning_run_dir / spec.status_name


def _write_leg_status(learning_run_dir: Path, spec: Direction, status: str) -> None:
    """The leg's own terminal status — the ONE place `visualize_judge.leg_status` reads to
    tell a leg that never ran from one that started and died."""
    _leg_status_path(learning_run_dir, spec).write_text(status, encoding="utf-8")


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
    dirs: LegDirs,
    disposition: str,
    alert_rule_key: str,
    run_id: str,
    *,
    paths: LoopPaths,
    agents: Subagents,
    box: Any,
) -> bool:
    run_dir, learning_run_dir = dirs.run_dir, dirs.learning_run_dir
    # STARTED before the actor call, not after: a leg the actor call itself raises out of
    # (never reaching the story write) must still read as started-and-died, not never-selected.
    _write_leg_status(learning_run_dir, spec, LEG_STATUS_STARTED)
    _log(f"step=actor ({spec.name})")
    actor_story = spec.invoke_actor(agents, run_dir, learning_run_dir, alert_rule_key, box=box)
    actor_story_path = learning_run_dir / spec.story_name
    actor_story_path.write_text(actor_story, encoding="utf-8")

    if is_skip_story(actor_story):
        _log(f"actor emitted SKIP ({spec.name}) — persisting, no findings")
        persist_run(
            run_dir, learning_run_dir,
            artifacts=DirectionArtifacts(
                actor_story=actor_story, story_name=spec.story_name,
                judge_yaml=None, judge_name=spec.judge_name,
            ),
            disposition=disposition, alert_rule_key=alert_rule_key,
        )
        _write_leg_status(learning_run_dir, spec, LEG_STATUS_COMPLETED)
        return False

    # No oracle stage: the judge is driven straight off the actor's story and the run's own
    # executed evidence.
    judge_raw = agents.judge(
        spec.judge_wiring, run_dir, actor_story_path, learning_run_dir,
        box=box,
    )
    judge_doc, judge_stripped = _validate_judge_yaml(
        judge_raw, spec.validate, learning_run_dir / raw_fallback_name(spec.judge_name)
    )

    _log(f"step=persist ({spec.name})")
    persist_run(
        run_dir, learning_run_dir,
        artifacts=DirectionArtifacts(
            actor_story=actor_story, story_name=spec.story_name,
            judge_yaml=judge_stripped, judge_name=spec.judge_name,
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
    _write_leg_status(learning_run_dir, spec, LEG_STATUS_COMPLETED)
    return True


def _directions_for(disposition: str) -> list[str]:
    return [d.name for d in directions_for(disposition)]


def _prepare_engines_for(directions: list[str], *, include_actor: bool = True) -> None:
    models: set[str] = set()
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
    """The run-cycle box's geography: the UNION of the actor's and the judge's gate scopes —
    learning_run_dir (ro, no in-box writer) + the defender infra tree + the judged run's
    gather_raw (ro), snapshotted at box-creation time — plus the actor's cwd_anchor, covered
    as the ro parent of the defender mount."""
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
        # The shared infra helper, so the box carries DEFENDER_RUN_DIR/RUNS_BASE too — box.py
        # re-derives DEFENDER_DIR/PATH/PYTHONPATH off the workdir to the same values.
        env=box_mod.infra_env(defender_dir, learning_run_dir),
    )


def _dispatch_directions(
    directions: list[str],
    dirs: LegDirs,
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
    """Tear the run-cycle box down and HOLD any fault instead of raising it here: the fault
    still propagates, but only after the run has reached the author queue — a box fault must
    not silently drop the case from authoring, the same invariant a failed LEG keeps."""
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
    if not is_valid_run_id(run_id):
        _log(f"run_id={run_id!r} fails the run-id grammar — REFUSING (its lock file and its "
             f"container name are both derived from it)")
        return 0
    # One live pass per run. `learn_drain`'s lease keeps two DRAINERS apart and this is not
    # about them: the single-run CLI stage reaches `run_one` holding no lease, and the
    # run-cycle box reuses one container name per run id, so a hand-run pass on a run the
    # worker already claimed put two lanes on one name (#955 F-49). Refusing is the whole
    # behaviour — a second pass has nothing to add to a run already being learned.
    from defender.learning.author import shared as _author_shared

    with _author_shared.flock_or_skip(paths.run_cycle_lock_file(run_id)) as locked:
        if not locked:
            _log(f"run_id={run_id} another pass is already live on this run — REFUSING "
                 f"(both would share the container name defender-runcycle-{run_id})")
            return 0
        return _run_one_locked(
            run_dir, paths=paths, agents=agents, start_box=start_box, stop_box=stop_box,
        )


def _run_one_locked(
    run_dir: Path,
    *,
    paths: LoopPaths,
    agents: Subagents,
    start_box: Callable[..., Any],
    stop_box: Callable[..., None],
) -> int:
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

    dirs = LegDirs(run_dir, learning_run_dir)

    box: Any = None
    if directions:
        # One run-cycle box, created before the legs dispatch (actor and judge share it), torn
        # down exactly once at run end — including on an exceptional exit, since neither leg's
        # own error handling may leak it.
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

    # The run cycle deliberately does not enqueue for authoring — catalog curation has its own
    # trigger at the investigation boundary (run.py's tail), so the author queue is untouched
    # regardless of how the legs came out.

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


def _render_transcript(run_dir: Path) -> None:
    from defender.scripts.visualize.visualize_run import render_and_mirror

    render_and_mirror(run_dir)


def _serve_marker(
    claim: ClaimedMarker,
    qdir: Path,
    run_one_fn: Callable[[Path], int],
    render: Callable[[Path], None],
) -> bool:
    try:
        run_one_fn(claim.run_dir)
    except Exception as e:  # noqa: BLE001 — one poison run must not wedge the worker
        quarantine_marker(claim.spec, claim.path, qdir, f"run-one-error: {e!r}")
        return False
    try:
        render(claim.run_dir)
    except Exception as e:  # noqa: BLE001 — render is best-effort
        _log(f"learn_drain: render failed for {claim.run_dir.name}: {e!r} (continuing)")
    with contextlib.suppress(OSError):
        claim.path.unlink()
    # The claim moved this identity OUT of the top level, freeing the slot for a retry to land
    # while the claim was held. That retry re-requests the run just learned, under the same
    # name — absorb it here rather than relearn it.
    with contextlib.suppress(OSError):
        claim.queued_path.unlink()
    return True


def learn_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    run_one_fn: Callable[[Path], int] | None = None,
    render: Callable[[Path], None] | None = None,
) -> int:
    # The single-drainer lease, load-bearing because this drain RECLAIMS `inflight/`: a claim
    # is only evidence of a DEAD pass if no live pass can be holding one. Without the lease a
    # second drainer reads a live drainer's claim as an orphan and learns the run twice.
    from defender.learning.author import shared as _author_shared

    with _author_shared.flock_or_skip(paths.learn_drain_lock_file) as locked:
        if not locked:
            _log("learn_drain: another drainer holds the lock — exiting")
            return 0
        return _learn_drain_locked(paths, run_one_fn=run_one_fn, render=render)


def _learn_drain_locked(
    paths: LoopPaths,
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
    if not qdir.is_dir():
        # The learn queue has no writer at all, hand or automatic — the absent/empty
        # distinction is the one instrument left, so the log says which this is.
        _log(
            f"learn_drain: queue root {qdir} does not exist — no automatic feed writes it "
            "anymore (#791 removed the investigation's own enqueue); nothing queued"
        )
        return 0

    drained = 0
    claims = claim_markers(
        qdir, identity_key="run_id", label="learn_drain", noun="learning",
        extra=" — no automatic feed writes this queue anymore (#791)",
    )
    for claim in claims:
        if _serve_marker(claim, qdir, run_one_fn, render):
            drained += 1
    _log(f"learn_drain: drained {drained} run(s)")
    return 0
