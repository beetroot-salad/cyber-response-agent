from __future__ import annotations

import contextlib
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from collections.abc import Callable

import yaml

from defender._yaml import safe_load
from defender.learning.core.config import (
    DEFAULT_PATHS,
    RunUnprocessable,
    LoopPaths,
    RunPaths,
    _log,
    source_first_party_key,
)
from defender._paths import PATHS
from defender.runtime import box as box_mod
from defender.run_common import is_held_out_alert_copy
from defender.learning.core.directions import (
    BY_NAME,
    Direction,
    directions_for,
    raw_fallback_name,
)
from defender.learning.core.markers import quarantine_marker
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
    """The leg's own terminal status (#791 R2/R15) — the ONE place `visualize_judge.leg_status`
    reads to tell a leg that never ran from one that started and died, now that the retired
    stage's declared-but-unwritten artifact can no longer stand in for that signal."""
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
    # The leg is marked STARTED before the actor call, not after: a leg the actor call itself
    # raises out of (never reaching the story write) must still read as started-and-died, not
    # as never-selected — the same confusion the status field exists to remove.
    _write_leg_status(learning_run_dir, spec, LEG_STATUS_STARTED)
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
            ),
            disposition=disposition, alert_rule_key=alert_rule_key,
        )
        _write_leg_status(learning_run_dir, spec, LEG_STATUS_COMPLETED)
        return False

    # #791: the retired oracle stage leaves the leg's own call chain entirely — the judge is
    # driven straight off the actor's story and the run's own executed evidence.
    judge_raw = agents.judge(
        spec.judge_wiring, run_dir, actor_story_path, learning_run_dir,
        box=box,
    )
    judge_doc, judge_stripped = _validate_judge_yaml(
        judge_raw, spec.validate, learning_run_dir / raw_fallback_name(spec.judge_name)
    )

    _log(f"step=persist ({spec.name})")
    persist_run(
        dirs,
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
    # #791 FK4/R13 gave this an `include_oracle` knob so the run cycle could opt OUT of
    # sourcing the retired stage's key while the secondary-metric eval — the one caller that
    # still drove that stage — kept opting in. That harness is retired, so every surviving
    # caller wants the exclusion and the knob selected nothing.
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

    # #791: the run cycle no longer enqueues for authoring — catalog curation gets its own
    # trigger at the investigation boundary (run.py's tail), so this leaves the author queue
    # untouched regardless of how the legs came out.

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


def _process_marker(
    marker: Path,
    inflight_dir: Path,
    qdir: Path,
    run_one_fn: Callable[[Path], int],
    render: Callable[[Path], None],
    *,
    already_claimed: bool = False,
) -> bool:
    if already_claimed:
        # A marker RECLAIMED from `inflight/` (#791 P1): a prior drain died mid-claim and left
        # it there, outside the top-level glob a plain count is computed from — it is served
        # exactly like a freshly claimed one, just not moved again.
        claimed = marker
    else:
        claimed = inflight_dir / marker.name
        try:
            os.replace(marker, claimed)
        except FileNotFoundError:
            return False
    try:
        spec = json.loads(claimed.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        quarantine_marker({"run_id": marker.stem}, claimed, qdir, f"unreadable: {e!r}")
        return False
    if not isinstance(spec, dict):
        # A row that PARSES but is not a mapping is unreadable in the same way: `spec.get`
        # below would raise an AttributeError past every dead-letter path, wedging the worker
        # on a marker the reclaim hands straight back next tick.
        quarantine_marker(
            {"run_id": marker.stem}, claimed, qdir,
            f"unreadable: not a mapping ({type(spec).__name__})",
        )
        return False
    run_dir = Path(spec.get("run_dir", ""))
    if not run_dir.is_dir():
        quarantine_marker(spec, claimed, qdir, "artifact-missing")
        return False
    try:
        run_one_fn(run_dir)
    except Exception as e:  # noqa: BLE001 — one poison run must not wedge the worker
        quarantine_marker(spec, claimed, qdir, f"run-one-error: {e!r}")
        return False
    try:
        render(run_dir)
    except Exception as e:  # noqa: BLE001 — render is best-effort
        _log(f"learn_drain: render failed for {run_dir.name}: {e!r} (continuing)")
    with contextlib.suppress(OSError):
        claimed.unlink()
    # #791 P2: the claim moved this identity OUT of the top level, which frees the slot for a
    # retry to land unobstructed while the claim was held. That retry is a re-request of the
    # run just learned, under the same name — absorb it here rather than relearn it.
    with contextlib.suppress(OSError):
        (qdir / claimed.name).unlink()
    return True


def learn_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    run_one_fn: Callable[[Path], int] | None = None,
    render: Callable[[Path], None] | None = None,
) -> int:
    # The single-drainer lease its two sibling drains already hold. It became load-bearing
    # when this drain started RECLAIMING `inflight/`: a claim is only evidence of a DEAD pass
    # if no live pass can be holding one, and without the lease a second drainer reads a live
    # drainer's claim as an orphan and learns the same run a second time.
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
        # #791 H1c: the learn queue has no writer at all anymore, hand or automatic — the
        # absent/empty distinction is the one instrument left, so it says which this is.
        _log(
            f"learn_drain: queue root {qdir} does not exist — no automatic feed writes it "
            "anymore (#791 removed the investigation's own enqueue); nothing queued"
        )
        return 0

    inflight_dir = qdir / "inflight"
    orphans = sorted(inflight_dir.glob("*.json")) if inflight_dir.is_dir() else []
    markers = sorted(qdir.glob("*.json"))
    _log(
        f"learn_drain: {len(markers)} run(s) queued for learning, {len(orphans)} reclaimed "
        "from a prior claim — no automatic feed writes this queue anymore (#791)"
    )
    if markers or orphans:
        inflight_dir.mkdir(parents=True, exist_ok=True)
    drained = 0
    for marker in orphans:
        if _process_marker(marker, inflight_dir, qdir, run_one_fn, render, already_claimed=True):
            drained += 1
    for marker in markers:
        if _process_marker(marker, inflight_dir, qdir, run_one_fn, render):
            drained += 1
    _log(f"learn_drain: drained {drained} run(s)")
    return 0
