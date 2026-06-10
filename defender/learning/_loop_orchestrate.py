"""Learning-loop orchestration: dispatch a finished run dir through the actor →
oracle → judge → persist → queue pipeline, per direction, and trigger the curators.

`run_one` takes injectable `paths` (filesystem layout) and `agents` (the subagent
seam), so tests drive it with a `LoopPaths(repo_root=tmp_path)` and a fake `Subagents`
instead of monkeypatching module globals.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

import yaml

from _loop_config import (
    ADVERSARIAL_DISPOSITIONS,
    BENIGN_DISPOSITIONS,
    DEFAULT_PATHS,
    GROUND_TRUTH_FILE,
    LEARNING_DIR,
    LoopError,
    LoopPaths,
    _log,
)
from _loop_directions import BY_NAME, Direction, ObsTrigger
from _loop_persist import append_findings, derive_alert_rule_key, persist_run
from _loop_subagents import ClaudePrintSubagents, Subagents, is_skip_story
from _loop_validate import (
    normalize_disposition,
    strip_yaml_fence,
)


# ---------------------------------------------------------------------------
# Ground-truth (held-out) gate
# ---------------------------------------------------------------------------


def read_ground_truth(run_dir: Path) -> dict | None:
    """Parsed ground_truth.yaml if the run dir carries one, else None.

    Held-out runs carry it (propagated from the fixture by ``defender/run.py``); the
    persist stage uses it to suppress queue appends so held-out runs never feed back
    into the learning corpora.
    """
    path = run_dir / GROUND_TRUTH_FILE
    if not path.is_file():
        return None
    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        raise LoopError(f"{path}: malformed YAML: {e}") from e
    if not isinstance(doc, dict):
        raise LoopError(f"{path}: expected a mapping at top level")
    return doc


def is_held_out(run_dir: Path) -> bool:
    gt = read_ground_truth(run_dir)
    return bool(gt and gt.get("held_out") is True)


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
    out_path.write_text(stripped)
    if stripped != oracle_raw:
        (learning_run_dir / (Path(out_name).stem + ".raw.txt")).write_text(oracle_raw)
    return out_path


def _validate_judge_yaml(
    judge_raw: str, validate: Callable, raw_path: Path
) -> tuple[dict, str]:
    """Strip + validate judge YAML; on failure/mutation dump the raw to ``raw_path``."""
    stripped = strip_yaml_fence(judge_raw)
    try:
        doc = validate(yaml.safe_load(stripped))
    except (yaml.YAMLError, LoopError) as e:
        raw_path.write_text(judge_raw)
        raise LoopError(f"judge YAML invalid: {e}") from e
    if stripped != judge_raw:
        raw_path.write_text(judge_raw)
    return doc, stripped


# ---------------------------------------------------------------------------
# Direction leg
# ---------------------------------------------------------------------------


def run_direction(
    spec: Direction,
    run_dir: Path,
    learning_run_dir: Path,
    disposition: str,
    alert_rule_key: str,
    run_id: str,
    held_out: bool,
    *,
    paths: LoopPaths,
    agents: Subagents,
) -> bool:
    """One direction: actor → oracle → judge → persist → append.

    Returns True if queue rows were appended (i.e. worth triggering the curators).
    """
    _log(f"step=actor ({spec.name})")
    actor_story = spec.invoke_actor(agents, run_dir, learning_run_dir, alert_rule_key)
    # Write the story now so oracle + judge can read it from disk downstream; the
    # later persist_run re-archives the same path (idempotent) and is the only writer
    # on the SKIP short-circuit below.
    actor_story_path = learning_run_dir / spec.story_name
    actor_story_path.write_text(actor_story)

    if is_skip_story(actor_story):
        _log(f"actor emitted SKIP ({spec.name}) — persisting, no findings")
        persist_run(
            run_dir, learning_run_dir,
            actor_story=actor_story, story_name=spec.story_name,
            judge_yaml=None, judge_name=spec.judge_name,
            telemetry_yaml=None, telemetry_name=spec.telemetry_name,
            disposition=disposition, alert_rule_key=alert_rule_key,
        )
        return False

    _log(f"step=oracle ({spec.name})")
    oracle_raw = agents.oracle(run_dir, actor_story_path)
    telemetry_path = _write_oracle_telemetry(
        oracle_raw, learning_run_dir, spec.telemetry_name
    )

    judge_raw = spec.invoke_judge(
        agents, run_dir, actor_story_path, telemetry_path, learning_run_dir
    )
    judge_doc, judge_stripped = _validate_judge_yaml(
        judge_raw, spec.validate, learning_run_dir / spec.judge_raw_name
    )

    _log(f"step=persist ({spec.name})")
    persist_run(
        run_dir, learning_run_dir,
        actor_story=actor_story, story_name=spec.story_name,
        judge_yaml=judge_stripped, judge_name=spec.judge_name,
        telemetry_yaml=telemetry_path.read_text(), telemetry_name=spec.telemetry_name,
        disposition=disposition, alert_rule_key=alert_rule_key,
    )

    if held_out:
        _log(f"held_out=true — {spec.name} appends suppressed")
        return False

    n_f = append_findings(
        judge_doc, run_id, alert_rule_key, learning_run_dir,
        direction=spec.name, paths=paths,
    )
    n_o = spec.append_observations(
        judge_doc, run_id, alert_rule_key, learning_run_dir, paths=paths
    )
    _log(f"appended {n_f} finding(s), {n_o} observation(s) ({spec.name})")
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

# Guards the transient `sys.path` mutation in `_run_curator_module`. The curators
# now run only from the serial `author_drain` (one at a time), so this is defensive
# rather than load-bearing — kept so a future concurrent caller can't corrupt
# `sys.path` mid-import.
_CURATOR_IMPORT_LOCK = threading.Lock()


def _invoke_lead_author(run_dir: Path) -> None:
    """Catalog/template refinement. Independent of disposition + actor/judge."""
    _log("step=lead-author")
    rc = _run_curator_module("lead_author", lambda mod: mod.run(run_dir))
    if rc not in (0, None):
        _log(f"lead-author returned rc={rc} (continuing — defender is experimental)")


def _maybe_trigger_author(
    pending_file: Path,
    threshold_env: str,
    module_name: str,
    pending_label: str,
) -> None:
    """Run the named curator if its pending queue meets the threshold."""
    threshold = int(os.environ.get(threshold_env, "5"))
    pending_count = 0
    if pending_file.is_file():
        pending_count = sum(
            1 for line in pending_file.read_text().splitlines() if line.strip()
        )
    if pending_count < threshold:
        _log(f"{pending_label}={pending_count} threshold={threshold} — {module_name} not invoked")
        return
    _log(f"step={module_name} {pending_label}={pending_count} threshold={threshold}")
    rc = _run_curator_module(module_name, lambda mod: mod.run_batch())
    if rc not in (0, None):
        _log(f"{module_name} returned rc={rc} (queue intact, retry next tick)")


def _run_curator_module(module_name: str, call: Callable[[Any], int]):
    """Import a sibling curator by name (loop runs as a script) and run it.

    Narrow swallow for ``lead_author``-style child-process / filesystem hiccups; real
    regressions (ImportError, TypeError, …) propagate so they fail loudly.

    The sibling dir is almost always already on ``sys.path`` (run.py inserts it; a
    standalone ``loop.py`` puts it on ``sys.path[0]``). The lock-guarded mutation +
    remove-by-value (never a positional ``pop(0)``) keep this safe even if a future
    caller runs curators off the serial drainer.
    """
    learning_dir = str(LEARNING_DIR)
    with _CURATOR_IMPORT_LOCK:
        added = learning_dir not in sys.path
        if added:
            sys.path.insert(0, learning_dir)
        try:
            mod = __import__(module_name)
        finally:
            if added:
                with contextlib.suppress(ValueError):
                    sys.path.remove(learning_dir)
    try:
        return call(mod)
    except (subprocess.SubprocessError, OSError) as e:
        _log(f"{module_name} crashed: {e!r} (continuing)")
        return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _enqueue_for_authoring(run_dir: Path, paths: LoopPaths) -> None:
    """Record this run for the serial author-drainer.

    The drainer needs the original (``/tmp``) run dir to lead-author its
    catalog/template refinements; carrying the path here lets the drainer detect
    a vanished artifact (``/tmp`` cleared between learn and author) instead of
    silently dropping it. Written atomically (tmp + replace)."""
    paths.author_queue_dir.mkdir(parents=True, exist_ok=True)
    marker = paths.author_queue_dir / f"{run_dir.name}.json"
    tmp = marker.with_suffix(".json.tmp")
    tmp.write_text(
        json.dumps({"run_id": run_dir.name, "run_dir": str(run_dir.resolve())}) + "\n"
    )
    os.replace(tmp, marker)
    _log(f"enqueued for authoring: {marker}")


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
        agents = ClaudePrintSubagents()

    run_id = run_dir.name
    _log(f"run_id={run_id} step=normalize")
    disposition = normalize_disposition(run_dir / "report.md")
    directions = _directions_for(disposition)

    alert = json.loads((run_dir / "alert.json").read_text())
    alert_rule_key = derive_alert_rule_key(alert)
    learning_run_dir = paths.runs_dir / run_id
    learning_run_dir.mkdir(parents=True, exist_ok=True)
    held_out = is_held_out(run_dir)
    _log(
        f"step=dispatch disposition={disposition} directions={directions} "
        f"alert_rule_key={alert_rule_key} held_out={held_out}"
    )

    # The direction legs are mutually independent: each writes disjoint
    # per-direction files and serializes shared findings/observation writes on a
    # flock (cross-process safe). subprocess.run releases the GIL while the claude
    # child runs, so threads give real wall-time overlap. Within a leg,
    # actor→oracle→judge stays serial.
    errors: list[tuple[str, BaseException]] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures: dict[Any, str] = {}
        for name in directions:
            futures[pool.submit(
                run_direction, BY_NAME[name], run_dir, learning_run_dir,
                disposition, alert_rule_key, run_id, held_out,
                paths=paths, agents=agents,
            )] = name
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                fut.result()
            except Exception as e:  # re-raised after all legs settle (fail loud)
                errors.append((name, e))

    if errors:
        for name, e in errors:
            _log(f"{name} leg failed: {e!r}")
        raise errors[0][1]

    # Hand the run to the serial author-drainer; commits happen there, never here.
    _enqueue_for_authoring(run_dir, paths)
    if not directions:
        _log(f"disposition={disposition} — no learning direction; findings queue untouched")
    return 0


# ---------------------------------------------------------------------------
# Author stage — serial drainer (the only stage that commits)
# ---------------------------------------------------------------------------


def _mark_artifact_missing(spec: dict, marker: Path, paths: LoopPaths) -> None:
    """Surface a vanished run dir (``/tmp`` cleared between learn and author)
    instead of silently dropping it — move the marker to author-queue/failed/."""
    failed_dir = paths.author_queue_dir / "failed"
    failed_dir.mkdir(parents=True, exist_ok=True)
    rec = dict(spec)
    rec["failed"] = "artifact-missing"
    (failed_dir / marker.name).write_text(json.dumps(rec) + "\n")
    with contextlib.suppress(OSError):
        marker.unlink()
    _log(f"author_drain: run_dir missing for {spec.get('run_id')} — marked artifact-missing")


def _author_drain_locked(
    paths: LoopPaths,
    run_lead_author: Callable[[Path], None],
    trigger_author: Callable[[Path, str, str, str], None],
) -> int:
    qdir = paths.author_queue_dir
    markers = sorted(qdir.glob("*.json")) if qdir.is_dir() else []
    _log(f"author_drain: {len(markers)} run(s) queued for lead-author")
    for marker in markers:
        try:
            spec = json.loads(marker.read_text())
        except (OSError, json.JSONDecodeError) as e:
            _log(f"author_drain: unreadable marker {marker.name}: {e!r}; skipping")
            continue
        run_dir = Path(spec.get("run_dir", ""))
        if not run_dir.is_dir():
            _mark_artifact_missing(spec, marker, paths)
            continue
        run_lead_author(run_dir)
        with contextlib.suppress(OSError):
            marker.unlink()

    # Findings + per-direction observation curators drain the accumulated queues
    # (threshold-gated — identical semantics to the old in-run trigger).
    trigger_author(paths.pending_file, "LEARNING_AUTHOR_THRESHOLD", "author", "pending")
    for direction in BY_NAME.values():
        t: ObsTrigger = direction.obs_trigger
        trigger_author(t.pending_file(paths), t.threshold_env, t.module_name, t.pending_label)
    return 0


def author_drain(
    paths: LoopPaths = DEFAULT_PATHS,
    *,
    run_lead_author: Callable[[Path], None] | None = None,
    trigger_author: Callable[[Path, str, str, str], None] | None = None,
) -> int:
    """Serial AUTHOR stage: drain the author-work queue (lead-author per run dir)
    then the findings/observation queues (threshold-gated), committing locally.

    One live drainer at a time, guarded by a non-blocking flock on a *dedicated*
    lock (``author_drain_lock_file``) — distinct from the curators' repo lock so
    the curators it calls can take that without a same-process deadlock. A second
    drainer that can't grab the lock simply exits; the live one will pick up any
    work it enqueued. ``run_lead_author`` / ``trigger_author`` are injectable for
    tests."""
    if run_lead_author is None:
        run_lead_author = _invoke_lead_author
    if trigger_author is None:
        trigger_author = _maybe_trigger_author

    lock_path = paths.author_drain_lock_file
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+")
    try:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            _log("author_drain: another drainer holds the lock — exiting")
            return 0
        return _author_drain_locked(paths, run_lead_author, trigger_author)
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        fh.close()


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
  defender/learning/_pending/environment_observations.jsonl   (benign direction)
    when count >= LEARNING_AUTHOR_ENV_THRESHOLD, author_actor_benign.py runs.

Environment:
  ACTOR_MODEL / BENIGN_ACTOR_MODEL     claude model for the adversarial / benign actor
  ORACLE_MODEL                         per-lead telemetry oracle (sonnet by design — generative)
  ORACLE_EFFORT                        oracle reasoning effort (default: low — each call sees
                                       only its own lead; no cross-lead matching to reason about)
  ORACLE_MAX_CONCURRENCY               max concurrent per-lead oracle calls (default: 8)
  JUDGE_EFFORT / BENIGN_JUDGE_EFFORT   judge reasoning effort (default: low — the prompt
                                       fully scaffolds the analysis, so high over-thinks)
  JUDGE_MODEL / BENIGN_JUDGE_MODEL     claude model for the adversarial / benign judge
  LEARNING_SUBAGENT_TIMEOUT_SECONDS    per-subagent timeout (default: 450)
  LEARNING_AUTHOR_THRESHOLD            pending findings before author runs (default: 5)
  LEARNING_AUTHOR_ACTOR_THRESHOLD      pending actor observations before author_actor runs
  LEARNING_AUTHOR_ENV_THRESHOLD        pending env observations before author_actor_benign runs

Typical use: invoked in-process by `defender/run.py` after the runtime loop exits. Run
standalone with `python3 defender/learning/loop.py <run_dir>` to re-process a run dir.

Exit codes: 0 success / 0 skipped (no direction, or actor SKIP) / 2 LoopError / 1 usage.
"""


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
        help="AUTHOR stage: serially drain the author-work + findings/observation "
             "queues and commit lessons/templates (takes no run_dir; one drainer at a time).",
    )
    ns = parser.parse_args(argv[1:])

    if ns.author_drain:
        if ns.run_dir is not None:
            print("--author-drain takes no run_dir", file=sys.stderr)
            return 1
        try:
            return author_drain()
        except LoopError as e:
            print(f"[loop] FATAL: {e}", file=sys.stderr)
            return 2

    if ns.run_dir is None:
        print("run_dir required (or pass --author-drain)", file=sys.stderr)
        return 1
    run_dir = ns.run_dir.resolve()
    if not run_dir.is_dir():
        print(f"not a directory: {run_dir}", file=sys.stderr)
        return 1
    try:
        return run_one(run_dir)
    except LoopError as e:
        print(f"[loop] FATAL: {e}", file=sys.stderr)
        return 2
