"""Learning-loop orchestration: dispatch a finished run dir through the actor →
oracle → judge → persist → queue pipeline, per direction, and trigger the curators.

`run_one` takes injectable `paths` (filesystem layout) and `agents` (the subagent
seam), so tests drive it with a `LoopPaths(repo_root=tmp_path)` and a fake `Subagents`
instead of monkeypatching module globals.
"""
from __future__ import annotations

import contextlib
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
    dump_oracle_doc,
    normalize_disposition,
    strip_yaml_fence,
    validate_oracle_doc,
)
from _oracle_router import _event_attrs, route


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
# Per-step validation (writes a *.raw.txt companion on failure / mutation)
# ---------------------------------------------------------------------------


def build_oracle_doc(footprint_raw: str, lead_sequence: dict) -> dict:
    """Oracle stage B as a pure function: parse the stage-A footprint, route it
    against the lead sequence's structured filters, and validate.

    The footprint LLM emits ``events:``; the deterministic router places each
    event under the leads it satisfies and emits ``projections`` + ``uncovered``
    + ``unrouted_leads``. Raises ``LoopError`` on a malformed footprint or an
    invalid routed doc.
    """
    expected_positions = [e.get("position") for e in lead_sequence.get("entries", [])]
    parsed = yaml.safe_load(strip_yaml_fence(footprint_raw))
    footprint = (parsed or {}).get("events") if isinstance(parsed, dict) else None
    if not isinstance(footprint, list):
        raise LoopError("footprint YAML has no `events` list")
    # Validate event shape before routing: the router accesses event/attrs as
    # mappings, so a stray scalar in the LLM-authored list would otherwise raise
    # an AttributeError that escapes the caller's (yaml.YAMLError, LoopError)
    # catch and aborts the run. Surface it as a clean LoopError instead.
    for i, ev in enumerate(footprint):
        attrs = _event_attrs(ev)
        if not isinstance(attrs, dict):
            raise LoopError(
                f"footprint event {i} is not a mapping (got {type(ev).__name__})"
            )
    doc = route(footprint, lead_sequence)
    validate_oracle_doc(doc, expected_positions)
    return doc


def _route_and_write_oracle(
    footprint_raw: str, run_dir: Path, learning_run_dir: Path, out_name: str
) -> Path:
    """Run stage B and write the projected telemetry; dump the raw footprint on
    any failure for debugging."""
    lead_sequence = yaml.safe_load((run_dir / "lead_sequence.yaml").read_text()) or {}
    raw_path = learning_run_dir / (Path(out_name).stem + ".raw.txt")
    try:
        doc = build_oracle_doc(footprint_raw, lead_sequence)
    except (yaml.YAMLError, LoopError) as e:
        raw_path.write_text(footprint_raw)
        raise LoopError(f"oracle footprint/route invalid: {e}") from e

    # Always persist the stage-A footprint: the projected_telemetry.yaml on disk
    # is the *routed transform* of it, so without the raw enumeration a wrong
    # coverage verdict can't be traced back to whether stage A or the router
    # produced it (the LLM call is not cheap to reproduce).
    raw_path.write_text(footprint_raw)

    # Degenerate-state signal: if leads exist but no query carried a structured
    # filter the router could read (e.g. no template declares `filter_keys` for
    # this deployment's catalog), every footprint event lands in `uncovered` and
    # the mechanical coverage signal is vacuous. Warn so this isn't read as
    # "every attack step is a proven gap" — the judge falls back to raw queries.
    n_entries = len(lead_sequence.get("entries", []))
    has_any_filter = any(
        isinstance(q.get("filters"), dict)
        for e in lead_sequence.get("entries", [])
        for q in (e.get("queries") or [])
    )
    if n_entries and not has_any_filter:
        _log(
            f"WARNING: oracle router routed 0 of {n_entries} leads — no query "
            "carried a structured filter (catalog has no filter_keys?); coverage "
            "signal is degenerate, all footprint events are 'uncovered modulo unrouted'."
        )

    out_path = learning_run_dir / out_name
    out_path.write_text(dump_oracle_doc(doc))
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
    footprint_raw = agents.footprint(run_dir, actor_story_path)
    telemetry_path = _route_and_write_oracle(
        footprint_raw, run_dir, learning_run_dir, spec.telemetry_name
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

# Serializes the transient `sys.path` mutation in `_run_curator_module`, which can
# run from the run_one thread pool (lead-author leg) concurrently with the direction
# legs.
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
    standalone ``loop.py`` puts it on ``sys.path[0]``), but ``_invoke_lead_author``
    runs inside the run_one thread pool, so guard the temporary mutation with a lock
    and remove our specific entry by value — never a positional ``pop(0)`` that a
    concurrent insert could clobber.
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


def run_one(
    run_dir: Path,
    *,
    paths: LoopPaths = DEFAULT_PATHS,
    agents: Subagents | None = None,
    run_lead_author: Callable[[Path], None] | None = None,
) -> int:
    if agents is None:
        agents = ClaudePrintSubagents()
    if run_lead_author is None:
        run_lead_author = _invoke_lead_author

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

    # Lead-author (disposition-independent catalog refinement) and the two direction
    # legs are mutually independent: lead-author mutates only the git catalog tree
    # under its own repo lock and reads the run dir read-only; each leg writes disjoint
    # per-direction files and serializes shared findings/observation writes on locks.
    # subprocess.run releases the GIL while the claude child runs, so threads give real
    # wall-time overlap. Within a leg, actor→oracle→judge stays serial.
    ran: dict[str, bool] = {}
    errors: list[tuple[str, BaseException]] = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures: dict[Any, str] = {pool.submit(run_lead_author, run_dir): "lead_author"}
        for name in directions:
            futures[pool.submit(
                run_direction, BY_NAME[name], run_dir, learning_run_dir,
                disposition, alert_rule_key, run_id, held_out,
                paths=paths, agents=agents,
            )] = name
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                result = fut.result()
            except Exception as e:  # re-raised after all legs settle (fail loud)
                errors.append((name, e))
                continue
            if name in BY_NAME:
                ran[name] = bool(result)

    if errors:
        for name, e in errors:
            _log(f"{name} leg failed: {e!r}")
        raise errors[0][1]

    if not directions:
        _log(f"disposition={disposition} — no learning direction; skipping")
        return 0

    # Shared defender-findings curator fires if either direction appended; each
    # per-corpus observation curator fires only for the direction that produced it.
    if any(ran.values()):
        _maybe_trigger_author(paths.pending_file, "LEARNING_AUTHOR_THRESHOLD", "author", "pending")
    for name, did_run in ran.items():
        if did_run:
            t: ObsTrigger = BY_NAME[name].obs_trigger
            _maybe_trigger_author(
                t.pending_file(paths), t.threshold_env, t.module_name, t.pending_label
            )
    return 0


_HELP_EPILOG = """\
Direction dispatch (by the defender's normalized disposition):
  benign        → adversarial direction only (hunt the missed attack / FN)
  malicious     → benign direction only      (hunt the over-escalation / FP)
  inconclusive  → both directions
A disposition that maps to no direction is skipped.

Inputs (must exist in <run_dir>):
  alert.json            verbatim alert input
  report.md             YAML frontmatter with disposition ∈ {benign, inconclusive, malicious}
  investigation.md      defender's invlang audit log
  lead_sequence.yaml    projected lead set (emitted by defender/scripts/project_lead_sequence.py)
  gather_raw/{N}.json   raw query payloads referenced by lead_sequence

Outputs:
  defender/learning/runs/<run_id>/
    actor_input.yaml               adversarial actor-facing projection (queries only)
    actor_story.md / *_benign.md   per-direction story (or "SKIP: ...")
    projected_telemetry[_benign].yaml  routed oracle output: projections + uncovered + unrouted_leads
    projected_telemetry[_benign].raw.txt  stage-A footprint (raw LLM enumeration, pre-routing)
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
  FOOTPRINT_MODEL                      oracle stage-A footprint (sonnet by design —
                                       generative; stage B is the deterministic router)
  FOOTPRINT_EFFORT                     footprint reasoning effort (default: low — matching
                                       is the router's job, not the LLM's)
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
    parser.add_argument("run_dir", type=Path, help="Defender run dir")
    ns = parser.parse_args(argv[1:])

    run_dir = ns.run_dir.resolve()
    if not run_dir.is_dir():
        print(f"not a directory: {run_dir}", file=sys.stderr)
        return 1
    try:
        return run_one(run_dir)
    except LoopError as e:
        print(f"[loop] FATAL: {e}", file=sys.stderr)
        return 2
