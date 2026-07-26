#!/usr/bin/env python3
"""Recruit one oracle-calibration case against the live stack (#711 M9, rebuilt §7).

Rebuilt thin. The previous recruiter polled 20 x 30s for a detection rule and then
`return 2` — discarding telemetry the activity had ALREADY produced. That threw away
two of the pilot campaign's six cells (`persistence-authorized-keys`,
`living-off-the-land`), which raise nothing once retargeted off canary-1.

The rule was never load-bearing. **The oracle does not see the alert** — `oracle/prompt.md`
opens by saying so — and the alert exists only to make `defender/run.py` emit a realistic
lead set. So a cell whose activity trips no rule is not an unrecruitable cell; it is a
cell whose alert has to come from somewhere else.

  fire       playground-v2/attacks/runner.py run <scenario> --seed --user --target
  alert      the rule's own alert if one fired, else synthesised from the runner record
  envelope   defender/run.py <alert.json> --run-id <slug> --no-learn
  story      story_from_run.py <meta.json> <story.md>
  assemble   build_case.py <run_dir> <story.md> <controls.yaml> cases/<id>
  controls   controls.py cases/<id>

Two properties the hand path could not guarantee, and this one gets for free:

  - **the story cannot leak the evaluation**, because the renderer's only input is the
    runner's record (`story_from_run.py`);
  - **a control uses the lead's own predicate**, because it IS the lead's own query with
    its `@timestamp` bounds moved (`controls.py`).

`--split` is a GENERATOR FLAG, set before the first replay ever runs. That is what makes
held-out honest here: there is no moment at which someone sees a result and then decides
which side of the split it belongs on.

Baseline generators stay **ON**. `attacks/catalog.yaml` used to advise disabling them,
which is right for capturing an alert fixture and wrong for calibration: the oracle's
answer is a signed diff over baseline, so with the generators off `+noise` cannot occur
at all and `+event` is easier than production.

Usage:
  generate_case.py --scenario persistence-authorized-keys --target db-1 \\
      --case-id case-006-... --split dev --activity-family persistence/T1098.004
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
RUNNER = REPO_ROOT / "playground-v2" / "attacks" / "runner.py"
RUNS_DIR = REPO_ROOT / "playground-v2" / "attacks" / "runs"
EXTRACT_ALERT = REPO_ROOT / "experiments" / "oracle-telemetry-fidelity" / "extract_alert.py"
DEFENDER_RUN = REPO_ROOT / "defender" / "run.py"

#: The subprocess seam. Injected in tests so alert selection and synthesis can be
#: exercised without a live stack — it is the piece that produced the campaign's one
#: silently-wrong case, so it needs to be testable.
Runner = Callable[..., subprocess.CompletedProcess]

#: How long to give a real rule before synthesising. The old recruiter waited ten
#: minutes and then threw the run away; the wait is now short because its outcome no
#: longer decides whether the case exists.
ALERT_ATTEMPTS = 4
ALERT_INTERVAL = 30


def _run(cmd: list[str | Path], *, timeout: int, label: str) -> str:
    print(f"  [{label}] {' '.join(str(c) for c in cmd)[:160]}")
    proc = subprocess.run([str(c) for c in cmd], capture_output=True, text=True,
                          encoding="utf-8", timeout=timeout, check=False,
                          cwd=REPO_ROOT)
    if proc.returncode != 0:
        raise RuntimeError(f"{label} failed ({proc.returncode}):\n"
                           f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    return proc.stdout


def fire(scenario: str, *, seed: int, user: str | None, target: str | None,
         intensity: int | None) -> Path:
    """Run the scenario and return its runner record directory."""
    before = {p.name for p in RUNS_DIR.iterdir()} if RUNS_DIR.is_dir() else set()
    cmd: list[str | Path] = [sys.executable, RUNNER, "run", scenario, "--seed", str(seed)]
    for flag, value in (("--user", user), ("--target", target), ("--intensity", intensity)):
        if value is not None:
            cmd += [flag, str(value)]
    _run(cmd, timeout=1800, label="fire")
    after = {p.name for p in RUNS_DIR.iterdir()}
    new = sorted(after - before)
    if not new:
        raise RuntimeError("runner wrote no new run record")
    return RUNS_DIR / new[-1]


def rules_fired_since(since: datetime, target_host: str | None = None, *,
                      run: Runner = subprocess.run) -> list[str]:
    """Detection rules that actually fired since `since`, most relevant first.

    The generator does NOT predict which rule a cell will trip. `cross-tier-ssh-probe`
    against db-1 raises `v2-sshd-failed-auth-burst`, not the `v2-cross-tier-ssh-pivot`
    its name suggests — so the case's alert is whatever the environment actually raised.
    """
    stamp = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    query = json.dumps({
        "size": 50,
        "sort": [{"@timestamp": "desc"}],
        "_source": ["kibana.alert.rule.rule_id", "host.name"],
        "query": {"range": {"@timestamp": {"gte": stamp}}},
    })
    proc = run([str(REPO_ROOT / "infra" / "bin" / "es.sh"),
                "/.internal.alerts-security.alerts-default-*/_search",
                "-H", "Content-Type: application/json", "-d", query],
               capture_output=True, text=True, encoding="utf-8", timeout=120, check=False)
    if proc.returncode != 0:
        return []
    try:
        hits = json.loads(proc.stdout)["hits"]["hits"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return []
    on_target, others = [], []
    for hit in hits:
        source = hit.get("_source") or {}
        rule = source.get("kibana.alert.rule.rule_id")
        if not rule:
            continue
        host = source.get("host.name")
        host = host[0] if isinstance(host, list) and host else host
        bucket = on_target if (target_host and host == target_host) else others
        if rule not in bucket:
            bucket.append(rule)
    return on_target + [r for r in others if r not in on_target]


def wait_for_alert(rule_id: str | None, since: datetime, out_path: Path, *,
                   target_host: str | None = None, run: Runner = subprocess.run,
                   attempts: int = ALERT_ATTEMPTS, interval: int = ALERT_INTERVAL,
                   sleep: Callable[[float], None] = time.sleep) -> str | None:
    """Poll for a real alert; return the rule id captured, or `None` if none fired.

    `None` is no longer terminal — see `synthesise_alert`.
    """
    stamp = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for attempt in range(1, attempts + 1):
        candidates = ([rule_id] if rule_id
                      else rules_fired_since(since, target_host, run=run))
        for candidate in candidates:
            try:
                _run([sys.executable, EXTRACT_ALERT, candidate, stamp, str(out_path)],
                     timeout=300, label=f"capture {attempt}/{attempts} {candidate}")
            except RuntimeError as exc:
                print(f"    {candidate}: {str(exc).splitlines()[0][:90]}")
                continue
            if out_path.is_file() and out_path.stat().st_size > 0:
                return candidate
        print(f"    attempt {attempt}/{attempts}: no usable alert yet")
        if attempt < attempts:
            sleep(interval)
    return None


def synthesise_alert(meta: dict, out_path: Path) -> dict:
    """Build the alert the activity WOULD have raised, from the runner's own record.

    The nine keys `defender/run.py` consumes, every one of them derived from what the
    activity actually did — host and user from the runner's resolved facts, the window
    from its timestamps, the index from the step it ran. Nothing here asserts that a
    detection rule fired: the rule id is `synthetic-<scenario>`, which names no rule in
    `install_detection_rules.py`, and the manifest records `alert_source: synthesised`
    beside it. A case whose alert claims a rule that never fired would be a fabricated
    record, and the whole suite is an argument about not fabricating records.

    What it deliberately does NOT do is tell the defender it is synthetic. The premise
    being preserved is "the envelope production actually issues", and a defender told
    its alert is a test artifact is not investigating under that premise. The synthesis
    is disclosed where a reader looks for provenance — the manifest — not inside the
    input whose realism is the point.
    """
    resolved = meta.get("resolved") or {}
    steps = meta.get("steps") or []
    host = resolved.get("target_host") or "unknown"
    scenario = meta.get("scenario_id") or "activity"
    run_id = meta.get("run_id") or scenario
    alert = {
        "alert_id": hashlib.sha256(run_id.encode("utf-8")).hexdigest(),
        "alert_timestamp": meta.get("finished_at") or meta.get("started_at"),
        "rule": {
            "id": f"synthetic-{scenario}",
            "name": f"synthetic {scenario.replace('-', ' ')}",
            "type": "query",
            "severity": "medium",
            "risk_score": 47,
            "tags": ["v2", "synthetic", scenario],
            "description": (meta.get("description") or "").strip()
            or f"Activity from the {scenario} scenario on {host}.",
            "language": "lucene",
            "query": f"host.name:{host}",
        },
        "reason": f"event on {host} created medium alert synthetic {scenario}.",
        "host": {"name": host},
        "user": {"name": resolved.get("source_user")},
        "ancestor_events": [
            {"id": f"{run_id}-{i}", "type": "event", "index": "logs-*", "depth": 0}
            for i, _ in enumerate(steps[:1])
        ],
        "signal_index": ".internal.alerts-security.alerts-default-*",
        "threshold_result": None,
    }
    out_path.write_text(json.dumps(alert, indent=1) + "\n", encoding="utf-8")
    return alert


def investigate(alert: Path, run_id: str) -> Path:
    """One defender investigation — the LLM cost floor, and the envelope source.

    `run.py` refuses to reuse an existing run dir, so a retried cell picks the next free
    suffix rather than clobbering the earlier attempt's transcript. Keeping the failed
    attempt is deliberate: it is the only record of why it failed.
    """
    env_base = Path(os.environ.get("DEFENDER_RUNS_BASE", "/tmp/defender-runs"))
    candidate, attempt = run_id, 1
    while (env_base / candidate).exists():
        attempt += 1
        candidate = f"{run_id}-{attempt}"
    _run([sys.executable, DEFENDER_RUN, str(alert), "--run-id", candidate, "--no-learn"],
         timeout=3600, label="investigate")
    run_dir = env_base / candidate
    if not run_dir.is_dir():
        raise RuntimeError(f"defender run dir missing: {run_dir}")
    return run_dir


def write_manifest(  # noqa: PLR0913 — the manifest's fields, each an independent fact
                   path: Path, *, case_id: str, split: str, activity_family: str,
                   capture_environment: str, scenario: str, seed: int, meta: dict,
                   rule: str, alert_source: str) -> None:
    resolved = meta.get("resolved") or {}
    source_host = (meta.get("steps") or [{}])[0].get("source_host", "?")
    path.write_text(
        f"case_id: {case_id}\n"
        f"kind: observed\n"
        f"# --- calibration metadata (#711) ---\n"
        f"# Assigned by the generator BEFORE the first replay: nothing has been scored\n"
        f"# at this point, so no result could have influenced which side this lands on.\n"
        f"split: {split}\n"
        f"unit:\n"
        f"  activity_family: {activity_family}\n"
        f"  host_pair: {source_host}->{resolved.get('target_host', '?')}\n"
        f"capture_environment: {capture_environment}\n"
        f"# Declare a class for every state/lookup system this case's leads touch.\n"
        f"# A lookup has no @timestamp bounds to move, so it has no baseline and no\n"
        f"# diff semantics — the judge reads that as `state-only`, not as a gap.\n"
        f"state_classes: {{}}\n"
        f"attack:\n"
        f"  scenario: {scenario}\n"
        f"  seed: {seed}\n"
        f"  runner_run_id: {meta.get('run_id')}\n"
        f"  window: [\"{meta.get('started_at')}\", \"{meta.get('finished_at')}\"]\n"
        f"  alert_rule: {rule}\n"
        f"  # `captured` = a real rule fired and its alert was extracted.\n"
        f"  # `synthesised` = nothing fired; the alert was built from the runner record\n"
        f"  # so the activity's telemetry is not discarded. The oracle never sees the\n"
        f"  # alert either way (oracle/prompt.md:1) — it only shapes the lead set.\n"
        f"  alert_source: {alert_source}\n"
        f"generated_by: generate_case.py\n",
        encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scenario", required=True)
    p.add_argument("--rule", default=None,
                   help="detection rule to wait for; omit to take whichever rule the "
                        "activity actually raises (the usual case)")
    p.add_argument("--case-id", required=True, help="cases/<case-id> — the dir name IS the id")
    p.add_argument("--split", required=True, choices=["dev", "held-out"],
                   help="assigned BEFORE the first replay; that is what makes it honest")
    p.add_argument("--activity-family", required=True, help="the unit's family axis")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--user", default=None)
    p.add_argument("--target", default=None)
    p.add_argument("--intensity", type=int, default=None)
    p.add_argument("--capture-environment", default="playground-v2@live")
    p.add_argument("--offsets-days", default=None,
                   help="whole-week control offsets, e.g. 14,21,28. The playground is "
                        "levered up and down, so the DEFAULT 7,14,21 can put a control "
                        "in a gap where the stack did not exist — a dead window is not "
                        "an empty baseline, and a third of the evidence is lost to it. "
                        "Probe the ingest timeline first and pick offsets that land on "
                        "live days; whole weeks keep the weekday, which the "
                        "schedule-shaped generators require.")
    p.add_argument("--cases-dir", type=Path, default=HERE / "cases")
    return p


def main(argv: list[str] | None = None) -> int:
    ns = build_parser().parse_args(argv)

    case_dir = ns.cases_dir / ns.case_id
    work = case_dir / ".generate"
    work.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC) - timedelta(minutes=2)

    print(f"== generating {ns.case_id}  (split={ns.split})")
    run_record = fire(ns.scenario, seed=ns.seed, user=ns.user, target=ns.target,
                      intensity=ns.intensity)
    meta = json.loads((run_record / "meta.json").read_text(encoding="utf-8"))
    print(f"  runner record: {run_record.name}")

    alert = work / "alert.json"
    fired = wait_for_alert(ns.rule, started, alert,
                           target_host=(meta.get("resolved") or {}).get("target_host"))
    if fired is None:
        synthetic = synthesise_alert(meta, alert)
        rule, alert_source = synthetic["rule"]["id"], "synthesised"
        print(f"  no rule fired — synthesised {rule} from the runner record. "
              f"The telemetry stands regardless; the oracle never sees the alert.")
    else:
        rule, alert_source = fired, "captured"
        print(f"  captured alert from rule: {rule}")

    story = work / "story.md"
    _run([sys.executable, HERE / "story_from_run.py", run_record / "meta.json", story],
         timeout=120, label="story")

    # build_case.py wants a controls.yaml verbatim; the real, per-query controls are
    # measured by controls.py below. This records the provenance of that measurement
    # rather than pretending to be a hand-measured baseline.
    controls_yaml = work / "controls.yaml"
    controls_yaml.write_text(
        "# Per-query controls are measured mechanically into hidden/controls/ by\n"
        "# controls.py: each is the lead's own query with only its @timestamp bounds\n"
        "# moved to a shape-matched window. This file records that provenance; it is\n"
        "# not a hand-measured baseline.\n"
        f"measured_by: controls.py\ngenerated_for: {ns.case_id}\n"
        f"operation_window: [\"{meta.get('started_at')}\", \"{meta.get('finished_at')}\"]\n",
        encoding="utf-8")

    run_dir = investigate(alert, f"golden-{ns.case_id}")
    _run([sys.executable, HERE / "build_case.py", run_dir, story, controls_yaml, case_dir],
         timeout=600, label="assemble")

    write_manifest(case_dir / "manifest.yaml", case_id=ns.case_id, split=ns.split,
                   activity_family=ns.activity_family,
                   capture_environment=ns.capture_environment, scenario=ns.scenario,
                   seed=ns.seed, meta=meta, rule=rule, alert_source=alert_source)

    controls_cmd: list[str | Path] = [sys.executable, HERE / "controls.py", case_dir]
    if ns.offsets_days:
        controls_cmd += ["--offsets-days", ns.offsets_days]
    _run(controls_cmd, timeout=3600, label="controls")

    print(f"\ngenerated {case_dir}")
    print("  next: declare state_classes in manifest.yaml, then replay.py to project "
          "and score.py to grade")
    return 0


if __name__ == "__main__":
    sys.exit(main())
