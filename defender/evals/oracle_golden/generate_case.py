#!/usr/bin/env python3
"""Generate one oracle-calibration case end to end against the live stack (#711 M9).

The recruitment method. Cases used to be hand-captured, which is why there are
six of them and why the suite cannot certify anything: the sizing arithmetic
needs ~35 independent units at a perfect observed rate, and a unit costs a human
an afternoon. This orchestrates the tools that already exist:

  fire       playground-v2/attacks/runner.py run <scenario> --seed --user --target
  capture    experiments/oracle-telemetry-fidelity/extract_alert.py <rule> <since> <out>
  envelope   defender/run.py <alert.json> --run-id <slug> --no-learn
  story      story_from_run.py <meta.json> <story.md>
  assemble   build_case.py <run_dir> <story.md> <controls.yaml> cases/<id>
  controls   controls.py cases/<id>
  label      label.py, via --write-expected

Two properties the hand path could not guarantee, and this one gets for free:

  - **the story cannot leak the evaluation**, because the renderer's only input is
    the runner's record (`story_from_run.py`);
  - **a control uses the lead's own predicate**, because it IS the lead's own
    query with its bounds moved (`controls.py`).

`--split` is a GENERATOR FLAG, set before the first replay ever runs. That is what
makes held-out honest here: there is no moment at which someone sees a result and
then decides which side of the split it belongs on.

Baseline generators stay **ON**. `attacks/catalog.yaml` used to advise disabling
them, which is right for capturing an alert fixture and wrong for calibration:
the oracle's class is a signed diff over baseline, so with the generators off
`+noise` cannot occur at all and `+event` is easier than production.

Usage:
  generate_case.py --scenario ssh-brute-force-canary --target db-1 --user dev.dana \\
      --rule v2-sshd-failed-auth-burst --case-id case-007-... --split held-out \\
      --activity-family brute-force/T1110.001
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, UTC
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
RUNNER = REPO_ROOT / "playground-v2" / "attacks" / "runner.py"
RUNS_DIR = REPO_ROOT / "playground-v2" / "attacks" / "runs"
EXTRACT_ALERT = REPO_ROOT / "experiments" / "oracle-telemetry-fidelity" / "extract_alert.py"
DEFENDER_RUN = REPO_ROOT / "defender" / "run.py"


def _run(cmd: list[str | Path], *, timeout: int, label: str) -> str:
    print(f"  [{label}] {' '.join(str(c) for c in cmd)[:160]}")
    proc = subprocess.run([str(c) for c in cmd], capture_output=True, text=True,
                          timeout=timeout, check=False, cwd=REPO_ROOT)
    if proc.returncode != 0:
        raise RuntimeError(f"{label} failed ({proc.returncode}):\n"
                           f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    return proc.stdout


def fire(scenario: str, *, seed: int, user: str | None, target: str | None,
         intensity: int | None) -> Path:
    """Run the scenario and return its runner record directory."""
    before = {p.name for p in RUNS_DIR.iterdir()} if RUNS_DIR.is_dir() else set()
    cmd: list[str | Path] = [sys.executable, RUNNER, "run", scenario,
                             "--seed", str(seed)]
    for flag, value in (("--user", user), ("--target", target),
                        ("--intensity", intensity)):
        if value is not None:
            cmd += [flag, str(value)]
    _run(cmd, timeout=1800, label="fire")
    after = {p.name for p in RUNS_DIR.iterdir()}
    new = sorted(after - before)
    if not new:
        raise RuntimeError("runner wrote no new run record")
    return RUNS_DIR / new[-1]


def rules_fired_since(since: datetime, target_host: str | None = None) -> list[str]:
    """Detection rules that actually fired since `since`, most relevant first.

    The generator does NOT predict which rule a cell will trip. `cross-tier-ssh-probe`
    against db-1 raises `v2-sshd-failed-auth-burst`, not the `v2-cross-tier-ssh-pivot`
    its name suggests — and waiting for a predicted rule would have recorded that
    cell as unreachable while its alert sat in the index. The case's alert is
    whatever the environment actually raised.

    Rules whose alert names `target_host` come FIRST, because the baseline
    generators are deliberately left running: unrelated alerts fire during the
    capture window, and investigating one of those would bind a story to an
    envelope its activity never touched. Alerts on other hosts are still returned,
    after — but a case built from one should be read as a negative control, not as
    a capture of this cell.
    """
    stamp = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = json.dumps({
        "size": 200, "sort": [{"@timestamp": "desc"}],
        "query": {"range": {"@timestamp": {"gte": stamp}}},
        "_source": ["kibana.alert.rule.rule_id", "host.name"],
    })
    proc = subprocess.run(
        [str(REPO_ROOT / "infra" / "bin" / "es.sh"),
         "/.internal.alerts-security.alerts-default-*/_search",
         "-H", "Content-Type: application/json", "-d", body],
        capture_output=True, text=True, timeout=180, check=False)
    if proc.returncode != 0:
        return []
    on_target: list[str] = []
    elsewhere: list[str] = []
    for hit in json.loads(proc.stdout).get("hits", {}).get("hits", []):
        source = hit.get("_source") or {}
        rule = source.get("kibana.alert.rule.rule_id")
        if not rule:
            continue
        host = source.get("host.name")
        if isinstance(host, dict):
            host = host.get("name")
        if isinstance(host, list):
            host = host[0] if host else None
        bucket = on_target if (target_host and host == target_host) else elsewhere
        if rule not in bucket:
            bucket.append(rule)
    return on_target + [r for r in elsewhere if r not in on_target]


def wait_for_alert(rule_id: str | None, since: datetime, out_path: Path, *,
                   target_host: str | None = None,
                   attempts: int = 20, interval: int = 30) -> str | None:
    """Poll until a rule fires; return the rule id captured, or `None`.

    `None` means no rule fired at all. That is a real outcome, not a generator
    failure: a cell whose activity trips nothing has no alert to investigate and
    therefore no CAPTURED envelope, which is exactly why cases 002-004 carry
    `lead_source: authored`.
    """
    stamp = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    for attempt in range(1, attempts + 1):
        candidates = ([rule_id] if rule_id
                      else rules_fired_since(since, target_host))
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
        time.sleep(interval)
    return None


def investigate(alert: Path, run_id: str) -> Path:
    """One defender investigation — the LLM cost floor, and the envelope source.

    `run.py` refuses to reuse an existing run dir, so a retried cell picks the next
    free suffix rather than clobbering the earlier attempt's transcript. Keeping
    the failed attempt is deliberate: it is the only record of why it failed.
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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scenario", required=True)
    p.add_argument("--rule", default=None,
                   help="detection rule to wait for; omit to take whichever rule "
                        "the activity actually raises (the usual case)")
    p.add_argument("--case-id", required=True, help="cases/<case-id> — the dir name IS the id")
    p.add_argument("--split", required=True, choices=["dev", "held-out"],
                   help="assigned BEFORE the first replay; that is what makes it honest")
    p.add_argument("--activity-family", required=True, help="the unit's family axis")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--user", default=None)
    p.add_argument("--target", default=None)
    p.add_argument("--intensity", type=int, default=None)
    p.add_argument("--capture-environment", default="playground-v2@live")
    p.add_argument("--cases-dir", type=Path, default=HERE / "cases")
    ns = p.parse_args(argv)

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
                           target_host=(meta.get('resolved') or {}).get('target_host'))
    if fired is None:
        print("!! no detection rule fired for this cell. No alert means no captured "
              "envelope; recruit it with authored leads instead.")
        return 2
    print(f"  captured alert from rule: {fired}")

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

    manifest = case_dir / "manifest.yaml"
    manifest.write_text(
        f"case_id: {ns.case_id}\n"
        f"kind: observed\n"
        f"# --- calibration metadata (#711) ---\n"
        f"# Assigned by the generator BEFORE the first replay: nothing has been scored\n"
        f"# at this point, so no result could have influenced which side this lands on.\n"
        f"split: {ns.split}\n"
        f"unit:\n"
        f"  activity_family: {ns.activity_family}\n"
        f"  host_pair: {meta.get('steps', [{}])[0].get('source_host', '?')}"
        f"->{(meta.get('resolved') or {}).get('target_host', '?')}\n"
        f"capture_environment: {ns.capture_environment}\n"
        f"# Declare a class for every state/lookup system this case's leads touch, or\n"
        f"# label.py emits `needs-label` rather than defaulting them to `0`.\n"
        f"state_classes: {{}}\n"
        f"attack:\n"
        f"  scenario: {ns.scenario}\n"
        f"  seed: {ns.seed}\n"
        f"  runner_run_id: {run_record.name}\n"
        f"  window: [\"{meta.get('started_at')}\", \"{meta.get('finished_at')}\"]\n"
        f"  alert_rule: {fired}\n"
        f"generated_by: generate_case.py\n",
        encoding="utf-8")

    _run([sys.executable, HERE / "controls.py", case_dir], timeout=3600, label="controls")

    print(f"\ngenerated {case_dir}")
    print("  next: declare state_classes in manifest.yaml, write expected.yaml from the\n"
          "        derived labels (audit_labels.py shows them), then replay.py + score.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
