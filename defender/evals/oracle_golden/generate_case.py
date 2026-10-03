#!/usr/bin/env python3
"""Recruit one oracle-calibration case against the live stack.

A detection rule firing is not required: the oracle never sees the alert, which exists
only to make `defender/run.py` emit a realistic lead set. If no rule fires, the alert is
synthesised from the runner record (`synthesise_alert`).

A `--target` the scenario cannot honour is refused before the stack is touched
(`retarget_problem`): a LOCAL scenario never reads `${target}`, but `runner.py` records the
override anyway, so every lead would investigate a host the activity never ran on.

  fire       playground-v2/attacks/runner.py run <scenario> --seed --user --target
  alert      the rule's own alert if one fired, else synthesised from the runner record
  envelope   defender/run.py <alert.json> --tenant playground --run-id <slug> --no-learn
  story      story_from_run.py <meta.json> <story.md>
  assemble   RETIRED — see the refusal in `main`
  controls   controls.py cases/<id>

**Recruitment is currently off.** The assemble step (finished run dir plus story into a
`cases/<id>` tree) has no implementation, so this refuses up front rather than firing a
scenario and failing after the expensive part. Every other step, and every reader of the
existing cases, still works. Restoring it needs the estate replay harness that succeeds
the oracle path.

Properties this path guarantees:

  - **the story cannot leak the evaluation**: the renderer's only input is the runner's
    record (`story_from_run.py`);
  - **a control uses the lead's own predicate**: it is the lead's own query with its
    `@timestamp` bounds moved (`controls.py`).

`--split` is set before the first replay runs, so no result can influence which side of
the split a case lands on.

Baseline generators stay **on**: the oracle's answer is a signed diff over baseline, so
with them off `+noise` cannot occur and `+event` is easier than production.

Usage (every run names its tenant, and there is no default — #1078; create one once with
`python3 defender/scripts/tenant.py setup playground`):
  generate_case.py --scenario cross-tier-ssh-probe --tenant playground --target web-2 \\
      --case-id case-010-... --split held-out --activity-family data-access/T1021.004
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
CATALOG = REPO_ROOT / "playground-v2" / "attacks" / "catalog.yaml"
RUNS_DIR = REPO_ROOT / "playground-v2" / "attacks" / "runs"
EXTRACT_ALERT = REPO_ROOT / "experiments" / "oracle-telemetry-fidelity" / "extract_alert.py"
DEFENDER_RUN = REPO_ROOT / "defender" / "run.py"
ENVIRONMENT_TEMPLATE = HERE / "environment_template.yaml"

#: The subprocess seam, injected in tests so alert selection and synthesis run without a
#: live stack.
Runner = Callable[..., subprocess.CompletedProcess]

#: How long to wait for a real rule before synthesising. Env-overridable because the right
#: wait is the rule's interval: a 5m-interval rule (the Falco ones) cannot fire within the
#: 2m default, so raise ORACLE_ALERT_ATTEMPTS past one rule tick to capture it.
ALERT_ATTEMPTS = int(os.environ.get("ORACLE_ALERT_ATTEMPTS", "4"))
ALERT_INTERVAL = int(os.environ.get("ORACLE_ALERT_INTERVAL", "30"))


def _run(cmd: list[str | Path], *, timeout: int, label: str) -> str:
    print(f"  [{label}] {' '.join(str(c) for c in cmd)[:160]}")
    proc = subprocess.run([str(c) for c in cmd], capture_output=True, text=True,
                          encoding="utf-8", timeout=timeout, check=False,
                          cwd=REPO_ROOT)
    if proc.returncode != 0:
        raise RuntimeError(f"{label} failed ({proc.returncode}):\n"
                           f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    return proc.stdout


def scenario_entry(scenario: str, catalog_path: Path) -> dict:
    # Imported here, like `_tenant` below: the script runs by path, and its stdlib-only paths
    # (`--help`, the argument checks) must not need `defender` importable.
    from defender import _yaml

    catalog = _yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    entries = catalog.get("scenarios") or catalog.get("attacks") or []
    for entry in entries:
        if entry.get("id") == scenario:
            return entry
    raise KeyError(f"{catalog_path.name} has no scenario {scenario!r}")


def honours_target(entry: dict) -> bool:
    """Do this scenario's own commands interpolate `${target}`?

    `runner.py` records a `--target` override whether or not any command reads it.
    """
    return any("${target}" in (step.get("cmd") or "")
               for step in entry.get("steps") or [])


def retarget_problem(scenario: str, target: str | None, source: str | None = None, *,
                     catalog_path: Path) -> str | None:
    """Why this scenario cannot be pointed at `target`, or `None` if it can.

    A LOCAL scenario never reads `${target}`; an override would reach only the record,
    story header and synthesised alert, so every lead would query an envelope that cannot
    contain the activity (unrecoverable by editing the manifest). `--source` is what
    relocates a local scenario, so it is coherent exactly when effective source equals
    effective target.
    """
    entry = scenario_entry(scenario, catalog_path)
    if honours_target(entry):
        # Source and target are meant to differ; the command carries the target itself.
        return None
    eff_source = source or entry.get("source_host")
    eff_target = target or entry.get("target_host")
    if eff_source == eff_target:
        return None
    return (
        f"scenario {scenario!r} runs entirely on {eff_source!r} — none of its steps "
        f"interpolate ${{target}} — but the story header, synthesised alert and every "
        f"lead would name {eff_target!r}. defender/run.py would investigate a host the "
        f"activity never touched. Point --source and --target at one host to relocate it "
        f"(e.g. --source {eff_target} --target {eff_target}), or recruit it at its own "
        f"default host."
    )


#: What a completed recruitment leaves behind; any of them means the id is taken.
#: `.generate/` alone means a run is in flight or died partway.
CASE_ARTIFACTS = ("manifest.yaml", "environment.yaml", "oracle_visible", "hidden")


def occupancy_problem(case_dir: Path) -> str | None:
    """Why this case id cannot be recruited into, or `None` if it is free.

    Two recruitments of one id interleave silently, producing a case assembled from both
    whose every file is individually well-formed. Refusing here makes the collision loud.
    """
    if not case_dir.exists():
        return None
    present = [name for name in CASE_ARTIFACTS if (case_dir / name).exists()]
    if present:
        return (f"{case_dir.name} already exists and holds {', '.join(present)}. "
                f"Recruiting into it would mix two captures into one case. Pick a new "
                f"case id, or delete the directory if the capture is being replaced.")
    if (case_dir / ".generate").exists():
        return (f"{case_dir.name}/.generate already exists — a recruitment is either in "
                f"flight or died partway. Two concurrent runs share this directory and "
                f"produce a case assembled from both. Wait for it, or delete the "
                f"directory if it is dead.")
    return None


def fire(scenario: str, *, seed: int, user: str | None, source: str | None,
         target: str | None, intensity: int | None) -> Path:
    """Run the scenario and return its runner record directory."""
    before = {p.name for p in RUNS_DIR.iterdir()} if RUNS_DIR.is_dir() else set()
    cmd: list[str | Path] = [sys.executable, RUNNER, "run", scenario, "--seed", str(seed)]
    for flag, value in (("--user", user), ("--source", source), ("--target", target),
                        ("--intensity", intensity)):
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

    The rule a scenario trips is not predictable from its name (`cross-tier-ssh-probe`
    against db-1 raises `v2-sshd-failed-auth-burst`), so take whatever actually fired.
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
    on_target: list[str] = []
    others: list[str] = []
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

    Every key `defender/run.py` consumes is derived from what the activity did. The rule
    id `synthetic-<scenario>` names no real rule, and the manifest records
    `alert_source: synthesised`, so nothing claims a rule fired.

    The alert itself does not say it is synthetic: the defender must investigate as it
    would in production. Provenance is disclosed in the manifest instead.
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


def investigate(
    alert: Path, run_id: str, *, tenant_id: object, run: Runner = subprocess.run,
) -> Path:
    """One defender investigation — the LLM cost floor, and the envelope source.

    `run.py` refuses to reuse a run dir, so a retry takes the next free suffix and the
    failed attempt's transcript survives. `tenant_id` is checked before anything is spent;
    the child `run.py` is handed it as `--tenant`.
    """
    from defender import _tenant

    tenant = _tenant.request_tenant(tenant_id)
    env_base = _tenant.runs_base_for(tenant)
    candidate, attempt = run_id, 1
    while (env_base / candidate).exists():
        attempt += 1
        candidate = f"{run_id}-{attempt}"
    proc = run(
        [sys.executable, DEFENDER_RUN, str(alert), "--run-id", candidate,
         "--tenant", tenant, "--no-learn"],
        capture_output=True, text=True, encoding="utf-8", timeout=3600, cwd=REPO_ROOT,
        check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"investigate failed ({proc.returncode}):\n"
                           f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    run_dir = env_base / candidate
    if not run_dir.is_dir():
        raise RuntimeError(f"defender run dir missing: {run_dir}")
    return run_dir


def write_environment(path: Path, capture_environment: str) -> None:
    """Emit the case's `environment.yaml`, a required input to both judge passes.

    Rendered from one template so every case says the same thing.
    """
    body = ENVIRONMENT_TEMPLATE.read_text(encoding="utf-8")
    path.write_text(body.format(capture_environment=capture_environment), encoding="utf-8")


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
        f"# No `state_classes:` here. It was the class-labelling architecture's way of\n"
        f"# declaring which lookups had nothing to diff; the label pass now derives\n"
        f"# `state-only` from the lead's own query systems and `environment.yaml`, so a\n"
        f"# hand-declared class could only disagree with the measurement (#711 §5).\n"
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


# lint-dup: ok — argparse scaffolding, not logic: a flag set for this one CLI, nothing to
# consolidate with the other `build_parser`s in the tree.
def build_parser() -> argparse.ArgumentParser:  # lint-dup: ok — argparse only
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scenario", required=True)
    p.add_argument("--tenant", required=True,
                   help="the tenant this case's investigation runs under (#1078 D4/J32)")
    p.add_argument("--rule", default=None,
                   help="detection rule to wait for; omit to take whichever rule the "
                        "activity actually raises (the usual case)")
    p.add_argument("--case-id", required=True, help="cases/<case-id> — the dir name IS the id")
    p.add_argument("--split", required=True, choices=["dev", "held-out"],
                   help="assigned BEFORE the first replay; that is what makes it honest")
    p.add_argument("--activity-family", required=True, help="the unit's family axis")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--user", default=None)
    p.add_argument("--source", default=None,
                   help="override source_host (where the commands run). For a LOCAL "
                        "scenario this is how it retargets; --target defaults to it so "
                        "the story, alert and leads all name the host it ran on.")
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


def _assemble(run_dir: Path, story: Path, controls_yaml: Path, case_dir: Path) -> None:
    """The unimplemented step, kept as a named hole documenting its shape: run dir, story and
    controls provenance in, one `cases/<id>` tree out. `main` refuses before reaching it."""
    raise SystemExit(
        "generate_case.py: the case assembler retired with the oracle in #922 "
        f"(wanted: {run_dir}, {story}, {controls_yaml} -> {case_dir})")


def main(argv: list[str] | None = None) -> int:
    """Parse, then refuse before the stack is touched: with no assemble step, a recruitment
    run would produce nothing usable. Argument validation still runs, `--tenant` first.
    """
    ns = build_parser().parse_args(argv)
    from defender import _tenant

    try:
        _tenant.request_tenant(ns.tenant)
    except _tenant.TenantRefused as refused:
        print(f"[generate_case] {refused}", file=sys.stderr)
        return 2
    print("!! generate_case.py cannot assemble a case: the assembler retired with the "
          "oracle in #922. The steps it drove are listed in this file's docstring; the "
          "existing cases under cases/ are still readable and scorable.", file=sys.stderr)
    return 2


def _recruit(argv: list[str] | None = None) -> int:
    """The recruitment run, uncalled; kept as the record of how the committed cases were made
    and as the template for a successor harness."""
    ns = build_parser().parse_args(argv)

    # A local scenario retargets on --source; default its target to match so `--source db-1`
    # alone is coherent.
    entry = scenario_entry(ns.scenario, CATALOG)
    if ns.source and ns.target is None and not honours_target(entry):
        ns.target = ns.source

    # Before touching the stack or creating `cases/<id>/`, so a refusal leaves nothing behind.
    problem = retarget_problem(ns.scenario, ns.target, ns.source, catalog_path=CATALOG)
    if problem is not None:
        print(f"!! {problem}", file=sys.stderr)
        return 2

    case_dir = ns.cases_dir / ns.case_id
    occupied = occupancy_problem(case_dir)
    if occupied is not None:
        print(f"!! {occupied}", file=sys.stderr)
        return 2

    work = case_dir / ".generate"
    work.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC) - timedelta(minutes=2)

    print(f"== generating {ns.case_id}  (split={ns.split})")
    run_record = fire(ns.scenario, seed=ns.seed, user=ns.user, source=ns.source,
                      target=ns.target, intensity=ns.intensity)
    meta = json.loads((run_record / "meta.json").read_text(encoding="utf-8"))
    print(f"  runner record: {run_record.name}")

    alert = work / "alert.json"  # lint-run-records: ok — an eval case's own file under the case tree, never a run record
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

    # Provenance only; the per-query controls are measured by controls.py below.
    controls_yaml = work / "controls.yaml"
    controls_yaml.write_text(
        "# Per-query controls are measured mechanically into hidden/controls/ by\n"
        "# controls.py: each is the lead's own query with only its @timestamp bounds\n"
        "# moved to a shape-matched window. This file records that provenance; it is\n"
        "# not a hand-measured baseline.\n"
        f"measured_by: controls.py\ngenerated_for: {ns.case_id}\n"
        f"operation_window: [\"{meta.get('started_at')}\", \"{meta.get('finished_at')}\"]\n",
        encoding="utf-8")

    run_dir = investigate(alert, f"golden-{ns.case_id}", tenant_id=ns.tenant)
    _assemble(run_dir, story, controls_yaml, case_dir)

    write_environment(case_dir / "environment.yaml", ns.capture_environment)
    write_manifest(case_dir / "manifest.yaml", case_id=ns.case_id, split=ns.split,
                   activity_family=ns.activity_family,
                   capture_environment=ns.capture_environment, scenario=ns.scenario,
                   seed=ns.seed, meta=meta, rule=rule, alert_source=alert_source)

    controls_cmd: list[str | Path] = [sys.executable, HERE / "controls.py", case_dir]
    if ns.offsets_days:
        controls_cmd += ["--offsets-days", ns.offsets_days]
    _run(controls_cmd, timeout=3600, label="controls")

    print(f"\ngenerated {case_dir}")
    print("  next: project the case, then score.py to grade")
    return 0


if __name__ == "__main__":  # lint-log-setup: ok — stdlib-only: run by path with no `defender` on the import path, so it cannot import the setup
    sys.exit(main())
