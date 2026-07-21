#!/usr/bin/env python3

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

DEFENDER_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEFENDER_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender._run_paths import RunPaths  # noqa: E402

VISUALIZE_SCRIPT = DEFENDER_DIR / "scripts" / "visualize" / "visualize_run.py"

DEFAULT_RUNS_BASE = Path("/tmp/defender-runs")


def resolve_runs_base() -> Path:
    base = Path(os.environ.get("DEFENDER_RUNS_BASE", str(DEFAULT_RUNS_BASE)))
    from defender._env import FatalConfigError
    from defender.learning.core.config import learning_state_root

    if base.resolve() == learning_state_root().resolve():
        raise FatalConfigError(
            "DEFENDER_RUNS_BASE and the learning state root "
            "(DEFENDER_LEARNING_STATE_DIR) resolve to the same directory "
            f"({base.resolve()}): the enforced runtime budget pool would be spent by "
            "unenforced learning agents. Point them at distinct directories."
        )
    return base


_GENERIC_ALERT_STEMS = {"alert"}


def _alert_label(alert: Path) -> str:
    return alert.parent.name if alert.stem in _GENERIC_ALERT_STEMS else alert.stem


def materialize_run_dir(alert: Path, run_id: str | None) -> tuple[Path, str]:
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    runs_base = resolve_runs_base()
    if run_id is None:
        ts = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{ts}-{_alert_label(alert)}"
    run_dir = runs_base / run_id
    if run_dir.exists():
        sys.exit(f"run dir already exists: {run_dir}")
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    shutil.copy(alert, RunPaths(run_dir).alert)
    salt = secrets.token_hex(8)
    return run_dir, salt


def run_env(defender_dir: Path, run_dir: Path) -> dict[str, str]:
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    env["DEFENDER_DIR"] = str(defender_dir)
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    env["DEFENDER_RUNS_BASE"] = str(run_dir.parent)
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    return env


def visualize(run_dir: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(VISUALIZE_SCRIPT), str(run_dir)],
        capture_output=True, text=True, encoding="utf-8"
    )
    sys.stderr.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(f"[run.py] visualize_run failed: {proc.stderr}")


def cross_check_tables(run_dir: Path) -> None:
    if not RunPaths(run_dir).investigation.is_file():
        return
    try:
        from defender.learning import lead_repository

        xcheck = lead_repository.narration_crosscheck_from_run(run_dir)
    except Exception as e:  # noqa: BLE001 — diagnostics must never break the run
        print(f"[run.py] narration cross-check skipped: {e!r}", file=sys.stderr)
        return
    if not xcheck["ok"]:
        print(
            "[run.py] WARN narration cross-check FAILED — the live tables "
            "disagree with investigation.md's :L rows:",
            file=sys.stderr,
        )
        if xcheck["missing_from_narration"]:
            print(f"[run.py]   table lead_ids with no :L row: {xcheck['missing_from_narration']}", file=sys.stderr)
        if xcheck["queries_without_lead"]:
            print(f"[run.py]   query FKs with no lead sidecar (orphans): {xcheck['queries_without_lead']}", file=sys.stderr)
    if xcheck["leads_without_queries"]:
        print(f"[run.py]   note: leads with no queries (monitor): {xcheck['leads_without_queries']}", file=sys.stderr)


HELD_OUT_FIXTURES = DEFENDER_DIR / "fixtures" / "held-out"


def is_held_out_fixture(alert: Path, fixtures_dir: Path = HELD_OUT_FIXTURES) -> bool:
    try:
        alert.resolve().relative_to(fixtures_dir.resolve())
    except ValueError:
        return False
    return True


def held_out_alert_digests(fixtures_dir: Path = HELD_OUT_FIXTURES) -> set[str]:
    out: set[str] = set()
    if not fixtures_dir.is_dir():
        return out
    for child in sorted(fixtures_dir.iterdir()):
        alert = RunPaths(child).alert
        try:
            out.add(hashlib.sha256(alert.read_bytes()).hexdigest())
        except OSError:
            continue
    return out


def is_held_out_alert_copy(alert: Path, fixtures_dir: Path = HELD_OUT_FIXTURES) -> bool:
    try:
        digest = hashlib.sha256(alert.read_bytes()).hexdigest()
    except OSError:
        return False
    return digest in held_out_alert_digests(fixtures_dir)


def enqueue_learning(run_dir: Path, alert: Path, *, truncated_by: str | None = None) -> bool:
    if truncated_by is not None:
        print(
            f"[run.py] run was truncated (truncated_by={truncated_by!r}) — NOT enqueuing "
            "for learning (a truncated investigation must not train the corpus)",
            file=sys.stderr,
        )
        return False
    if is_held_out_fixture(alert):
        print(
            f"[run.py] {alert.parent.name}/{alert.name} is a held-out eval fixture — NOT "
            "enqueuing for learning (its findings must never feed a corpus it is scored "
            "against)",
            file=sys.stderr,
        )
        return False
    from defender.learning import loop as _loop
    from defender.learning.core.config import REPO_ROOT as _LEARN_REPO_ROOT
    from defender.learning.core.config import LoopPaths, _env_state_dir

    paths = LoopPaths(repo_root=_LEARN_REPO_ROOT, state_dir=_env_state_dir())
    _loop.enqueue_for_learning(run_dir, paths)
    return True
