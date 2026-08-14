#!/usr/bin/env python3

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

DEFENDER_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEFENDER_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender._run_id import RUN_ID_ALLOWED, is_valid_run_id  # noqa: E402
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


def materialize_run_dir(alert: Path, run_id: str | None) -> Path:
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    if run_id is None:
        ts = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{ts}-{_alert_label(alert)}"
    if not is_valid_run_id(run_id):
        sys.exit(f"invalid run id {run_id!r} (allowed: {RUN_ID_ALLOWED})")
    runs_base = resolve_runs_base()
    run_dir = runs_base / run_id
    if run_dir.exists():
        sys.exit(f"run dir already exists: {run_dir}")
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    shutil.copy(alert, RunPaths(run_dir).alert)
    return run_dir


def run_env(defender_dir: Path, run_dir: Path) -> dict[str, str]:
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    env["DEFENDER_DIR"] = str(defender_dir)
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    env["DEFENDER_RUNS_BASE"] = str(run_dir.parent)
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    # PREPENDED, not assigned: this env also drives the adapter/query/orient host
    # subprocesses, which inherit whatever PYTHONPATH the operator's shell set. Clobbering it
    # would silently drop those entries — mirror the additive shape PATH uses one line up.
    env["PYTHONPATH"] = _prepend(str(defender_dir.parent), env.get("PYTHONPATH"))
    return env


def _prepend(head: str, tail: str | None) -> str:
    return f"{head}{os.pathsep}{tail}" if tail else head


class VisualizeFailed(Exception):
    """The visualizer subprocess exited non-zero; the caller must not treat the run dir
    as rendered — a page left over from a prior render is not proof this one succeeded."""


def visualize(run_dir: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(VISUALIZE_SCRIPT), str(run_dir)],
        capture_output=True, text=True, encoding="utf-8"
    )
    sys.stderr.write(proc.stdout)
    if proc.returncode != 0:
        sys.stderr.write(f"[run.py] visualize_run failed: {proc.stderr}")
        raise VisualizeFailed(
            f"visualize_run failed for {run_dir} (exit {proc.returncode}): {proc.stderr}")


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


def learning_refusal_gate(
    run_dir: Path,
    alert: Path,
    *,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
    truncated_by: str | None = None,
) -> str | None:
    """The ONE refusal predicate both the learning enqueue and the curation enqueue consult
    (#791 R3): a copied guard drifts from the thing it documents, a shared one cannot. Returns
    the reason a run must be refused, or `None` if it clears every net.

    Held out is checked by CONTENT DIGEST *and* by path containment, because neither net alone
    is the whole set: the digest catches a copy of a fixture taken outside `fixtures_dir`
    (containment misses it by construction), and containment catches anything inside the
    fixture tree that the digest walk never reads — it only digests `<slug>/alert.json`."""
    if truncated_by is not None:
        return f"run was truncated (truncated_by={truncated_by!r}) — a truncated " \
            "investigation must not train the corpus"
    # BOTH nets, not the digest alone. The digest catches a copy taken outside `fixtures_dir`,
    # which path containment misses by construction — but containment catches a fixture whose
    # alert the digest walk never reads (it only reads `<fixtures>/<slug>/alert.json`), which
    # the digest misses by construction. Dropping either one narrows the guard.
    if is_held_out_fixture(alert, fixtures_dir) or is_held_out_alert_copy(alert, fixtures_dir):
        return f"{alert} is a held-out eval fixture (or a copy of one) — its findings must " \
            "never feed a corpus it is scored against"
    from defender.runtime import scrub as _scrub

    if not _scrub.tree_verified(run_dir):
        # §7 D2/D9: a tree carrying no scan verdict, or one recording that the walk never ran,
        # is not fed to the learning loop — the crash path this marker exists to describe is
        # exactly the one most likely to hold what a box planted.
        return f"{run_dir} carries no completed reap-scan verdict — an unverified tree " \
            "must not feed the corpus"
    return None


def enqueue_learning(
    run_dir: Path,
    alert: Path,
    *,
    truncated_by: str | None = None,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
) -> bool:
    reason = learning_refusal_gate(
        run_dir, alert, fixtures_dir=fixtures_dir, truncated_by=truncated_by
    )
    if reason is not None:
        print(f"[run.py] NOT enqueuing for learning: {reason}", file=sys.stderr)
        return False
    from defender.learning import loop as _loop
    from defender.learning.core.config import REPO_ROOT as _LEARN_REPO_ROOT
    from defender.learning.core.config import LoopPaths, _env_state_dir

    paths = LoopPaths(repo_root=_LEARN_REPO_ROOT, state_dir=_env_state_dir())
    _loop.enqueue_for_learning(run_dir, paths)
    return True


def enqueue_curation(
    run_dir: Path,
    alert: Path,
    *,
    truncated_by: str | None = None,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
) -> bool:
    """Catalog curation's own trigger, at the investigation boundary (#791) — welded to the
    shared refusal predicate rather than left to caller discipline (PR5): this is the one new
    caller in the change that hands attacker-influenced content (the investigation's goal
    text, bound parameters, rendered queries) to the lead-author curator, and the predicate is
    what makes misuse constructible at all now that it is no longer inline in the enqueue that
    "not refused" used to mean "already enqueued"."""
    reason = learning_refusal_gate(
        run_dir, alert, fixtures_dir=fixtures_dir, truncated_by=truncated_by
    )
    if reason is not None:
        print(f"[run.py] NOT enqueuing for curation: {reason}", file=sys.stderr)
        return False
    from defender.learning.core import markers as _markers
    from defender.learning.core.config import REPO_ROOT as _LEARN_REPO_ROOT
    from defender.learning.core.config import LoopPaths, _env_state_dir

    paths = LoopPaths(repo_root=_LEARN_REPO_ROOT, state_dir=_env_state_dir())
    # The case-key derivation is inside the guard with the write it feeds: it reads the alert
    # off disk, and an alert the operator moved mid-run would otherwise take the investigation's
    # exit status and its remaining human-facing steps down with it — for a corpus optimisation
    # this call site has already declared cheap to lose.
    try:
        case_id = f"case-{hashlib.sha256(alert.read_bytes()).hexdigest()[:16]}"
        _markers.enqueue_case_for_curation(case_id, run_dir, paths)
    except OSError as e:
        print(f"[run.py] NOT enqueuing for curation: could not write the request: {e!r}",
              file=sys.stderr)
        return False
    return True
