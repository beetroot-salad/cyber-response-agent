#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import subprocess
import sys
import dataclasses as _dataclasses
from pathlib import Path
from typing import TYPE_CHECKING

DEFENDER_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEFENDER_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender import _io, _provenance, _tenant  # noqa: E402
from defender._io import guarded_mkdir  # noqa: E402
from defender._run_handle import Run, case_ref  # noqa: E402
from defender._run_id import mint_run_id, refuse_bad_run_id  # noqa: E402
from defender._run_paths import RunPaths, artifact_dir  # noqa: E402

_logger = logging.getLogger(__name__)

VISUALIZE_SCRIPT = DEFENDER_DIR / "scripts" / "visualize" / "visualize_run.py"

if TYPE_CHECKING:
    from defender.runtime.branch._family import ResumeWorld

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


def _setup_state(run: Run) -> str:
    """What is under this run id already: `absent`, `setup` (only what setup writes; resumable)
    or `ran` (a run has been in this tree; never materialised into again).

    Judged by name without following links: a link at the run id is refused, and any sidecar
    beside the directory counts as the run's trace."""
    run_dir = run.run_dir
    if not _io.entry_present(run_dir):
        return "absent"
    if not artifact_dir(run_dir):
        sys.exit(f"{run_dir} is not a directory — refusing to materialise a run over it")
    with _io.bind(run_dir) as tree:
        listing = tree.entries()
    if listing.reason is not None:
        sys.exit(f"{run_dir} could not be listed ({listing.reason}) — refusing to resume it")
    # Everything setup writes; anything else means a run has been here.
    paths = RunPaths(run_dir)
    setup_names = {paths.alert.name, paths.gather_raw.name, paths.provenance.name}
    extra = sorted(set(listing.entries or {}) - setup_names)
    # The scrub verdict is written at box start, so even a box that died before writing into
    # the tree leaves a sidecar.
    sidecars = (run.facts.run_end.path, run.facts.scrub_verdict.path, run.facts.accounting.path)
    if extra or any(_io.entry_present(p) for p in sidecars):
        return "ran"
    return "setup"


def materialize_run_dir(
    alert: Path, run_id: str | None, *, model: str | None = None,
    world: ResumeWorld | None = None, tenant_id: str | None = None,
    expected_record: _tenant.TenantRecord | None = None,
) -> Path:
    """Build (or finish building) the run directory for `run_id` through the handle.

    `tenant_id` is the tenant the caller resolved, and `expected_record` the tenant record it
    resolved it from (`None` if the base had none); with no `tenant_id` the record decides.
    The record is created here when absent, then a record naming another tenant or differing
    from `expected_record` is refused rather than stamped.

    Every write is a guarded write-once verb (written when absent, kept when equal, refused
    when different), so resuming needs no ordering of checks and follows no planted link.
    `world` is a fork's `ResumeWorld`, handed in by the launcher — never derived from paths.
    """
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    run_id = _admit_run_id(alert, run_id)
    runs_base = resolve_runs_base()
    # The runs base is the host-controlled trust root; nothing above it is judged.
    guarded_mkdir(runs_base, base=runs_base)
    # The tenant record comes before the provenance stamp (which must match it) and before the
    # box exists. Unlike the stamp, its failures propagate: a forged tenant is worse than no run.
    if tenant_id is None:
        tenant_record = _tenant.ensure_tenant(runs_base)
        chosen = tenant_record.tenant_id
    else:
        tenant_record = _tenant.ensure_tenant(runs_base, tenant_id=tenant_id)
        chosen = tenant_id
    if expected_record is not None and tenant_record != expected_record:
        raise _tenant.TenantRecordMismatch(
            f"the tenant record at {_tenant.record_path(runs_base)} changed after this run's "
            f"tenant was chosen from it (read {expected_record}, now {tenant_record}) — the "
            "run would be stamped with a record its settings were not resolved from")
    run = Run.for_tenant(chosen, run_id, runs_base=runs_base)
    run_dir = run.run_dir
    paths = RunPaths(run_dir)

    state = _setup_state(run)
    if state == "ran":
        sys.exit(
            f"run dir already exists and a run has been in it: {run_dir} — a run id names "
            "one investigation; pick a fresh id (only a directory holding nothing but what "
            "setup writes is resumed)")
    if state == "absent":
        _clear_stale_sidecars(run)
    # Judged component by component: a link at the run id or `gather_raw` is refused.
    guarded_mkdir(paths.gather_raw, base=runs_base)
    _write_alert_once(run, alert)
    # Every executed run is stamped here, by its own process (branched siblings each reach
    # this, and `verify_family` compares their stamps), before the box exists: the run dir is
    # the box's rw bind, so a later stamp could have been moved by the run. There is no seam to
    # hand a stamp in. A resumed setup is re-stamped, since no box has run in it yet.
    if state == "setup":
        # Anything else at the stamp's name is left for the guarded write to refuse.
        with contextlib.suppress(OSError):
            paths.provenance.unlink()
    _stamp(
        run, model=model, tenant_id=tenant_record.tenant_id,
        world_id=world.world_id if world is not None else tenant_record.base_world_id,
        parent_run_id=world.family.source_run_id if world is not None else None,
        fork_turn=world.family.branch_message_id if world is not None else None,
    )
    return run_dir


def _admit_run_id(alert: Path, run_id: str | None) -> str:
    """The run id this call will materialise, or the refusal — minted from the alert when the
    operator pinned none."""
    # The explicit collision guard first; the run-id grammar refusing `_` is a coincidence.
    if run_id is not None:
        collision = _tenant.refuse_colliding_run_id(run_id)
        if collision is not None:
            sys.exit(str(collision))
    # The same admission rule as the handle's constructors, for minted and pinned ids alike.
    try:
        if run_id is None:
            run_id = mint_run_id(_alert_label(alert))
        refuse_bad_run_id(run_id)
    except ValueError as bad:
        sys.exit(f"invalid run id: {bad}")
    return run_id


def _clear_stale_sidecars(run: Run) -> None:
    """Remove sidecars a previous attempt under this reused run id left beside its removed dir
    — exact-run-id-keyed, never a glob. Only called when the dir is absent."""
    for sidecar in (
        run.facts.run_end.path, run.facts.scrub_verdict.path, run.facts.accounting.path,
    ):
        try:
            sidecar.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            sys.exit(f"cannot clear a stale sidecar at {sidecar}: {e!r}")


def _write_alert_once(run: Run, alert: Path) -> None:
    """The alert is write-once: written through the guarded exclusive lane when absent;
    when present it must match byte for byte, or the id is being reused for another case."""
    alert_bytes = alert.read_bytes()
    existing, reason = _io.read_bytes_guarded(run.facts.alert.path)
    if existing is None and _io.entry_present(run.facts.alert.path):
        sys.exit(
            f"{run.facts.alert.path} is not a readable plain file ({reason}) — refusing to "
            "resume over it")
    if existing is None:
        run.facts.alert.write(alert_bytes)
    elif existing != alert_bytes:
        sys.exit(
            f"run dir {run.run_dir} already holds a different alert than {alert} — a run id "
            "names one case; pick a fresh id for a different alert")


def _stamp(
    run: Run, *, model: str | None = None,
    tenant_id: str | None = None, world_id: str | None = None,
    parent_run_id: str | None = None, fork_turn: int | None = None,
) -> None:
    """Write the run's stamp, never taking the run down doing it (ENOSPC, read-only remount,
    a planted alias). Unlike a missing alert, a missing stamp only means the run's code cannot
    be proven later, so it is logged loudly and the run continues."""
    path = run.facts.provenance.path
    try:
        record = _provenance.capture_tree(REPO_ROOT)
        # Set in the single pre-box write; a later write would land in the box's rw bind.
        if model is not None:
            record = _dataclasses.replace(record, model=model)
        # Tenant fields equal the tenant record's values; a fork's lineage rides beside them.
        record = _dataclasses.replace(
            record, tenant_id=tenant_id, world_id=world_id,
            parent_run_id=parent_run_id, fork_turn=fork_turn)
        run.facts.provenance.write(record.as_json())
    except OSError as e:
        _logger.error(f"could not stamp {path}: {e!r} — the run continues UNSTAMPED, so "
                      "nothing downstream can prove which code it ran")


def run_env(defender_dir: Path, run_dir: Path) -> dict[str, str]:
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    env["DEFENDER_DIR"] = str(defender_dir)
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    env["DEFENDER_RUNS_BASE"] = str(run_dir.parent)
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    # Prepended: host subprocesses also need the operator's own PYTHONPATH entries.
    env["PYTHONPATH"] = _prepend(str(defender_dir.parent), env.get("PYTHONPATH"))
    # A host lane never carries the in-box mark, even if the operator's shell set it.
    env.pop("DEFENDER_BOX", None)
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
    if proc.stdout.strip():
        _logger.info(proc.stdout.strip())
    if proc.returncode != 0:
        raise VisualizeFailed(
            f"visualize_run failed for {run_dir} (exit {proc.returncode}): {proc.stderr}")


def cross_check_tables(run_dir: Path) -> None:
    if not RunPaths(run_dir).investigation.is_file():
        return
    try:
        from defender.learning import lead_repository

        xcheck = lead_repository.narration_crosscheck_from_run(run_dir)
    except Exception as e:  # noqa: BLE001 — diagnostics must never break the run
        _logger.warning(f"narration cross-check skipped: {e!r}")
        return
    if not xcheck["ok"]:
        _logger.warning(
            "narration cross-check FAILED — the live tables "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "disagree with investigation.md's :L rows:",
        )
        if xcheck["missing_from_narration"]:
            _logger.warning(f"table lead_ids with no :L row: {xcheck['missing_from_narration']}")
        if xcheck["queries_without_lead"]:
            _logger.warning(f"query FKs with no lead sidecar (orphans): {xcheck['queries_without_lead']}")
    if xcheck["leads_without_queries"]:
        _logger.info(f"note: leads with no queries (monitor): {xcheck['leads_without_queries']}")


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
    """The refusal predicate every learning enqueue consults: the reason a run must not feed
    a corpus, or `None`.

    Held-out fixtures are checked by content digest (catches copies outside `fixtures_dir`)
    and by path containment (catches files the digest walk, which reads only
    `<slug>/alert.json`, never sees)."""
    if truncated_by is not None:
        return f"run was truncated (truncated_by={truncated_by!r}) — a truncated " \
            "investigation must not train the corpus"
    if is_held_out_fixture(alert, fixtures_dir) or is_held_out_alert_copy(alert, fixtures_dir):
        return f"{alert} is a held-out eval fixture (or a copy of one) — its findings must " \
            "never feed a corpus it is scored against"
    from defender.runtime import scrub as _scrub

    if not _scrub.tree_verified(run_dir):
        # No completed scan verdict: the crash path most likely to hold what a box planted.
        return f"{run_dir} carries no completed reap-scan verdict — an unverified tree " \
            "must not feed the corpus"
    return None




def enqueue_curation(
    run_dir: Path,
    alert: Path,
    *,
    truncated_by: str | None = None,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
) -> bool:
    """Enqueue catalog curation for a run, through `learning_refusal_gate` — this hands
    attacker-influenced content (goal text, bound params, rendered queries) to the curator."""
    reason = learning_refusal_gate(
        run_dir, alert, fixtures_dir=fixtures_dir, truncated_by=truncated_by
    )
    if reason is not None:
        _logger.info(f"NOT enqueuing for curation: {reason}")
        return False
    from defender.learning.core import markers as _markers
    from defender.learning.core.config import REPO_ROOT as _LEARN_REPO_ROOT
    from defender.learning.core.config import LoopPaths, _env_state_dir

    paths = LoopPaths(repo_root=_LEARN_REPO_ROOT, state_dir=_env_state_dir())
    # Reading the alert is inside the guard too: a moved alert must not fail the run.
    try:
        case_id = case_ref(alert.read_bytes())
        _markers.enqueue_case_for_curation(case_id, run_dir, paths)
    except OSError as e:
        _logger.error(f"NOT enqueuing for curation: could not write the request: {e!r}")
        return False
    return True
