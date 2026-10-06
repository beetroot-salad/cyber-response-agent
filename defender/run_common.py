#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
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
from defender.run_repository import (  # noqa: E402
    Run, RunId, RunPaths, RunRefused, artifact_dir, case_ref, episode_sibling_ids,
    hold_runs_folder, run_name_fault,
)
from defender.scripts.visualize._page_failed import VisualizeFailed  # noqa: E402

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from defender.runtime.branch._family import ResumeWorld

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
    if extra or any(_io.entry_present(p) for p in _sidecars(run)):
        return "ran"
    return "setup"


def materialize_run(
    alert: Path, run_id: str | None, *, tenant: _tenant.Tenant, model: str | None = None,
    world: ResumeWorld | None = None,
) -> Run:
    """Build (or finish building) the run directory for `run_id` and return the tenant-bound
    handle the run's later records are saved through.

    `tenant` is the request's tenant, accepted by the entry point (`_tenant.accept_tenant`);
    nothing here resolves the data root or re-accepts it. The runs-base record is created here
    when absent; a record naming another tenant is refused rather than stamped.

    Every write is a guarded write-once verb (written when absent, kept when equal, refused
    when different), so resuming needs no ordering of checks and follows no planted link.
    `world` is a fork's `ResumeWorld`, handed in by the launcher — never derived from paths.

    Order (#1105 D3.7): the run id is admitted (the `_tenant.json` collision guard, then
    `RunId`, then the sidecar clause); the runs base is the tenant's own (`<data root>/<T>/runs`)
    or, for a fork, its episode's `runs/`, and a link or non-directory there is refused before
    anything is created in it; then the runs-base record; then, for a pinned id outside a fork,
    the claimed-id check against the episode records; then `Run.for_tenant` as the race
    backstop.
    """
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    pinned = run_id is not None
    run_id = _admit_run_id(alert, run_id)
    if world is not None:
        from defender._episode_paths import EpisodePaths

        runs_base = EpisodePaths(world.episode_dir).runs
    else:
        runs_base = tenant.runs
    # One no-follow hold of the runs base serves its state check and the claimed-id read.
    with hold_runs_folder(runs_base, create=True) as held:
        # The tenant record comes before the provenance stamp (which must match it) and before
        # the box exists. Unlike the stamp, its failures propagate: a forged tenant is worse
        # than no run.
        tenant_record = _tenant.ensure_runs_base_record(runs_base, tenant.id)
        if pinned and world is None:
            _refuse_claimed_run_id(held, runs_base, run_id)
    run = Run.for_tenant(tenant_record.tenant_id, run_id, runs_base=runs_base)
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
    return run


def _admit_run_id(alert: Path, run_id: str | None) -> str:
    """The run id this call will materialise, or the refusal — minted from the alert when the
    operator pinned none."""
    # The explicit collision guard first; the run-id grammar refusing `_` is a coincidence.
    if run_id is not None:
        collision = _tenant.refuse_colliding_run_id(run_id)
        if collision is not None:
            sys.exit(str(collision))
    # `RunId` is the admission rule for minted and pinned ids alike: the handle's grammar and
    # case stability, plus the 206-byte bound every sidecar write beside the run needs.
    try:
        admitted = (RunId.mint(_alert_label(alert)) if run_id is None
                    else RunId.parse(run_id))
    except RunRefused as bad:
        sys.exit(f"invalid run id: {bad}")
    # The sidecar clause (D2.1): the repository's one answer to "may this text name a run?".
    if (why := run_name_fault(str(admitted))) is not None:
        sys.exit(f"invalid run id: {why}")
    return str(admitted)


def _refuse_claimed_run_id(held: _io.Held, runs_base: Path, run_id: str) -> None:
    """Exit when an episode record in the held runs base claims the pinned `run_id`: that id
    names a sibling, not a run of its own (#1105 D3.7). No tenant compare (the record step has
    already judged `_tenant.json`), so a record naming another tenant still claims — the
    fail-safe direction. A corrupt record, or anything else in `_episodes` that is not a record,
    refuses every pinned id."""
    try:
        claimed = episode_sibling_ids(held.view(), where=str(runs_base))
    except RunRefused as bad:
        sys.exit(str(bad))
    if RunId.parse(run_id) in claimed:
        sys.exit(f"run id {run_id!r} is claimed by an episode record in {runs_base} — it "
                 "names an episode's sibling run; pick a fresh id")


def _sidecars(run: Run) -> tuple[Path, ...]:
    """The four files beside the run dir, keyed by its run id: the run-end record, the scrub
    verdict, the accounting failures and the ticket receipt (#1107 moved it out of the tree)."""
    return (run.facts.run_end.path, run.facts.scrub_verdict.path, run.facts.accounting.path,
            run.observability.ticket_write.path)


def _clear_stale_sidecars(run: Run) -> None:
    """Remove sidecars a previous attempt under this reused run id left beside its removed dir
    — exact-run-id-keyed, never a glob. Only called when the dir is absent."""
    for sidecar in _sidecars(run):
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
    be proven later, so it is logged loudly and the run continues. An interrupted setup is
    resumable, so a retry re-stamps."""
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


def provider_scrubbed_environ() -> dict[str, str]:
    """The process's environment as a copy, with every registered provider's API-key variable removed — the base of
    every host child's environment (`run_env` adds a run's variables on top; the branch
    launcher's write door, which has no run yet, takes it as is). The ONE scrub, so no host
    child is handed a registered provider's key by a caller that forgot to drop it (other
    credential variables are not this scrub's to know)."""
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    return env


def run_env(defender_dir: Path, run_dir: Path) -> dict[str, str]:
    env = provider_scrubbed_environ()
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


def visualize(run: Run, *, update_ticket: bool = False) -> None:
    """The post-run page step as `run.py` takes it: load the renderer, then hand it the run
    (`visualize_run.publish_page` renders, saves the record through `run`, and makes the dev-only
    copy). Runs in the process holding the handle, after the sandbox has exited and the tree has
    been scrubbed, so the model never had a chance to rewrite its own report.

    `update_ticket` is `run.py`'s own `--update-ticket` (#1107 O6), passed on as an argument.

    Only the load is decided here. The renderer is imported lazily — it reads its stylesheet at
    import time, and nothing but this step needs it — and inside the `try`, so a renderer that
    cannot even load is a `VisualizeFailed` like any other failed render, and never reaches the
    run's exit code.
    """
    try:
        from defender.scripts.visualize import visualize_run as vr
    except Exception as e:
        raise VisualizeFailed("the renderer could not be loaded") from e
    vr.publish_page(run, update_ticket=update_ticket)


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
    from defender._env import FatalConfigError
    from defender.learning.core.config import loop_paths
    from defender.learning.core.state import LearningState, StateRefused

    # Reading the alert is inside the guard too: a moved alert must not fail the run. So is the
    # state tree: a refused entry or a missing root costs this request, never the investigation.
    try:
        case_id = case_ref(alert.read_bytes())
        with LearningState.open(loop_paths()) as state:
            state.enqueue_curation(
                case_id, {"case_id": case_id, "run_dir": str(run_dir.resolve())})
    except OSError as e:
        _logger.error(f"NOT enqueuing for curation: could not write the request: {e!r}")
        return False
    except StateRefused as refused:
        _logger.error(f"NOT enqueuing for curation: could not enqueue the request, refused "
                      f"{refused.record}: {refused.reason}")
        return False
    except FatalConfigError as config_error:
        _logger.error(f"NOT enqueuing for curation: could not enqueue the request: "
                      f"{config_error}")
        return False
    return True
