#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import datetime as _dt
import logging
import sys
import dataclasses as _dataclasses
from pathlib import Path
from typing import TYPE_CHECKING

DEFENDER_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEFENDER_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import defender.skills.invlang.validate  # noqa: F401 — loading it registers the validator the records write gate needs
from defender import _io
from defender.records import _alert_input
from defender.records import _provenance
from defender.tenancy import _tenant  # noqa: E402
from defender._io import read_bytes_capped  # noqa: E402
from defender.records import (  # noqa: E402
    RUN_LAYOUT, Run, RunAddress, RunId, RunPaths, RunRefused, artifact_dir, artifact_file, case_ref_of_digest, sidecar_names,
)
from defender.presentation._page_failed import VisualizeFailed  # noqa: E402
from defender.records._tenant_id import TenantId, TenantRefused

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from defender.records._family import ResumeWorld
    from defender.tenancy.run_knowledge import KnowledgeSource

_GENERIC_ALERT_STEMS = {"alert"}


def _alert_label(alert: Path) -> str:
    return alert.parent.name if alert.stem in _GENERIC_ALERT_STEMS else alert.stem


def materialize_run(  # noqa: PLR0913 — the run's case, its tenant, and the knowledge it reads
    alert: Path, *, tenant: _tenant.Tenant, run: Run | None = None, model: str | None = None,
    world: ResumeWorld | None = None,
    settings: Path | None = None, knowledge: KnowledgeSource | None = None,
) -> Run:
    """Build the run directory of a fresh run and return the tenant-bound handle the run's later
    records are saved through. No caller names the run's id (#1279 A3): `run` is the handle the
    runs repository handed out — `RunsRepository.create()` mints one, and an arm's is its
    episode's `EpisodeRuns.create(<the roster's arm id>)` — so run.py can name the run's knowledge
    copy by it before setup (#1279 rev 6). Without `run`, setup makes a fresh ordinary run of the
    tenant; an arm (`world`) always comes as its handle. A run dir or sidecar already at that id
    is refused; there is no resume (O8).

    `settings` is the settings half the run reads (its run copy's, #1108 P4: the alert mapping
    comes from it) and `knowledge` the source of the knowledge it reads, whose commit the stamp
    records (O-B: the export copied, never a clone's HEAD). Both default to what a caller that
    names no run copy has: the tenant's own folder, and a stamp that says nothing of knowledge."""
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    if world is not None and run is None:
        raise TypeError("materialize_run(world=…) needs the arm's handle (`run=`): an arm is made "
                        "only from its episode's roster")
    started_at = _started_at()
    if settings is None:
        settings = _tenant.clone_halves(tenant)[1]
    front_door = _admit_input(alert, settings=settings, world=world)
    world_id: str | None = None
    if run is None:
        try:
            run = tenant.runs_repository().create()
        except RunRefused as refused:
            sys.exit(str(refused))
    run_dir = run.run_dir

    # A sidecar beside the dir is a trace of an earlier run at this id; nothing clears it.
    for name in sidecar_names(RunId.parse(run_dir.name)):
        if _io.entry_present(run_dir.parent / name):
            sys.exit(f"run id already used: {run_dir.parent / name} exists beside {run_dir} — a run "
                     "id names one investigation")
    # Judged component by component, and exclusive at the run dir itself: anything already at
    # the run id (a directory, a file, a link) is refused as found.
    try:
        run.make_run_dir()
    except FileExistsError:
        sys.exit(f"run dir already exists: {run_dir} — a run id names one investigation and a "
                 "run dir is never resumed")
    _write_input(run, front_door)
    # Every executed run is stamped here, by its own process (branched siblings each reach
    # this, and `verify_family` compares their stamps), before the box exists: the run dir is
    # the box's rw bind, so a later stamp could have been moved by the run. There is no seam to
    # hand a stamp in.
    _stamp(
        run, knowledge=knowledge, model=model, tenant_id=run.tenant_id,
        world_id=world_id,
        started_at=started_at, alert_label=_alert_label(alert),
    )
    return run


def _started_at() -> str:
    """When run setup started this run, as ISO-8601 UTC text to the second (#1187 O7)."""
    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@_dataclasses.dataclass(frozen=True)
class _FrontDoor:
    """What run start settled about the alert before any folder existed: its admitted bytes, and
    the record text that goes beside them."""

    raw: bytes
    record: str


def _admit_input(alert: Path, *, settings: Path, world: ResumeWorld | None) -> _FrontDoor:
    """Admit the operator's alert (A8) and settle its facts through the alert mapping of the
    run's `settings`, read once (A1) — or exit with the fixed reason, before a run folder
    exists. A sibling's input
    is its episode's copy of the source run's alert, carried with the record launch copied
    beside it; neither is derived again."""
    try:
        raw = _alert_input.read_operator_alert(alert)
        admitted = _alert_input.admit(raw)
    except _alert_input.AlertRefused as refused:
        sys.exit(f"[run.py] {refused}")
    except OSError as e:
        sys.exit(f"[run.py] the alert {alert} could not be read: {e}")
    if world is not None:
        from defender.records._episode_paths import EpisodePaths

        record_path = EpisodePaths(world.episode_dir).source_record
        text, reason = _io.read_guarded(record_path)
        parsed = None if text is None else _alert_input.parse_alert_record(text)
        if text is None or parsed is None or parsed.digest != admitted.digest:
            sys.exit(f"[run.py] episode {world.episode_dir.name}: its copy of the source alert does not "
                     f"match the record beside it "
                     f"({reason or 'the record is missing, malformed or for another alert'})")
        return _FrontDoor(raw=raw, record=text)
    try:
        mapping = _alert_input.load_alert_mapping(settings)
    except _alert_input.AlertMappingFault as fault:
        sys.exit(f"[run.py] this run's tenant cannot be used: {fault}")
    facts = _alert_input.derive_facts(admitted.document, mapping)
    return _FrontDoor(raw=raw, record=_alert_input.record_text(admitted.digest, facts))


def _write_input(run: Run, door: _FrontDoor) -> None:
    """The alert and its record, written once into the run's read-only input directory through
    the guarded exclusive lane. The run dir was just created exclusively (O8), so neither file
    can be there yet."""
    paths = RunPaths(run.run_dir)
    _unseal(paths.alert_input_dir)
    try:
        run.facts.alert.write(door.raw)
        _io.rooted_write(run.run_dir, RUN_LAYOUT.alert_record, door.record, mode="create")
    except OSError as e:
        sys.exit(f"cannot write the run's input at {paths.alert_input_dir}: {e!r} — no run "
                 f"starts without its alert and {paths.alert_record.name}")
    finally:
        _seal(paths.alert_input_dir)


def _unseal(input_dir: Path) -> None:
    """Make the input directory (and what it holds) writable for the owner, for the one write
    run start makes into it. Best effort: the box's read-only bind is the real protection."""
    with contextlib.suppress(OSError):
        if artifact_dir(input_dir):
            input_dir.chmod(0o755)


def _seal(input_dir: Path) -> None:
    """Take the owner's write permission off the input directory and its files, so a host
    process running as the same user cannot rewrite them by accident. Best effort, like
    `_unseal`: the box's read-only bind is what holds against the run."""
    with contextlib.suppress(OSError):
        if not artifact_dir(input_dir):
            return
        for child in input_dir.iterdir():
            if artifact_file(child):
                child.chmod(0o444)
        input_dir.chmod(0o555)


def _stamp(  # noqa: PLR0913 — one keyword per stamped fact
    run: Run, *, knowledge: KnowledgeSource | None, model: str | None = None,
    tenant_id: str | None = None, world_id: str | None = None,
    started_at: str | None = None, alert_label: str | None = None,
) -> None:
    """Write the run's stamp, never taking the run down doing it (ENOSPC, read-only remount,
    a planted alias). Unlike a missing alert, a missing stamp only means the run's code cannot
    be proven later, so it is logged loudly and the run continues. An interrupted setup is
    resumable, so a retry re-stamps. `knowledge` is where the run's tenant knowledge came from:
    its export's commit rides beside the product's (#1204; #1108 P4 O-B: the export copied,
    never a clone's checked-out commit), with the informational `knowledge_source` (OD17)."""
    path = run.facts.provenance.path
    try:
        record = _provenance.capture_tree(REPO_ROOT)
        if knowledge is not None:
            record = _dataclasses.replace(
                record, knowledge=_provenance.KnowledgeRevision.at(knowledge.commit))
        # Set in the single pre-box write; a later write would land in the box's rw bind.
        if model is not None:
            record = _dataclasses.replace(record, model=model)
        # Both run types expose the same stamp shape; lineage stays in host episode records.
        record = _dataclasses.replace(
            record, tenant_id=tenant_id, world_id=world_id,
            started_at=started_at, alert_label=alert_label)
        run.facts.provenance.write(record.as_json(
            knowledge_source=None if knowledge is None else knowledge.stamp_view()))
    except OSError as e:
        _logger.error(f"could not stamp {path}: {e!r} — the run continues UNSTAMPED, so "
                      "nothing downstream can prove which code it ran")


def visualize(run: Run, *, tenant: _tenant.Tenant, update_ticket: bool = False) -> None:
    """The post-run page step as `run.py` takes it: load the renderer, then hand it the run
    (`visualize_run.publish_page` renders, saves the record through `run`, and makes the dev-only
    copy). Runs in the process holding the handle, after the sandbox has exited and the tree has
    been scrubbed, so the model never had a chance to rewrite its own report."""
    try:
        from defender.presentation import visualize_run as vr
    except Exception as e:
        raise VisualizeFailed("the renderer could not be loaded") from e
    vr.publish_page(run, tenant=tenant, update_ticket=update_ticket)


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


HELD_OUT_FIXTURES = REPO_ROOT / "evaluations" / "fixtures" / "held_out"


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
        try:
            out.add(_alert_input.digest_of(read_bytes_capped(child / "alert.json")))  # lint-run-records: ok — a held-out fixture folder's own file, not a run's record
        except OSError:
            continue
    return out


def learning_refusal_gate(
    run_dir: Path,
    alert: Path | None = None,
    *,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
    truncated_by: str | None = None,
) -> str | None:
    """The refusal predicate every learning enqueue consults: the reason a run must not feed
    a corpus, or `None`.

    Held-out fixtures are checked by the run's RECORDED digest (the alert it admitted at run
    start, whatever has become of the operator's input file since: catches copies outside
    `fixtures_dir`) and, when the operator's input path is given, by path containment (catches
    files the digest walk, which reads only `<slug>/alert.json`, never sees)."""
    if truncated_by is not None:
        return f"run was truncated (truncated_by={truncated_by!r}) — a truncated " \
            "investigation must not train the corpus"
    record = _alert_input.read_record(RunPaths(run_dir).alert_record)
    if record is None:
        return f"{run_dir} carries no readable record of its alert — a folder without one is " \
            "not a run, and nothing is learned from it"
    held_out_input = alert is not None and is_held_out_fixture(alert, fixtures_dir)
    if held_out_input or record.digest in held_out_alert_digests(fixtures_dir):
        return f"{run_dir.name} investigated a held-out eval fixture (or a copy of one) — its " \
            "findings must never feed a corpus it is scored against"
    import defender.box._scrub as _scrub

    if _scrub.tree_unsandboxed(run_dir):
        return f"{run_dir.name} ran without a sandbox, so its input directory was never bound " \
            "read-only — nothing is learned from it"
    if not _scrub.tree_verified(run_dir):
        # No completed scan verdict: the crash path most likely to hold what a box planted.
        return f"{run_dir} carries no completed reap-scan verdict — an unverified tree " \
            "must not feed the corpus"
    return None




def enqueue_curation(
    run: Run,
    alert: Path | None = None,
    *,
    truncated_by: str | None = None,
    fixtures_dir: Path = HELD_OUT_FIXTURES,
) -> bool:
    """Enqueue catalog curation for a run, through `learning_refusal_gate` — this hands
    attacker-influenced content (goal text, bound params, rendered queries) to the curator. The
    request is keyed on the run's recorded digest; `alert`, the operator's input path, is only
    the held-out gate's path arm."""
    run_dir = run.run_dir
    reason = learning_refusal_gate(
        run_dir, alert, fixtures_dir=fixtures_dir, truncated_by=truncated_by
    )
    if reason is not None:
        _logger.info(f"NOT enqueuing for curation: {reason}")
        return False
    from defender.configuration._env import FatalConfigError
    from defender.learning.core.config import LoopPaths
    from defender.learning.core.state import LearningState, StateRefused

    address = RunAddress(tenant_id=TenantId(run.tenant_id), run_id=run.id)
    # Reading the alert is inside the guard too: a moved alert must not fail the run. So is the
    # state tree: a refused entry or a missing root costs this request, never the investigation.
    try:
        record = _alert_input.read_record(RunPaths(run_dir).alert_record)
        if record is None:
            raise OSError("the run's record vanished")
        case_id = case_ref_of_digest(record.digest)
        with LearningState.open(LoopPaths.for_tenant(
                _tenant.requested_tenant(_tenant.resolve_data_root(), run.tenant_id))) as state:
            state.enqueue_curation(
                case_id, {"case_id": case_id, "tenant_id": str(address.tenant_id),
                          "run_id": str(address.run_id)})
    except OSError as e:
        _logger.error(f"NOT enqueuing for curation: could not write the request: {e}")
        return False
    except StateRefused as refused:
        _logger.error(f"NOT enqueuing for curation: could not enqueue the request, refused "
                      f"{refused.record}: {refused.reason}")
        return False
    except (FatalConfigError, TenantRefused) as config_error:
        _logger.error(f"NOT enqueuing for curation: could not enqueue the request: "
                      f"{config_error}")
        return False
    return True
