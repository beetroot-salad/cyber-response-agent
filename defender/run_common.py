#!/usr/bin/env python3

from __future__ import annotations

import contextlib
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

from defender import _alert_input, _io, _provenance, _tenant  # noqa: E402
from defender._io import read_bytes_capped  # noqa: E402
from defender.run_repository import (  # noqa: E402
    RUN_LAYOUT, Run, RunAddress, RunId, RunPaths, RunRefused, artifact_dir, artifact_file, case_ref_of_digest,
    run_name_fault,
)
from defender.scripts.visualize._page_failed import VisualizeFailed  # noqa: E402

_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from defender.run_repository import EpisodeRuns
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
    setup_names = {paths.alert_input_dir.name, paths.gather_raw.name, paths.provenance.name}
    extra = sorted(set(listing.entries or {}) - setup_names)
    # The scrub verdict is written at box start, so even a box that died before writing into
    # the tree leaves a sidecar.
    if extra or any(_io.entry_present(p) for p in _sidecars(run)):
        return "ran"
    return "setup"


def materialize_run(
    alert: Path, run_id: str | None, *, tenant: _tenant.Tenant, model: str | None = None,
    world: ResumeWorld | None = None, episode_runs: EpisodeRuns | None = None,
) -> Run:
    """Build (or finish building) the run directory for `run_id` and return the tenant-bound
    handle the run's later records are saved through.

    `tenant` is the request's tenant, accepted by the entry point (`_tenant.accept_tenant`);
    nothing here resolves the data root or re-accepts it. The run's handle comes from the
    tenant's runs repository (#1105 PR 2, D-create (a)): a natural run's from
    `tenant.runs_repository().create`, which makes the runs folder when absent with its record
    (a record naming another tenant is refused rather than stamped); a fork's from
    `episode_runs.create` — the sibling's episode view, whose container the launcher made for
    the tenant before any arm and which is never made here.

    Every write is a guarded write-once verb (written when absent, kept when equal, refused
    when different), so resuming needs no ordering of checks and follows no planted link.
    `world` is a fork's `ResumeWorld`, handed in by the launcher — never derived from paths.

    Order (#1105 D3.7): the run id is admitted (the `_tenant.json` collision guard, then
    `RunId`, then the sidecar clause); then the repository's create: the container held
    no-follow (a link or non-directory refused before anything is created in it), its tenant
    record, for a pinned id outside a fork the claimed-id check, and the handle's record
    compare as the race backstop.
    """
    if not alert.is_file():
        sys.exit(f"alert not found: {alert}")
    pinned = run_id is not None
    admitted = _admit_run_id(alert, run_id)
    front_door = _admit_input(alert, tenant=tenant, world=world)
    try:
        if world is not None:
            if episode_runs is None:
                raise TypeError("materialize_run(world=…) needs the sibling's episode view "
                                "(`episode_runs=`): an arm is made only in its episode's "
                                "container")
            run = episode_runs.create(admitted)
            world_id = world.world_id
        else:
            runs = tenant.runs_repository()
            run = runs.create(admitted, pinned=pinned)
            world_id = runs.base_world_id()
    except RunRefused as refused:
        sys.exit(str(refused))
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
    run.make_run_dir()
    _write_input_once(run, front_door)
    # Every executed run is stamped here, by its own process (branched siblings each reach
    # this, and `verify_family` compares their stamps), before the box exists: the run dir is
    # the box's rw bind, so a later stamp could have been moved by the run. There is no seam to
    # hand a stamp in. A resumed setup is re-stamped, since no box has run in it yet.
    if state == "setup":
        # Anything else at the stamp's name is left for the guarded write to refuse.
        with contextlib.suppress(OSError):
            paths.provenance.unlink()
    _stamp(
        run, knowledge_dir=tenant.knowledge, model=model, tenant_id=run.tenant_id,
        world_id=world_id,
        parent_run_id=world.family.source_run_id if world is not None else None,
        fork_turn=world.family.branch_message_id if world is not None else None,
    )
    return run


def _admit_run_id(alert: Path, run_id: str | None) -> RunId:
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
    return admitted


def _sidecars(run: Run) -> tuple[Path, ...]:
    """The files beside the run dir, keyed by its run id: the run-end record, the scrub
    verdict, the ticket receipt (#1107 moved it out of the tree) and the run -> case link
    (#1235 did)."""
    return (run.facts.run_end.path, run.facts.scrub_verdict.path,
            run.observability.ticket_write.path, run.observability.session_pointer.path)


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


@_dataclasses.dataclass(frozen=True)
class _FrontDoor:
    """What run start settled about the alert before any folder existed: its admitted bytes, and
    the record text that goes beside them."""

    raw: bytes
    record: str


def _admit_input(alert: Path, *, tenant: _tenant.Tenant, world: ResumeWorld | None) -> _FrontDoor:
    """Admit the operator's alert (A8) and settle its facts through the tenant's alert mapping,
    read once (A1) — or exit with the fixed reason, before a run folder exists. A sibling's input
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
        from defender._episode_paths import EpisodePaths

        record_path = EpisodePaths(world.episode_dir).source_record
        text, reason = _io.read_guarded(record_path)
        parsed = None if text is None else _alert_input.parse_alert_record(text)
        if text is None or parsed is None or parsed.digest != admitted.digest:
            sys.exit(f"[run.py] episode {world.episode_dir.name}: its copy of the source alert does not "
                     f"match the record beside it "
                     f"({reason or 'the record is missing, malformed or for another alert'})")
        return _FrontDoor(raw=raw, record=text)
    try:
        mapping = _alert_input.load_alert_mapping(tenant.settings)
    except _alert_input.AlertMappingFault as fault:
        sys.exit(f"[run.py] this run's tenant cannot be used: {fault}")
    facts = _alert_input.derive_facts(admitted.document, mapping)
    return _FrontDoor(raw=raw, record=_alert_input.record_text(admitted.digest, facts))


def _read_input_file(path: Path, what: str) -> bytes | None:
    """A file of the input directory as found: its bytes, `None` when nothing is there, or the
    exit when something unreadable stands at its name (a squatting directory, a link)."""
    data, reason = _io.read_bytes_guarded(path)
    if data is None and _io.entry_present(path):
        sys.exit(f"{path} is not a readable plain file ({reason}) — refusing to resume over "
                 f"the run's {what}")
    return data


def _write_input_once(run: Run, door: _FrontDoor) -> None:
    """The alert and its record are write-once, in the run's read-only input directory: written
    through the guarded exclusive lane when absent; when present the alert must agree with what
    run start admitted, byte for byte, and the record must carry that alert's digest (its facts
    are not compared), or the id is being reused for another case. Nothing present
    is rewritten (a restart keeps both files' bytes, inode and mtime), and the record found wins
    over the one just derived (a mapping edited since stays the operator's business for the next
    run)."""
    paths = RunPaths(run.run_dir)
    held_alert = _read_input_file(paths.alert, "alert")
    held_record = _read_input_file(paths.alert_record, "record")
    if held_alert is not None and held_alert != door.raw:
        sys.exit(
            f"run dir {run.run_dir} already holds a different alert than the one given — a run "
            "id names one case; pick a fresh id for a different alert")
    if held_record is not None:
        kept = _alert_input.parse_alert_record(held_record.decode("utf-8", errors="replace"))
        if kept is None or kept.digest != _alert_input.digest_of(door.raw):
            sys.exit(
                f"run dir {run.run_dir} holds a record that is not this alert's "
                f"({paths.alert_record.name}) — a run id names one case; pick a fresh id")
    _unseal(paths.alert_input_dir)
    try:
        if held_alert is None:
            run.facts.alert.write(door.raw)
        if held_record is None:
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


def _stamp(
    run: Run, *, knowledge_dir: Path, model: str | None = None,
    tenant_id: str | None = None, world_id: str | None = None,
    parent_run_id: str | None = None, fork_turn: int | None = None,
) -> None:
    """Write the run's stamp, never taking the run down doing it (ENOSPC, read-only remount,
    a planted alias). Unlike a missing alert, a missing stamp only means the run's code cannot
    be proven later, so it is logged loudly and the run continues. An interrupted setup is
    resumable, so a retry re-stamps. `knowledge_dir` is the run's tenant knowledge clone,
    whose checked-out commit rides beside the product's (#1204)."""
    path = run.facts.provenance.path
    try:
        record = _provenance.capture_run(REPO_ROOT, knowledge_dir)
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


def run_env(
    defender_dir: Path, run_dir: Path, *, tenant_agent: Path | None = None,
) -> dict[str, str]:
    env = provider_scrubbed_environ()
    env["DEFENDER_DIR"] = str(defender_dir)
    env.pop("DEFENDER_AGENT_DIR", None)
    if tenant_agent is not None:
        env["DEFENDER_AGENT_DIR"] = str(tenant_agent)
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    env["DEFENDER_RUNS_BASE"] = RunPaths(run_dir).runs_base_export()
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
    from defender.runtime import scrub as _scrub

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
    from defender._env import FatalConfigError
    from defender.learning.core.config import loop_paths
    from defender.learning.core.state import LearningState, StateRefused

    address = RunAddress(tenant_id=_tenant.TenantId(run.tenant_id), run_id=run.id)
    # Reading the alert is inside the guard too: a moved alert must not fail the run. So is the
    # state tree: a refused entry or a missing root costs this request, never the investigation.
    try:
        record = _alert_input.read_record(RunPaths(run_dir).alert_record)
        if record is None:
            raise OSError("the run's record vanished")
        case_id = case_ref_of_digest(record.digest)
        with LearningState.open(loop_paths()) as state:
            state.enqueue_curation(
                case_id, {"case_id": case_id, "tenant_id": str(address.tenant_id),
                          "run_id": str(address.run_id)})
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
