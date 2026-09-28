#!/usr/bin/env python3
"""Defender entrypoint — investigate one alert end-to-end.

The investigation is driven by the in-process PydanticAI driver
(`runtime/driver.py`): materialize the run dir → run → cross-check the two live
tables → enqueue learning → visualize. Run-dir + post-step helpers are shared
via `run_common.py`.

Usage:
    python3 defender/run.py <alert.json> [--run-id ID] [--no-learn] [--model M]

Billing / credentials: the engine calls the first-party Anthropic REST API and
needs a real billable API key. Inside a Claude Code session the *ambient*
ANTHROPIC_API_KEY is the subscription credential (it 401s against the REST API),
so the billable key is sourced from a `.env` file (`resolve_first_party_key`) and
takes precedence over the ambient value.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Hand-rolled rather than `scripts/_venv.reexec_into_venv`: this must run before any
# `defender.*` import, and reaching that helper is one.
_DEFENDER_DIR = Path(__file__).resolve().parent
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse  # noqa: E402
import asyncio  # noqa: E402
import functools  # noqa: E402
import inspect  # noqa: E402
from collections.abc import Callable  # noqa: E402
from typing import Any, Protocol  # noqa: E402

if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender import _log  # noqa: E402
from defender import _provenance  # noqa: E402
from defender import run_common as _run  # noqa: E402
from defender._paths import adapters_under  # noqa: E402
from defender._run_handle import Run  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender._tenant import TenantRecord  # noqa: E402
from defender._tenants import default_tenants_root  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime import providers  # noqa: E402
from defender.runtime.run_tenant import RunTenant  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry, read_roster  # noqa: E402
from defender.scripts.case_history import ticket_writer as _default_ticket_writer  # noqa: E402

DEFENDER_DIR = _DEFENDER_DIR


from defender._first_party_key import (  # noqa: E402,F401
    _read_env_key,
    resolve_first_party_key,
)

_logger = logging.getLogger(__name__)


def parse_args(argv: list[str]) -> argparse.Namespace:
    """The entry point's arguments, for an ordinary run and for a sibling world.

    A sibling is `--resume <family manifest> --world <label>`; everything else it needs is
    derived from the manifest. The positional alert is refused with `--resume`, since the
    manifest already names the source run and there would be two case inputs.
    """
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("alert", type=Path, nargs="?", default=None,
                   help="Path to alert.json fixture (illegal with --resume)")  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    p.add_argument("--resume", type=Path, default=None,
                   help="a family manifest (episodes/<id>/family.yaml) to resume a world of")  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    p.add_argument("--world", default=None,
                   help="which world of --resume's manifest this process is")
    p.add_argument("--run-id", default=None,
                   help="Pin the run id for a named A/B or live run (learning-loop "
                        "commits reference it) instead of the auto timestamp id. Lower case "
                        "only. An existing run dir under this id is RESUMED (setup finishes "
                        "what an interrupted attempt left undone and re-stamps) — for the same "
                        "alert; a different alert under a used id is refused")
    p.add_argument("--no-learn", action="store_true",
                   help="Skip enqueuing for learning (also skips catalog curation — the "
                        "flag now governs both lanes)")
    p.add_argument("--update-ticket", action="store_true",
                   help="Write/close a case-history ticket for this alert (default off)")
    p.add_argument("--tenants-root", type=Path, default=None,
                   help="the folder holding one sub-folder per tenant (#1106); default "
                        "<this checkout>/knowledge/tenants. The run's tenant is the one its "
                        "runs base's tenant record names")
    p.add_argument("--model", default=None,
                   help="model id (overrides $DEFENDER_MODEL); e.g. a claude-* id, "
                        "or 'glm-5.3' / 'fireworks:<id>' for the Fireworks-served GLM")
    ns = p.parse_args(argv)
    if ns.resume is not None and ns.alert is not None:
        p.error(
            "the positional alert is illegal with --resume: the manifest already names the "
            "source run the alert would come from, and a command line carrying both names two "
            "case inputs with no rule for which wins")
    if ns.resume is None and ns.alert is None:
        p.error("an alert path is required unless --resume names a family manifest")
    if ns.resume is not None and not ns.world:
        p.error("--resume needs --world: a manifest declares a family, and a process is one arm")
    return ns


def _source_one_provider_key(prov: providers.Provider) -> int:
    var = prov.api_key_var
    key, src = resolve_first_party_key(var=var)
    if key:
        os.environ[var] = key
        note = " (overrides the ambient subscription credential)" if prov.id == "anthropic" else ""
        _logger.info(f"{var} sourced from {src}{note}")
        return 0
    if os.environ.get(var):
        if prov.id == "anthropic":
            _logger.warning("no .env key found; using the ambient "
                            "ANTHROPIC_API_KEY — inside a Claude Code session this is the "
                            "subscription credential and will 401 against the first-party API.")
        else:
            _logger.info(f"using the ambient {var} for the {prov.id} model")
        return 0
    if prov.id == "anthropic":
        _logger.error("no first-party ANTHROPIC_API_KEY — set it in "
                      "<repo>/.env or $DEFENDER_ENV_FILE (the PydanticAI engine bills the "
                      "first-party Anthropic API).")
    else:
        _logger.error(f"a {prov.id} model is selected but no {var} — set it "
                      f"in <repo>/.env or $DEFENDER_ENV_FILE ({prov.id} bills its "
                      "OpenAI-compatible API).")
    return 2


def _accepts(sig: inspect.Signature, *args: Any, **kwargs: Any) -> bool:
    """Can the accessor this signature describes be called this way? Asked of the signature
    so a `TypeError` raised inside the accessor is not mistaken for a non-matching call."""
    try:
        sig.bind(*args, **kwargs)
    except TypeError:
        return False
    return True


def _role_model_name(defn: Any, model_override: str | None) -> str:
    """The model name this role will actually run on.

    `--model` reaches every role whose accessor can take it (read off the signature, not a
    hand-list); roles with their own knob keep it. A single keyword-only parameter is passed by
    name (`def m(*, explicit=None)` refuses a positional call); several keyword-only parameters
    name no single override, so the role keeps its own model."""
    if model_override is None:
        return str(defn.model())
    try:
        sig = inspect.signature(defn.model)
    except (TypeError, ValueError):
        return str(defn.model())
    if _accepts(sig, model_override):
        return str(defn.model(model_override))
    by_keyword = [p.name for p in sig.parameters.values() if p.kind is p.KEYWORD_ONLY]
    if len(by_keyword) == 1 and _accepts(sig, **{by_keyword[0]: model_override}):
        return str(defn.model(**{by_keyword[0]: model_override}))
    return str(defn.model())


def preflight_role_models(model_override: str | None = None) -> int:
    """Check every registered role's model config at startup and fail fast if a provider key
    is unusable. Some providers only fail on first live call, and review agents are built per
    call, so a broken review role would otherwise silently downgrade runs to unresolved."""
    from defender.agents import AGENTS

    seen_provider_ids: set[str] = set()
    for defn in AGENTS.values():
        try:
            name = _role_model_name(defn, model_override)
        except Exception as e:  # noqa: BLE001 — a broken model accessor is a preflight failure
            _logger.error(f"preflight: {defn.role.name} model config raised: {e!r}")
            return 2
        try:
            prov = providers.provider_for(name)
        except ValueError as e:
            _logger.error(f"preflight: {defn.role.name}: {e}")
            return 2
        if prov.id in seen_provider_ids:
            continue
        seen_provider_ids.add(prov.id)
        rc = _source_one_provider_key(prov)
        if rc:
            _logger.error(f"preflight: {defn.role.name} ({name}) has no usable model config")
            return rc
    return 0


class _Investigate(Protocol):
    """The investigation seam's exact shape, so both the call site and `_drive_investigation`
    stay type-checked (tests inject the seam, so only a real run would catch a renamed keyword).
    """

    def __call__(  # noqa: PLR0913 — the investigation's whole identity, one keyword each
        self, *, alert_path: Path, run_dir: Path, run_id: str, defender_dir: Path,
        model_name: str, model_override: str | None, box: Any, tenant: RunTenant,
        world: Any = None,
    ) -> dict[str, Any]: ...


def _run_the_driver(**kwargs: Any) -> dict[str, Any]:
    """The driver's coroutine, as a synchronous call — separate so tests can observe the
    registry decision without an event loop.
    """
    return asyncio.run(driver.run_investigation(**kwargs))


def _drive_investigation(  # noqa: PLR0913 — one investigation's whole identity plus its seams
    *,
    alert_path: Path,
    run_dir: Path,
    run_id: str,
    defender_dir: Path,
    model_name: str,
    model_override: str | None,
    box: Any,
    #: The run's tenant (folder, grants, lead-zero dispatch), resolved by `main` before the box.
    tenant: RunTenant,
    #: The world this process is, on the `--resume` path; `None` on an ordinary run.
    world: Any = None,
    registry_cls: Any = ModuleVerbRegistry,
    investigate: Callable[..., dict[str, Any]] = _run_the_driver,
) -> dict[str, Any]:
    """The production investigation call, as a synchronous callable (injected by the
    lifecycle so tests can pass a plain function).

    Passes `verbs=` explicitly: `run_investigation`'s fallback registry deliberately does not
    enable lead-0, which hermetic tests rely on.

    On the resume path the production registry is never constructed: a sibling's queries must
    be answered from the primed recording and staged corpus, and a module registry beside them
    would route uncaptured keys to real adapters. The two registries are built in separate
    arms of one `if` so both can never exist.
    """
    # Read once and handed down to the registry and `run_investigation`.
    roster = read_roster(adapters_under(defender_dir))
    if world is not None:
        from defender.learning.branch.estate.applier import WorldApplier
        from defender.learning.branch.estate.registry import WorldRegistry
        from defender.learning.branch.ledger import Ledger
        from defender.runtime import branch as branch_mod

        family = world.family
        verbs: Any = WorldRegistry(
            roster, tenant.grants.gather,
            # Declared up front: a world that serves nothing must still leave a ledger.
            world=world, ledger=Ledger.for_world(
                world.episode_dir, world.world_id).declare(),
            as_of=world.as_of, applier=WorldApplier(),
            settings_dir=tenant.settings, grant_home=tenant.table_pointer,
        )
        resume = branch_mod.BranchSpec(
            source_run_dir=Path(family.source_run_dir),
            branch_message_id=family.branch_message_id,
            continuation_prompt=family.continuation_prompt,
            as_of=family.as_of,
        )
        return investigate(
            alert_path=alert_path, run_dir=run_dir, run_id=run_id,
            defender_dir=defender_dir, model_name=model_name,
            model_override=model_override, box=box, verbs=verbs, roster=roster, resume=resume,
            tenant=tenant,
        )
    verbs = registry_cls(roster, tenant.grants.gather, grant_home=tenant.table_pointer)
    return investigate(
        alert_path=alert_path, run_dir=run_dir, run_id=run_id, defender_dir=defender_dir,
        model_name=model_name, model_override=model_override, box=box, verbs=verbs,
        roster=roster, tenant=tenant,
    )


def _run_investigation_lifecycle(  # noqa: PLR0913 — the lifecycle's inputs plus its four injection seams
    *,
    run_dir: Path,
    model: str,
    #: The operator's raw `--model`, kept separate from the resolved `model` so roles with
    #: their own default still see `None` when no override was given.
    model_override: str | None,
    defender_dir: Path,
    #: The run's tenant: the box mounts only `tenant.agent`, read-only.
    tenant: RunTenant,
    #: The world this process is, threaded through so the drive function builds the world
    #: registry rather than the production one.
    world: Any = None,
    investigate: _Investigate = _drive_investigation,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> dict[str, Any]:
    """Start the box, run the investigation inside it, and reap both on every exit
    (`box_mod.stop_and_scrub` owns the stop/scrub ordering and rules).
    """
    box = start_box(run_dir, defender_dir, tenant_agent=tenant.agent)
    investigation_ok = False
    try:
        summary = investigate(
            alert_path=RunPaths(run_dir).alert,
            run_dir=run_dir,
            run_id=run_dir.name,
            defender_dir=defender_dir,
            model_name=model,
            model_override=model_override,
            box=box,
            tenant=tenant,
            world=world,
        )
        investigation_ok = True
    finally:
        box_mod.stop_and_scrub(
            box, run_dir, stop_box=stop_box, scrub_tree=scrub,
            in_flight=not investigation_ok,
        )
    return summary


def _tenant_id_of(record: TenantRecord | None) -> str:
    """The tenant a run on this runs base is for: its record's, or `DEFAULT_TENANT_ID` on a
    fresh base (whose record the run-dir builder creates)."""
    from defender import _tenant

    return record.tenant_id if record is not None else _tenant.DEFAULT_TENANT_ID


def _record_reader(runs_base: Path, *, sibling: bool) -> Callable[[], TenantRecord | None]:
    """This runs base's tenant record, read at most once and never created here, so an
    invocation refused before the run dir exists leaves no tenant choice on disk.

    A sibling's base must already hold one (the launcher seeds it); absence is refused, since a
    sibling on the bootstrap tenant would run another tenant's settings on the staged corpus."""
    from defender import _tenant

    @functools.cache
    def read() -> TenantRecord | None:
        try:
            if not sibling:
                return _tenant.peek_tenant(runs_base)
            return _tenant.read_tenant(runs_base)
        except _tenant.TenantRecordCorrupt as refusal:
            where = ("a sibling's runs base carries the episode's tenant record, seeded by the "
                     "branching launcher" if sibling else "this runs base's tenant record")
            sys.exit(f"[run.py] {where}: {refusal}")

    return read


def _resolve_run_tenant(
    tenants_root: Path, runs_base: Path, record: TenantRecord | None, *, defender_dir: Path,
    dispatches_lead_zero: bool,
) -> RunTenant:
    """The run's tenant, or the refusal — before the run dir, the box and any model call, so
    tenant misconfiguration fails early. Refusals name the file to edit and where the tenant
    came from.

    `dispatches_lead_zero` is False for a `--resume` sibling, which dispatches no turn-0 lead."""
    from defender import _tenant
    from defender.runtime import run_tenant as run_tenant_mod

    tenant_id = _tenant_id_of(record)
    try:
        return run_tenant_mod.resolve_tenant(
            tenants_root, tenant_id, defender_dir=defender_dir,
            dispatches_lead_zero=dispatches_lead_zero, box_mounted=(runs_base,))
    except run_tenant_mod.TenantRefused as refusal:
        source = (f"recorded in {_tenant.record_path(runs_base)}" if record is not None else
                  f"the bootstrap tenant of a fresh runs base — {runs_base} has no tenant "
                  "record yet")
        legacy = (
            " — edit the record to name this runs base's tenant. Runs already made under "
            "`default` stay unbranchable either way: their stamps name no tenant a family could "
            "run on" if not _tenant.is_usable_tenant_id(tenant_id) else "")
        sys.exit(f"[run.py] this run's tenant {tenant_id!r} ({source}) cannot be used: "
                 f"{refusal}{legacy}")


def _sibling_tenant_agrees(
    world: Any, record_of: Callable[[], TenantRecord | None], runs_base: Path,
) -> None:
    """Refuse a sibling whose runs base names a tenant other than the episode's (the source
    run's). That means a hand-resumed sibling on the wrong base, which would query the staged
    corpus with another tenant's grants."""
    from defender import _tenant

    if world is None:
        return
    record = record_of()
    source = Path(world.family.source_run_dir)
    try:
        episode = _tenant.tenant_of_run(source)
    except _tenant.TenantRecordCorrupt as refusal:
        sys.exit(f"[run.py] the episode's tenant is the source run's, read from its runs "
                 f"base's record: {refusal}")
    if record is None or record.tenant_id != episode.tenant_id:
        sys.exit(
            f"[run.py] this sibling's runs base ({_tenant.record_path(runs_base)}) names tenant "
            f"{record.tenant_id if record is not None else None!r}, but the episode's tenant — "
            f"the source run {source}'s — is {episode.tenant_id!r}; resume a sibling on the "
            "runs base the branching launcher seeded for it")


def _announce_provenance(run_dir: Path) -> None:
    """Log what this run was made against, read back from the stamp (not re-asking git) so
    the operator sees the record itself, including whether the tree was dirty."""
    rec = _provenance.read(RunPaths(run_dir).provenance)
    if rec is None:
        _logger.info("commit=unrecorded")
        return
    if rec.commit is None:
        _logger.info(f"commit=unavailable ({rec.unavailable})")
        return
    # `dirty is None` is unknown, neither clean nor dirty.
    mark = {True: " +dirty", False: "", None: " +dirt-unknown"}[rec.dirty]
    if rec.dirty is None:
        # Include the reason: it tells the operator what to fix.
        detail = f" ({rec.unavailable})" if rec.unavailable else ""
    else:
        # Keyed on the count: a corrupted count reads back as 0, and "(0 paths)" would be
        # invented.
        detail = f" ({rec.dirty_path_count} paths)" if rec.dirty_path_count else ""
    _logger.info(f"commit={rec.commit[:12]}{mark}{detail}")


def resume_world(manifest: Path, world_label: str, *, settings: Callable[[], Path]) -> Any:
    """The world this process is, from the manifest.

    The episode dir is the manifest's parent, so the world ledger sits beside the family's
    primed recording and depends on nothing the manifest does not say.

    A manifest that records no `configured_patterns` is judged against the tenant's corpus
    config, read from `settings`; otherwise no tenant is looked up.
    """
    from defender.learning.branch.estate.stagers.elastic import configured_patterns  # lint-shippable: ok — the tenant's configured corpus patterns an older manifest's overlays were judged against
    from defender.runtime.branch import _family

    manifest = Path(manifest)
    return _family.resume_world_from(
        _family.load_family(
            manifest, configured_patterns=lambda: configured_patterns(settings())),
        world_label, manifest.parent)


def _screened_source_alert(source_run_dir: Path) -> Path:
    """The source run's alert, or the refusal that says it is not a plain file.

    The source run dir was a box's writable bind, so `alert.json` may be a planted link, and
    `materialize_run` follows links. Checked before the copy so outside bytes never become
    this run's alert.
    """
    from defender._run_paths import artifact_file

    alert = RunPaths(Path(source_run_dir)).alert
    if not artifact_file(alert):
        sys.exit(
            f"source alert {alert} is not a plain file — the alert is the case input this "
            "sibling investigates, and a link wearing its name would copy bytes from outside "
            "the source run into this run dir")
    return alert


def _resume_target(ns: argparse.Namespace, *, settings: Callable[[], Path]) -> Any:
    """The world this process is, or `None` for an ordinary run — plus the sibling's two
    refusals, before anything is spent.

    `--update-ticket` is refused outright rather than ignored: the two ticket calls are paired
    around the curation marker. An undeclared world label is refused before a run dir exists.
    """
    if ns.resume is None:
        return None
    from defender.runtime.branch._family import FamilyError

    if ns.update_ticket:
        sys.exit(
            "--update-ticket is not available with --resume: a sibling world is a synthetic "
            "continuation of someone else's case, and a ticket row for it would enter the "
            "case history as a real investigation of a real alert")
    try:
        return resume_world(ns.resume, ns.world, settings=settings)
    except FamilyError as refusal:
        sys.exit(f"[run.py] {refusal}")


def _materialize_run(
    alert: Path, run_id: str | None, *, model: str | None, world: Any = None,
    tenant_id: str, expected_record: TenantRecord | None,
) -> Run:
    """Build this run's directory via `run_common.materialize_run` and return its tenant-bound
    handle, stamped with code, model, tenant and (for a sibling) the manifest's world and
    lineage.

    The single call site of the builder and the seam `main` injects; turns a tenant record that
    changed since `main` read it into a named refusal.
    """
    from defender._tenant import TenantRecordMismatch

    try:
        run = _run.materialize_run(
            alert, run_id, model=model, world=world, tenant_id=tenant_id,
            expected_record=expected_record)
    except TenantRecordMismatch as refusal:
        sys.exit(f"[run.py] {refusal}")
    return run


def main(  # noqa: PLR0913 — the entry point's inputs plus its six injection seams
    argv: list[str],
    *,
    lifecycle: Callable[..., dict[str, Any]] = _run_investigation_lifecycle,
    visualize: Callable[[Run], None] = _run.visualize,
    ticket_writer: Any = _default_ticket_writer,
    enqueue: Callable[..., bool] = _run.enqueue_curation,
    preflight: Callable[[str | None], int] = preflight_role_models,
    materialize: Callable[..., Run] = _materialize_run,
) -> int:
    # Undrivable dependencies (credentialed lifecycle, HTML render, ticket endpoint) are
    # injection seams defaulting to production.
    ns = parse_args(argv)
    # Bound under its production name so the curation lane is visibly reached from here.
    enqueue_curation = enqueue

    # This entry point hands the tenants root down; nothing below finds it for itself.
    tenants_root = (ns.tenants_root if ns.tenants_root is not None
                    else default_tenants_root(DEFENDER_DIR.parent))

    runs_base = _run.resolve_runs_base()
    record_of = _record_reader(runs_base, sibling=ns.resume is not None)

    # One tenant resolution, shared by the old-manifest judge and the run.
    tenant_of = functools.cache(lambda: _resolve_run_tenant(
        tenants_root, runs_base, record_of(), defender_dir=DEFENDER_DIR,
        dispatches_lead_zero=ns.resume is None))
    world = _resume_target(ns, settings=lambda: tenant_of().settings)
    _sibling_tenant_agrees(world, record_of, runs_base)

    # The case input is screened before the preflight, like other argument errors.
    if world is not None:
        alert = _screened_source_alert(Path(world.family.source_run_dir))
        run_id: str | None = world.run_id
    else:
        alert = ns.alert.resolve()
        run_id = ns.run_id

    # Resolved before anything is spent; the builder holds the stamp to this record.
    tenant_record = record_of()
    tenant = tenant_of()

    model = driver.resolve_main_model(ns.model)
    # Runs in siblings too: models are resolved per process, so each sibling must check (and
    # record) its own.
    rc = preflight(ns.model)
    if rc:
        return rc

    # The handle, not just its directory: the post-run step saves the run page through it.
    run = materialize(alert, run_id, model=model, world=world, tenant_id=tenant.tenant_id,
                      expected_record=tenant_record)
    run_dir = run.run_dir

    # Every log line from here on, the crash included, names this run and tenant.
    with _log.run_context(run_dir.name, tenant.tenant_id, logger=_logger):
        if ns.update_ticket:
            ticket_writer.open_case_ticket(run_dir, settings_dir=tenant.settings)

        _logger.info(f"run_dir={run_dir} model={model}")
        _announce_provenance(run_dir)

        summary = lifecycle(
            run_dir=run_dir,
            model=model,
            model_override=ns.model,
            defender_dir=DEFENDER_DIR,
            tenant=tenant,
            world=world,
        )

        # Everything below reads the scrubbed tree; a lifecycle failure propagates uncaught.
        out = str(summary.get("output") or "")
        _logger.info(f"done ({summary.get('requests')} model requests); "
                     f"output: {out[:200]}")

        artifacts = [entry.name for entry in sorted(run_dir.iterdir())]
        _logger.info("artifacts: %s", ", ".join(artifacts), extra={"artifacts": artifacts})
        # The reap-scan verdict sits outside the tree it judges (in-tree, the box could forge
        # it), so the listing above cannot show it; name it for the operator.
        verdict = box_mod.verdict_path(run_dir)
        if verdict.is_file():
            _logger.info(f"../{verdict.name}: the reap scan's verdict — sits beside the run dir, "
                         "not in it")
        else:
            _logger.warning(f"../{verdict.name} MISSING — this tree was never scrubbed")

        _run.cross_check_tables(run_dir)

        # No automatic feed into the learning pipeline; only catalog curation is triggered
        # here, and its failure does not affect the exit status. The ticket comment (never a
        # close — that is a person's act) is recorded before the curation marker, which a
        # drainer may pick up immediately.
        if ns.update_ticket:
            # Both inputs come from the driver's summary, not from a possibly stale sidecar.
            ticket_writer.record_case_ticket(
                run_dir, settings_dir=tenant.settings, truncated_by=summary.get("truncated_by"),
                closed_before_cut=summary.get("closed_before_cut") is True)

        # A sibling's evidence was staged on purpose, so it must never feed the catalog.
        if world is not None:
            _logger.info("--resume: a sibling world is not enqueued for curation")
        elif ns.no_learn:
            _logger.info("--no-learn set; not enqueuing for curation")
        elif enqueue_curation(run_dir, alert, truncated_by=summary.get("truncated_by")):
            _logger.info("enqueued for catalog curation")

        try:
            visualize(run)
        except _run.VisualizeFailed:
            _logger.warning("the run page was not saved", exc_info=True)
        return 0

if __name__ == "__main__":
    _log.configure_from_env()
    sys.exit(main(sys.argv[1:]))
