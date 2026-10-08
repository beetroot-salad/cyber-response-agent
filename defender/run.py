#!/usr/bin/env python3
"""Defender entrypoint — investigate one alert end-to-end.

The investigation is driven by the in-process PydanticAI driver
(`runtime/driver.py`): materialize the run dir → run → cross-check the two live
tables → enqueue learning → visualize. Run-dir + post-step helpers are shared
via `run_common.py`.

Usage (every run names its tenant, and there is no default; on the host,
clone the tenant's repo into `$DEFENDER_DATA_ROOT/<tenant>/knowledge`, then set it up once with
    `python3 defender/scripts/tenant.py setup <tenant>`):
    python3 defender/run.py <alert.json> --tenant <tenant> [--run-id ID] [--no-learn] [--model M]

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

# Hand-rolled rather than `_venv.reexec_into_venv`: this must run before any
# `defender.*` import, and reaching that helper is one.
_DEFENDER_DIR = Path(__file__).resolve().parent
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse  # noqa: E402
import asyncio  # noqa: E402
import contextlib  # noqa: E402
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
from defender.run_repository import Run  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender import _tenant  # noqa: E402
from defender._episode_handle import Episode  # noqa: E402
from defender._episode_paths import LAYOUT  # noqa: E402
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
    p.add_argument("--model", default=None,
                   help="model id (overrides $DEFENDER_MODEL); e.g. a claude-* id, "
                        "or 'glm-5.3' / 'fireworks:<id>' for the Fireworks-served GLM")
    p.add_argument("--tenant", default=None,
                   help="the tenant this run belongs to; required on every run, --resume "
                        "included (there is no default). On --resume it must be the source "
                        "run's tenant, as its runs-base record names it")
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
        world: Any = None, episode: Episode | None = None,
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
    #: The sibling's episode, held by `main`: the world ledger is written through it.
    episode: Episode | None = None,
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
        if episode is None:
            # The world's ledger is written through the episode `main` holds; there is no path
            # to fall back to.
            raise TypeError("_drive_investigation(world=…) needs the sibling's held `episode=`")
        from defender.learning.branch.estate.applier import WorldApplier
        from defender.learning.branch.estate.registry import WorldRegistry
        from defender.learning.branch.ledger import Ledger
        from defender.runtime import branch as branch_mod

        family = world.family
        verbs: Any = WorldRegistry(
            roster, tenant.grants.gather,
            # Declared up front: a world that serves nothing must still leave a ledger.
            world=world, ledger=Ledger.for_world(episode, world.world_id).declare(),
            as_of=world.as_of, applier=WorldApplier(),
            grant_home=tenant.table_pointer,
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
    #: The sibling's held episode, threaded beside `world` for the world ledger's writes.
    episode: Episode | None = None,
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
            episode=episode,
        )
        investigation_ok = True
    finally:
        box_mod.stop_and_scrub(
            box, run_dir, stop_box=stop_box, scrub_tree=scrub,
            in_flight=not investigation_ok,
        )
    return summary


def _resolve_run_tenant(
    tenant: _tenant.Tenant, *, defender_dir: Path, dispatches_lead_zero: bool,
) -> RunTenant:
    """The accepted tenant ready to run — its grants and lead-zero dispatch from run start's
    readiness function — or the refusal, before the run dir, the box and any model call, so
    tenant misconfiguration fails early. Refusals name the file to edit.

    `dispatches_lead_zero` is False for a `--resume` sibling, which dispatches no turn-0
    lead."""
    from defender.runtime import run_tenant as run_tenant_mod

    try:
        return run_tenant_mod.run_tenant_for(
            tenant, defender_dir=defender_dir, dispatches_lead_zero=dispatches_lead_zero)
    except run_tenant_mod.TenantRefused as refusal:
        sys.exit(f"[run.py] this run's tenant {tenant.id!r} cannot be used: {refusal}")


def _sibling_tenant_agrees(world: Any, tenant: _tenant.Tenant) -> None:
    """Refuse a sibling whose request names a tenant other than the episode's — the source
    run's, read from its runs-base record, never its box-writable stamp. The launcher names
    the episode's tenant on each sibling's command line, so a disagreement is a sibling resumed
    by hand for another tenant, which would query the staged corpus with that tenant's grants."""
    if world is None:
        return
    try:
        source_tenant = _tenant.tenant_of_run_dir(
            tenant.data_root, Path(world.family.source_run_dir))
    except _tenant.TenantRefused as refused:
        sys.exit(f"[run.py] {refused}")
    if source_tenant != tenant.id:
        sys.exit(f"[run.py] the requested tenant {tenant.id!r} disagrees with the source run's "
                 f"tenant {source_tenant!r}")


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


def resume_world(episode: Episode, world_label: str, *, tenant: Callable[[], Any]) -> Any:
    """The world this process is, from `episode`'s manifest — judged against the episode
    tenant's configured corpus patterns only where the manifest does not record them.

    The episode dir is the manifest's own, so the world ledger sits beside the family's
    primed recording and depends on nothing the manifest does not say.

    A manifest that records no `configured_patterns` was judged against the checkout's corpus
    config when it was authored. That config now lives in the tenant's record (#1107), so for
    such a manifest — and only for one — the loader asks `tenant` for the sibling's own
    `RunTenant` (resolved from the record the launcher seeded its runs base with, naming the
    source's tenant) and takes its corpus patterns from the record's corpus-engine view. A
    manifest that records its set is judged by the manifest, and no tenant is looked up.
    """
    from defender.learning.branch.estate.stagers.elastic import configured_patterns  # lint-shippable: ok — the tenant's configured corpus patterns an older manifest's overlays were judged against
    from defender.runtime.branch import _family

    return _family.resume_world_from(
        _family.load_family(
            episode.view(), configured_patterns=lambda: configured_patterns(tenant().elastic)),  # lint-shippable: ok — the record's field name (#1107)
        world_label, episode.dir)


def _screened_source_alert(source_run_dir: Path) -> Path:
    """The source run's alert, or the refusal that says it is not a plain file.

    The source run dir was a box's writable bind, so `alert.json` may be a planted link, and
    `materialize_run` follows links. Checked before the copy so outside bytes never become
    this run's alert.
    """
    from defender.run_repository import artifact_file

    alert = RunPaths(Path(source_run_dir)).alert
    if not artifact_file(alert):
        sys.exit(
            f"source alert {alert} is not a plain file — the alert is the case input this "
            "sibling investigates, and a link wearing its name would copy bytes from outside "
            "the source run into this run dir")
    return alert


def _resume_target(ns: argparse.Namespace, *, episode: Episode | None,
                   tenant: Callable[[], Any]) -> Any:
    """The world this process is, or `None` for an ordinary run — plus the sibling's two
    refusals, before anything is spent.

    `--update-ticket` is refused outright rather than ignored: the two ticket calls are paired
    around the curation marker. An undeclared world label is refused before a run dir exists.
    """
    if ns.resume is None:
        return None
    if episode is None:
        # A sibling is only ever resumed through its held episode; without one it must not
        # run on as an ordinary investigation.
        sys.exit(f"[run.py] --resume {ns.resume}: no episode is held for it")
    from defender.runtime.branch._family import FamilyError

    if ns.update_ticket:
        sys.exit(
            "--update-ticket is not available with --resume: a sibling world is a synthetic "
            "continuation of someone else's case, and a ticket row for it would enter the "
            "case history as a real investigation of a real alert")
    try:
        return resume_world(episode, ns.world, tenant=tenant)
    except FamilyError as refusal:
        sys.exit(f"[run.py] {refusal}")


def _materialize_run(
    alert: Path, run_id: str | None, *, tenant: _tenant.Tenant, model: str | None,
    world: Any = None,
) -> Run:
    """Build this run's directory via `run_common.materialize_run` and return its tenant-bound
    handle, stamped with code, model, the request's tenant and (for a sibling) the manifest's
    world and lineage.

    The single call site of the builder and the seam `main` injects; turns a tenant refusal
    (a runs-base record naming another tenant, say) into a named `[run.py]` exit.
    """
    try:
        run = _run.materialize_run(alert, run_id, tenant=tenant, model=model, world=world)
    except _tenant.TenantRefused as refusal:
        sys.exit(f"[run.py] {refusal}")
    return run


def _accept_request_tenant(
    ns: argparse.Namespace, *, box_mounted: tuple[Path, ...],
) -> _tenant.Tenant:
    """The request's tenant, accepted, or a `[run.py]` refusal before the preflight. Every run
    names it with `--tenant`, a sibling included: it comes from the request (for a platform,
    the acting user's authentication context), never from a record or a stamp, and there is no
    default. The data root is resolved here, once, and accepted under through
    `_tenant.accept_tenant` — the one acceptance every entry point shares; a sibling's
    tenant is also checked against its source's record once the manifest is resolved
    (`_sibling_tenant_agrees`). `box_mounted` is what the run's box mounts besides the
    checkout — a sibling's runs base, inside its held episode — and the tenant's settings must
    sit under none of it."""
    try:
        tenant_id = _tenant.requested_tenant_id(ns.tenant)
        return _tenant.accept_tenant(
            _tenant.resolve_data_root(), tenant_id, defender_dir=DEFENDER_DIR,
            box_mounted=box_mounted)
    except _tenant.TenantRefused as refused:
        sys.exit(f"[run.py] this run's tenant cannot be used: {refused}")


def _resume_episode_dir(ns: argparse.Namespace) -> Path | None:
    """The episode dir a `--resume` sibling resumes, or `None` for an ordinary run: the
    manifest's parent, RESOLVED AT ENTRY (§7 J42) so no path built from it is relative or
    symlinked. A manifest not named `LAYOUT.family` is refused before anything is opened."""
    if ns.resume is None:
        return None
    manifest = ns.resume.resolve()
    if manifest.name != LAYOUT.family.name:
        sys.exit(f"[run.py] --resume {ns.resume} is not an episode manifest — a sibling resumes "
                 f"from its episode dir's {LAYOUT.family}")
    return manifest.parent


def _case_input(ns: argparse.Namespace, world: Any) -> tuple[Path, str | None]:
    """The alert this run investigates and its run id: a sibling's from its world (the source
    run's alert, screened before the preflight like other argument errors), else the
    operator's."""
    if world is not None:
        return _screened_source_alert(Path(world.family.source_run_dir)), world.run_id
    return ns.alert.resolve(), ns.run_id


def main(  # noqa: PLR0913 — the entry point's inputs plus its six injection seams
    argv: list[str],
    *,
    lifecycle: Callable[..., dict[str, Any]] = _run_investigation_lifecycle,
    visualize: Callable[..., None] = _run.visualize,
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

    # A sibling's door: the episode it resumes, held for the whole run. The handle serves the
    # manifest read and the world ledger's writes; nothing below reopens the episode by name.
    episode_dir = _resume_episode_dir(ns)
    try:
        door: contextlib.AbstractContextManager[Episode | None] = (
            contextlib.nullcontext() if episode_dir is None else Episode.open(episode_dir))
    except OSError as missing:
        sys.exit(f"[run.py] --resume {ns.resume}: its episode dir cannot be held ({missing})")
    with door as episode:
        # The tenant, from the request, accepted under the data root before anything is spent;
        # nothing below resolves the root or a tenant path again. A sibling's runs base is its
        # episode's, which the box mounts and the tenant's settings must not sit under.
        accepted = _accept_request_tenant(
            ns, box_mounted=() if episode is None else (episode.runs.path,))
        # One readiness check, shared by the old-manifest judge (only for a manifest recording
        # no corpus patterns) and the run.
        tenant_of = functools.cache(lambda: _resolve_run_tenant(
            accepted, defender_dir=DEFENDER_DIR, dispatches_lead_zero=ns.resume is None))
        world = _resume_target(ns, episode=episode, tenant=tenant_of)
        _sibling_tenant_agrees(world, accepted)

        alert, run_id = _case_input(ns, world)

        # The tenant's settings, resolved before anything is spent; nothing below reads them again.
        tenant = tenant_of()

        model = driver.resolve_main_model(ns.model)
        # Runs in siblings too: models are resolved per process, so each sibling must check (and
        # record) its own.
        rc = preflight(ns.model)
        if rc:
            return rc

        # The handle, not just its directory: the post-run step saves the run page through it.
        run = materialize(alert, run_id, tenant=accepted, model=model, world=world)
        run_dir = run.run_dir

        # Every log line from here on, the crash included, names this run and the tenant this
        # process resolved once above and hands inward as one value.
        with _log.run_context(run_dir.name, tenant.tenant_id, logger=_logger):
            if ns.update_ticket:
                ticket_writer.open_case_ticket(
                    run_dir, tenant=tenant, defender_dir=DEFENDER_DIR,
                    env=_run.run_env(DEFENDER_DIR, run_dir))

            _logger.info(f"run_dir={run_dir} model={model}")
            _announce_provenance(run_dir)

            summary = lifecycle(
                run_dir=run_dir,
                model=model,
                model_override=ns.model,
                defender_dir=DEFENDER_DIR,
                tenant=tenant,
                world=world,
                episode=episode,
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
                    run_dir, tenant=tenant, defender_dir=DEFENDER_DIR,
                    env=_run.run_env(DEFENDER_DIR, run_dir), truncated_by=summary.get("truncated_by"),
                    closed_before_cut=summary.get("closed_before_cut") is True)

            # A sibling's evidence was staged on purpose, so it must never feed the catalog.
            if world is not None:
                _logger.info("--resume: a sibling world is not enqueued for curation")
            elif ns.no_learn:
                _logger.info("--no-learn set; not enqueuing for curation")
            elif enqueue_curation(run_dir, alert, truncated_by=summary.get("truncated_by")):
                _logger.info("enqueued for catalog curation")

            try:
                visualize(run, update_ticket=ns.update_ticket)
            except _run.VisualizeFailed:
                _logger.warning("the run page was not saved", exc_info=True)
            return 0


if __name__ == "__main__":
    _log.configure_from_env()
    sys.exit(main(sys.argv[1:]))
