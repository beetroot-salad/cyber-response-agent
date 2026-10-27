#!/usr/bin/env python3
"""Defender entrypoint — investigate one alert end-to-end.

The investigation is driven by the in-process PydanticAI driver
(`runtime/driver.py`): materialize the run dir → run → cross-check the two live
tables → enqueue learning → visualize. Run-dir + post-step helpers are shared
via `run_common.py`.

Usage (every run names its tenant, and there is no default; on the host,
clone the tenant's repo into `$DEFENDER_DATA_ROOT/<tenant>/knowledge`, then set it up once with
    `python3 defender/cli/tenant.py setup <tenant>`):
    python3 defender/run.py <alert.json> --tenant <tenant> [--no-learn] [--model M]
        [--knowledge-commit SHA]

Every launch first publishes the tenant's latest approved knowledge in a separate short-lived
child process, then reads its own copy of that export; `--knowledge-commit` pins the run to an
export already published and skips the publish (#1108 P4).

Billing / credentials: the engine calls the first-party Anthropic REST API and
needs a real billable API key. Inside a Claude Code session the *ambient*
ANTHROPIC_API_KEY is the subscription credential (it 401s against the REST API),
so the billable key is sourced from a `.env` file (`resolve_first_party_key`) and
takes precedence over the ambient value.
"""

from __future__ import annotations

from defender.records._locations import DataRoot, RunsBase, EpisodesRoot

import logging
import json
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
from collections.abc import Callable, Collection, Mapping  # noqa: E402
from typing import Any, Protocol  # noqa: E402

if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender import _log  # noqa: E402
from defender.records import _provenance  # noqa: E402
from defender import run_common as _run  # noqa: E402
from defender._paths import adapters_under  # noqa: E402
from defender.records import Run  # noqa: E402
from defender.records import RunPaths  # noqa: E402
from defender.tenancy import _tenant  # noqa: E402
from defender.records._episode_handle import Episode  # noqa: E402
from defender import box as box_mod  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender import providers  # noqa: E402
from defender.runtime import run_end  # noqa: E402
from defender.runtime import run_knowledge  # noqa: E402
from defender.runtime import system_status  # noqa: E402
from defender._agent_role import AgentRole  # noqa: E402
from defender.runtime.run_tenant import RunTenant  # noqa: E402
from defender.runtime.system_status import RunSystems  # noqa: E402
from defender.runtime.verb_grant import GrantError  # noqa: E402
from defender.runtime.verbs import (  # noqa: E402
    ModuleVerbRegistry,
    RegistryError,
    RosterRead,
    ServingAbort,
    read_roster,
)
from defender.runtime import ticket_writer as _default_ticket_writer  # noqa: E402

DEFENDER_DIR = _DEFENDER_DIR


from defender._first_party_key import (  # noqa: E402,F401
    _read_env_key,
    resolve_first_party_key,
)
from defender.records._tenant_id import TenantRefused

_logger = logging.getLogger(__name__)


def parse_args(argv: list[str]) -> argparse.Namespace:
    """The entry point's arguments, for an ordinary run and for a sibling world.

    A sibling is `--tenant T --episode <episode_id> --world <label>` (#1105 PR 2): its
    request's tenant, the episode it is an arm of, and which arm — ids, never a path;
    everything else it needs is derived from the episode's manifest. The positional alert is
    refused with `--episode`, since the manifest already names the source run and there would
    be two case inputs.
    """
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("alert", type=Path, nargs="?", default=None,
                   help="Path to alert.json fixture (illegal with --episode)")  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    p.add_argument("--episode", default=None,
                   help="the episode this process is a sibling arm of, by id (under the "
                        "tenant's own episodes folder)")
    p.add_argument("--world", default=None,
                   help="which world of --episode's manifest this process is")
    p.add_argument("--no-learn", action="store_true",
                   help="Skip enqueuing for learning (also skips catalog curation — the "
                        "flag now governs both lanes)")
    p.add_argument("--update-ticket", action="store_true",
                   help="Write/close a case-history ticket for this alert (default off)")
    p.add_argument("--model", default=None,
                   help="model id (overrides $DEFENDER_MODEL); e.g. a claude-* id, "
                        "or 'glm-5.3' / 'fireworks:<id>' for the Fireworks-served GLM")
    p.add_argument("--knowledge-commit", default=None, metavar="SHA",
                   help="run on the tenant's export at this full commit id (already published "
                        "or materialised) and skip the launch-time publish")
    p.add_argument("--tenant", default=None,
                   help="the tenant this run belongs to; required on every run, --episode "
                        "included (there is no default). On --episode the episode is looked "
                        "up under this tenant's folder, and its arm roster must name --world")
    ns = p.parse_args(argv)
    if ns.episode is not None and ns.alert is not None:
        p.error(
            "the positional alert is illegal with --episode: the manifest already names the "
            "source run the alert would come from, and a command line carrying both names two "
            "case inputs with no rule for which wins")
    if ns.episode is None and ns.alert is None:
        p.error("an alert path is required unless --episode names the episode of a sibling")
    if ns.episode is not None and not ns.world:
        p.error("--episode needs --world: a manifest declares a family, and a process is one "
                "arm")
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


#: The roles only a branching process uses (#1224, M25=A): preflighted where `branching=True`
#: (the launcher and its siblings), never on a plain alert run. Each role's effort knob is read
#: at call time and checked against the provider its model routes to.
def _branching_roles() -> dict[AgentRole, Callable[[], str]]:
    from defender.learning.core import config

    return {AgentRole.ORACLE: config.oracle_effort,
            AgentRole.ORACLE_CHECK: config.oracle_check_effort}


def preflight_role_models(  # noqa: C901 — one fail-fast check per role, plus the branching roles' efforts
        model_override: str | None = None, *, branching: bool = False) -> int:
    """Check every registered role's model config at startup and fail fast if a provider key
    is unusable. Some providers only fail on first live call, and review agents are built per
    call, so a broken review role would otherwise silently downgrade runs to unresolved.

    The oracle roles are checked only when `branching` (M25=A): a plain alert run never
    depends on them. A branching role with no definition fails loudly, naming it."""
    from defender.agents import AGENTS

    efforts = _branching_roles()
    if branching:
        missing = [role.name for role in efforts if role not in AGENTS]
        if missing:
            _logger.error(f"preflight: branching role(s) {missing} have no agent definition")
            return 2
    seen_provider_ids: set[str] = set()
    for defn in AGENTS.values():
        if defn.role in efforts and not branching:
            continue
        try:
            name = _role_model_name(defn, model_override if defn.role not in efforts else None)
        except Exception as e:  # noqa: BLE001 — a broken model accessor is a preflight failure
            _logger.error(f"preflight: {defn.role.name} model config raised: {e!r}")
            return 2
        try:
            prov = providers.provider_for(name)
        except ValueError as e:
            _logger.error(f"preflight: {defn.role.name}: {e}")
            return 2
        if defn.role in efforts:
            effort = efforts[defn.role]()
            try:
                prov.settings_for_effort(effort)
            except ValueError as e:
                _logger.error(f"preflight: {defn.role.name} ({name}) effort {effort!r}: {e}")
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

    The run's judgement of its systems is not part of it: the lifecycle binds the one `main`
    made at run start (`system_status.RunSystems`: the roster the run reads and each system down
    at its start) into whichever seam it drives (`_judged`), which hands it to
    `_drive_investigation(systems=…)`.
    """

    def __call__(  # noqa: PLR0913 — the investigation's whole identity, one keyword each
        self, *, alert_path: Path, run: Run, defender_dir: Path,
        model_name: str, model_override: str | None, box: Any, tenant: RunTenant,
        world: Any = None, episode: Episode | None = None, serving: Any = None,
        source: Run | None = None,
    ) -> dict[str, Any]: ...


def _run_the_driver(**kwargs: Any) -> dict[str, Any]:
    """The driver's coroutine, as a synchronous call — separate so tests can observe the
    registry decision without an event loop.
    """
    return asyncio.run(driver.run_investigation(**kwargs))


def _drive_investigation(  # noqa: PLR0913 — one investigation's whole identity plus its seams
    *,
    alert_path: Path,
    run: Run,
    defender_dir: Path,
    model_name: str,
    model_override: str | None,
    box: Any,
    #: The run's tenant (folder, grants, lead-zero dispatch), resolved by `main` before the box.
    tenant: RunTenant,
    #: The world this process is, on the `--episode` path; `None` on an ordinary run.
    world: Any = None,
    #: The sibling's episode, held by `main`: the world ledger is written through it.
    episode: Episode | None = None,
    #: The world's settled oracle side (#1224, `registry.oracle_serving`), resolved by `main`;
    #: `None` exactly when `world` is.
    serving: Any = None,
    #: The source run the world forks, opened by `main` in the tenant's repository from the
    #: manifest's `source_run_id` (#1105 PR 2); `None` exactly when `world` is.
    source: Run | None = None,
    registry_cls: Any = ModuleVerbRegistry,
    investigate: Callable[..., dict[str, Any]] = _run_the_driver,
    #: The run's one judgement of its systems (#1256), made by `main` before the run folder
    #: existed: the roster the run reads and each granted system down at its start. The
    #: registry is built over that roster and the driver holds that verdict, so the run is
    #: judged once. `None` (a direct caller with no `main` before it): the roster is
    #: `defender_dir`'s, read here, and the driver judges it.
    systems: RunSystems | None = None,
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
    # The roster `main` judged, handed down to the registry and `run_investigation` with its
    # verdict; read here only for a direct caller, whose run the driver judges.
    roster = systems.roster if systems is not None else read_roster(adapters_under(defender_dir))
    if world is not None:
        if episode is None:
            # The world's ledger is written through the episode `main` holds; there is no path
            # to fall back to.
            raise TypeError("_drive_investigation(world=…) needs the sibling's held `episode=`")
        if serving is None:
            raise TypeError("_drive_investigation(world=…) needs the world's settled `serving=`")
        if source is None:
            # The fork's source is the opened `Run`, never the manifest's recorded path.
            raise TypeError("_drive_investigation(world=…) needs the opened source run "
                            "`source=`")
        from defender.learning.branch.estate.limiter import RateLimiter
        from defender.learning.branch.estate.registry import (
            WorldRegistry,
            default_oracle_dir,
            prebranch_calls,
        )
        from defender.learning.branch.ledger import Ledger
        from defender.runtime import branch as branch_mod

        family = world.family
        # Declared up front: a world that serves nothing must still leave a ledger.
        ledger = Ledger.for_world(episode, world.world_id).declare()
        verbs: Any = WorldRegistry(
            roster, tenant.grants.gather, world=world, ledger=ledger, as_of=world.as_of,
            serving=serving, oracle_dir=default_oracle_dir(world, ledger),
            # This sibling's one limiter, at its slice of the episode rate (S16).
            limiter=RateLimiter(serving.settings.rate),
            tenant=tenant, grant_home=tenant.table_pointer,
            # The source run's pre-branch calls, by pre-flight's own rule (M01=A): a re-ask
            # still takes its oracle turn (S1), and is served unchanged or not at all.
            prebranch=prebranch_calls(source, family.branch_message_id),
            source_run=source,
        )
        resume = branch_mod.BranchSpec(
            source_run_dir=source.run_dir,
            branch_message_id=family.branch_message_id,
            as_of=family.as_of,
        )
        try:
            return investigate(
                alert_path=alert_path, run=run,
                defender_dir=defender_dir, model_name=model_name,
                model_override=model_override, box=box, verbs=verbs, roster=roster,
                systems=systems, resume=resume, tenant=tenant, source_run=source,
            )
        finally:
            verbs.close()
    verbs = registry_cls(roster, tenant.grants.gather, grant_home=tenant.table_pointer)
    return investigate(
        alert_path=alert_path, run=run, defender_dir=defender_dir,
        model_name=model_name, model_override=model_override, box=box, verbs=verbs,
        roster=roster, systems=systems, tenant=tenant,
    )


def _judged(investigate: _Investigate, systems: RunSystems | None) -> _Investigate:
    """`investigate` with the run's one judgement of its systems bound in (`systems=`), when
    `main` made one (#1256): the seam's shape (`_Investigate`) stays the investigation's
    identity, and the judgement rides beside it to the drive that holds it
    (`_drive_investigation`, or a seam composed over it), so the run is not judged twice.
    Without one, the seam as it is: its driver judges."""
    if systems is None:
        return investigate
    seam: Callable[..., dict[str, Any]] = investigate
    return functools.partial(seam, systems=systems)


def _run_investigation_lifecycle(  # noqa: PLR0913 — the lifecycle's inputs plus its four injection seams
    *,
    run: Run,
    model: str,
    #: The operator's raw `--model`, kept separate from the resolved `model` so roles with
    #: their own default still see `None` when no override was given.
    model_override: str | None,
    defender_dir: Path,
    #: The run's tenant: the box mounts its run copy's `stage/` only (`tenant.agent` and the
    #: staged token), read-only.
    tenant: RunTenant,
    #: The world this process is, threaded through so the drive function builds the world
    #: registry rather than the production one.
    world: Any = None,
    #: The sibling's held episode, threaded beside `world` for the world ledger's writes.
    episode: Episode | None = None,
    #: The world's settled oracle side (#1224), threaded to the world registry.
    serving: Any = None,
    #: The opened source run a world forks, threaded beside `world`.
    source: Run | None = None,
    #: The run's one judgement of its systems, made by `main` at run start (#1256), handed to
    #: the investigation beside its seam's shape (`_judged`) so the run reads that roster and
    #: holds that verdict (`None`: the drive reads `defender_dir`'s roster and the driver
    #: judges it, as for a direct caller).
    systems: RunSystems | None = None,
    investigate: _Investigate = _drive_investigation,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[..., None] = box_mod.scrub,
) -> dict[str, Any]:
    """Start the box, run the investigation inside it, and reap both on every exit
    (`box_mod.stop_and_scrub` owns the stop/scrub ordering and rules).
    """
    run_dir = run.run_dir
    verdict = run.facts.scrub_verdict

    def write_verdict(doc: dict) -> None:
        verdict.write(json.dumps(doc))

    def scrub_tree(tree: Path) -> None:
        scrub(tree, write_verdict=write_verdict)

    # The startup token of the run copy's stage (#1108 P4, U9): the `RunTenant` run start builds
    # over its run copy carries it, and `start_box` checks the stage and reads it back. A run box
    # is never started over a tenant with no run copy (`start_box` refuses one).
    token = getattr(tenant, "stage_token", None)
    staged = {} if token is None else {"staged_token": token}
    box = start_box(run_dir, defender_dir, tenant_agent=tenant.agent, tenant_id=tenant.tenant_id,
                    write_verdict=write_verdict, **staged)
    drive = _judged(investigate, systems)
    investigation_ok = False
    try:
        summary = drive(
            alert_path=RunPaths(run_dir).alert,
            run=run,
            defender_dir=defender_dir,
            model_name=model,
            model_override=model_override,
            box=box,
            tenant=tenant,
            world=world,
            episode=episode,
            serving=serving,
            source=source,
        )
        investigation_ok = True
    finally:
        box_mod.stop_and_scrub(
            box, run_dir, stop_box=stop_box, scrub_tree=scrub_tree,
            read_verdict=verdict.read, write_verdict=write_verdict,
            in_flight=not investigation_ok,
        )
    return summary


def _resolve_run_tenant(
    tenant: _tenant.Tenant, *, defender_dir: Path | None = None, dispatches_lead_zero: bool,
    copy: run_knowledge.RunCopy | None = None,
) -> RunTenant:
    """The accepted tenant ready to run — its grants and lead-zero dispatch from run start's
    readiness function, over the run's own copy of its knowledge (#1108 P4, O-B: settings,
    catalog and lessons from one export) — or the refusal, before the run dir, the box and any
    model call, so tenant misconfiguration fails early. Refusals name the file to edit.

    `dispatches_lead_zero` is False for an `--episode` sibling, which dispatches no turn-0
    lead. Without `copy` (a direct caller), the record is resolved over the tenant's own
    folder. `defender_dir` is not read: the code tree holds no tenant knowledge (O1)."""
    from defender.runtime import run_tenant as run_tenant_mod

    del defender_dir
    roots = ({} if copy is None else
             {"agent_root": copy.agent, "settings_root": copy.settings,
              "stage_token": copy.token})
    try:
        return run_tenant_mod.run_tenant_for(
            tenant, dispatches_lead_zero=dispatches_lead_zero, **roots)
    except run_tenant_mod.TenantRefused as refusal:
        sys.exit(f"[run.py] this run's tenant {tenant.id!r} cannot be used: {refusal}")


def _family_pin(ns: argparse.Namespace, pin: str | None, episode: Any) -> str | None:
    """The commit a sibling (`--episode`) reads: its family's knowledge pin, read from the
    episode, where only its launcher writes (`records._knowledge_pin`), so a sibling started or
    resumed by hand reads its family's knowledge, never a newer `current`. A `--knowledge-commit`
    naming another commit refuses. An episode with no pin (launched before the pin was
    recorded) keeps `pin` as given, as before. An ordinary run's `pin` is kept."""
    if episode is None:
        return pin
    from defender.records._knowledge_pin import PinUnreadable, read_pin

    try:
        family = read_pin(episode.view())
    except PinUnreadable as unreadable:
        sys.exit(f"[run.py] --episode {ns.episode}: the family's knowledge pin is unreadable: "
                 f"{unreadable}")
    if family is None:
        return pin
    if pin is not None and pin != family:
        sys.exit(f"[run.py] --episode {ns.episode}: --knowledge-commit {pin} is not the family's "
                 f"knowledge commit {family}")
    return family


def _knowledge_pin(ns: argparse.Namespace) -> str | None:
    """`--knowledge-commit`, held to a full commit id (O-PIN), or `None` for an unpinned run."""
    if ns.knowledge_commit is None:
        return None
    try:
        return run_knowledge.pinned_commit(ns.knowledge_commit)
    except run_knowledge.KnowledgeRefused as refused:
        sys.exit(f"[run.py] {refused}")


def _publish_report(
    publish: Callable[..., object] | None, tenant: _tenant.Tenant, data_root: DataRoot,
) -> run_knowledge.PublishReport:
    """The launch-time publish's outcome (#1108 P4, U7): the child is handed identifiers only
    — the tenant id and the data root (O8: no login material passes through the run process)
    — and its one report line is read back. The real launcher never raises and records every
    outcome itself; a seam that raises is U11's `stale:operator`, never fresh, recorded by the
    same recorder the launcher uses."""
    try:
        launch = publish if publish is not None else _default_publish()
        line = launch(str(tenant.id), data_root=_tenant.data_root_for_child(data_root))
    except Exception as failed:  # noqa: BLE001 — U11: a failed child is stale:operator, recorded
        from defender.tenancy._publish_status import record_report

        line = run_knowledge.failed_line(f"{type(failed).__name__}: {failed}")
        record_report(tenant, line, by="launch-time publish")
    return run_knowledge.read_publish_report(line)


def _default_publish() -> Callable[..., object]:
    """The real launch-time publish: a separate child process (O-BUDGET, P-3)."""
    from defender.runtime.publish_launch import launch_publish as real

    return real


def _knowledge_source(
    tenant: _tenant.Tenant, *, pin: str | None, publish: Callable[..., object] | None,
    data_root: DataRoot,
) -> run_knowledge.KnowledgeSource:
    """Which export this run reads and why: the pinned one (no publish), else `current` after
    the launch-time publish — or the refusal before the box (O-A, O9)."""
    report = None if pin is not None else _publish_report(publish, tenant, data_root)
    try:
        source = run_knowledge.resolve_source(tenant, report=report, pinned=pin)
    except run_knowledge.KnowledgeRefused as refused:
        sys.exit(f"[run.py] {refused}")
    if source.kind == run_knowledge.STALE:
        _logger.warning(f"knowledge is stale ({source.stale_kind}): the run reads the last "
                        f"published snapshot {source.commit[:12]}; the publish said: "
                        f"{source.reason}")
    return source


def _copy_knowledge(tenant: _tenant.Tenant, source: run_knowledge.KnowledgeSource,
                    run_id: str) -> run_knowledge.RunCopy:
    """The run's own copy of its export (U9), or the refusal before the box."""
    try:
        copy = run_knowledge.copy_for_run(tenant, source, run_id)
    except (run_knowledge.KnowledgeRefused, OSError) as refused:
        sys.exit(f"[run.py] the run's knowledge could not be copied: {refused}")
    try:
        _tenant.check_run_settings(copy.settings)
    except TenantRefused as refused:
        copy.remove()
        sys.exit(f"[run.py] this run's tenant cannot be used: {refused}")
    return copy


def _early_run(ns: argparse.Namespace, accepted: _tenant.Tenant, world: Any,
               episode_runs: Any) -> Run:
    """The run's handle, settled before its knowledge is copied (the copy is named by its id) and
    handed to setup whole (#1279 rev 6): a sibling's arm from its episode's roster, else a fresh
    one the tenant's runs repository mints. No caller names the id (A3); nothing is made on disk
    for an arm, and only the natural runs container for an ordinary run."""
    from defender.records import RunRefused

    try:
        if world is not None:
            return episode_runs.create(episode_runs.arm_id(world.world_id))
        return accepted.runs_repository().create()
    except (RunRefused, TenantRefused) as refused:
        where = f"--episode {ns.episode}: " if world is not None else ""
        sys.exit(f"[run.py] {where}{refused}")

def _write_knowledge_record(run_dir: Path, source: run_knowledge.KnowledgeSource) -> None:
    """The host-held knowledge-source record beside the run dir (U12): what every reader of
    the run's knowledge status reads. A run that cannot write it does not start: a missing
    record would read as unreadable everywhere (OD22')."""
    path = RunPaths(run_dir).knowledge_source()
    try:
        run_knowledge.write_host_record(path, source)
    except OSError as e:
        sys.exit(f"[run.py] could not write the run's knowledge record {path}: {e}")


def _run_roster(defender_dir: Path) -> RosterRead:
    """The adapters roster of the tree this run reads, read ONCE by `main` — or its refusal: an
    adapters tree that cannot be read stops the run before it exists."""
    try:
        return read_roster(adapters_under(defender_dir))
    except RegistryError as unreadable:
        sys.exit(f"[run.py] {unreadable}")


def _judge_start(tenant: RunTenant, *, roster: RosterRead, defender_dir: Path,
                 known_ids: Collection[str] = ()) -> RunSystems:
    """#1256 O-8, before the run exists: the run's ONE judgement of its systems
    (`system_status.judge_run`) — each granted system judged by its own adapter's settings check
    over `roster`, the roster this run reads — handed back whole, for `main` to hand on to the
    investigation, which holds it and does not judge again. A run (fresh or a sibling's) at
    whose start gather could query nothing through the systems that are up is refused
    (`system_status.require_usable`), naming each down system and its cause. Before the run
    folder, the box and any model call; nothing is logged or held here — the driver does that
    once, when the run starts. Never in the tenant resolution `tenant.py setup` and
    `defender-policy` share: whether a system is usable is a run's question, not the tenant's
    (D4)."""
    try:
        systems = system_status.judge_run(
            roster, tenant, defender_dir=defender_dir, known_ids=known_ids)
        system_status.require_usable(tenant.grants, systems.down)
    except (GrantError, system_status.NoUsableSystem) as refusal:
        sys.exit(f"[run.py] this run's tenant {tenant.tenant_id!r} cannot be used: {refusal}")
    return systems


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


def resume_world(episode: Episode, world_label: str, *, tenant: Callable[[], Any],
                 arm_ids: Mapping[str, Any] | None = None) -> Any:
    """The world this process is, from `episode`'s manifest alone — read through the one
    loader, held to the episode folder's own name (R5) — and the episode's arm roster
    (`arm_ids`), when the caller read it.

    The episode dir is the manifest's own, so the world ledger sits beside the family's
    primed recording and depends on nothing the manifest does not say. The manifest records
    its served systems, so no tenant is resolved to read it: `tenant` is never called here.
    """
    from defender.runtime.branch import _family

    del tenant  # the manifest is the whole record; see the docstring
    family = _family.load_family(episode.view(), expected_episode_id=episode.dir.name)
    return _family.resume_world_from(family, world_label, episode.dir, arm_ids=arm_ids)


def _screened_source_alert(episode: Episode) -> Path:
    """The alert a sibling investigates — the source run's, as launch copied it into the
    episode — or the refusal that says it is not a plain file.

    The episode dir is the launcher's own, but a link planted at the copy's name would have
    `materialize_run` follow it. Checked before the copy so outside bytes never become this
    run's alert.
    """
    from defender.records import artifact_file

    alert = episode.source_alert.path
    if not artifact_file(alert):
        sys.exit(
            f"the episode's copy of the source alert {alert} is not a plain file — the alert "
            "is the case input this sibling investigates, and a link wearing its name would "
            "copy bytes from outside the episode into this run dir")
    return alert


def _open_world_source(runs: Any, world: Any) -> Run:
    """The source run a world forks: the manifest's `source_run_id`, opened in the request's
    tenant's natural container (#1105 PR 2, decision A — an old manifest's `source_run_dir` is
    never read). An id the repository refuses, or a run that is not there, is the sibling's
    refusal, before anything is spent."""
    from defender.records import RunId, RunRefused

    try:
        return runs.open(RunId.parse(world.family.source_run_id))
    except RunRefused as refused:
        sys.exit(f"[run.py] the episode's source run cannot be opened: {refused}")


def _resume_target(ns: argparse.Namespace, *, episode: Episode | None,
                   tenant: Callable[[], Any],
                   arm_ids: Callable[[], Mapping[str, Any] | None] = lambda: None) -> Any:
    """The world this process is, or `None` for an ordinary run — plus the sibling's
    refusals, before anything is spent."""
    if ns.episode is None:
        return None
    if episode is None:
        # A sibling is only ever resumed through its held episode; without one it must not
        # run on as an ordinary investigation.
        sys.exit(f"[run.py] --episode {ns.episode}: no episode is held for it")
    from defender.records import RunRefused
    from defender.runtime.branch._family import FamilyError

    if ns.update_ticket:
        sys.exit(
            "--update-ticket is not available with --episode: a sibling world is a synthetic "
            "continuation of someone else's case, and a ticket row for it would enter the "
            "case history as a real investigation of a real alert")
    try:
        return resume_world(episode, ns.world, tenant=tenant, arm_ids=arm_ids())
    except (FamilyError, RunRefused) as refusal:
        sys.exit(f"[run.py] --episode {ns.episode}: {refusal}")


def _materialize_run(  # noqa: PLR0913 — the builder's whole call
    alert: Path, *, tenant: _tenant.Tenant, model: str | None, run: Run | None = None,
    world: Any = None, settings: Path | None = None,
    knowledge: run_knowledge.KnowledgeSource | None = None,
) -> Run:
    """Build this run's directory via `run_common.materialize_run` and return its tenant-bound
    handle, stamped with code, model, the request's tenant and (for a sibling) the manifest's
    world and lineage. `run` is the handle `main` settled first (`_early_run`): a sibling's arm
    from its episode's roster, or a fresh ordinary run.

    The single call site of the builder and the seam `main` injects; turns a tenant refusal
    (a runs-base record naming another tenant, say) into a named `[run.py]` exit.
    """
    try:
        run = _run.materialize_run(alert, run=run, tenant=tenant, model=model, world=world,
                                   settings=settings, knowledge=knowledge)
    except TenantRefused as refusal:
        sys.exit(f"[run.py] {refusal}")
    return run


def _request_data_root(ns: argparse.Namespace) -> DataRoot:
    """The request's tenant id checked (`--tenant` is required, there is no default), then the
    data root resolved — once, here — or a `[run.py]` refusal before the preflight."""
    try:
        _tenant.requested_tenant_id(ns.tenant)
        return _tenant.resolve_data_root()
    except TenantRefused as refused:
        sys.exit(f"[run.py] this run's tenant cannot be used: {refused}")


def _accept_request_tenant(
    ns: argparse.Namespace, *, data_root: DataRoot, box_mounted: tuple[Path | RunsBase | EpisodesRoot, ...],
) -> _tenant.Tenant:
    """The request's tenant, accepted, or a `[run.py]` refusal before the preflight. Every run
    names it with `--tenant`, a sibling included: it comes from the request (for a platform,
    the acting user's authentication context), never from a record or a stamp, and there is no
    default. It is accepted under `data_root` (`_request_data_root`) through
    `_tenant.accept_tenant` — the one acceptance every entry point shares; a sibling's
    episode is then looked up under that tenant's own folder (`_open_episode_runs`).
    `box_mounted` is what the run's box mounts besides the checkout — a sibling's arm
    container — and the tenant's settings must sit under none of it."""
    try:
        tenant_id = _tenant.requested_tenant_id(ns.tenant)
        return _tenant.accept_tenant(
            data_root, tenant_id, defender_dir=DEFENDER_DIR, box_mounted=box_mounted,
            clone_tree=False)
    except TenantRefused as refused:
        sys.exit(f"[run.py] this run's tenant cannot be used: {refused}")


def _sibling_box_mounted(ns: argparse.Namespace, data_root: DataRoot) -> tuple[RunsBase, ...]:
    """What a sibling's box mounts besides the checkout — its arm container,
    `<data root>/<T>/episodes/<episode id>/runs`, named before the tenant is accepted, so
    acceptance holds the tenant's settings out of it — or nothing for an ordinary run. The
    episode id is judged first (canonical UUID text, before any path is built); nothing is
    read."""
    if ns.episode is None:
        return ()
    from defender.records._episode_handle import EpisodeRefused

    try:
        return (_tenant.box_mounted_arm_container(data_root, ns.tenant, ns.episode),)
    except (EpisodeRefused, TenantRefused) as refused:
        sys.exit(f"[run.py] --episode {ns.episode}: {refused}")


def _open_episode_runs(ns: argparse.Namespace, accepted: _tenant.Tenant) -> Any:
    """The sibling's episode view, in its sibling form (`require_roster=True`, O4b): the episode is
    walked from the accepted tenant's own folder, no link followed at any level, and its arm
    roster must have been published — an episode that never reached RUNS, a roster that does not
    contain UUID identities, a missing episode (another tenant's included) or a link anywhere is refused
    here, right after acceptance and before the manifest is read (G5/G19). `None` for an
    ordinary run."""
    if ns.episode is None:
        return None
    from defender.records._episode_handle import EpisodeRefused
    from defender.records import RunRefused

    try:
        return accepted.runs_repository().episode(ns.episode, require_roster=True)
    except (TenantRefused, RunRefused, EpisodeRefused, OSError) as refused:
        sys.exit(f"[run.py] --episode {ns.episode} for tenant {accepted.id!r}: {refused}")


def _case_input(ns: argparse.Namespace, world: Any, episode_runs: Any) -> Path:
    """The alert this run investigates: a sibling's from its world (the source run's alert,
    screened before the preflight like other argument errors), else the operator's. The run's id
    is no input: setup mints it, or for an arm reads the one its episode's roster holds."""
    if world is not None:
        return _screened_source_alert(episode_runs.episode)
    return ns.alert.resolve()


def _world_seams(world: Any, *, oracle: Any, verifier: Any, source: Run | None) -> dict[str, Any]:
    """The lifecycle's world-only keywords: none for an ordinary run; for a sibling its oracle
    side, settled once here from its knobs (the launcher hands it its rate slice through the
    environment) and threaded inward whole, and the opened source run it forks."""
    if world is None:
        return {}
    from defender.learning.branch.estate.registry import oracle_serving
    from defender.learning.core.config import process_oracle_settings

    return {"serving": oracle_serving(process_oracle_settings(), oracle=oracle,
                                      verifier=verifier),
            "source": source}


def main(  # noqa: C901, PLR0913, PLR0915 — the entry point's inputs plus its injection seams; the unservable exit is one more arm
    argv: list[str],
    *,
    lifecycle: Callable[..., dict[str, Any]] = _run_investigation_lifecycle,
    visualize: Callable[..., None] = _run.visualize,
    ticket_writer: Any = _default_ticket_writer,
    enqueue: Callable[..., bool] = _run.enqueue_curation,
    preflight: Callable[..., int] = preflight_role_models,
    materialize: Callable[..., Run] = _materialize_run,
    oracle: Any = None,
    verifier: Any = None,
    roster: Any = None,
    publish: Callable[..., object] | None = None,
) -> int:
    """`oracle` / `verifier` are a sibling's oracle and verifier models (#1224; `None` builds
    them from their knobs). `roster` is the adapters roster this run reads (`None`: the
    checkout's, read once here): run start judges each granted system's settings check over it
    (#1256 O-8), once, and the lifecycle hands that judgement — the roster with its verdict, one
    value — to the investigation, so the roster judged and the roster used are one and the run
    is not judged twice.

    `publish` is the launch-time publish (#1108 P4, U7/O11): called once per unpinned launch
    with the tenant id and the data root, it returns the child's one report line. `None` is the
    real child process (`launch_publish`); only an in-process caller passes a stand-in."""
    # Undrivable dependencies (credentialed lifecycle, HTML render, ticket endpoint) are
    # injection seams defaulting to production.
    ns = parse_args(argv)
    # Bound under its production name so the curation lane is visibly reached from here.
    enqueue_curation = enqueue

    # The request's tenant id, then the data root, resolved once; nothing below resolves either
    # again.
    data_root = _request_data_root(ns)
    # The tenant, from the request, accepted under the data root before anything is spent. A
    # sibling's arm container is mounted by its box, so the tenant's settings must not sit
    # under it; its path is named here, before acceptance, and nothing is opened by it.
    accepted = _accept_request_tenant(
        ns, data_root=data_root, box_mounted=_sibling_box_mounted(ns, data_root))
    pin = _knowledge_pin(ns)
    # A sibling's door, right after acceptance: its episode walked from the tenant's own
    # folder and its roster publication checked before anything else of the episode is
    # read. The view's episode handle is held for the whole run; it serves the manifest read
    # and the world ledger's writes, and nothing below reopens the episode by name.
    episode_runs = _open_episode_runs(ns, accepted)
    door: contextlib.AbstractContextManager[Any] = (
        contextlib.nullcontext() if episode_runs is None else episode_runs)
    with door:
        episode = None if episode_runs is None else episode_runs.episode
        # A sibling's knowledge is its family's: the pin its launcher recorded in the episode.
        pin = _family_pin(ns, pin, episode)
        # One readiness check, shared by the old-manifest judge (only for a manifest recording
        # no corpus patterns) and the run; resolved over the run's own copy of its knowledge.
        tenant_of = functools.cache(lambda: _resolve_run_tenant(
            accepted, dispatches_lead_zero=ns.episode is None, copy=copy))
        world = _resume_target(ns, episode=episode, tenant=lambda: tenant_of(),
                               arm_ids=(lambda: None) if episode_runs is None
                               else episode_runs.arm_ids)
        source = (None if world is None
                  else _open_world_source(accepted.runs_repository(), world))

        # The one refusal knowable without the run's knowledge, made before the launch-time
        # publish spends up to its budget on the issuer and the forge: an ordinary run's alert
        # file is not there (looked at, not read). The tenant's readiness and the billable role
        # preflight are judged over the run's own copy of its knowledge, so they follow it.
        if world is None and not ns.alert.is_file():
            sys.exit(f"alert not found: {ns.alert.resolve()}")

        # #1108 P4 (flow 3): the knowledge this run reads — the launch-time publish's outcome
        # (or the pin), one export — copied into the run's own folder, named by its run id,
        # before anything reads it. The copy is the run's alone and is removed when it ends.
        early = _early_run(ns, accepted, world, episode_runs)
        knowledge = _knowledge_source(accepted, pin=pin, publish=publish, data_root=data_root)
        copy = _copy_knowledge(accepted, knowledge, early.run_dir.name)
        try:
            # The tenant's settings (and with them the one tenant check), over the run's copy:
            # resolved before the input is read and before anything billable is spent; nothing
            # below reads them again.
            tenant = tenant_of()
            # The run's one judgement of its systems (#1256), before the run is made: the roster
            # this run reads (the injected one, or the checkout's, read once here), judged by the
            # adapters' own settings checks over those settings — a start at which no granted
            # system is usable refused here (O-8, a sibling's own start too) — and handed to the
            # lifecycle whole, so the investigation reads that roster and does not judge again.
            from defender.runtime.branch._family import family_identities

            known_ids = (() if world is None else family_identities(world.family, world.arm_ids))
            systems = _judge_start(
                tenant, defender_dir=DEFENDER_DIR,
                roster=roster if roster is not None else _run_roster(DEFENDER_DIR),
                known_ids=known_ids)

            model = driver.resolve_main_model(ns.model)
            # Runs in siblings too: models are resolved per process, so each sibling must check (and
            # record) its own; a sibling also checks the oracle roles it serves through (M25=A).
            rc = preflight(ns.model, branching=True) if world is not None else preflight(ns.model)
            if rc:
                return rc
            seams = _world_seams(world, oracle=oracle, verifier=verifier, source=source)

            # The input is read after the tenant check and the role preflight: a tenant the check
            # refuses is told so before anything about its input is — save that an ordinary
            # run's alert file is absent, refused above before the publish spends anything.
            alert = _case_input(ns, world, episode_runs)

            # The handle, not just its directory: the post-run step saves the run page through it.
            # The alert mapping is the run copy's, and the stamp records the export copied (O-B).
            run = (materialize(alert, run=early, tenant=accepted, model=model,
                               settings=copy.settings, knowledge=knowledge)
                   if world is None
                   else materialize(alert, run=early, tenant=accepted, model=model, world=world,
                                    settings=copy.settings, knowledge=knowledge))
            run_dir = run.run_dir
            # The run's id, announced as the first line of stdout (#1279 O5), before the ticket
            # or the box exists.
            print(f"run_id={run_dir.name}", flush=True)
            _write_knowledge_record(run_dir, knowledge)

            # Every log line from here on, the crash included, names this run and the tenant this
            # process resolved once above and hands inward as one value.
            with _log.run_context(run_dir.name, tenant.tenant_id, logger=_logger):
                if ns.update_ticket:
                    ticket_writer.open_case_ticket(
                        run, tenant=tenant, defender_dir=DEFENDER_DIR,
                        env=box_mod.run_env(DEFENDER_DIR, run_dir, tenant_agent=tenant.agent))

                _logger.info(f"run_dir={run_dir} model={model}")
                _announce_provenance(run_dir)

                try:
                    summary = lifecycle(
                        run=run,
                        model=model,
                        model_override=ns.model,
                        defender_dir=DEFENDER_DIR,
                        tenant=tenant,
                        world=world,
                        episode=episode,
                        systems=systems,
                        **seams,
                    )
                except (ServingAbort, BaseExceptionGroup) as escaped:
                    abort = _serving_abort(escaped)
                    if abort is None or world is None or episode is None:
                        raise
                    _record_unservable_world(episode, world, abort)
                    _logger.error(f"--episode: world {world.label} is unservable; the sibling ends "
                                  f"({getattr(abort, 'reason', '')})")
                    return UNSERVABLE_EXIT

                # Everything below reads the scrubbed tree; a lifecycle failure propagates uncaught.
                out = str(summary.get("output") or "")
                _logger.info(f"done ({summary.get('requests')} model requests); "
                             f"output: {out[:200]}")

                artifacts = [entry.name for entry in sorted(run_dir.iterdir())]
                _logger.info("artifacts: %s", ", ".join(artifacts), extra={"artifacts": artifacts})
                # The reap-scan verdict sits outside the tree it judges (in-tree, the box could
                # forge it), so the listing above cannot show it; name it for the operator.
                verdict = box_mod.verdict_path(run_dir)
                if verdict.is_file():
                    _logger.info(f"../{verdict.name}: the reap scan's verdict — sits beside the "
                                 "run dir, not in it")
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
                        run, tenant=tenant, defender_dir=DEFENDER_DIR,
                        env=box_mod.run_env(DEFENDER_DIR, run_dir, tenant_agent=tenant.agent), truncated_by=summary.get("truncated_by"),
                        closed_before_cut=summary.get("closed_before_cut") is True)

                # A sibling's evidence was staged on purpose, so it must never feed the catalog.
                if world is not None:
                    _logger.info("--episode: a sibling world is not enqueued for curation")
                elif ns.no_learn:
                    _logger.info("--no-learn set; not enqueuing for curation")
                elif enqueue_curation(run, alert, truncated_by=summary.get("truncated_by")):
                    _logger.info("enqueued for catalog curation")

                try:
                    visualize(run, tenant=accepted, update_ticket=ns.update_ticket)
                except _run.VisualizeFailed:
                    _logger.warning("the run page was not saved", exc_info=True)
                return _exit_code(summary)
        finally:
            copy.remove()


#: A sibling whose world went unservable exits with this (its world record says why).
UNSERVABLE_EXIT = 3
#: A run whose model provider stayed down past the retrier ends with this: rerun later. Non-zero, so
#: a branched sibling that hits it is recorded `did not finish`.
PROVIDER_DOWN_EXIT = 4


def _exit_code(summary: dict) -> int:
    """The exit status of a run whose post-steps are done: `PROVIDER_DOWN_EXIT` when its model
    provider stayed down (the run wrote no report, so say why), else 0."""
    if summary.get("truncated_by") == run_end.TRUNCATED_BY_PROVIDER_DOWN:
        _logger.error("the model provider stayed down; the run ended with no report (rerun later)")
        return PROVIDER_DOWN_EXIT
    return 0


def _serving_abort(exc: BaseException) -> ServingAbort | None:
    """The `ServingAbort` an escaping exception carries (an exception group may wrap it)."""
    if isinstance(exc, ServingAbort):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for inner in exc.exceptions:
            found = _serving_abort(inner)
            if found is not None:
                return found
    return None


def _record_unservable_world(episode: Episode, world: Any, abort: ServingAbort) -> None:
    """Write the world's own record, once: a resumed sibling never rewrites it (N13). The
    record's shape is `outcome.write_world_record`'s."""
    from defender.learning.branch import outcome as outcome_mod

    call = getattr(abort, "call", None)
    system, verb, params = call if isinstance(call, tuple) and len(call) == 3 else ("", "", {})
    reason = getattr(abort, "reason", "")
    written = outcome_mod.write_world_record(
        episode, world.world_id,
        outcome_mod.BUDGET if reason == "budget" else outcome_mod.ORACLE_UNSERVABLE,
        call={"system": system, "verb": verb, "params": dict(params)},
        detail=str(getattr(abort, "detail", "") or reason))
    if not written:
        _logger.info(f"--episode: world {world.label} already has its record; left as it is")


if __name__ == "__main__":
    _log.configure_from_env()
    sys.exit(main(sys.argv[1:]))
