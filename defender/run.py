#!/usr/bin/env python3
"""Defender entrypoint — investigate one alert end-to-end.

The investigation is driven by the in-process PydanticAI driver
(`investigation/driver.py`): materialize the run dir → run → cross-check the two live
tables → enqueue learning → visualize. Run-dir + post-step helpers are shared
via `run_common.py`.

Usage (every run names its tenant, and there is no default; the tenant must be `active` in the
tenant records `DEFENDER_DATABASE_DSN` names, its folder prepared on this host by its creation,
#1214):
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

import logging
import json
import os
import sys
from pathlib import Path

# Hand-rolled rather than `venv_guard.reexec_into_venv`: this must run before any
# `defender.*` import, and reaching that helper is one.
_DEFENDER_DIR = Path(__file__).resolve().parent
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse  # noqa: E402
import asyncio  # noqa: E402
import contextlib  # noqa: E402
import dataclasses  # noqa: E402
import functools  # noqa: E402
import inspect  # noqa: E402
import re  # noqa: E402
import signal  # noqa: E402
from collections.abc import Callable, Collection, Iterator, Mapping  # noqa: E402
from typing import Any, Literal, Protocol  # noqa: E402

if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender import _clock, _log  # noqa: E402
from defender.records.formats import AlertMapping, DataRoot, RunsBase  # noqa: E402
from defender.records import formats  # noqa: E402
from defender import run_common as _run  # noqa: E402
from defender import job_socket  # noqa: E402
from defender.records import Run  # noqa: E402
from defender.records import job_facts, job_lane  # noqa: E402
from defender.records.job_facts import BOX_STARTED as _BOX_STARTED  # noqa: E402 — `lifecycle`'s `job_facts` keyword shadows the module
from defender.records import RunPaths  # noqa: E402
from defender import tenancy  # noqa: E402
from defender.records.formats import Episode  # noqa: E402
from defender import box as box_mod  # noqa: E402
from defender.investigation import driver  # noqa: E402
from defender.investigation.run_clock import AnchoredOrigin, ClockOrigin, origin_reading  # noqa: E402
from defender.investigation.run_state import RunState  # noqa: E402
from defender import providers  # noqa: E402
from defender.records import run_end  # noqa: E402
from defender.tenancy import run_knowledge  # noqa: E402
from defender.systems import case_system, system_status  # noqa: E402
from defender._agent_role import AgentRole  # noqa: E402
from defender.systems.run_tenant import Admitted, RunTenant, host_tenant  # noqa: E402
from defender.tenancy.record_values import TenantRecords  # noqa: E402
from defender.systems.system_status import RunSystems  # noqa: E402
import time  # noqa: E402
from datetime import UTC, datetime  # noqa: E402
from defender.credential_proxy import helper_access, request_access, run_token_mint, signing_access  # noqa: E402
from defender.kit.access import TOKEN_SEC, AccessDeclaration, RequestAccess  # noqa: E402
from defender.kit.faults import AdapterFault, ConfigFault  # noqa: E402
from defender.systems.verb_grant import GrantError  # noqa: E402
from defender.systems.verbs import (  # noqa: E402
    ModuleVerbRegistry,
    RosterRead,
    ServingAbort,
)
from defender.investigation import ticket_writer as _default_ticket_writer  # noqa: E402

DEFENDER_DIR = _DEFENDER_DIR


from defender._first_party_key import (  # noqa: E402,F401
    read_env_key,
    resolve_first_party_key,
)
from defender.records.formats import TenantRefused

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
                   help="Add one comment of findings to the ticket the alert names, through the tenant's "
                        "case system (default off)")
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
    p.add_argument("--as-of", default=None, type=_aware_moment, metavar="T",
                   help="start the run clock at T (ISO-8601 with an offset or Z); not with "
                        "--update-ticket, --episode or --world")
    p.add_argument("--as-of-anchor", default=None, type=_aware_moment, metavar="W",
                   help="with --as-of: the wall instant at which the run clock read T; the run "
                        "starts at T plus the time since W (a frozen lab node's clock, #1347)")
    ns = p.parse_args(argv)
    now = datetime.now(UTC)
    if ns.as_of_anchor is not None and ns.as_of is None:
        p.error("--as-of-anchor needs --as-of: it says when the run clock read T")
    if ns.as_of is not None and ns.as_of > now:
        p.error("--as-of names a future time: a frozen run replays a moment that has passed")
    if ns.as_of_anchor is not None and ns.as_of_anchor > now:
        p.error("--as-of-anchor names a future time: the anchor is when the clock was set")
    # A frozen run's refusals, before any run dir or episode is looked up (#1347 O5).
    if ns.as_of is not None and (ns.episode is not None or ns.world is not None):
        p.error("--as-of is not available with --episode/--world: a sibling's clock is its "
                "branch point's")
    if ns.as_of is not None and ns.update_ticket:
        p.error("--update-ticket is not available with --as-of: a run started at another "
                "moment is not a live investigation, and its ticket row would enter the case "
                "history as one")
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


#: The offset an `--as-of` value must end with.
_SPELLED_OFFSET = re.compile(r"(Z|[+-]\d\d:?\d\d)\Z")


def _aware_moment(text: str) -> datetime:
    """An `--as-of` value: ISO-8601 carrying its offset (or `Z`), as aware UTC. A time with no
    offset is refused rather than read as UTC: the operator says which instant."""
    text = text.strip()
    if not _SPELLED_OFFSET.search(text):
        raise argparse.ArgumentTypeError(f"{text!r} names no offset; spell it with Z or +HH:MM")
    moment = _clock.parse_iso_utc(text)
    if moment is None:
        raise argparse.ArgumentTypeError(f"{text!r} is not an ISO-8601 time")
    try:
        return moment.astimezone(UTC)
    except OverflowError:
        raise argparse.ArgumentTypeError(f"{text!r} is outside the years a run can be served") from None


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


@dataclasses.dataclass
class _JobEndFacts:
    """The job-end facts a job's run sets as each becomes true (#1342 r5 C2, r7 D-ad), on an
    object the job entry holds, so a raise out of the run cannot discard one already set.

    `box` is set to `started` by the lifecycle once `start_box` has returned; the job entry
    records `start_failed` for a run that raised while it was still `not_started`.

    `review_state` is the run's review-state dict, which the driver uses as
    `AgentDeps.review_state` (`{"state": ReviewState}` once the close gate first runs): the
    report is committed once that state is closed. `scrub_verified` is set by the lifecycle,
    only once `stop_and_scrub` has returned, to whether the scrub walked the tree.

    `cut_short` is the summary's `truncated_by` (#1421), set by the lifecycle when the driver
    returns, before the teardown, so a teardown or scrub that raises cannot lose it; `None` for a
    run nothing cut short or one whose driver never returned."""

    review_state: dict[str, Any] = dataclasses.field(default_factory=dict)
    scrub_verified: bool = False
    box: str = job_facts.BOX_NOT_STARTED
    cut_short: str | None = None

    @property
    def report_committed(self) -> bool:
        """The close tool's `ReviewState.closed`: false while the dict is empty or the state
        never closed."""
        return getattr(self.review_state.get("state"), "closed", False) is True


class _Investigate(Protocol):
    """The investigation seam's exact shape, so both the call site and `_drive_investigation`
    stay type-checked (tests inject the seam, so only a real run would catch a renamed keyword).

    `systems` is the run's one judgement of its systems, `main`'s at run start
    (`system_status.RunSystems`: the tenant's roster the run reads and each system down at its
    start), handed to every seam (#1366 R16: required, never computed by the drive).

    `job_facts` is a job's facts holder (#1342 r5 C2), handed on the job lane only: the driver
    keeps its review state in the holder's dict.
    """

    def __call__(  # noqa: PLR0913 — the investigation's whole identity, one keyword each
        self, *, alert_path: Path, run: Run, defender_dir: Path,
        model_name: str, model_override: str | None, box: Any, tenant: RunTenant,
        systems: RunSystems,
        world: Any = None, episode: Episode | None = None, serving: Any = None,
        source: Run | None = None, job_facts: _JobEndFacts | None = None,
        access: RequestAccess | None = None, clock_origin: ClockOrigin | None = None,
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
    #: existed: the tenant's roster the run reads and each granted system down at its start.
    #: The registry is built over that roster and the driver holds that verdict, so the run is
    #: judged once. Required (#1366 R16): the drive never reads a roster of its own.
    systems: RunSystems,
    #: A job's facts holder (#1342 r5 C2): the driver keeps its review state in the holder's
    #: dict, so the job entry reads the close however the run ends. `None` off the job lane.
    job_facts: _JobEndFacts | None = None,
    #: The run clock's start when it is not the source's own (`--as-of`, #1347 O5); `None`
    #: on an ordinary run and on a world, whose clock is its branch point's.
    clock_origin: ClockOrigin | None = None,
    #: The run's live state (#1414), handed to the investigation when the caller built one.
    run_state: Any = None,
    #: The credential proxy's address and the run's read token (#1163); `None` when the run has
    #: no `http-proxy` system.
    access: RequestAccess | None = None,
) -> dict[str, Any]:
    """The production investigation call, as a synchronous callable (injected by the
    lifecycle so tests can pass a plain function).

    Passes `verbs=` explicitly: `run_investigation`'s fallback registry deliberately does not
    enable lead-0, which hermetic tests rely on.

    On the resume path the production registry is never constructed: a sibling's queries are
    served by its world registry (the primed recording, else one live read through the run's
    proxy access, #1449), and a module registry beside it would route keys around the oracle.
    The two registries are built in separate arms of one `if` so both can never exist.
    """
    # The roster `main` judged, handed down to the registry and `run_investigation` with its
    # verdict.
    roster = systems.roster
    held: dict[str, Any] = {} if job_facts is None else {"review_state": job_facts.review_state}
    if run_state is not None:
        held["run_state"] = run_state
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
        from defender.investigation import branch as branch_mod

        family = world.family
        # Declared up front: a world that serves nothing must still leave a ledger.
        ledger = Ledger.for_world(episode, world.world_id).declare()
        verbs: Any = WorldRegistry(
            roster, tenant.grants.gather, world=world, ledger=ledger,
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
                systems=systems, resume=resume, tenant=tenant, source_run=source, **held,
                **_access_kwargs(access),
            )
        finally:
            verbs.close()
    verbs = registry_cls(roster, tenant.grants.gather, grant_home=tenant.table_pointer)
    # Passed only when set, so an ordinary run calls its seam exactly as before `--as-of`.
    clock_kw: dict[str, Any] = {} if clock_origin is None else {"clock_origin": clock_origin}
    return investigate(
        alert_path=alert_path, run=run, defender_dir=defender_dir,
        model_name=model_name, model_override=model_override, box=box, verbs=verbs,
        roster=roster, systems=systems, tenant=tenant, **clock_kw, **held, **_access_kwargs(access),
    )


def _access_kwargs(access: RequestAccess | None) -> dict[str, RequestAccess]:
    """`access=` for a seam to take, only when the run has one: a seam that predates the
    credential proxy is not handed a keyword it has no use for."""
    return {} if access is None else {"access": access}


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
    #: the investigation so the run reads that roster and holds that verdict. Required (#1366
    #: R16): no drive reads a roster of its own.
    systems: RunSystems,
    #: The run clock's start (`--as-of`, #1347), threaded to the drive; `None` on an ordinary run.
    clock_origin: ClockOrigin | None = None,
    #: The credential proxy's address and the run's read token (#1163), signed at run start.
    access: RequestAccess | None = None,
    investigate: _Investigate = _drive_investigation,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[..., None] = box_mod.scrub,
    #: A job-lane run (#1342): its box start never degrades to host execution (R2), and a start
    #: fault leaves as `BoxStartFault` (M3), told from a teardown fault by its type.
    job_lane: bool = False,
    #: The box's start token, when the caller minted it (#1342 r5 C1: a job's launch record
    #: carries its worker's); `None`, the box mints its own.
    start_token: str | None = None,
    #: A job's facts holder (#1342 r5 C2), handed to the investigation; its `box` set here once
    #: the box started (r7 D-ad) and its `scrub_verified` once the teardown and scrub returned.
    #: `None` off the job lane.
    job_facts: _JobEndFacts | None = None,
    #: A job container's socket client (#1170 A4): the box is started by the job's host helper and
    #: reached over the socket (`box.start_box(..., relay=)`); `None` off the job lane.
    relay: Callable[..., Any] | None = None,
    #: The run's live state (#1414), built by `main`, handed to the investigation.
    run_state: Any = None,
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
    # A job's box is started by its host helper over the job socket (`relay`, #1170 A4).
    staged: dict[str, Any] = {name: value for name, value in (
        ("staged_token", getattr(tenant, "stage_token", None)), ("start_token", start_token), ("relay", relay))
        if value is not None}
    if not job_lane:
        box = start_box(run_dir, defender_dir, tenant_agent=tenant.agent,
                        tenant_id=tenant.tenant_id, write_verdict=write_verdict, **staged)
    else:
        try:
            box = start_box(run_dir, defender_dir, tenant_agent=tenant.agent,
                            tenant_id=tenant.tenant_id, write_verdict=write_verdict,
                            require_sandbox=True, **staged)
        except box_mod.BoxFault as fault:
            raise box_mod.BoxStartFault(f"the run's box did not start: {fault}") from fault
    if job_facts is not None:
        job_facts.box = _BOX_STARTED
    # The job's facts holder (#1342) and the run's request access (#1163), each only when the run
    # has one: a seam that predates either is not handed a keyword it has no use for.
    keywords: dict[str, Any] = {} if job_facts is None else {"job_facts": job_facts}
    keywords |= _access_kwargs(access)
    keywords |= {} if clock_origin is None else {"clock_origin": clock_origin}
    keywords |= {} if run_state is None else {"run_state": run_state}
    investigation_ok = False
    # A run its box ended (#1421) returns normally, but its failure is in flight all the same: a
    # teardown fault on it is logged, never raised over the ending.
    box_ending = False
    try:
        summary = investigate(
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
            systems=systems,
            **keywords,
        )
        investigation_ok = True
        cut_short = run_end.normalized_truncated_by(summary.get("truncated_by"))
        box_ending = cut_short in run_end.BOX_ENDINGS
        if job_facts is not None:
            job_facts.cut_short = cut_short
    finally:
        box_down = box_mod.stop_and_scrub(
            box, run_dir, stop_box=stop_box, scrub_tree=scrub_tree,
            read_verdict=verdict.read, write_verdict=write_verdict,
            in_flight=box_ending or not investigation_ok,
        )
        # Reached only when the teardown and scrub returned: a tainted tree or a teardown fault
        # raised out of them, so the verdict's `ran: true` alone never makes a tree verified.
        if job_facts is not None:
            job_facts.scrub_verified = box_mod.tree_verified(run_dir)
    if not box_down:
        # Only a box ending's teardown fault gets here: its box may still be alive, so the
        # compositions skip the post-steps that read or publish its tree.
        summary = {**summary, TEARDOWN_FAULTED: True}
    return summary


class _TokenMint:
    """Signs this run's request tokens in the run process (#1163 A1): a read token over the
    granted `http-proxy` systems when a call first needs one, held by the process's one access
    holder (#1363 O1, `RequestAccess`), and a write-back token (`rw` on the case system only) at the record step (#1359 D-9).
    Building one checks configuration only; nothing contacts OpenBao until a token is asked for,
    and a run with no `http-proxy` system to reach never does (A7)."""

    def __init__(self, signer: Any, proxy_url: str | None, *, tenant_id: str, run_id: str,  # noqa: PLR0913 — the run's identity plus the holder's two seams
                 reads: tuple[str, ...], case_system: str | None,
                 unsigned: str | None = None, clock: Callable[[], float] = time.time,
                 on_fault: Callable[[AdapterFault], None] | None = None) -> None:
        self._proxy_url = proxy_url
        self._clock = clock
        #: Signs the write-back token the way the holder signs the read token (`run_token_mint`).
        self._mint = (None if signer is None else
                      run_token_mint(signer, tenant_id=tenant_id, investigation=run_id))
        self._case_system = case_system
        #: Why a write-back token cannot be signed (R4), when it cannot: the run goes on, and the
        #: record step says so.
        self._unsigned = unsigned
        #: The process's access holder: built here, signs nothing until a call first needs a
        #: token. `clock` is the holder's own; `on_fault` is its owner's callback (#1363 B1).
        self._access: RequestAccess | None = (
            request_access(signer, proxy_url or "", tenant_id=tenant_id, investigation=run_id,
                        reads=reads, clock=clock, on_fault=on_fault) if reads else None)

    @classmethod
    def for_run(  # noqa: PLR0913 — the run's identity plus the operator's three seams
            cls, tenant: RunTenant, systems: RunSystems, *, ns: argparse.Namespace,
                world: Any, case: case_system.CaseTarget | case_system.CaseSettingsFault | None,
                run_id: str, accepted: tenancy.Tenant,
                records: tenancy.TenantDirectory, signer: Any, proxy_url: str | None,
                issuer_transport: Any, clock: Callable[[], float] = time.time,
                on_fault: Callable[[AdapterFault], None] | None = None) -> _TokenMint:
        """The mint for a run, or a mint that signs nothing when no `http-proxy` system is in
        reach. A configuration that cannot sign (no proxy address; a tenant whose live generation
        in `records` records no sign login, A24', whether or not a `signer` is injected, r8.6)
        refuses run start when the run needs a READ token, naming the cause, and contacts no
        OpenBao; called before the run folder is made, so the refusal leaves none behind (r7
        A20). A run that needs only the write-back token goes on instead (R4): it mints nothing
        and the record step says why. The signer is the tenant's own
        (`credential_proxy.request_signer`, r8.5) unless one is injected."""
        # A branched run is a run (#1449): a world reads its granted systems on a run's terms.
        reads = system_status.read_grant(tenant, systems.down)
        # The write-back token is for a case system run start judged sound (`case`), reached
        # through the proxy; a case system with bad settings is told so by the record step.
        # A world never gets one: `--update-ticket` with `--episode` is refused before this
        # (`_resume_target`); `world is None` is the mint's own guard behind that refusal (#1449).
        named = case.system if isinstance(case, case_system.CaseTarget) else None
        written = named if (world is None and ns.update_ticket
                                and isinstance(tenant.access.get(named or ""), AccessDeclaration)) else None
        if not reads and written is None:
            return cls(None, None, tenant_id=str(tenant.tenant_id), run_id=run_id, reads=(),
                       case_system=None)
        try:
            signer, address = signing_access(accepted.id, directory=records, signer=signer,
                                             proxy_url=proxy_url, transport=issuer_transport)
        except ConfigFault as refused:
            if reads:
                sys.exit(f"run start refused: {refused.detail}")
            _logger.warning(f"the write-back token cannot be signed: {refused.detail}")
            return cls(None, None, tenant_id=str(tenant.tenant_id), run_id=run_id, reads=(),
                       case_system=written, unsigned=refused.detail)
        return cls(signer, address, tenant_id=str(tenant.tenant_id), run_id=run_id,
                   reads=reads, case_system=written, clock=clock, on_fault=on_fault)

    def access_kwargs(self) -> dict[str, RequestAccess]:
        return _access_kwargs(self._access)

    def access_lost(self) -> str | None:
        """Why the process lost its credential-proxy access (the holder's latched detail), or None
        while it has not, or never held any (#1363 D11)."""
        return None if self._access is None else self._access.lost

    def write_back(self) -> dict[str, str]:
        """The record step's keywords: a fresh write-back token (`rw` on the case system only) and
        the proxy's address, when the case system is an `http-proxy` system run start judged sound
        (a system with bad settings is told so by the step, not by a token it would never use);
        nothing otherwise. A mint that fails here is a warning: the step reports the missing token
        itself."""
        if self._case_system is None or self._unsigned is not None or self._mint is None:
            return {}
        try:
            token = self._mint({(self._case_system, "rw")}, self._clock() + TOKEN_SEC)
        except AdapterFault as refused:
            _logger.warning(f"no write-back token for the record step: {refused.detail}")
            return {}
        return {"request_token": token, "proxy_url": self._proxy_url or ""}


# Run setup's host half lives in `run_common` (#1170 A6): the per-job host helper runs it for a job, and the
# operator command runs it here, beside its run half.
_resolve_run_tenant = _run.run_tenant_or_exit
_publish_report = _run.publish_report
PublishLaunch = _run.PublishLaunch
_knowledge_source = _run.resolve_knowledge
_copy_knowledge = _run.copy_knowledge
_write_knowledge_record = _run.write_knowledge_record
_read_alert_mapping = _run.read_alert_mapping
_read_records = _run.read_records
_write_record_versions = _run.write_versions_record
_tenant_verdict = _run.tenant_verdict
_run_roster = _run.run_roster


def _family_pin(ns: argparse.Namespace, pin: str | None, episode: Any) -> str | None:
    """The commit a sibling (`--episode`) reads: its family's knowledge pin, read from the
    episode, where only its launcher writes (`records._knowledge_pin`), so a sibling started or
    resumed by hand reads its family's knowledge, never a newer `current`. A `--knowledge-commit`
    naming another commit refuses. An episode with no pin (launched before the pin was
    recorded) keeps `pin` as given, as before. An ordinary run's `pin` is kept."""
    if episode is None:
        return pin
    from defender.records.formats import PinUnreadable, read_pin

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


def _early_run(ns: argparse.Namespace, accepted: tenancy.Tenant, world: Any, episode_runs: Any) -> Run:
    """The run's handle, settled before its knowledge is copied (the copy is named by its id) and
    handed to setup whole (#1279 rev 6): a sibling's arm from its episode's roster, else a fresh one
    the tenant's runs repository mints. No caller names the id (A3); nothing is made on disk for an
    arm, and only the natural runs container for an ordinary run. (A job's run is made at its
    launch record's id by its host helper, #1170 A6.)"""
    from defender.records import RunRefused

    try:
        if world is not None:
            return episode_runs.create(episode_runs.arm_id(world.world_id))
        return accepted.runs_repository().create()
    except (RunRefused, TenantRefused) as refused:
        where = f"--episode {ns.episode}: " if world is not None else ""
        sys.exit(f"[run.py] {where}{refused}")


def _judge_start(tenant: RunTenant, *, roster: RosterRead, defender_dir: Path,
                 known_ids: Collection[str] = (), catalog: RosterRead | None = None) -> RunSystems:
    """#1256 O-8, before the run exists: the run's ONE judgement of its systems
    (`system_status.judge_run`) — each granted system judged by its own adapter's settings check
    over `roster`, the roster this run reads — handed back whole, for `main` to hand on to the
    investigation, which holds it and does not judge again. A run (fresh or a sibling's) at
    whose start gather could query nothing through the systems that are up is refused
    (`system_status.require_usable`), naming each down system and its cause. Before the run
    folder, the box and any model call; nothing is logged or held here — the driver does that
    once, when the run starts. Never in the tenant resolution the tenant check and
    `defender-policy` share: whether a system is usable is a run's question, not the tenant's
    (D4). `catalog`, the whole catalog `roster` was drawn from, is handed on with the judgement."""
    try:
        systems = system_status.judge_run(
            roster, tenant, defender_dir=defender_dir, known_ids=known_ids, catalog=catalog)
        system_status.require_usable(tenant.grants, systems.down)
    except (GrantError, system_status.NoUsableSystem) as refusal:
        sys.exit(f"[run.py] this run's tenant {tenant.tenant_id!r} cannot be used: {refusal}")
    return systems


def _announce_provenance(run_dir: Path) -> None:
    """Log what this run was made against, read back from the stamp (not re-asking git) so
    the operator sees the record itself, including whether the tree was dirty."""
    rec = formats.read_provenance(RunPaths(run_dir).provenance)
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
    from defender.records import formats

    del tenant  # the manifest is the whole record; see the docstring
    family = formats.load_family(episode.view(), expected_episode_id=episode.dir.name)
    return formats.resume_world_from(family, world_label, episode.dir, arm_ids=arm_ids)


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


def _open_run(runs: Any, run_id: Any, *, what: str) -> Run:
    """The run `run_id` names, opened by its id in `runs` (a tenant's runs repository, or an
    episode's arms), or `what`'s refusal naming why: the one place `run.py` opens a run it did not
    make itself."""
    from defender.records import RunId, RunRefused

    try:
        return runs.open(run_id if isinstance(run_id, RunId) else RunId.parse(run_id))
    except (RunRefused, TenantRefused) as refused:
        sys.exit(f"[run.py] {what} cannot be opened: {refused}")


def _open_world_source(runs: Any, world: Any) -> Run:
    """The source run a world forks: the manifest's `source_run_id`, opened in the request's
    tenant's natural container (#1105 PR 2, decision A — an old manifest's `source_run_dir` is
    never read). An id the repository refuses, or a run that is not there, is the sibling's
    refusal, before anything is spent."""
    return _open_run(runs, world.family.source_run_id, what="the episode's source run")


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
    from defender.records.formats import FamilyError

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
    alert: Path, *, tenant: tenancy.Tenant, model: str | None, run: Run | None = None,
    world: Any = None, mapping: AlertMapping | None = None,
    knowledge: run_knowledge.KnowledgeSource | None = None, started_at: datetime | None = None,
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
                                   mapping=mapping, knowledge=knowledge, started_at=started_at)
    except TenantRefused as refusal:
        sys.exit(f"[run.py] {refusal}")
    return run


@contextlib.contextmanager
def _tenant_refusal_exits() -> Iterator[None]:
    """A refusal of the request's tenant (its id, the data root, the host acceptance) is the
    `[run.py]` exit, before the preflight."""
    try:
        yield
    except TenantRefused as refused:
        sys.exit(f"[run.py] this run's tenant cannot be used: {refused}")


def _request_data_root(ns: argparse.Namespace) -> DataRoot:
    """The request's tenant id checked (`--tenant` is required, there is no default), then the
    data root resolved — once, here — or a `[run.py]` refusal before the preflight."""
    with _tenant_refusal_exits():
        tenancy.requested_tenant_id(ns.tenant)
        return tenancy.resolve_data_root()


def _sibling_box_mounted(ns: argparse.Namespace, data_root: DataRoot) -> Iterator[RunsBase]:
    """What a sibling's box mounts besides the checkout — its arm container,
    `<data root>/<T>/episodes/<episode id>/runs` — or nothing for an ordinary run, named lazily:
    acceptance's folder rules draw it, so the tenant's record is judged first (r10 A1 order) and
    acceptance holds the tenant's settings out of it. The episode id is judged when it is drawn
    (canonical UUID text, before any path is built), a refusal exiting with the hold released;
    nothing is read."""
    if ns.episode is None:
        return
    from defender.records.formats import EpisodeRefused

    try:
        mounted = tenancy.box_mounted_arm_container(data_root, ns.tenant, ns.episode)
    except (EpisodeRefused, TenantRefused) as refused:
        sys.exit(f"[run.py] --episode {ns.episode}: {refused}")
    yield mounted


def _open_episode_runs(ns: argparse.Namespace, accepted: tenancy.Tenant) -> Any:
    """The sibling's episode view, in its sibling form (`require_roster=True`, O4b): the episode is
    walked from the accepted tenant's own folder, no link followed at any level, and its arm
    roster must have been published — an episode that never reached RUNS, a roster that does not
    contain UUID identities, a missing episode (another tenant's included) or a link anywhere is refused
    here, right after acceptance and before the manifest is read (G5/G19). `None` for an
    ordinary run."""
    if ns.episode is None:
        return None
    from defender.records.formats import EpisodeRefused
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


def _world_seams(world: Any, *, oracle: Any, verifier: Any, source: Run | None, tenant_id: str) -> dict[str, Any]:
    """The lifecycle's world-only keywords: none for an ordinary run; for a sibling its oracle
    side, settled once here from its knobs (the launcher hands it its rate slice through the
    environment), its box labelled with the run's tenant, and threaded inward whole, and the
    opened source run it forks."""
    if world is None:
        return {}
    from defender.learning.branch.estate.registry import oracle_serving
    from defender.learning.core.config import process_oracle_settings

    return {"serving": oracle_serving(process_oracle_settings(), oracle=oracle,
                                      verifier=verifier, tenant_id=tenant_id),
            "source": source}


class _PreflightRefused(Exception):  # noqa: N818 — named for what it reports
    """The role preflight's non-zero return, before the lifecycle (#1342 M3): an internal
    refusal setup raises, so the job lane records it as `setup: refused`; the operator path
    turns it back into its return code."""

    def __init__(self, rc: int) -> None:
        super().__init__(f"the role preflight returned {rc}")
        self.rc = rc


class _ReadAccess(Protocol):
    """A run's read access for its lifecycle: `access=` when the run reads through the credential
    proxy, nothing otherwise."""

    def access_kwargs(self) -> dict[str, RequestAccess]: ...

    def access_lost(self) -> str | None: ...


@dataclasses.dataclass(frozen=True)
class _Started:
    """What run setup hands the lifecycle and the post-steps: the run made, its tenant (accepted
    and resolved over the run's copy of its knowledge), its one judgement of its systems, and
    the world-only seams, and the run's request-token signer. Held by `_set_up` for the length
    of its block."""

    accepted: tenancy.Tenant
    tenant: RunTenant
    run: Run
    model: str
    world: Any
    episode: Episode | None
    systems: RunSystems
    seams: dict[str, Any]
    alert: Path
    #: Where the run's read pass comes from (#1163): the operator run's own signer (`_TokenMint`,
    #: #1342 R6-8), or in a job container its host helper (`_HelperPass`, #1170 H2).
    minting: _ReadAccess
    #: The case system's verdict, judged once at setup when the run records its case
    #: (`--update-ticket`); `None` otherwise.
    case: case_system.CaseTarget | case_system.CaseSettingsFault | None = None
    #: The run clock's start (`--as-of`, with `--as-of-anchor` its wall instant, #1347); `None`
    #: on an ordinary run.
    as_of: ClockOrigin | None = None

    def record_case(self) -> case_system.CaseTarget | case_system.CaseSettingsFault:
        """The verdict the record step comments on: set at setup whenever the run records its case,
        so its absence there is a caller bug, never a reason to judge again (#1366 R16)."""
        if self.case is None:
            raise TypeError("the record step needs the case verdict judged at run start "
                            "(`--update-ticket`), and setup made none")
        return self.case

    def lifecycle_kwargs(self, ns: argparse.Namespace) -> dict[str, Any]:
        # The origin only when set, so a lifecycle seam that predates it is called as before.
        origin_kw: dict[str, Any] = {} if self.as_of is None else {"clock_origin": self.as_of}
        return {"run": self.run, "model": self.model, "model_override": ns.model,
                "defender_dir": DEFENDER_DIR, "tenant": self.tenant, "world": self.world,
                "episode": self.episode, "systems": self.systems,
                **self.minting.access_kwargs(), **self.seams, **origin_kw}


def _acceptance_args(ns: argparse.Namespace, data_root: DataRoot) -> dict[str, Any]:
    """The host acceptance's folder-rule arguments, the same for the operator run and the job
    entry (r6 R6-6); each entry calls `host_tenant` itself with them (R6-3). The acceptance holds
    this process recorded under the tenant's host lock for the whole run (prepare and teardown
    wait for the run, and a teardown finds it to stop it), the tenant `active` with its forge
    wiring, its folder accepted. A sibling's arm container is mounted by its box, so the tenant's
    settings must not sit under it; its path is drawn by the folder rules, and nothing is opened
    by it."""
    return {"defender_dir": DEFENDER_DIR, "box_mounted": _sibling_box_mounted(ns, data_root),
            "clone_tree": False}



@contextlib.contextmanager
def _set_up(  # noqa: C901, PLR0913 — run setup's whole call: the request, its lane and the seams setup reaches
    ns: argparse.Namespace, data_root: DataRoot, admitted: Admitted, *,
    preflight: Callable[..., int],
    materialize: Callable[..., Run],
    oracle: Any,
    verifier: Any,
    roster: Any,
    publish: PublishLaunch | None,
    signer: Any = None,
    proxy_url: str | None = None,
    issuer_transport: Any = None,
) -> Iterator[_Started]:
    """The operator command's run setup, both halves in one process (#1342 M3; a job's are split
    between its host helper and its container, #1170 A6, sharing `run_common`'s host half and this
    module's run-half steps), for the tenant the
    entry's own host acceptance admitted (`admitted`, r6 R6-3: the entry holds it and releases
    it; setup never accepts a tenant): a sibling's episode door opened, the knowledge published
    and copied, the tenant resolved and its systems judged, the preflight, the run made and
    announced, its knowledge recorded — or the refusal (`SystemExit` naming it;
    `_PreflightRefused`). Yields the started run, holding the episode door and the knowledge copy
    until the block ends (the post-steps included); the copy is removed however it ends.

    `signer`, `proxy_url` and `issuer_transport` are the credential proxy's seams (#1163)."""
    records = admitted.directory
    accepted = admitted.tenant
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
            accepted, dispatches_lead_zero=ns.episode is None, records=current, copy=copy))
        world = _resume_target(ns, episode=episode, tenant=lambda: tenant_of(),
                               arm_ids=(lambda: None) if episode_runs is None
                               else episode_runs.arm_ids)
        source = (None if world is None
                  else _open_world_source(accepted.runs_repository(), world))
        # A fresh run derives its facts through the tenant's alert mapping, read from the tenant records once,
        # here: before the knowledge copy and the run folder, so a tenant with none (or records that cannot be
        # reached) is refused with nothing made (#1345 O3, O4). A sibling carries its source's record.
        # The tenant's current records (#1366 O6), read once here for every lane, siblings too
        # (H9): a tenant not imported is refused (R8) before its alert mapping is looked at.
        current = _read_records(records, accepted.id)
        mapping = None if world is not None else _read_alert_mapping(records, accepted.id)

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
        knowledge = _knowledge_source(accepted, pin=pin, publish=publish, data_root=data_root,
                                      records=records)
        copy = _copy_knowledge(accepted, knowledge, early.run_dir.name)
        try:
            # The tenant's settings (and with them the one tenant check), over the run's copy:
            # resolved before the input is read and before anything billable is spent; nothing
            # below reads them again.
            # The tenant's systems over the catalog this run reads (the injected roster, or the
            # checkout's, read once here): R12's grants x records verdict (#1366), the grants
            # narrowed to the systems the tenant has records for.
            verdict = _tenant_verdict(
                tenant_of(), roster if roster is not None else _run_roster(DEFENDER_DIR))
            tenant = verdict.tenant
            # The run's one judgement of its systems (#1256), before the run is made: the roster
            # this run reads (the injected one, or the checkout's, read once here), judged by the
            # adapters' own settings checks over those settings — a start at which no granted
            # system is usable refused here (O-8, a sibling's own start too) — and handed to the
            # lifecycle whole, so the investigation reads that roster and does not judge again.
            from defender.records.formats import family_identities

            known_ids = (() if world is None else family_identities(world.family, world.arm_ids))
            systems = _judge_start(
                tenant, defender_dir=DEFENDER_DIR, roster=verdict.systems.roster,
                known_ids=known_ids, catalog=verdict.systems.catalog.roster)
            # The request tokens' signer, over the systems just judged (#1342
            # R6-8): a configuration that cannot sign them refuses here, before the run is made;
            # nothing is signed until a call or a ticket leg asks (r7 A20).
            # The case system the record step will comment through, judged once here by run
            # start's own adapter rules over the roster just read (#1359 D-17); nothing is called.
            case = (case_system.case_verdict(tenant, defender_dir=DEFENDER_DIR, roster=systems.roster)
                    if ns.update_ticket else None)
            minting = _TokenMint.for_run(
                tenant, systems, ns=ns, world=world, case=case, run_id=early.run_dir.name,
                accepted=accepted, records=records, signer=signer, proxy_url=proxy_url,
                issuer_transport=issuer_transport)

            model = driver.resolve_main_model(ns.model)
            # Runs in siblings too: models are resolved per process, so each sibling must check (and
            # record) its own; a sibling also checks the oracle roles it serves through (M25=A).
            rc = preflight(ns.model, branching=True) if world is not None else preflight(ns.model)
            if rc:
                raise _PreflightRefused(rc)
            seams = _world_seams(world, oracle=oracle, verifier=verifier, source=source,
                                 tenant_id=str(tenant.tenant_id))

            # The input is read after the tenant check and the role preflight: a tenant the check
            # refuses is told so before anything about its input is — save that an ordinary
            # run's alert file is absent, refused above before the publish spends anything.
            alert = _case_input(ns, world, episode_runs)
            # The run clock's origin (#1347 O5, r6.4.6): T, or T anchored at its wall instant W.
            origin: ClockOrigin | None = (
                None if ns.as_of is None else ns.as_of if ns.as_of_anchor is None
                else AnchoredOrigin(at=ns.as_of, wall=ns.as_of_anchor))

            # The handle, not just its directory: the post-run step saves the run page through it.
            # The stamp records the export copied (O-B).
            if world is not None:
                run = materialize(alert, run=early, tenant=accepted, model=model, world=world,
                                  knowledge=knowledge)
            elif origin is not None:
                # A frozen run's recorded start is its run clock's origin, never the wall time
                # (#1347 O5); named only then, so a seam that predates `--as-of` is called as before.
                run = materialize(alert, run=early, tenant=accepted, model=model,
                                  mapping=mapping, knowledge=knowledge,
                                  started_at=origin_reading(origin, datetime.now(UTC)))
            else:
                run = materialize(alert, run=early, tenant=accepted, model=model,
                                  mapping=mapping, knowledge=knowledge)
            run_dir = run.run_dir
            # The run's id, announced as the first line of stdout (#1279 O5), before the ticket
            # or the box exists.
            print(f"run_id={run_dir.name}", flush=True)
            _write_knowledge_record(run_dir, knowledge)
            _write_record_versions(run_dir, current)
            yield _Started(accepted=accepted, tenant=tenant, run=run, model=model, world=world,
                           episode=episode, systems=systems, seams=seams, alert=alert,
                           minting=minting, case=case, as_of=origin)
        finally:
            copy.remove()


#: The one key the lifecycle adds to a run's summary (#1421), only when the teardown of a run its
#: box ended could not prove the box stopped: its tree was not scrubbed and a live box may still
#: write it, so the post-steps (the cross-check, the page, the case comment and the curation
#: enqueue) are skipped and only the exit status is returned.
TEARDOWN_FAULTED = "teardown_faulted"


def _post_steps(  # noqa: PLR0913 — the run, its summary, and the page's inputs
    started: _Started, summary: dict[str, Any], *,
    visualize: Callable[..., None], update_ticket: bool,
    operator_steps: Callable[[], None] | None = None, mirror: bool = True,
) -> None:
    """The post-steps both compositions share (#1342 M4), after the lifecycle has scrubbed the
    run folder: the readers of the scrubbed tree and the run page. `operator_steps` is the
    operator composition's own (the ticket comment and the curation enqueue), run where they
    always ran: after the table cross-check, before the page, which shows the ticket's receipt.
    `mirror=False` is a job container's page (#1170 A10): saved in the run's own folder only, the
    helper copying it to the shared publish folder after the container exits.

    None of them runs for a run whose box ending's teardown faulted (`TEARDOWN_FAULTED`, #1421):
    they assume a dead box and a scrubbed tree, and a possibly live box's writes must not be read
    or published. The composition still returns the run's exit status."""
    if summary.get(TEARDOWN_FAULTED):
        _logger.error("the box could not be proven stopped after the run ended; its folder was not "
                      "scrubbed, so nothing is read from it or published (no run page, no case "
                      "comment, no curation)")
        return
    run = started.run
    run_dir = run.run_dir
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

    if operator_steps is not None:
        operator_steps()

    try:
        visualize(run, tenant=started.accepted, update_ticket=update_ticket,
                  **({} if mirror else {"mirror": False}))
    except _run.VisualizeFailed:
        _logger.warning("the run page was not saved", exc_info=True)



@contextlib.contextmanager
def _operator_set_up(ns: argparse.Namespace, data_root: DataRoot, admitted: Admitted,
                     **seams: Any) -> Iterator[_Started]:
    """The operator command's setup under the host acceptance `main` opened (r10 A1; #1342 r6
    R6-3), held here for the whole run: both halves of run setup (`_set_up`)."""
    with admitted, _set_up(ns, data_root, admitted, **seams) as started:
        yield started


def _not_curated(started: _Started, *, no_learn: bool) -> str | None:
    """Why this run is not enqueued for catalog curation, or `None` when it is. A sibling's
    evidence was staged on purpose and a run started with `--as-of` read a frozen lab (#1347):
    neither is today's evidence, so neither ever feeds the catalog."""
    if started.world is not None:
        return "--episode: a sibling world is not enqueued for curation"
    if started.as_of is not None:
        return "--as-of: a frozen run is not enqueued for curation"
    if no_learn:
        return "--no-learn set; not enqueuing for curation"
    return None


def main(  # noqa: PLR0913 — the entry point's inputs plus its injection seams
    argv: list[str],
    *,
    environ: Mapping[str, str] | None = None,
    lifecycle: Callable[..., dict[str, Any]] = _run_investigation_lifecycle,
    visualize: Callable[..., None] = _run.visualize,
    ticket_writer: Any = _default_ticket_writer,
    enqueue: Callable[..., bool] = _run.enqueue_curation,
    enqueue_feedback: Callable[..., bool] = _run.enqueue_feedback_issue,
    preflight: Callable[..., int] = preflight_role_models,
    materialize: Callable[..., Run] = _materialize_run,
    oracle: Any = None,
    verifier: Any = None,
    roster: Any = None,
    publish: PublishLaunch | None = None,
    directory: tenancy.TenantDirectory | None = None,
    signer: Any = None,
    proxy_url: str | None = None,
    issuer_transport: Any = None,
) -> int:
    """`oracle` / `verifier` are a sibling's oracle and verifier models (#1224; `None` builds
    them from their knobs). `roster` is the adapters roster this run reads (`None`: the
    checkout's, read once here): run start judges each granted system's settings check over it
    (#1256 O-8), once, and the lifecycle hands that judgement — the roster with its verdict, one
    value — to the investigation, so the roster judged and the roster used are one and the run
    is not judged twice.

    `publish` is the launch-time publish (#1108 P4, U7/O11): called once per unpinned launch
    with the tenant id and the data root, it returns the child's one report line. `None` is the
    real child process (`launch_publish`); only an in-process caller passes a stand-in.

    `directory` is the tenant records (#1214 Flow 4): a test's or a launcher's; a production run
    passes none and reads them from `DEFENDER_DATABASE_DSN`. The run's tenant must be `active`
    there, with its forge wiring recorded, before anything else of it is read.

    `environ` is the process's environment (`None`: `os.environ`): with a job socket in it the
    command is a learning sibling inside its job container (#1170 A6), whose tenant its job's host
    helper admitted and holds, and which gets its run folder, knowledge copy and pass from it.

    `signer`, `proxy_url` and `issuer_transport` are the operator's seams for the credential
    proxy (#1163): the request-token signer (else the tenant's own sign login, over `directory`'s
    live generation, through `issuer_transport` when given), and the proxy's address (else
    `PROXY_URL_ENV`).

    The operator composition (#1342 M3, M4): setup, the lifecycle, then the shared post-steps,
    with the case ticket and the curation enqueue this composition alone owns."""
    # Undrivable dependencies (credentialed lifecycle, HTML render, ticket endpoint) are
    # injection seams defaulting to production.
    ns = parse_args(argv)
    # In a job container (#1170 A6) only a learning sibling runs here: its host half is its job's
    # helper's, which `request` (the job socket's client) asks; elsewhere the operator's own.
    request = job_socket.from_environ(os.environ if environ is None else environ)
    # Bound under its production name so the curation lane is visibly reached from here.
    enqueue_curation = enqueue
    setup: contextlib.AbstractContextManager[_Started]
    if request is None:
        # The request's tenant id, then the data root, resolved once; nothing below resolves
        # either again. The one host acceptance (r10 A1; #1342 r6 R6-3), this command's own,
        # held for the whole run by its setup.
        data_root = _request_data_root(ns)
        with _tenant_refusal_exits():
            admitted = host_tenant(data_root, ns.tenant, directory=directory, **_acceptance_args(ns, data_root))
        setup = _operator_set_up(ns, data_root, admitted, preflight=preflight, materialize=materialize,
                                 oracle=oracle, verifier=verifier, roster=roster, publish=publish,
                                 signer=signer, proxy_url=proxy_url, issuer_transport=issuer_transport)
    else:
        setup = _sibling_set_up(ns, request, preflight=preflight, roster=roster, oracle=oracle, verifier=verifier)
    # A sibling in its container: its box over the socket, its page left in its own run folder.
    in_container: dict[str, Any] = {} if request is None else {"job_lane": True, "relay": request}
    try:
        with setup as started:
            run, tenant, world, episode = started.run, started.tenant, started.world, started.episode
            run_dir = run.run_dir
            # Every log line from here on, the crash included, names this run and the tenant this
            # process resolved once above and hands inward as one value.
            with _log.run_context(run_dir.name, tenant.tenant_id, logger=_logger):
                if ns.update_ticket:
                    # Nothing is called at run start (#1359 O1): a receipt an earlier attempt
                    # left is cleared, and the record step does the rest.
                    ticket_writer.clear_receipt(run)

                _logger.info(f"run_dir={run_dir} model={started.model}")
                _announce_provenance(run_dir)

                run_state = RunState(run_dir, run_dir.name)
                try:
                    summary = lifecycle(**started.lifecycle_kwargs(ns), **in_container, run_state=run_state)
                except (ServingAbort, BaseExceptionGroup) as escaped:
                    return _unservable_exit(escaped, world=world, episode=episode,
                                            lost=started.minting.access_lost())

                def ticket_and_curation() -> None:
                    # No automatic feed into the learning pipeline; only catalog curation is
                    # triggered here, and its failure does not affect the exit status. The ticket
                    # comment (never a close — that is a person's act) is recorded before the
                    # curation marker, which a drainer may pick up immediately.
                    if ns.update_ticket:
                        # Both inputs come from the driver's summary, not from a possibly stale sidecar.
                        # The case system was judged once, at setup (`started.case`), and the token
                        # minted on that verdict — and only for a run that will comment.
                        truncated_by = summary.get("truncated_by")
                        closed_before_cut = summary.get("closed_before_cut") is True
                        minting = started.minting  # the operator's own signer: `_set_up` builds a `_TokenMint`
                        token = (minting.write_back()
                                 if isinstance(minting, _TokenMint)
                                 and _default_ticket_writer.comments_on(truncated_by, closed_before_cut) else {})
                        ticket_writer.record_case_ticket(
                            run, tenant=tenant, defender_dir=DEFENDER_DIR,
                            env=box_mod.run_env(DEFENDER_DIR, run_dir, tenant_agent=tenant.agent),
                            truncated_by=truncated_by, closed_before_cut=closed_before_cut,
                            case=started.record_case(), **token)

                    skipped = _not_curated(started, no_learn=ns.no_learn)
                    if skipped is not None:
                        _logger.info(skipped)
                    else:
                        if enqueue_curation(run, started.alert, tenant=started.accepted,
                                            truncated_by=summary.get("truncated_by")):
                            _logger.info("enqueued for catalog curation")
                        # After curation, under its own predicate: a feedback issue is wanted
                        # for the escalated endings the learning gate refuses (#1414 F1). It
                        # never raises, so it cannot cost the run its curation or its page.
                        enqueue_feedback(
                            run, started.alert, tenant=started.tenant,
                            truncated_by=summary.get("truncated_by"),
                            closed_before_cut=summary.get("closed_before_cut") is True,
                            run_state=run_state)

                _post_steps(started, summary, visualize=visualize, update_ticket=ns.update_ticket,
                            operator_steps=ticket_and_curation, mirror=request is None)
                return _exit_code(summary)
    except _PreflightRefused as refused:
        return refused.rc


# -- the job lane (#1342; in its job container, #1170 A4-A6) ------------------------------------------

def parse_job_args(argv: list[str]) -> argparse.Namespace:
    """The job entry's arguments: `--job <id> --tenant <T>` and nothing else (#1170 A5: the job's
    death tie is its stdin, not a parent pid). The id is the investigation's (its launch record
    names it); the data root comes from `DEFENDER_DATA_ROOT`. The namespace carries the operator
    run's other arguments at their defaults, so the run half reads one shape: a job has no alert
    path, episode, model override, knowledge pin, ticket or learning flag."""
    p = argparse.ArgumentParser(description="Run one queued investigation in its job container (the job lane).")
    p.add_argument("--job", required=True, help="the investigation id its launch record names")
    p.add_argument("--tenant", required=True, help="the tenant the investigation belongs to")
    ns = p.parse_args(argv)
    for name, default in (("alert", None), ("episode", None), ("world", None), ("no_learn", False),
                          ("update_ticket", False), ("model", None), ("knowledge_commit", None),
                          ("as_of", None), ("as_of_anchor", None)):
        setattr(ns, name, default)
    return ns


def _interrupt_on_sigterm() -> None:
    """The first SIGTERM is a `KeyboardInterrupt` (#1342 O7): the one interrupt every broad
    handler in the runtime passes through, so the run unwinds into its box teardown. Every later
    SIGTERM is ignored, so the teardown it unwinds into is not itself interrupted."""
    def on_term(_signum: int, _frame: Any) -> None:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_term)


class _JobFacts:
    """The job-end record's facts (#1342 O8), each set as it becomes true, and the record
    written create-only when the block exits, however it exits (`__exit__` records and swallows
    nothing). Before setup completes, a `SystemExit` or the preflight's refusal is `refused`,
    anything else `crashed`. The run's two facts are set on `held`, the holder the lifecycle is
    handed (r5 C2), so a raise after either became true does not lose it."""

    def __init__(self, lane: job_lane.JobLane, job: str) -> None:
        self._lane = lane
        self._job = job
        self.setup: str | None = None
        self.held = _JobEndFacts()

    def __enter__(self) -> _JobFacts:
        return self

    def __exit__(self, kind: type[BaseException] | None, exc: BaseException | None,
                 _tb: Any) -> Literal[False]:
        if self.setup is None:
            refused = isinstance(exc, (SystemExit, _PreflightRefused))
            self.setup = job_facts.SETUP_REFUSED if refused else job_facts.SETUP_CRASHED
        if exc is not None and self.held.box == job_facts.BOX_NOT_STARTED and self.setup == job_facts.SETUP_DONE:
            # Raised after setup with no box started: whatever stopped it, the box did not start
            # (r7 D-ad). A run whose box started keeps `started`, however it ended.
            self.held.box = job_facts.BOX_START_FAILED
        end = job_lane.JobEnd(setup=self.setup, box=self.held.box,
                             report_committed=self.held.report_committed,
                             scrub_verified=self.held.scrub_verified,
                             cut_short=self.held.cut_short)
        try:
            self._lane.write_job_end(self._job, end)
        except FileExistsError:
            _logger.error(f"job {self._job}: a job-end record is already there; it is kept, and "
                          f"this one ({end.text()}) is not written")
        except (OSError, job_lane.JobLaneRefused) as e:
            _logger.error(f"job {self._job}: the job-end record could not be written: {e}")
        return False


class _HelperPass:
    """A job's read pass, asked of its host helper over the job socket (#1170 O5, O6, H2): the
    helper signs it (the job holds no sign login) for this run's id, the grant and the lifetime it
    decided (`credential_proxy.helper_access`, the one in-container pass, which a learning sibling's
    pre-flight uses too)."""

    def __init__(self, request: Callable[..., dict[str, Any]], *, run_id: str, proxy_url: str,
                 granted: bool) -> None:
        self._access = helper_access(request, run_id, proxy_url) if granted else None

    def access_kwargs(self) -> dict[str, RequestAccess]:
        return _access_kwargs(self._access)

    def access_lost(self) -> str | None:
        """Why the process lost its credential-proxy access (the holder's latched detail), or None
        while it has not, or never held any (#1363 D11)."""
        return None if self._access is None else self._access.lost


def _launch_facts(request: Callable[..., dict[str, Any]], *, kind: str, tenant: str, job: str,
                  label: str) -> dict[str, Any]:
    """The helper's launch facts for this job (#1170 A6), or the refusal naming why there are none or
    why they are not this job's (`kind`, `tenant`, `job`; `label` names the caller in each refusal):
    the helper admitted the tenant and ran the publish before this container started, and says so
    here. An investigation's job is its own id; a learning sibling's, its learning job's (its episode)."""
    try:
        launch = request("launch")
    except job_socket.Refused as refused:
        sys.exit(f"[run.py] {label}: the job's host helper refused its launch facts ({refused.code}): {refused}")
    except (OSError, ValueError) as lost:
        sys.exit(f"[run.py] {label}: the job's host helper did not answer for its launch facts: "
                 f"{type(lost).__name__}: {lost}")
    said = {key: launch.get(key) for key in ("kind", "tenant", "job")}
    if said != {"kind": kind, "tenant": tenant, "job": job}:
        sys.exit(f"[run.py] {label}: this job container's launch facts are not this {kind} job's: {said}")
    if launch.get("tenant_state") != "active":
        sys.exit(f"[run.py] {label}: this run's tenant cannot be used: it is {launch.get('tenant_state')!r}")
    return launch


def _container_tenant(ns: argparse.Namespace, data_root: DataRoot) -> tenancy.Tenant:
    """The job's tenant inside its container: the folder rules only, over its own tenant folder (the
    one the container mounts), as run start judges them (`clone_tree=False`). No host lock and no
    admission: the job's host helper holds the one and ran the other, and their verdict is in the
    launch facts (#1170 A6, C19)."""
    try:
        return tenancy.accept_tenant(data_root, ns.tenant, defender_dir=DEFENDER_DIR, clone_tree=False)
    except TenantRefused as refused:
        sys.exit(f"[run.py] job {ns.job}: this run's tenant cannot be used: {refused}")


def _helper_made(ns: argparse.Namespace, accepted: tenancy.Tenant,
                 launch: Mapping[str, Any]) -> tuple[Run, run_knowledge.RunCopy]:
    """The run folder and its knowledge copy the job's host helper made at the job's id (#1170 A6):
    opened, never made. The launch facts must name the same two places."""
    copy = run_knowledge.RunCopy(accepted.run_knowledge / ns.job)
    run = _open_run(accepted.runs_repository(), ns.job, what=f"job {ns.job}: its run folder")
    for what, made, said in (("run folder", run.run_dir, launch.get("run_dir")),
                             ("knowledge copy", copy.root, launch.get("run_copy"))):
        if str(made) != str(said):
            sys.exit(f"[run.py] job {ns.job}: the helper's {what} {said!r} is not this job's {made}")
    return run, copy


def _container_systems(  # noqa: PLR0913 — the tenant, its copy and records, the roster, the lead flag, the ids
    accepted: tenancy.Tenant, *, copy: run_knowledge.RunCopy, records: TenantRecords, roster: Any,
    dispatches_lead_zero: bool, known_ids: Any = (),
) -> tuple[RunTenant, RunSystems]:
    """A job container's tenant and its one judgement of its systems (#1170 A6, #1366): the tenant
    over its copy and the records its host helper read (no database here), its systems over the
    catalog this container reads, its grants narrowed to them, then judged by the adapters' own
    settings checks. The judgement runs adapter code, so it is the container's, never the
    helper's (#1170 O5, N7)."""
    tenant = _resolve_run_tenant(accepted, dispatches_lead_zero=dispatches_lead_zero, records=records,
                                 copy=copy)
    verdict = _tenant_verdict(tenant, roster if roster is not None else _run_roster(DEFENDER_DIR))
    systems = _judge_start(verdict.tenant, defender_dir=DEFENDER_DIR, roster=verdict.systems.roster,
                           known_ids=known_ids, catalog=verdict.systems.catalog.roster)
    return verdict.tenant, systems


def _set_up_in_container(  # noqa: PLR0913 — the request, its launch facts, the socket and the run half's seams
    ns: argparse.Namespace, data_root: DataRoot, launch: Mapping[str, Any],
    request: Callable[..., dict[str, Any]], *, preflight: Callable[..., int], roster: Any,
) -> _Started:
    """A job's run half (#1170 A6; #1342 M3's second half): the tenant judged by the folder rules,
    resolved over the copy its helper made, its systems judged once, the preflight, the run its
    helper made opened and announced — or the refusal (`SystemExit` naming it; `_PreflightRefused`).
    Its read pass comes from the helper, asked when a call needs it."""
    accepted = _container_tenant(ns, data_root)
    run, copy = _helper_made(ns, accepted, launch)
    current = _run.handed_records(launch, label=f"job {ns.job}")
    tenant, systems = _container_systems(
        accepted, copy=copy, records=current, roster=roster, dispatches_lead_zero=True)
    passes = _HelperPass(request, run_id=ns.job, proxy_url=str(launch.get("proxy_url") or ""),
                         granted=bool(launch.get("grant")))
    model = driver.resolve_main_model(ns.model)
    rc = preflight(ns.model)
    if rc:
        raise _PreflightRefused(rc)
    # The run's id, announced as the first line of stdout (#1279 O5), before the box exists.
    print(f"run_id={run.run_dir.name}", flush=True)
    return _Started(accepted=accepted, tenant=tenant, run=run, model=model, world=None, episode=None,
                    systems=systems, seams={}, alert=RunPaths(run.run_dir).alert, minting=passes)


def job_main(  # noqa: PLR0913 — the job entry's inputs plus its injection seams
    argv: list[str],
    *,
    environ: Mapping[str, str] | None = None,
    lifecycle: Callable[..., dict[str, Any]] = _run_investigation_lifecycle,
    visualize: Callable[..., None] = _run.visualize,
    preflight: Callable[..., int] = preflight_role_models,
    roster: Any = None,
) -> int:
    """The job entry (#1342), inside its job container only (#1170 A6): `run.py --job <id> --tenant
    <T>`, the process the job's host helper starts. `environ` is the container's environment
    (`None`: this process's): the job socket it names is the helper's door, and without one the
    entry does nothing (host mode is retired). The job composition: the job lane's door, then the
    run half (its host half is the helper's: admission, launch check, alert mapping, publish, run
    copy, read grant, run folder), the lifecycle with its box started by the helper over the socket,
    and the post-steps — with no ticket and no curation (M4: neither is a parameter), no database,
    no host lock and no signer, and a box that never degrades to host execution (R2). The job-end
    record is written however it ends, while the helper still holds the tenant (R6-6). Signals and
    the stdin death tie are the process's (`serve_job`)."""
    ns = parse_job_args(argv)
    request = job_socket.from_environ(os.environ if environ is None else environ)
    if request is None:
        print(f"[run.py] job {ns.job}: no job socket ({job_socket.SOCKET_ENV} is unset): the job entry runs "
              "only inside its job container, started by its host helper; nothing was done", file=sys.stderr)
        return 2
    data_root = _request_data_root(ns)
    try:
        lane = job_lane.JobLane.open(data_root, ns.tenant)
    except job_lane.JobLaneRefused as refused:
        sys.exit(f"[run.py] job {ns.job}: {refused}")
    try:
        with lane, _JobFacts(lane, ns.job) as facts:
            launch = _launch_facts(request, kind="investigation", tenant=ns.tenant, job=ns.job,
                                    label=f"job {ns.job}")
            started = _set_up_in_container(ns, data_root, launch, request, preflight=preflight, roster=roster)
            facts.setup = job_facts.SETUP_DONE
            run = started.run
            with _log.run_context(run.run_dir.name, started.tenant.tenant_id, logger=_logger):
                _logger.info(f"run_dir={run.run_dir} model={started.model}")
                _announce_provenance(run.run_dir)
                token = launch.get("box_token")
                summary = lifecycle(**started.lifecycle_kwargs(ns), job_lane=True, job_facts=facts.held,
                                    relay=request, **({"start_token": token} if token else {}))
                # The page is saved in the run's own folder only: the helper copies it to the shared
                # publish folder once this container has exited (#1170 A10).
                _post_steps(started, summary, visualize=visualize, update_ticket=False, mirror=False)
                return _exit_code(summary)
    except _PreflightRefused as refused:
        return refused.rc


def serve_job(  # noqa: PLR0913 — the entries' inputs plus their injection seams
    argv: list[str],
    *,
    lifecycle: Callable[..., dict[str, Any]] = _run_investigation_lifecycle,
    visualize: Callable[..., None] = _run.visualize,
    preflight: Callable[..., int] = preflight_role_models,
    roster: Any = None,
) -> int:
    """`run.py` as a job container's process (#1170 A5, A6): its command line, `--job <id> --tenant
    <T>` for an investigation (`job_main`) or a learning sibling's `--tenant <T> --episode <id>
    --world <label>` (`main`), with the process's own wiring around it. The first SIGTERM is the
    run's `KeyboardInterrupt` and later ones are ignored (#1342 O7); end of file on stdin, the job's
    host helper gone, is that SIGTERM (A5). Without a job socket in its environment it does nothing."""
    if job_socket.from_environ(os.environ) is None:
        print(f"[run.py] no job socket ({job_socket.SOCKET_ENV} is unset): a job container's entry runs only "
              "inside its job container, started by its host helper; nothing was done", file=sys.stderr)
        return 2
    _interrupt_on_sigterm()
    job_socket.sigterm_on_stdin_eof()
    try:
        if any(a == "--job" or a.startswith("--job=") for a in argv):
            return job_main(argv, environ=os.environ, lifecycle=lifecycle, visualize=visualize,
                            preflight=preflight, roster=roster)
        return main(argv, environ=os.environ, lifecycle=lifecycle, visualize=visualize, preflight=preflight,
                    roster=roster)
    except KeyboardInterrupt:
        # Stopped (SIGTERM or the helper gone): the run unwound through its teardown, and a job's
        # end record is written; the process says it was terminated.
        return 128 + signal.SIGTERM


# -- a learning sibling in its job container (#1170 A6, #1449) ---------------------------------------

def _sibling_made(request: Callable[..., dict[str, Any]], ns: argparse.Namespace, accepted: tenancy.Tenant,
                  episode_runs: Any, world: Any) -> tuple[Run, run_knowledge.RunCopy]:
    """The sibling's run and knowledge copy, made by the job's host helper (`copy.make`, #1170 A6, C20):
    its id the episode roster's for this world, its folder materialized there (input and stamp), its
    copy owned by the helper. Opened here, never made: the id, the folder and the copy must be the ones
    this sibling's own roster and tenant name."""
    from defender.records import RunRefused

    try:
        made = request("copy.make", world=world.world_id)
    except job_socket.Refused as refused:
        sys.exit(f"[run.py] --episode {ns.episode}: the job's host helper refused the sibling's run "
                 f"({refused.code}): {refused}")
    except (OSError, ValueError) as lost:
        sys.exit(f"[run.py] --episode {ns.episode}: the job's host helper did not make the sibling's run: "
                 f"{type(lost).__name__}: {lost}")
    try:
        arm = episode_runs.arm_id(world.world_id)
    except RunRefused as refused:
        sys.exit(f"[run.py] --episode {ns.episode}: the sibling's run cannot be opened: {refused}")
    run = _open_run(episode_runs, arm, what=f"--episode {ns.episode}: the sibling's run")
    copy = run_knowledge.RunCopy(accepted.run_knowledge / run.run_dir.name)
    for what, ours, said in (("run id", run.run_dir.name, made.get("run")), ("run folder", run.run_dir, made.get("run_dir")),
                             ("knowledge copy", copy.root, made.get("path"))):
        if str(ours) != str(said):
            sys.exit(f"[run.py] --episode {ns.episode}: the helper's {what} {said!r} is not this sibling's {ours}")
    return run, copy


@contextlib.contextmanager
def _sibling_set_up(  # noqa: PLR0913 — the request, the socket and the sibling's seams
    ns: argparse.Namespace, request: Callable[..., dict[str, Any]], *, preflight: Callable[..., int],
    roster: Any, oracle: Any, verifier: Any,
) -> Iterator[_Started]:
    """`run.py --tenant <T> --episode <id> --world <label>` inside its learning job's container (#1170
    A6, #1449): the sibling's run half, which `main` composes. Its tenant judged by the folder rules
    (the job's helper holds the lock and ran the admission), its episode door opened, its world
    resumed, its run (id, folder with input and stamp) and copy made by the helper at the family's
    knowledge, its systems judged, its preflight, the run its helper made announced, a read pass
    from the helper — or the refusal (`SystemExit` naming it; `_PreflightRefused`). No database,
    host lock, publish or signer. Yields the started run, holding the episode door."""
    from defender.records.formats import family_identities

    if ns.episode is None:
        sys.exit("[run.py] inside a job container `run.py` runs a learning sibling only (`--tenant --episode "
                 "--world`); an alert is investigated by its own job (`--job`)")
    launch = _launch_facts(request, kind="learning", tenant=ns.tenant, job=ns.episode,
                            label=f"--episode {ns.episode}")
    data_root = _request_data_root(ns)
    try:
        accepted = tenancy.accept_tenant(data_root, ns.tenant, defender_dir=DEFENDER_DIR,
                                         box_mounted=_sibling_box_mounted(ns, data_root), clone_tree=False)
    except TenantRefused as refused:
        sys.exit(f"[run.py] this run's tenant cannot be used: {refused}")
    episode_runs = _open_episode_runs(ns, accepted)
    with episode_runs:
        episode = episode_runs.episode
        world = _resume_target(ns, episode=episode, tenant=lambda: None, arm_ids=episode_runs.arm_ids)
        source = _open_world_source(accepted.runs_repository(), world)
        run, copy = _sibling_made(request, ns, accepted, episode_runs, world)
        _family_pin(ns, _knowledge_pin(ns), episode)  # a `--knowledge-commit` naming another export refuses
        current = _run.handed_records(launch, label=f"--episode {ns.episode}")
        tenant, systems = _container_systems(
            accepted, copy=copy, records=current, roster=roster, dispatches_lead_zero=False,
            known_ids=family_identities(world.family, world.arm_ids))
        passes = _HelperPass(request, run_id=run.run_dir.name, proxy_url=str(launch.get("proxy_url") or ""),
                             granted=bool(launch.get("grant")))
        model = driver.resolve_main_model(ns.model)
        rc = preflight(ns.model, branching=True)
        if rc:
            raise _PreflightRefused(rc)
        seams = _world_seams(world, oracle=oracle, verifier=verifier, source=source,
                             tenant_id=str(tenant.tenant_id))
        alert = _screened_source_alert(episode)
        print(f"run_id={run.run_dir.name}", flush=True)
        yield _Started(accepted=accepted, tenant=tenant, run=run, model=model, world=world, episode=episode,
                       systems=systems, seams=seams, alert=alert, minting=passes)


#: A sibling whose world went unservable exits with this (its world record says why).
UNSERVABLE_EXIT = 3
#: What a run ended by an exit class with its own status says on the way out (#1243, #1421).
_EXIT_WORDS = {
    run_end.TRUNCATED_BY_PROVIDER_DOWN: "the model provider stayed down; the run ended with no "
                                        "report (rerun later)",
    run_end.TRUNCATED_BY_PROVIDER_REJECTED: "the model provider refused a request for good; the "
                                            "run ended (rerunning will not help: the run log "
                                            "names the HTTP status and the provider's reason)",
    run_end.TRUNCATED_BY_PROXY_ACCESS: "the run lost its access to the credential proxy; the run "
                                       "ended with no report (nothing is wrong with the systems it "
                                       "was reading: the run log names the cause)",
    run_end.TRUNCATED_BY_BOX_LOST: "the run's box became unusable; the run ended (the operator's "
                                   "to fix: the run log names the command that found it)",
    run_end.TRUNCATED_BY_BOX_OUTPUT_LIMIT: "a process in the run's box wrote past its helper and "
                                           "tripped the host fence; the run ended",
}


def _exit_code(summary: dict) -> int:
    """The exit status of a run whose post-steps are done or skipped: its exit class's own code
    from the one table (`run_end.EXIT_CLASSES`: provider-down 4, box-lost 5, box-output-limit 6,
    provider-rejected 7, proxy-access 8),
    said on the way out, else 0."""
    truncated_by = run_end.normalized_truncated_by(summary.get("truncated_by"))
    code = run_end.exit_code_of(truncated_by)
    if code and truncated_by is not None:
        _logger.error(_EXIT_WORDS.get(truncated_by, f"the run ended {truncated_by}"))
    return code


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


def _unservable_exit(escaped: BaseException, *, world: Any, episode: Episode | None,
                     lost: str | None = None) -> int:
    """A sibling whose world went unservable: its world record written and `UNSERVABLE_EXIT`.
    Anything else that escaped the lifecycle is raised again."""
    abort = _serving_abort(escaped)
    if abort is None or world is None or episode is None:
        raise escaped
    ours = getattr(abort, "our_fault", False) or lost is not None
    if ours and getattr(abort, "reason", "") != "budget":
        # The oracle gave up because a lookup met our own failure, or the process lost its access
        # while it served (#1363 D11): the world is not unservable, so no world record is written;
        # the sibling ends as a run that lost its access.
        system, detail = getattr(abort, "our_cause", None) or ("", lost or "")
        _logger.error(f"--episode: world {world.label}: the oracle's lookup of {system or 'a system'} "
                      f"failed on our side ({detail}); the sibling ends proxy-access, no world "
                      "record is written")
        return run_end.exit_code_of(run_end.TRUNCATED_BY_PROXY_ACCESS)
    _record_unservable_world(episode, world, abort)
    _logger.error(f"--episode: world {world.label} is unservable; the sibling ends "
                  f"({getattr(abort, 'reason', '')})")
    return UNSERVABLE_EXIT


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
    _argv = sys.argv[1:]
    # In a job container (its job socket set, #1170 A6) `run.py` is the container's process; elsewhere the
    # operator command. A host shell's `run.py --job` is therefore refused by the operator's arguments.
    sys.exit(serve_job(_argv) if job_socket.SOCKET_ENV in os.environ else main(_argv))
