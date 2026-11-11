"""Episode launch checks and original-query calibration."""
from __future__ import annotations


import concurrent.futures
import contextlib

import contextvars


import json





import threading

from collections.abc import Callable, Mapping, Sequence

from dataclasses import dataclass

from pathlib import Path

from contextlib import AbstractContextManager
from typing import Any, NamedTuple

import time

from defender.credential_proxy import request_access, signing_access
from defender.kit.access import RequestAccess
from defender.kit.faults import AdapterFault, ConfigFault
from defender.records import formats

from defender.records.formats import Episode




from defender.records import (
    Run,
)

from defender.systems import system_status
from defender.systems.run_tenant import RunTenant

from defender.learning.branch import outcome as outcome_mod
from defender.learning.branch.endings import (
    HISTORY_UNREADABLE,
    LAUNCH_REFUSED,
    LauncherRefused,
    ending,
)






from defender.learning.branch.ledger import Ledger



from defender.investigation import branch

from defender.records.formats import runnable_worlds





#: The words pre-flight's outcome record may hold (`outcome.OUTCOMES`); there is no fourth.
ACCEPTED, UNUSABLE, REFUSED = outcome_mod.ACCEPTED, outcome_mod.UNUSABLE, outcome_mod.REFUSED
#: The key of `preflight_replay`'s returned record (never of the outcome record it writes) that
#: says the refusal was the environment's, not the family's or its source's: the read token for
#: the credential proxy could not be signed. A job ends that one `failed: launch_refused`; every
#: other refusal before the first sibling is `skipped: family_unusable` (#1344 r5 table).
ENVIRONMENT_REFUSED = "environment_refused"
#: The values of `ENVIRONMENT_REFUSED` on a refusal that was the environment's (#1363 O6, B5), each
#: choosing the job's fixed brief: the read token `sign`s no longer, the proxy cannot be used
#: (`access`), our `setup` for one system failed, or every system the source run's calls reached
#: is down for this run (`down-systems`, D9). The record holds None for any other refusal.
CAUSE_SIGN, CAUSE_ACCESS, CAUSE_SETUP, CAUSE_DOWN = "sign", "access", "setup", "down-systems"
ENVIRONMENT_CAUSES = (CAUSE_SIGN, CAUSE_ACCESS, CAUSE_SETUP, CAUSE_DOWN)








class LaunchChecked(NamedTuple):
    """What the launch checks hand on: the source's stamp, and the live tree's waived kinds."""

    source_stamp: dict
    waived: list[str]


def preflight_episode(  # noqa: PLR0913 — every refusal knowable before a model call is asked in this one block
    *, source: Run, branch_message_id: int,
    preflight: Callable[..., int], model: str | None,
    allow_dirty: bool,
    live_tree: Callable[[], formats.RunProvenance],
    oracle: Any = None, verifier: Any = None,
) -> LaunchChecked:
    """Everything that can refuse before the questioner is paid for, in one block, so an
    operator with several problems hears about them all before spending anything. Returns the
    source's stamp (the family's anchor) and the fault kinds `--allow-dirty` waived for the live
    tree, which the family stamp records with its siblings' own."""
    source_run_dir = source.run_dir
    _check_oracle_side(oracle=oracle, verifier=verifier, tenant_id=str(source.tenant_id))
    _check_branch_point(source, branch_message_id)
    # The live tree is judged as a one-member family by `verify_family`'s own rules, before the
    # paid role preflight: on its own stamp (#1344 r5), never against the source's commit or
    # scope, which the family stamp only records; its knowledge stays the source's.
    source_stamp = _stamp_of(source)
    if source_stamp is None:
        raise _no_stamp(source_run_dir)
    members: dict[str, dict | None] = {"the live tree": _as_stamp(live_tree())}
    judged = _family_refusal(
        source_stamp, members,
        source_who=f"source run {source_run_dir}", allow_dirty=allow_dirty)
    refusal = judged.refusal
    if refusal is not None:
        raise ending(f"[branch] {refusal}", reason=LAUNCH_REFUSED,
                     brief="the launch checks refused the code or knowledge the family would run on")
    rc = preflight(model, branching=True)
    if rc:
        raise ending(
            f"[branch] the role-model preflight refused (exit {rc}) — every role a branch uses, "
            "the oracle and its verifier included, is checked at launch so a missing key or an "
            "unroutable model surfaces before anything is spent, never as a world's failure",
            reason=LAUNCH_REFUSED, brief=f"the role-model preflight refused (exit {rc})")
    return LaunchChecked(source_stamp, list(judged.waived))




def _check_oracle_side(*, oracle: Any, verifier: Any, tenant_id: str) -> None:
    """Refuse a launch whose oracle `preflight_replay` could not configure: a bad oracle knob
    (`FatalConfigError`) or a role with no pricing row (`OraclePricingError`). The same
    functions pre-flight's `oracle_settings_with` and each world's `Oracle` call, so the rule
    lives once; asked here only to refuse before the questioner is paid for."""
    from defender.configuration import FatalConfigError
    from defender.learning.branch.estate.oracle import OraclePricingError, price_row
    from defender.learning.branch.estate.registry import oracle_serving
    from defender.learning.core.config import oracle_settings_with

    try:
        serving = oracle_serving(oracle_settings_with(), oracle=oracle, verifier=verifier, tenant_id=tenant_id)
        price_row("oracle", serving.oracle)
        price_row("verifier", serving.verifier)
    except (FatalConfigError, OraclePricingError) as bad:
        raise ending(
            f"[branch] the oracle cannot be configured: {bad} — pre-flight would refuse it "
            "after the question-writer was paid for", reason=LAUNCH_REFUSED,
            brief=f"the oracle cannot be configured ({type(bad).__name__})", cause=bad) from bad




def _no_stamp(source_run_dir: Path) -> LauncherRefused:
    return ending(
        f"[branch] source run {source_run_dir} carries no usable provenance stamp — a "
        "family is anchored to the commit its source ran, and a source with no readable "
        "stamp cannot anchor one", reason=HISTORY_UNREADABLE,
        brief="the source run carries no provenance stamp current code can read")




#: A generous ceiling on any session's message id, far beyond `DEFAULT_REQUEST_LIMIT` times the
#: messages per request. Only a sanity bound: where a store exists, the session itself decides
#: which messages may be branched from.
MAX_BRANCH_MESSAGE_ID = 100 * 60

#: The job's message for a branch point the launch checks refuse.
_POINT_REFUSED = "the branch admission refused the fork point"




def _check_branch_point(source: Run, branch_message_id: int) -> None:
    """Refuse a branch point the source run could not have produced."""
    source_run_dir = source.run_dir
    if branch_message_id < 0:
        raise ending(
            f"[branch] branch message id {branch_message_id} is negative — it names a message "
            "in the source run's own session, and there is no message before the first",
            reason=LAUNCH_REFUSED, brief=_POINT_REFUSED)
    if branch_message_id > MAX_BRANCH_MESSAGE_ID:
        raise ending(
            f"[branch] branch message id {branch_message_id} is beyond {MAX_BRANCH_MESSAGE_ID}, "
            "the most any one investigation's session could hold — no run produced a message "
            "there, so this is a typo rather than a branch point", reason=LAUNCH_REFUSED,
            brief=_POINT_REFUSED)
    opened = _source_store(source)
    if opened is None:
        raise ending(
            f"[branch] {source.id} carries no session store, so it recorded no fork snapshot "
            f"for message {branch_message_id} — nothing says what it held when that response "
            "arrived, and no arm can be restored from it", reason=LAUNCH_REFUSED,
            brief="the source run carries no session store to fork")
    try:
        with opened as store:
            as_of = branch.branch_point_time(store, Path(source_run_dir), branch_message_id, source_run=source)
            # An empty capture is not refused here: pre-flight records it as a `refused` episode
            # (M05=A), so the operator finds the reason in the outcome record.
            branch.validate(store, branch.BranchSpec(
                source_run_dir=Path(source_run_dir),
                branch_message_id=branch_message_id,
                as_of=as_of,
            ), source_run=source, require_capture=False)
    except branch.BranchError as bad:
        raise ending(f"[branch] {bad}", reason=LAUNCH_REFUSED, brief=_POINT_REFUSED,
                     cause=bad) from bad




def _source_store(source: Run) -> AbstractContextManager[Any] | None:
    """The source run's own session store to open in a `with`, or `None` when it does not
    carry one (`branch.source_store_if_any`: a pointer that does not reconcile still
    refuses)."""
    return branch.source_store_if_any(source.run_dir, source_run=source)




# ---------------------------------------------------------------------------------------
# `Step.PREFLIGHT` — calibrating every world through its own oracle
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Original:
    """One distinct call the source run made: replayed once per key (N15)."""

    system: str
    verb: str
    params: dict

    @property
    def entry(self) -> dict[str, Any]:
        return {"system": self.system, "verb": self.verb, "params": dict(self.params)}




def _originals(source_run_dir: Path) -> list[_Original]:
    """The source run's calls, first occurrence of each key, in capture order. Sentinels (a
    `∅.` row never reached a system) are not calls (N15). Nor are a platform-served system's: a
    world re-runs that verb against its pinned knowledge and never takes an oracle's answer for
    it (`_serve_platform`), so there is nothing to calibrate, and it is no failure to replay."""
    from defender.learning.branch.ledger import request_key
    from defender.learning.lead_repository import load_queries_report
    from defender.systems.verbs import is_platform_served

    rows, _unreadable = load_queries_report(Path(source_run_dir))
    seen: set[str] = set()
    out: list[_Original] = []
    for row in rows:
        if row.is_sentinel or not row.system or not row.verb or is_platform_served(row.system):
            continue
        key = request_key(row.system, row.verb, row.params)
        if key in seen:
            continue
        seen.add(key)
        out.append(_Original(system=row.system, verb=row.verb, params=dict(row.params)))
    return out




def _not_admitted(reader: Any, call: _Original) -> str | None:
    """Why the live gather grant does not admit `call` for replay, or `None` when it does
    (M22=A: every replayed call goes through `decide`; only read verbs are replayed)."""
    from defender.systems.verbs import GRANTED
    from defender.kit.verbs import verb_class_of

    try:
        decision = reader.decide(call.system, call.verb)
    except Exception as refused:  # noqa: BLE001 — a grant/declaration disagreement is a refusal
        return f"the grant decision refused it: {refused}"
    if decision.outcome != GRANTED:
        return decision.refusal or f"{call.system}.{call.verb}: {decision.outcome}"
    fn = reader.verbs(call.system).get(call.verb)
    if fn is None or verb_class_of(fn) != "r":
        return f"{call.system}.{call.verb} is not a read verb, and only reads are replayed"
    return None




#: The checkout's `defender/`, from this file's own location (not `$DEFENDER_DIR`).
_DEFENDER_DIR = Path(__file__).resolve().parents[2]


def _preflight_context(episode_dir: Path, source: Run, tenant: Any,
                       access: Any = None) -> Any:
    """The host-side context pre-flight's reads run in: the episode's tenant record and no
    capture (pre-flight is not a run and writes no query row); like every adapter's context it
    carries neither the branch point nor a run state (#1385 O1). `DEFENDER_RUNS_BASE` is the source run's container — the tenant's natural runs folder
    — from the source `Run`'s own hand-out, not `run_env`'s `run_dir.parent`."""
    from defender.box import run_env
    from defender.systems.verbs import VerbContext

    env = run_env(_DEFENDER_DIR, Path(episode_dir))
    env["DEFENDER_RUNS_BASE"] = source.runs_base_export()
    # The token is asked of its source inside each verb's call, so a pass that nears its end is asked for afresh
    # (O6: inside a job container the helper signs each one).
    proxied = ({} if access is None
               else {"proxy_url": access.proxy_url, "access": access})
    return VerbContext(defender_dir=_DEFENDER_DIR, run_dir=Path(episode_dir), env=env,
                       capture=None, tenant=tenant, **proxied)


def _preflight_access(source: Run, tenant: RunTenant, reads: Sequence[str], *, signer: Any,  # noqa: PLR0913 — the pass's identity plus the operator's seams
                      proxy_url: str | None, issuer_transport: Any, directory: Any,
                      clock: Callable[[], float],
                      on_fault: Callable[[AdapterFault], None],
                      container: Any = None, job_id: str | None = None) -> RequestAccess | None:
    """The pass's one access holder (#1363 O1), built as a run builds its own
    (`request_access`): the read token over `reads`, the run's read grant, with the source run as
    its investigation; `None` when the grant is empty. A configuration that cannot sign (no proxy
    address, no sign login recorded) raises before anything is contacted. With no `signer`
    injected, the tenant's own (`request_signer`) over the episode's tenant records `directory`.
    Curators and the author are handed none."""
    if not reads:
        return None
    if container is not None:
        # Inside a job container (#1170 O5, O6): the per-job host helper signs every pass, for the learning job's own
        # id and the read grant it computed; asked afresh as each nears its end, never one long pass.
        if job_id is None:
            raise ConfigFault("pre-flight in a job container needs the learning job's id to ask its passes for")
        return container.access(job_id, clock=clock, on_fault=on_fault)
    if directory is None:
        raise ConfigFault("no tenant records were handed to pre-flight to sign its read token with")
    signer, address = signing_access(tenant.tenant_id, directory=directory, signer=signer,
                                     proxy_url=proxy_url, transport=issuer_transport)
    return request_access(signer, address, tenant_id=str(tenant.tenant_id),
                          investigation=source.run_dir.name, reads=reads, clock=clock,
                          on_fault=on_fault)


def preflight_replay(  # noqa: C901, PLR0912, PLR0913, PLR0915 — one pass: admit, refuse, read drift, calibrate, record
    episode: Episode, *, source: Run, roster: Any, tenant: RunTenant, oracle: Any = None,
    verifier: Any = None, signer: Any = None, proxy_url: str | None = None,
    issuer_transport: Any = None, directory: Any = None, container: Any = None, job_id: str | None = None,
    **knobs: Any,
) -> dict[str, Any]:
    """`Step.PREFLIGHT`: replay every original call through each fact world's oracle and
    verifier, and write the episode's write-once outcome record (`outcome.write_outcome`)."""
    if not isinstance(episode, Episode):
        raise TypeError("preflight_replay requires the walked episode handle")
    from defender.learning.branch.estate.limiter import RateLimiter
    from defender.learning.branch.estate.oracle import DEFAULT_RESTART_AFTER, OracleUnservable
    from defender.learning.branch.estate.registry import (
        PrebranchChanged,
        WorldRegistry,
        calibrate_one,
        default_oracle_dir,
        fixed_call,
        oracle_serving,
        prebranch_calls,
        read_family_answers,
    )
    from defender.learning.branch.ledger import payload_text, request_key
    from defender.learning.core.config import oracle_settings_with
    from defender.systems.verbs import ModuleVerbRegistry

    # The reader first, unguarded: a tenant with no gather grant refuses here (`GrantError`),
    # before anything is read or sent (O-16).
    reader = ModuleVerbRegistry(roster, tenant.grants.gather, grant_home=tenant.table_pointer)
    family = formats.load_family(episode.view(), expected_episode_id=episode.dir.name)
    originals = _originals(source.run_dir)
    # The systems the run could not use (#1363 D5, D9): judged as a run judges them.
    down = system_status.judge_run(roster, tenant, defender_dir=_DEFENDER_DIR).down
    not_replayable: list[dict[str, Any]] = []
    replayable: list[_Original] = []
    held_down = 0
    for call in originals:
        if call.system in down:
            held_down += 1
            not_replayable.append({**call.entry, "reason": f"{call.system} is down for this run"})
            continue
        why = _not_admitted(reader, call)
        if why is None:
            replayable.append(call)
        else:
            not_replayable.append({**call.entry, "reason": why})
    fact_worlds = [w for w in runnable_worlds(family) if w.facts]

    access: RequestAccess | None = None

    def record(outcome: str, reason: str, *, unservable: Sequence[Mapping[str, Any]] = (),
               environment: str | None = None) -> dict[str, Any]:
        if access is not None:
            access.shut()
        outcome_mod.write_outcome(episode, outcome, reason=reason, unservable_worlds=unservable,
                                  not_replayable=not_replayable)
        return {"outcome": outcome, "reason": reason,
                "unservable_worlds": [dict(u) for u in unservable],
                "not_replayable": list(not_replayable), ENVIRONMENT_REFUSED: environment}

    # M05=A: nothing to calibrate, for a reason that belongs to no world — refused before any
    # tenant read or oracle turn.
    if not fact_worlds:
        return record(REFUSED, "no world of the family carries a fact, so there is no world "
                               "change to calibrate and nothing a sibling could measure")
    if not originals:
        return record(REFUSED, "the source run made no call that reached a system a world "
                               "can vary, so there is no original call to replay")
    if not replayable and held_down == len(not_replayable):
        return record(REFUSED, f"every call the source run made reached a system that is down "
                               f"for this run ({', '.join(sorted({c.system for c in originals}))})",
                      environment=CAUSE_DOWN)
    if not replayable:
        return record(REFUSED, f"none of the source run's {len(originals)} call(s) can be "
                               "replayed: the live gather grant admits none of them (see "
                               "not_replayable)")

    # The oracle's knobs, settled once for every world of the pass: `knobs` over the process's
    # knobs. Each world's serving is built from them in its own thread (`calibrate`).
    box = knobs.pop("box", None)
    if box is None and container is not None and job_id is not None:
        # Inside a job container the oracle's boxes are the helper's to start (#1170 O2, C21), for the job's own id.
        box = container.box_factory("oracle", job_id)
    knobs_clock = knobs.pop("clock", time.time)
    restart_after = knobs.pop("restart_after", DEFAULT_RESTART_AFTER)
    settings = oracle_settings_with(**knobs)
    limiter = RateLimiter(settings.rate)
    # `stop` first: the holder's owner callback sets it, so a world stops before its next call once
    # access is lost or a setup fault is known (#1363 O5).
    stop = threading.Event()
    clock = knobs_clock
    try:
        access = _preflight_access(
            source, tenant, system_status.read_grant(tenant, down), signer=signer,
            proxy_url=proxy_url, issuer_transport=issuer_transport, directory=directory,
            clock=clock, on_fault=lambda _fault: stop.set(), container=container, job_id=job_id)
        # Pre-flight is the gate that proves the environment before any sibling launches, so it
        # signs once now rather than at first need: a pass whose reads all come from the
        # recording would otherwise accept without ever signing.
        if access is not None:
            access.token()
    except AdapterFault as unsigned:
        return record(REFUSED, f"the read token for the credential proxy cannot be signed: "
                               f"{unsigned.detail}", environment=CAUSE_SIGN)

    def environment_refusal() -> dict[str, Any] | None:
        """The pass's refusal when its holder has lost access or met a setup fault, else None.
        Decided under the holder's lock, which shuts it (#1363 O6)."""
        if access is None or (access.lost is None and not access.setup_faults):
            return None
        with access.deciding():
            if access.lost is not None:
                if access.sign_failed:
                    return record(
                        REFUSED, "the read token for the credential proxy cannot be signed: "
                                 f"{access.lost}", environment=CAUSE_SIGN)
                return record(REFUSED, f"the credential proxy could not be used: {access.lost}",
                              environment=CAUSE_ACCESS)
            system, detail = next(iter(access.setup_faults.items()))
            return record(REFUSED, f"our setup for {system or 'a system'} failed (the credential "
                                   f"proxy's setup): {detail}", environment=CAUSE_SETUP)

    ctx = _preflight_context(episode.dir, source, tenant, access)
    resumed = {w.label: formats.resume_world_from(family, w.label, episode.dir)
               for w in fact_worlds}
    recording = Ledger.for_world(episode, resumed[fact_worlds[0].label].world_id)
    # The family's base recording, parsed once for every world's registry.
    family_answers = read_family_answers(recording.base_path)
    # M01=A's fixed prefix, by the one rule the sibling's registry is handed too (`run.py`).
    prebranch = prebranch_calls(source, family.branch_message_id)
    # D6 (#1255): the calls the primer recorded unanswered are never fixed.
    unrecorded = recording.unrecorded_keys()

    calibrated: list[tuple[_Original, Any, bool, bool]] = []
    for call in replayable:
        recorded = recording.base_payload(call.system, call.verb, call.params)
        if recorded is None:
            # No recording holds this call's answer: its base is a live read, as the system
            # stands now, which the oracle serves as the world stood at the branch point. A
            # recorded call is read no further: it is the source's own answer (#1385 H6).
            limiter.acquire()
            try:
                base_text = payload_text(reader.verbs(call.system)[call.verb](ctx, **call.params))
            except Exception:  # noqa: BLE001 — the capture's own failure, still failing
                refused = environment_refusal()
                if refused is not None:
                    return refused
                # World telemetry, passed through as itself to any sibling that asks
                # (`real-error`), never the oracle's to serve.
                continue
        else:
            base_text = recorded
        # D6 (#1255): a pre-branch call is fixed only over its recorded answer; one the primer
        # recorded unanswered, or whose answer the recording lacks, is read live and re-askable.
        key = request_key(call.system, call.verb, call.params)
        fixed = fixed_call(key, recorded=recorded is not None, prebranch=prebranch,
                           unrecorded=unrecorded)
        calibrated.append((call, json.loads(base_text), fixed, recorded is None))

    failures: list[dict[str, Any]] = []
    tally = threading.Lock()

    def fail(label: str, call: _Original, reason: str) -> None:
        with tally:
            failures.append({"world": label, "reason": reason, "call": call.entry})
            if len(failures) >= outcome_mod.UNUSABLE_AT:
                stop.set()

    def calibrate(label: str) -> None:
        try:
            calibrate_world(label)
        except BaseException:
            # Anything but the world's own failure is the launch's: the other worlds stop
            # before their next paid turn, and `future.result()` re-raises it below.
            stop.set()
            raise

    def calibrate_world(label: str) -> None:
        world = resumed[label]
        ledger = Ledger.for_world(episode, world.world_id)
        # The world's own oracle side (`oracle_serving`), as a sibling builds its own in its own
        # process: every world calibrates on its own thread, each attempt on that thread's own
        # event loop, so the production models — each with its provider and HTTP client — are
        # never shared across loops. Only the limiter is the pass's one (S18).
        serving = oracle_serving(settings, oracle=oracle, verifier=verifier, box=box,
                                 tenant_id=str(tenant.tenant_id), restart_after=restart_after)
        registry = WorldRegistry(
            roster, tenant.grants.gather, world=world, ledger=ledger,
            serving=serving, oracle_dir=default_oracle_dir(world, ledger), limiter=limiter,
            tenant=tenant, grant_home=tenant.table_pointer, family_answers=family_answers,
            source_run=source)
        try:
            for call, base, fixed, live in calibrated:
                if stop.is_set():
                    return
                try:
                    calibrate_one(registry, ctx, call.system, call.verb, call.params, base,
                                  fixed=fixed, live=live)
                except OracleUnservable as unservable:
                    fail(label, call, f"{unservable.reason}: {unservable.detail}")
                    return
                except PrebranchChanged as changed:
                    fail(label, call, str(changed))
                    return
        finally:
            registry.close()

    # One thread per world: worlds calibrate side by side and finish in any order; the outcome
    # is written once, from every world's result. Each runs in a copy of this context, so its
    # log lines keep the run and tenant.
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(fact_worlds)) as pool:
        futures = [pool.submit(contextvars.copy_context().run, calibrate, w.label)
                   for w in fact_worlds]
    for future in futures:
        if future.exception() is not None and access is not None:
            access.shut()
        # Anything but a world's own failure is the launch's (it stopped every other world's
        # calibration), and leaves no outcome record: the outcome words are the family's
        # (accepted, unusable, refused), and an episode with none is never graded.
        future.result()

    # Decided under the holder's lock, which shuts it: a token request still running on a thread an
    # oracle turn abandoned is counted first, and nothing signs afterwards (#1363 O6).
    with access.deciding() if access is not None else contextlib.nullcontext():
        if access is not None and (access.lost is not None or access.setup_faults):
            refused = environment_refusal()
            assert refused is not None
            return refused
        unservable = sorted(failures, key=lambda entry: entry["world"])
        names = ", ".join(entry["world"] for entry in unservable)
        if len(unservable) >= outcome_mod.UNUSABLE_AT:
            return record(UNUSABLE, f"{len(unservable)} worlds failed calibration ({names}), so "
                                    "the family cannot be compared (O5)",
                          unservable=unservable)
        reason = ("every fact world calibrated" if not unservable else
                  f"world {names} failed calibration and runs no sibling; the family is graded "
                  "on the rest")
        return record(ACCEPTED, reason, unservable=unservable)




def _stamp_of(run: Run) -> dict | None:
    """A run's own provenance record, or `None` when it has none this reader can use.

    Used for both the source and every sibling, so both ends of the comparison share one shape.
    Absent and unreadable both answer `None`: neither is an agreeing stamp.

    Read through `formats.read_provenance`, which refuses aliases and type-checks fields: the file is
    in a box's rw bind, and a forged `"commit": ["x"]` would otherwise crash `verify_family`
    before anything was archived. Returned as the record's wire-shape mapping, which
    `_write_family_stamp` publishes verbatim.
    """
    record = formats.read_provenance(run.facts.provenance.path)
    return None if record is None else _as_stamp(record)




def _as_stamp(record: formats.RunProvenance) -> dict:
    """A typed provenance record as the mapping every comparison below asks."""
    # lint-parse: ok — a round-trip of a typed record through its own `as_json`, not untyped
    # input.
    return json.loads(record.as_json())




#: The kinds of fault `--allow-dirty` waives: a tree git did not certify clean, and tenant
#: knowledge no commit proves (unversioned, unavailable, or not recorded). The family stamp
#: records which of them a waived family actually had (`waived`).
DIRT = "dirt"


UNPROVEN_KNOWLEDGE = "knowledge"




#: One reason a family cannot be archived as a comparison against its source. `kind` is the
#: waivable kind, or `None` for a fault `--allow-dirty` never reaches — so waivability is a
#: property of the fault, not the site.
class _Fault(NamedTuple):
    kind: str | None
    text: str

    @property
    def waivable(self) -> bool:
        return self.kind is not None




#: Every `RunProvenance` field, classed by how the fork check judges it (#1204 D4, as amended by
#: #1344 r5: a family runs on current code, so only knowledge stays held to the source). The
#: comparison below is driven by this table, and `test_1204` holds its keys to the record's
#: fields, so a new stamp field cannot be silently left out of the check.
#: - `anchored`: each member must match the source, when the source pins a value; siblings
#:   must agree with each other when it does not;
#: - `constant`: siblings must agree with each other (the source's value is recorded, never
#:   compared);
#: - `dedicated`: judged by its own rule (`_clean_stamp`, `_cross_tenant_fault`);
#: - `informational`: recorded, never compared;
#: - `expected_to_differ`: differs between siblings by design.
STAMP_FIELD_CLASSES: dict[str, str] = {
    "commit": "constant", "scope": "constant", "knowledge": "anchored",
    "model": "constant",
    "dirty": "dedicated", "tenant_id": "dedicated",
    "dirty_paths": "informational", "dirty_path_count": "informational",
    "unavailable": "informational",
    "world_id": "expected_to_differ", "parent_run_id": "expected_to_differ",
    "fork_turn": "expected_to_differ",
    "started_at": "expected_to_differ", "alert_label": "informational",
    # #1108 P4 (O-STALE, OD17): fresh, stale or pinned is how a run came by its knowledge, not
    # which knowledge it read (`knowledge` holds that), so it is recorded, never compared.
    "knowledge_source": "informational",
    # #1344 r5: where a stamp's commit came from (git, a build stamp, a code copy's marker).
    # Clean is judged by `dirty` alone, so this is recorded, never compared.
    "origin": "informational",
}



class _HeldRule(NamedTuple):
    """How the fork check holds one `anchored` or `constant` field: the value compared, the
    waivable kind a stamp with no such value is faulted as (`None`: an absent value is just a
    value), and, for an anchored field, the refusal for a member off the source's value."""

    compared: Callable[[dict], object]
    unknown_kind: str | None = None
    off_anchor: Callable[[str, object, object], str] | None = None




def _knowledge_commit(stamp: dict) -> str | None:
    """Knowledge is compared as its commit alone, so two unavailable reasons with different
    text are not a disagreement."""
    revision = formats.KnowledgeRevision.from_wire(stamp.get("knowledge"))
    return None if revision is None else revision.commit




def _off_knowledge(who: str, got: object, want: object) -> str:
    return (f"{who} read tenant knowledge at commit {got!r} while the source run it continues "
            f"read {want!r} — a family is anchored to the knowledge its source read, and a "
            "comparison against other settings and lessons is never archived as comparable")




#: The rule of every held field that is more than "compare the value as recorded". An anchored
#: field must have one (its refusal text), which is held at import below, so no anchored field
#: falls back to a vague message.
_HELD_RULES: dict[str, _HeldRule] = {
    "knowledge": _HeldRule(compared=_knowledge_commit, unknown_kind=UNPROVEN_KNOWLEDGE,
                           off_anchor=_off_knowledge),
}




def _as_recorded(field: str) -> _HeldRule:
    return _HeldRule(compared=lambda stamp: stamp.get(field))




_ANCHORED = tuple(f for f, c in STAMP_FIELD_CLASSES.items() if c == "anchored")


_HELD = {f: _HELD_RULES.get(f) or _as_recorded(f)
         for f, c in STAMP_FIELD_CLASSES.items() if c in ("anchored", "constant")}




def _unknown_faults(who: str, stamp: dict) -> list[_Fault]:
    """The waivable faults of a stamp with no value on a field whose unknown is its own fault."""
    return [_Fault(rule.unknown_kind, _unprovable(field, who, stamp))
            for field, rule in _HELD.items()
            if rule.unknown_kind is not None and rule.compared(stamp) is None]




def _family_faults(
    source: dict, members: dict[str, dict | None], *, source_who: str,
) -> list[_Fault]:
    """Every reason `members` are not provably one family continuing `source` (#1344 r5): the
    members are held to each other on every constant field and to the source on knowledge
    alone. The source's commit and cleanliness are recorded, never judged; only knowledge no
    commit proves on the source is a (waivable) fault of its own."""
    faults: list[_Fault] = list(_unknown_faults(source_who, source))
    for who, stamp in members.items():
        faults.extend(_member_faults(who, stamp, anchor=source))
    # Agreement is over every stamp that names a commit, dirty ones included: excluding dirty
    # arms would let `--allow-dirty` waive the whole agreement, since siblings share one
    # checkout and are all dirty together.
    comparable = {who: stamp for who, stamp in members.items()
                  if stamp is not None and _stamp_speaks(stamp)}
    for field, rule in _HELD.items():
        # A field the source pinned was compared member by member above.
        if field in _ANCHORED and rule.compared(source) is not None:
            continue
        values = {who: rule.compared(stamp) for who, stamp in comparable.items()}
        if rule.unknown_kind is not None:
            # An unknown here is its own (waivable) fault, not a disagreeing value.
            values = {who: value for who, value in values.items() if value is not None}
        if len(set(values.values())) > 1:
            faults.append(_Fault(None, (
                f"siblings disagree on {field}: {values} — the family is held constant on it, "
                "so a comparison across two values is never archived as comparable")))
    return faults




def _member_faults(who: str, stamp: dict | None, *, anchor: dict) -> list[_Fault]:
    """One tree's faults: its own stamp (it names a commit, git certified it clean, its
    knowledge is proven) and, on every anchored field the source pins, the source's value."""
    if stamp is None:
        return [_Fault(None, (
            f"{who} carries no readable provenance stamp — an absent or unreadable stamp is "
            "not an agreeing one"))]
    if not _stamp_speaks(stamp):
        return [_Fault(None, (
            f"{who} names no commit (unavailable={stamp.get('unavailable')!r}) — a silent "
            "stamp cannot be held to anything"))]
    faults: list[_Fault] = []
    for field in _ANCHORED:
        rule = _HELD[field]
        want = rule.compared(anchor)
        got = rule.compared(stamp)
        # The source pins nothing here, or the member's unknown is its own fault (below).
        if want is None or (got is None and rule.unknown_kind is not None):
            continue
        if got != want and rule.off_anchor is not None:
            faults.append(_Fault(None, rule.off_anchor(who, got, want)))
    faults.extend(_unknown_faults(who, stamp))
    if not _clean_stamp(stamp):
        faults.append(_Fault(DIRT, _not_certified_clean(who, stamp)))
    return faults




def _unprovable(field: str, who: str, stamp: dict) -> str:
    """The waivable fault text for a stamp with no value on `field` (today only knowledge)."""
    revision = formats.KnowledgeRevision.from_wire(stamp.get(field))
    if revision is None:
        what = f"records no tenant {field} revision (stamped before #1204, or it does not say)"
    elif revision.unavailable is not None:
        what = f"could not name its tenant {field} commit ({revision.unavailable})"
    else:
        what = f"read an unversioned tenant {field} folder"
    return (f"{who} {what} — nothing proves it read the same {field} as the rest of the "
            "family")




def _not_certified_clean(who: str, stamp: dict) -> str:
    return (f"{who} was not certified clean by git (dirty={stamp.get('dirty')!r}, "
            f"commit={stamp.get('commit')!r}, unavailable={stamp.get('unavailable')!r}) — its "
            "commit does not name the bytes that ran")




class _Judgement(NamedTuple):
    #: The faults `--allow-dirty` did not waive, as one refusal — or `None`.
    refusal: str | None
    #: The kinds of fault the flag waived, sorted; `[]` when nothing was waived.
    waived: list[str]




def _family_refusal(
    source: dict, members: dict[str, dict | None], *, source_who: str, allow_dirty: bool,
) -> _Judgement:
    """The family's faults as one refusal, and the kinds the override waived.

    Non-waivable faults are listed first, and `--allow-dirty` is suggested only when passing it
    would let the family through; fault messages themselves never mention the flag.
    """
    found = _family_faults(source, members, source_who=source_who)
    waived = sorted({f.kind for f in found if f.kind is not None}) if allow_dirty else []
    faults = [fault for fault in found if not (fault.waivable and allow_dirty)]
    if not faults:
        return _Judgement(None, waived)
    text = "; ".join(fault.text for fault in sorted(faults, key=lambda fault: fault.waivable))
    if all(fault.waivable for fault in faults):
        text += " — pass --allow-dirty to waive these faults, recorded in the family stamp as such"
    return _Judgement(text, waived)




def _clean_stamp(stamp: dict | None) -> bool:
    """Did git answer for this sibling's tree, and say it was clean?

    Only `dirty is False` with a commit counts; a dirty tree, an unreachable git, or a sha with
    no answer for the tree are all unknowns, and an unknown is not clean.
    """
    if stamp is None:
        return False
    return stamp.get("dirty") is False and bool(stamp.get("commit"))




def _stamp_speaks(stamp: dict | None) -> bool:
    """Did git answer at all for this tree — whatever it said about dirt?

    The agreement is taken over stamps that speak. A stamp with no commit is a silence, held to
    nothing and never waived; a dirty stamp still speaks.
    """
    return stamp is not None and bool(stamp.get("commit"))
