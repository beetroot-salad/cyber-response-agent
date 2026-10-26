"""Episode launch checks and original-query calibration."""
from __future__ import annotations


import concurrent.futures

import contextvars


import json





import threading

from collections.abc import Callable, Mapping, Sequence

from dataclasses import dataclass

from pathlib import Path

from typing import Any, NamedTuple

from defender.records import _provenance

from defender.records._episode_handle import Episode




from defender.records import (
    Run,
)

from defender.runtime.run_tenant import RunTenant

from defender.learning.branch import outcome as outcome_mod






from defender.learning.branch.ledger import Ledger



from defender.runtime import branch

from defender.runtime.branch import _family

from defender.runtime.branch._family import (
    runnable_worlds,
)





#: The words pre-flight's outcome record may hold (`outcome.OUTCOMES`); there is no fourth.
ACCEPTED, UNUSABLE, REFUSED = outcome_mod.ACCEPTED, outcome_mod.UNUSABLE, outcome_mod.REFUSED




class LauncherRefused(SystemExit):
    """An episode this launcher will not run, reported as an operator's exit with an
    explanation rather than a traceback."""




def preflight_episode(  # noqa: PLR0913 — every refusal knowable before a model call is asked in this one block
    *, source: Run, branch_message_id: int,
    preflight: Callable[..., int], model: str | None,
    allow_dirty: bool,
    live_tree: Callable[[], _provenance.RunProvenance],
    oracle: Any = None, verifier: Any = None,
) -> dict:
    """Everything that can refuse before the questioner is paid for, in one block, so an
    operator with several problems hears about them all before spending anything."""
    source_run_dir = source.run_dir
    _check_oracle_side(oracle=oracle, verifier=verifier)
    _check_branch_point(source, branch_message_id)
    # The live tree is judged as a one-member family by `verify_family`'s own rules, before the
    # paid role preflight.
    source_stamp = _stamp_of(source)
    if source_stamp is None:
        raise _no_stamp(source_run_dir)
    # Capturing the live tree runs git (up to 60 s per call); skip it when the source names no
    # commit, since the refusal is then the source's own.
    members: dict[str, dict | None] = (
        {"the live tree": _as_stamp(live_tree())} if _stamp_speaks(source_stamp) else {})
    refusal = _family_refusal(
        source_stamp, members,
        source_who=f"source run {source_run_dir}", allow_dirty=allow_dirty).refusal
    if refusal is not None:
        raise LauncherRefused(f"[branch] {refusal}")
    rc = preflight(model, branching=True)
    if rc:
        raise LauncherRefused(
            f"[branch] the role-model preflight refused (exit {rc}) — every role a branch uses, "
            "the oracle and its verifier included, is checked at launch so a missing key or an "
            "unroutable model surfaces before anything is spent, never as a world's failure")
    return source_stamp




def _check_oracle_side(*, oracle: Any, verifier: Any) -> None:
    """Refuse a launch whose oracle `preflight_replay` could not configure: a bad oracle knob
    (`FatalConfigError`) or a role with no pricing row (`OraclePricingError`). The same
    functions pre-flight's `oracle_settings_with` and each world's `Oracle` call, so the rule
    lives once; asked here only to refuse before the questioner is paid for."""
    from defender.configuration._env import FatalConfigError
    from defender.learning.branch.estate.oracle import OraclePricingError, price_row
    from defender.learning.branch.estate.registry import oracle_serving
    from defender.learning.core.config import oracle_settings_with

    try:
        serving = oracle_serving(oracle_settings_with(), oracle=oracle, verifier=verifier)
        price_row("oracle", serving.oracle)
        price_row("verifier", serving.verifier)
    except (FatalConfigError, OraclePricingError) as bad:
        raise LauncherRefused(
            f"[branch] the oracle cannot be configured: {bad} — pre-flight would refuse it "
            "after the question-writer was paid for") from bad




def _no_stamp(source_run_dir: Path) -> LauncherRefused:
    return LauncherRefused(
        f"[branch] source run {source_run_dir} carries no usable provenance stamp — a "
        "family is anchored to the commit its source ran, and a source with no readable "
        "stamp cannot anchor one")




#: A generous ceiling on any session's message id, far beyond `DEFAULT_REQUEST_LIMIT` times the
#: messages per request. Only a sanity bound: where a store exists, the session itself decides
#: which messages may be branched from.
MAX_BRANCH_MESSAGE_ID = 100 * 60




def _check_branch_point(source: Run, branch_message_id: int) -> None:
    """Refuse a branch point the source run could not have produced."""
    source_run_dir = source.run_dir
    if branch_message_id < 0:
        raise LauncherRefused(
            f"[branch] branch message id {branch_message_id} is negative — it names a message "
            "in the source run's own session, and there is no message before the first")
    if branch_message_id > MAX_BRANCH_MESSAGE_ID:
        raise LauncherRefused(
            f"[branch] branch message id {branch_message_id} is beyond {MAX_BRANCH_MESSAGE_ID}, "
            "the most any one investigation's session could hold — no run produced a message "
            "there, so this is a typo rather than a branch point")
    store = _source_store(source)
    if store is None:
        raise LauncherRefused(
            f"[branch] {source.id} carries no session store, so it recorded no fork snapshot "
            f"for message {branch_message_id} — nothing says what it held when that response "
            "arrived, and no arm can be restored from it")
    try:
        as_of = branch.branch_point_time(store, Path(source_run_dir), branch_message_id, source_run=source)
        # An empty capture is not refused here: pre-flight records it as a `refused` episode
        # (M05=A), so the operator finds the reason in the outcome record.
        branch.validate(store, branch.BranchSpec(
            source_run_dir=Path(source_run_dir),
            branch_message_id=branch_message_id,
            as_of=as_of,
        ), source_run=source, require_capture=False)
    except branch.BranchError as bad:
        raise LauncherRefused(f"[branch] {bad}") from bad
    finally:
        store.close()




def _source_store(source: Run) -> Any:
    """The source run's own session store, or `None` when it does not carry one
    (`branch.source_store_if_any`: a pointer that does not reconcile still refuses)."""
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
    #: The capture recorded an error for it (no base answer was primed).
    failed: bool

    @property
    def entry(self) -> dict[str, Any]:
        return {"system": self.system, "verb": self.verb, "params": dict(self.params)}




def _originals(source_run_dir: Path) -> list[_Original]:
    """The source run's calls, first occurrence of each key, in capture order. Sentinels (a
    `∅.` row never reached a system) are not calls (N15)."""
    from defender.learning.branch.ledger import request_key
    from defender.learning.lead_repository import load_queries_report

    rows, _unreadable = load_queries_report(Path(source_run_dir))
    seen: set[str] = set()
    out: list[_Original] = []
    for row in rows:
        if row.is_sentinel or not row.system or not row.verb:
            continue
        key = request_key(row.system, row.verb, row.params)
        if key in seen:
            continue
        seen.add(key)
        out.append(_Original(system=row.system, verb=row.verb, params=dict(row.params),
                             failed=row.exit_code != 0))
    return out




def _not_admitted(reader: Any, call: _Original) -> str | None:
    """Why the live gather grant does not admit `call` for replay, or `None` when it does
    (M22=A: every replayed call goes through `decide`; only read verbs are replayed)."""
    from defender.runtime.verbs import GRANTED
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




def _preflight_context(episode_dir: Path, source: Run, tenant: Any, as_of: Any) -> Any:
    """The host-side context pre-flight's reads run in: the episode's tenant record, the
    family's branch-point clock, and no capture (pre-flight is not a run and writes no query
    row). `DEFENDER_RUNS_BASE` is the source run's container — the tenant's natural runs folder
    — from the source `Run`'s own hand-out, not `run_env`'s `run_dir.parent`."""
    from defender.run_common import DEFENDER_DIR, run_env
    from defender.runtime.verbs import VerbContext

    env = run_env(DEFENDER_DIR, Path(episode_dir))
    env["DEFENDER_RUNS_BASE"] = source.runs_base_export()
    return VerbContext(defender_dir=DEFENDER_DIR, run_dir=Path(episode_dir), env=env,
                       capture=None, tenant=tenant, as_of=as_of)




def preflight_replay(  # noqa: C901, PLR0912, PLR0915 — one pass: admit, refuse, read drift, calibrate, record
    episode: Episode, *, source: Run, roster: Any, tenant: RunTenant, oracle: Any = None,
    verifier: Any = None, **knobs: Any,
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
        oracle_serving,
        prebranch_calls,
        read_family_answers,
    )
    from defender.learning.branch.estate.checks import canonical_json
    from defender.learning.branch.ledger import payload_text, request_key
    from defender.learning.core.config import oracle_settings_with
    from defender.runtime.verbs import ModuleVerbRegistry

    # The reader first, unguarded: a tenant with no gather grant refuses here (`GrantError`),
    # before anything is read or sent (O-16).
    reader = ModuleVerbRegistry(roster, tenant.grants.gather, grant_home=tenant.table_pointer)
    family = _family.load_family(episode.view(), expected_episode_id=episode.dir.name)
    originals = _originals(source.run_dir)
    not_replayable: list[dict[str, Any]] = []
    replayable: list[_Original] = []
    for call in originals:
        why = _not_admitted(reader, call)
        if why is None:
            replayable.append(call)
        else:
            not_replayable.append({**call.entry, "reason": why})
    fact_worlds = [w for w in runnable_worlds(family) if w.facts]

    def record(outcome: str, reason: str, *, unservable: Sequence[Mapping[str, Any]] = (),
               drift: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
        outcome_mod.write_outcome(episode, outcome, reason=reason, unservable_worlds=unservable,
                                  not_replayable=not_replayable, drift=drift)
        return {"outcome": outcome, "reason": reason,
                "unservable_worlds": [dict(u) for u in unservable],
                "not_replayable": list(not_replayable), "drift": [dict(d) for d in drift]}

    # M05=A: nothing to calibrate, for a reason that belongs to no world — refused before any
    # tenant read or oracle turn.
    if not fact_worlds:
        return record(REFUSED, "no world of the family carries a fact, so there is no world "
                               "change to calibrate and nothing a sibling could measure")
    if not originals:
        return record(REFUSED, "the source run made no call that reached a system, so there "
                               "is no original call to replay")
    if not replayable:
        return record(REFUSED, f"none of the source run's {len(originals)} call(s) can be "
                               "replayed: the live gather grant admits none of them (see "
                               "not_replayable)")

    # The oracle's knobs, settled once for every world of the pass: `knobs` over the process's
    # knobs. Each world's serving is built from them in its own thread (`calibrate`).
    box = knobs.pop("box", None)
    restart_after = knobs.pop("restart_after", DEFAULT_RESTART_AFTER)
    settings = oracle_settings_with(**knobs)
    limiter = RateLimiter(settings.rate)
    ctx = _preflight_context(episode.dir, source, tenant, family.as_of)
    resumed = {w.label: _family.resume_world_from(family, w.label, episode.dir)
               for w in fact_worlds}
    recording = Ledger.for_world(episode, resumed[fact_worlds[0].label].world_id)
    # The family's base recording, parsed once for every world's registry.
    family_answers = read_family_answers(recording.base_path)
    # M01=A's fixed prefix, by the one rule the sibling's registry is handed too (`run.py`).
    prebranch = prebranch_calls(source, family.branch_message_id)
    # D6 (#1255): the calls the primer recorded unanswered are never fixed.
    unrecorded = recording.unrecorded_keys()

    drift: list[dict[str, Any]] = []
    calibrated: list[tuple[_Original, Any, bool, bool]] = []
    for call in replayable:
        recorded = recording.base_payload(call.system, call.verb, call.params)
        limiter.acquire()
        try:
            live_text = payload_text(reader.verbs(call.system)[call.verb](ctx, **call.params))
        except Exception:  # noqa: BLE001 — a tenant error on a drift read is drift-unknown (N16)
            if recorded is None:
                # The capture's own failure, still failing: world telemetry, passed through as
                # itself to any sibling that asks (`real-error`), never the oracle's to serve.
                continue
            drift.append({**call.entry, "status": "unknown"})
            base_text = recorded
        else:
            if recorded is None:
                drift.append({**call.entry, "status": "drifted" if call.failed else "unknown"})
                base_text = live_text
            else:
                if canonical_json(json.loads(recorded)) != canonical_json(json.loads(live_text)):
                    drift.append({**call.entry, "status": "drifted"})
                base_text = recorded
        # D6 (#1255): a pre-branch call the primer recorded unanswered is never fixed; a live
        # base is the system now, which the oracle serves as it stood at the fork.
        live = recorded is None
        key = request_key(call.system, call.verb, call.params)
        fixed = key in prebranch and key not in unrecorded
        calibrated.append((call, json.loads(base_text), fixed, live))

    stop = threading.Event()
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
                                 restart_after=restart_after)
        registry = WorldRegistry(
            roster, tenant.grants.gather, world=world, ledger=ledger, as_of=family.as_of,
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
        # Anything but a world's own failure is the launch's (it stopped every other world's
        # calibration), and leaves no outcome record: the outcome words are the family's
        # (accepted, unusable, refused), and an episode with none is never graded.
        future.result()

    unservable = sorted(failures, key=lambda entry: entry["world"])
    names = ", ".join(entry["world"] for entry in unservable)
    if len(unservable) >= outcome_mod.UNUSABLE_AT:
        return record(UNUSABLE, f"{len(unservable)} worlds failed calibration ({names}), so "
                                "the family cannot be compared (O5)",
                      unservable=unservable, drift=drift)
    reason = ("every fact world calibrated" if not unservable else
              f"world {names} failed calibration and runs no sibling; the family is graded "
              "on the rest")
    return record(ACCEPTED, reason, unservable=unservable, drift=drift)




def _stamp_of(run: Run) -> dict | None:
    """A run's own provenance record, or `None` when it has none this reader can use.

    Used for both the source and every sibling, so both ends of the comparison share one shape.
    Absent and unreadable both answer `None`: neither is an agreeing stamp.

    Read through `_provenance.read`, which refuses aliases and type-checks fields: the file is
    in a box's rw bind, and a forged `"commit": ["x"]` would otherwise crash `verify_family`
    before anything was archived. Returned as the record's wire-shape mapping, which
    `_write_family_stamp` publishes verbatim.
    """
    record = _provenance.read(run.facts.provenance.path)
    return None if record is None else _as_stamp(record)




def _as_stamp(record: _provenance.RunProvenance) -> dict:
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




#: Every `RunProvenance` field, classed by how the fork check judges it (#1204 D4). The
#: comparison below is driven by this table, and `test_1204` holds its keys to the record's
#: fields, so a new stamp field cannot be silently left out of the check.
#: - `anchored`: each member must match the source, when the source pins a value; siblings
#:   must agree with each other when it does not;
#: - `constant`: siblings must agree with each other;
#: - `dedicated`: judged by its own rule (`_clean_stamp`, `_cross_tenant_fault`);
#: - `informational`: recorded, never compared;
#: - `expected_to_differ`: differs between siblings by design.
STAMP_FIELD_CLASSES: dict[str, str] = {
    "commit": "anchored", "scope": "anchored", "knowledge": "anchored",
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
    revision = _provenance.KnowledgeRevision.from_wire(stamp.get("knowledge"))
    return None if revision is None else revision.commit




def _off_commit(who: str, got: object, want: object) -> str:
    return (f"{who} is at commit {got!r} while the source run it continues ran at {want!r} — a "
            "family is anchored to its source's commit, and a comparison against other code is "
            "never archived as comparable")




def _off_scope(who: str, got: object, want: object) -> str:
    return (f"the dirt of {who} was measured over scope {got!r} and the source's over {want!r} "
            "— the two clean bits answer different questions, so agreeing on the commit does not "
            "make them a match")




def _off_knowledge(who: str, got: object, want: object) -> str:
    return (f"{who} read tenant knowledge at commit {got!r} while the source run it continues "
            f"read {want!r} — a family is anchored to the knowledge its source read, and a "
            "comparison against other settings and lessons is never archived as comparable")




#: The rule of every held field that is more than "compare the value as recorded". An anchored
#: field must have one (its refusal text), which is held at import below, so no anchored field
#: falls back to a vague message.
_HELD_RULES: dict[str, _HeldRule] = {
    "commit": _HeldRule(compared=lambda stamp: stamp.get("commit"), off_anchor=_off_commit),
    "scope": _HeldRule(compared=lambda stamp: stamp.get("scope"), off_anchor=_off_scope),
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
    """Every reason `members` are not provably one family continuing `source`."""
    faults: list[_Fault] = []
    anchored = _stamp_speaks(source)
    if not anchored:
        faults.append(_Fault(None, (
            f"{source_who} names no commit (unavailable={source.get('unavailable')!r}) — a "
            "family is anchored to the commit its source ran, and there is none to anchor to")))
    else:
        if not _clean_stamp(source):
            faults.append(_Fault(DIRT, _not_certified_clean(source_who, source)))
        faults.extend(_unknown_faults(source_who, source))
    for who, stamp in members.items():
        faults.extend(_member_faults(who, stamp, anchor=source if anchored else None))
    # Agreement is over every stamp that names a commit, dirty ones included: excluding dirty
    # arms would let `--allow-dirty` waive the whole agreement, since siblings share one
    # checkout and are all dirty together.
    comparable = {who: stamp for who, stamp in members.items()
                  if stamp is not None and _stamp_speaks(stamp)}
    for field, rule in _HELD.items():
        # A field the anchor pinned was compared member by member above.
        if anchored and field in _ANCHORED and rule.compared(source) is not None:
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




def _member_faults(who: str, stamp: dict | None, *, anchor: dict | None) -> list[_Fault]:
    """One tree's faults against the anchor. `anchor` is `None` when the source could not
    anchor (already reported); the tree is then judged on its own stamp alone."""
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
        want = None if anchor is None else rule.compared(anchor)
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
    revision = _provenance.KnowledgeRevision.from_wire(stamp.get(field))
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
