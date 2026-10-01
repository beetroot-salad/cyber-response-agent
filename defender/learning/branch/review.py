"""Review by replay: what the estate says now, against what the capture recorded.

The one gate between staging and the first sibling process. It answers two questions per world
and records both.

**Does this world contradict the corpus?** The captured query set is replayed through the
world's staging and each answer compared to the recording. The base world is replayed first as
the control; the keys it mismatches on are drift, subtracted from every other world's result,
so what remains is a difference the world made. Anything beyond `formatting` is a
contradiction, and one contradiction rejects the whole episode before anything runs.

**Is the declared difference observable?** The manifest's discriminating envelope is run in the
world; an injection nothing retrieves, a patch that applies to nothing, or an exclusion that
removes no base document means the world is not what it claims.

The replay reads through a scratch ledger with an empty base, outside the episode. The serving
path answers from the primed capture before calling any adapter (`estate/registry.py`'s
`_base_payload`), so replaying through the episode's own ledger would compare the capture with
itself. The episode's `served/` gains no row, and the verb context has no capture recorder.

The review asks the estate nothing beyond those two questions, since every extra call is one
the base run never made: an entity in no captured row is recorded as an invention rather than
chased, and the exclusion count goes through the staging door, whose `_count` is kept off the
adapter allowlist.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import tempfile
from collections.abc import Iterator, Sequence
from defender._model import model
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import SkipValidation

from defender._io import read_jsonl_rows, read_jsonl_rows_report
from defender.run_common import DEFENDER_DIR, run_env
from defender.runtime.branch._family import (
    BASE_ROLE,
    ElasticEntry,
    Family,
    World,
    episode_token_for,
    resume_world_from,
    runnable_worlds,
)
from defender.runtime.verbs import VerbContext

from .comparator import Verdict, compare, mechanical
from .estate.applier import WorldApplier
from .estate.lookups import apply_patches
from .estate.registry import refuse_a_foreign_world_view
from .estate.stagers.dispatch import STAGERS
from defender._episode_handle import Episode

from .ledger import (
    BASE,
    Ledger,
    ServedCall,
    base_file,
    correlation_key_of,
    payload_text,
)
from .staging import INJECT_SUFFIX as _staging_inject_suffix

#: The suffix staging gives a world's injection index. Imported from staging, which builds the
#: names: a count asked of a name staging did not write answers zero and rejects the world.
#: Re-exported for the review's consumers.
INJECT_SUFFIX = _staging_inject_suffix

#: The two decisions a world or an episode can carry.
ACCEPTED = "accepted"
REJECTED = "rejected"


class ReviewError(Exception):
    """A review that cannot be honestly completed.

    Never raised for what the estate said (contradictions, unreachable differences and faulted
    calls are recorded readings), only for the frame itself failing. The launcher exits
    differently: a rejected episode is a measurement, a broken review is not.
    """


# ---------------------------------------------------------------------------------------
# the replay's own seams
# ---------------------------------------------------------------------------------------


class ScratchLedger(Ledger):
    """A `Ledger` over an empty base, so every captured key reaches the estate rather than
    answering from the recording.

    `base_payload` also accepts a single correlation key, since a reviewer holds keys where the
    serving path holds calls.
    """

    def base_payload(self, *key: Any) -> str | None:
        """The recorded answer for a correlation key, or for `(system, verb, params)`."""
        if len(key) == 1:
            return self._memo.get(str(key[0]))
        return super().base_payload(*key)

    def base_rows(self) -> Iterator[dict]:
        """Every row in the base this ledger reads through — none, by construction."""
        yield from read_jsonl_rows(self.base_path)


def scratch_ledger(scratch: Episode, *, world_label: str = "review") -> ScratchLedger:
    """A ledger for the replay: this world's own rows over a base file that holds nothing.

    `scratch` is the review's own scratch episode, outside the episode under review, because
    that episode's `served/` is the family's recording and the replay is not part of it. One
    scratch serves every world of a review: each world gets its own file over the one base.
    """
    # Created empty (once; a later world finds it): `Ledger.__post_init__` refuses a missing
    # base, and that refusal should keep meaning what it means for a real run.
    with contextlib.suppress(FileExistsError):
        scratch.served_base.create("")
    book = ScratchLedger.for_world(scratch, world_label)
    if any(book.base_rows()):
        # A base holding rows (the episode's capture, or a reused scratch tree) would answer every
        # captured key from the recording and the review would agree with itself.
        raise ReviewError(
            f"the replay's base at {book.base_path} holds rows — a review reads through an "
            "EMPTY base so that every captured key reaches the estate; a base with a recording "
            "in it makes the replay agree with itself and proves nothing")
    return book


def verb_context(episode_dir: Path, tenant: Any, *, runs_base: Path) -> VerbContext:
    """The host-side context the replay's adapter calls run under.

    `tenant` is the EPISODE's tenant record (#1107) — the source run's tenant, resolved by the
    launcher and handed down; the replay's adapters read that record's systems, corpus-engine
    view and secrets and nothing they find for themselves. `capture` is `None`: a review is not
    a run, so it writes no `executed_queries.jsonl` row.

    `DEFENDER_RUNS_BASE` is set explicitly to `runs_base`, the episode tenant's runs base the
    launcher threads down: `run_common.run_env` sets it to `run_dir.parent`, which for an
    episode dir is the episodes root, not a runs base.
    """
    episode_dir = Path(episode_dir)
    env = run_env(DEFENDER_DIR, episode_dir)
    env["DEFENDER_RUNS_BASE"] = str(runs_base)
    return VerbContext(
        defender_dir=DEFENDER_DIR, run_dir=episode_dir, env=env, capture=None, tenant=tenant)


@model(frozen=True)
class Replay:
    """One replayed call: the payload the world would have been served, and its canonical text.

    Reachability walks the payload and the comparison reads the text; carrying both avoids
    re-dumping one into a different spelling of the same answer.
    """

    payload: Any
    text: str


def replay_one(call: tuple[str, str, dict], *, episode_dir: Path, adapters: Any,
               world: Any = None, applier: Any = None, ledger: Any = None,
               ctx: Any = None, captured: str | None = None) -> Replay:
    """Ask one call again, as `world` would have asked it, and hand back what came back.

    The serving path's shape, host-side: stage the call onto the world's corpus, take the base
    answer, then apply the world's difference to it. `world is None` is the bare replay.

    During the review, `captured` supplies the base answer and the adapter is never reached:
    re-asking would measure the estate's drift since the source run rather than the world's
    difference. A captured payload never carried a world's corpus identity, so nothing needs
    restoring. The adapter arm serves only the discriminating envelope, the one question the
    capture does not hold.

    The foreign-world-view refusal runs first, as in `serve_one` and `WorldRegistry._served`.
    The envelope is model-authored, and checking before `prepare` refuses a hand-named sibling
    view before a stager can rewrite it or the adapter is reached — reachable via the control,
    which stages nothing and passes params straight through.
    """
    system, verb, params = call
    if world is not None and ctx is None:
        # The world arm stages and restores through the context (its tenant's patterns and
        # config), which cannot be built here without the episode's tenant.
        raise TypeError("replay_one(world=…) needs the review's verb context (`ctx=`)")
    if world is not None:
        refuse_a_foreign_world_view(world, system, verb, params, ctx)
    context = ctx
    if ledger is None:
        # A replay of its own: a scratch episode for this one call, removed with it.
        with tempfile.TemporaryDirectory(
                prefix=f"defender-review-{Path(episode_dir).name}-") as tmp, \
                Episode.create(Path(tmp) / "scratch") as scratch:
            return replay_one(call, episode_dir=episode_dir, adapters=adapters, world=world,
                              applier=applier, ledger=scratch_ledger(scratch), ctx=ctx,
                              captured=captured)
    book = ledger
    prepared = dict(params) if world is None else applier.prepare(
        system, verb, dict(params), world, context)
    asked = dict(params) if prepared != params else None
    recorded = captured if captured is not None else book.base_payload(system, verb, prepared)
    if recorded is None:
        served = adapters(system, verb, **prepared)
        restored = served if asked is None else applier.restore(
            system, verb, served, asked, prepared, context)
        recorded = payload_text(restored)
        book.record(ServedCall(
            system=system, verb=verb, params=dict(prepared), payload_text=recorded,
            source=BASE, world_id=None, asked_params=asked))
    payload = json.loads(recorded)
    if world is None:
        # lint-parse: ok — `Replay.payload` is the adapter's untyped answer, declared `Any` since
        # no shape is shared across systems; the canonical text is narrowed by `payload_text`.
        return Replay(payload=payload, text=recorded)
    _decision, applied = applier.apply(system, verb, prepared, payload, world, asked)
    # lint-parse: ok — same seam, same reason as the arm above.
    return Replay(payload=applied, text=payload_text(applied))


# ---------------------------------------------------------------------------------------
# the review
# ---------------------------------------------------------------------------------------


def review(family: Family, *, episode: Episode, adapters: Any, door: Any,  # noqa: PLR0913 — the review's injected estate plus the episode's tenant folder and runs base
           invoke: Any, tenant: Any, runs_base: Path, write: Any = None) -> dict:
    """Replay the capture through every world, judge each, and write `review.yaml`.

    The control runs first, since every other world's mismatches are measured against its drift.

    `adapters` is the estate's read side, `door` the host-side staging door (the only thing
    that may count), and `invoke` the model seam the comparator calls at most once per
    undecided key. None has a default: a default would be a second opinion about which estate
    the episode was reviewed against. `write` is the whole-record write seam, injectable so
    tests can observe the single write. `tenant` is the episode's tenant record (#1107),
    carried by the replay's verb context so every staged read resolves that tenant's config.
    """
    write = write if write is not None else episode.review.write  # lint-default: ok — DI seam owning its own default
    episode_dir = episode.dir
    rows, unreadable = read_jsonl_rows_report(base_file(episode_dir))
    context = verb_context(episode_dir, tenant, runs_base=runs_base)
    token = episode_token_for(family.episode_id)
    drifted = frozenset(_capture_drift(rows))
    # The temp dir is named after the episode so a leaked one is diagnosable.
    scratch_root = Path(tempfile.mkdtemp(prefix=f"defender-review-{episode_dir.name}-"))
    try:
        with Episode.create(scratch_root / "scratch") as scratch:
            worlds: dict[str, dict] = {}
            control: list[str] = []
            deps = _Deps(adapters=adapters, door=door, invoke=invoke, ctx=context,
                         scratch=scratch, token=token, drifted=drifted, captured_rows=rows,
                         base_memo={})
            for world in _control_first(family):
                result = _review_world(
                    world, family=family, episode_dir=episode_dir, rows=rows, control=control,
                    deps=deps)
                if world.role == BASE_ROLE:
                    control = list(result["consistency"]["control_mismatch_keys"])
                worlds[world.world_id] = result
    finally:
        # The scratch rows are review reads, not run evidence; left behind they would look like
        # an episode's `served/` somewhere no reader expects one.
        shutil.rmtree(scratch_root, ignore_errors=True)
    record = _record(family, worlds=worlds, unreadable=unreadable)
    write(yaml.safe_dump(record, sort_keys=False, allow_unicode=True, default_flow_style=False))
    return record


@model(frozen=True)
class _Deps:
    """One world's collaborators, threaded as a value rather than as six parameters."""

    adapters: Any
    door: Any
    invoke: Any
    ctx: Any
    #: The review's one scratch `Episode`, every world's replay ledger in it.
    scratch: Any
    token: str
    #: The keys the capture itself answers two ways — episode-wide, so derived once.
    drifted: frozenset[str]
    #: Every captured row, read once per review. `SkipValidation`: validating would only
    #: rebuild every row without checking anything inside it.
    captured_rows: Annotated[Sequence[dict], SkipValidation]
    #: Base-arm memo, `(system, verb, canonical(params))` -> canonical text, episode-scoped so a
    #: key re-asked by several worlds is read once. Successes only, so a faulted read is retried
    #: for the next world.
    base_memo: dict[str, str]


def _control_first(family: Family) -> list[World]:
    """The runnable worlds with the base world at the head.

    Order matters: every later world is measured against the control's mismatch set, and the
    record is written in computation order.
    """
    # Only the worlds the launcher stages and runs: `runnable_worlds` drops the `role: null`
    # replicate arm, which has no staged corpus and would be rejected as unreachable, ending the
    # whole episode.
    runnable = runnable_worlds(family)
    base = [w for w in runnable if w.role == BASE_ROLE]
    return base + [w for w in runnable if w.role != BASE_ROLE]


def _review_world(world: World, *, family: Family, episode_dir: Path, rows: Sequence[dict],
                  control: Sequence[str], deps: _Deps) -> dict:
    """One world's whole result: consistency, reachability, inventions and the decision."""
    resumed = resume_world_from(family, world.world_id, episode_dir)
    # No `patches=`: `WorldApplier.patch_table` reads the world's own overlay, so a table passed
    # here would be an unconsulted second copy. The sibling path (`run.py`) builds it bare too.
    applier = WorldApplier()
    ledger = scratch_ledger(deps.scratch, world_label=world.world_id)
    is_control = world.role == BASE_ROLE

    def replay(call: tuple[str, str, dict], captured: str | None = None) -> Replay:
        return replay_one(call, episode_dir=episode_dir, adapters=deps.adapters,
                          world=resumed, applier=applier, ledger=ledger, ctx=deps.ctx,
                          captured=captured)

    consistency = _consistency(rows, replay=replay, control=control, is_control=is_control,
                               invoke=deps.invoke, drifted=deps.drifted)
    reachability = _reachability(world, family=family, replay=replay, deps=deps,
                                 is_control=is_control, resumed=resumed, applier=applier)
    inventions = _inventions(world, rows=rows, reachability=reachability)
    reason = _rejection(world, consistency=consistency, reachability=reachability)
    result: dict[str, Any] = {
        "role": world.role,
        "world_token": resumed.token,
        "consistency": consistency,
        "reachability": reachability,
        "inventions": inventions,
        "decision": REJECTED if reason is not None else ACCEPTED,
    }
    if reason is not None:
        result["reason"] = reason
    return result


# ---------------------------------------------------------------------------------------
# consistency: drift, contradiction and the control
# ---------------------------------------------------------------------------------------


def _consistency(rows: Sequence[dict], *, replay: Any, control: Sequence[str],
                 is_control: bool, invoke: Any, drifted: frozenset[str]) -> dict:
    """Replay every captured call in this world and classify what came back.

    Keys the control also mismatches on are shared drift and are subtracted; what remains is a
    difference this world made. A fault is recorded in its own class and never reaches the
    comparator — it is the harness, not a contradiction. No adapter is reached: each answer is
    the world's difference applied to the captured payload.
    """
    replayed: list[dict] = []
    mismatches: list[dict] = []
    faults: list[dict] = []
    drift: list[str] = []
    for row in rows:
        # `correlation_key_of`, never `row.get("correlation_key")`: the key is a property of
        # `ServedCall`, not a written column. Shared with `episode._pair_key`.
        derived = correlation_key_of(row)
        captured = row.get("payload_text")
        call = (str(row.get("system")), str(row.get("verb")), dict(row.get("params") or {}))
        if derived is None:
            faults.append({"key": None,
                           "detail": "the captured row names no call, so it pairs with nothing"})
            continue
        key = derived
        if not isinstance(captured, str):
            faults.append({"key": key, "detail": "the captured row carries no payload text"})
            continue
        try:
            answer = replay(call, captured)
        except Exception as fault:  # noqa: BLE001 — every estate fault is a reading, not a raise
            faults.append({"key": key, "detail": str(fault) or type(fault).__name__})
            continue
        replayed.append({"key": key})
        # The comparator is outside the handler above: a wrong-seat verdict is not an estate
        # fault and must abort the episode, not be recorded as unreadable.
        outcome = _row_outcome(key, captured, answer.text, drifted=drifted, control=control,
                               is_control=is_control, invoke=invoke)
        if outcome is None:
            continue
        if outcome is DRIFT:
            if is_control and key not in drift:
                drift.append(key)
            continue
        mismatches.append({"key": key, "verdict": outcome.value})
    return {
        "replayed": replayed,
        "mismatches": mismatches,
        "control_mismatch_keys": drift if is_control else list(control),
        "faults": faults,
    }


#: "This key is the episode's drift, not this world's difference." A sentinel rather than a
#: `Verdict` member, because `Verdict` is what a model may answer and this is the review's own
#: reading.
DRIFT = object()


def _row_outcome(key: str, captured: str, replayed: str, *, drifted: frozenset[str],
                 control: Sequence[str], is_control: bool, invoke: Any) -> Any:
    """How one replayed row stands to its capture: agreed (`None`), `DRIFT`, or a verdict.

    A key the capture answers two ways is drift, shared by every world. The control never
    reaches the comparator: it applies nothing, so any difference it shows is drift by
    definition.
    """
    if key in drifted:
        return DRIFT
    verdict = mechanical(captured, replayed)
    if verdict is None and not is_control and key not in control:
        # The model's verdict goes through the same checks below: `compare` may answer `same`,
        # which must not be recorded as a mismatch.
        verdict = compare(captured, replayed, None, invoke=invoke)
    if verdict is Verdict.SAME:
        return None
    if is_control:
        return DRIFT
    if key in control:
        return None
    return verdict


def _capture_drift(rows: Sequence[dict]) -> set[str]:
    """The correlation keys the capture itself answers two different ways.

    Such a key's truth moved while the evidence was gathered — a fact about the episode, not any
    world, so it is subtracted from every world. Every later row is compared against the first.
    """
    first: dict[str, str] = {}
    drifted: set[str] = set()
    for row in rows:
        key = correlation_key_of(row)
        text = row.get("payload_text")
        if key is None or not isinstance(text, str):
            continue
        if key not in first:
            first[key] = text
        elif mechanical(first[key], text) is not Verdict.SAME:
            drifted.add(key)
    return drifted


# ---------------------------------------------------------------------------------------
# reachability
# ---------------------------------------------------------------------------------------


def _reachability(world: World, *, family: Family, replay: Any, deps: _Deps,
                  is_control: bool, resumed: Any = None, applier: Any = None) -> dict:
    """Is the difference this world declares observable in this world?

    The manifest's discriminating envelope is run in the world: an injection is reachable if
    the envelope retrieves it, a patch is visible if it applies to what the envelope returned,
    and an exclusion is real if it removes at least one base document.

    `envelope_ran` means rows came back; an envelope that faulted or retrieved nothing measured
    nothing, and must not reject a world for a quiet corpus. `envelope_failed` records whether it
    raised, so "not observable" and "measured nothing" stay distinguishable; it does not reject
    on its own, since an outage is the harness's fault.

    Every world but the control also gets the capture re-ask fields (`capture_replays`,
    `capture_addressed`, `capture_reasks_faulted`, `reachable_by_capture`); the control declares
    no difference to reach.
    """
    envelope = _envelope(family)
    rows: list[dict] = []
    ran = False
    faulted: str | None = None
    if envelope is not None:
        try:
            payload = replay(envelope).payload
        except Exception as fault:  # noqa: BLE001 — a faulted envelope is "nothing was measured"
            payload = None
            faulted = str(fault) or type(fault).__name__
        rows = _rows_of(payload)
        ran = bool(rows)
    retrieved, present = _injected_counts(world, rows=rows)
    matched, failed, total = _exclusion_matches(world, deps=deps)
    block: dict[str, Any] = {
        "envelope_ran": ran,
        "envelope_failed": faulted,
        "injected_retrieved": retrieved,
        "injected_present": present,
        "patched_visible": _patched_visible(world, rows=rows),
        "exclusion_matches": matched,
        "exclusion_count_failed": failed,
        "base_documents": total,
    }
    if not is_control:
        block.update(_capture_reachability(
            world, deps=deps, resumed=resumed, applier=applier))
    return block


def _addressing_patterns(world: World) -> frozenset[str]:
    """This world's own staged corpus patterns — what a captured row's `source_pattern` must
    equal for the pattern arm of `capture_addressed` to fire."""
    return frozenset(pattern for pattern, _entry in _elastic_entries(world))


def _addressed(call: tuple[str, str, dict], *, world: World, ctx: Any,
               staged: frozenset[str]) -> bool:
    """Does this captured call name a pattern this world stages, or a system it patches?

    The patched-system arm matters: a patch-only world stages no pattern, and without it would
    read as unaddressed and have its defender findings withheld under a false reason. `staged`
    is `_addressing_patterns(world)`, resolved once by the caller.
    """
    system, verb, params = call
    if system in world.overlay.patches:
        return True
    stager = STAGERS.get(system)
    if stager is None:
        return False
    try:
        pattern = stager.source_pattern(verb, dict(params), ctx)
    except Exception:  # noqa: BLE001 — an unreadable call names no pattern to be addressed by
        return False
    return pattern is not None and pattern in staged


def _capture_reachability(world: World, *, deps: _Deps, resumed: Any, applier: Any) -> dict:
    """Re-ask the capture's own queries live, and record what the re-ask measured.

    Rows are selected by `_addressed`. For each: the base arm (un-rewritten params, through the
    episode memo) and the world arm (`_world_arm`, with staging/patching and the foreign-view
    refusal, never memoised). An apparent difference is confirmed by re-reading the world arm
    before it is recorded.
    """
    staged = _addressing_patterns(world)
    selected: list[tuple[str, str, dict, str | None]] = []
    for row in deps.captured_rows:
        call = (str(row.get("system")), str(row.get("verb")), dict(row.get("params") or {}))
        if _addressed(call, world=world, ctx=deps.ctx, staged=staged):
            selected.append((*call, correlation_key_of(row)))
    addressed = bool(selected)
    # One read side per world, not per call: the registry is shared and only the world
    # declaration differs.
    read = deps.adapters.for_world(resumed.world_id)
    replays: list[dict] = []
    faulted_count = 0
    any_differs = False
    any_completed = False
    for system, verb, params, key in selected:
        call = (system, verb, params)
        differs, faulted = _one_reask(call, world=resumed, applier=applier, deps=deps,
                                      read=read)
        if faulted:
            faulted_count += 1
        else:
            any_completed = True
            if differs:
                any_differs = True
        replays.append({"key": key, "differs": differs, "faulted": faulted})
    reachable: bool | None
    if not addressed:
        reachable = None
    elif any_differs:
        reachable = True
    elif any_completed:
        reachable = False
    else:
        reachable = None
    return {
        "capture_replays": replays,
        "capture_addressed": addressed,
        "capture_reasks_faulted": faulted_count,
        "reachable_by_capture": reachable,
    }


def _base_arm(call: tuple[str, str, dict], *, deps: _Deps) -> str | None:
    """The base arm: un-rewritten capture params via `deps.adapters`, read once per key.

    Only successes are memoised, so a faulted read is retried for the next world. The memo key
    and `payload_text` dumps are inside the `try` too: `json.dumps(sort_keys=True)` raises
    `TypeError` on non-comparable mapping keys, and nothing up to `review()` catches it, so an
    escape would abort the episode after staging with no `review.yaml` written.
    """
    system, verb, params = call
    try:
        memo_key = json.dumps([system, verb, params], sort_keys=True, default=str)
        cached = deps.base_memo.get(memo_key)
        if cached is not None:
            return cached
        payload = deps.adapters(system, verb, **params)
        text = payload_text(payload)
    except Exception:  # noqa: BLE001 — an unanswerable base arm is a faulted re-ask, not a raise
        return None
    deps.base_memo[memo_key] = text
    return text


def _world_arm(call: tuple[str, str, dict], *, world: Any, applier: Any, deps: _Deps,
               read: Any) -> str:
    """One uncached live read of `call` as this world would answer it.

    `read` must be this world's own read side (`EpisodeAdapters.for_world`), never
    `deps.adapters`: staging retargets the call at a `wv-` alias that `confine_index` admits
    only from a context declaring the world.

    Not `replay_one`, whose scratch ledger memoises answers and would make the confirming
    re-read look at the same cached bytes. The foreign-view refusal and prepare/restore/apply
    order are otherwise the same.
    """
    system, verb, params = call
    refuse_a_foreign_world_view(world, system, verb, params, deps.ctx)
    prepared = applier.prepare(system, verb, dict(params), world, deps.ctx)
    asked = dict(params) if prepared != params else None
    served = read(system, verb, **prepared)
    restored = served if asked is None else applier.restore(
        system, verb, served, asked, prepared, deps.ctx)
    _decision, applied = applier.apply(system, verb, prepared, restored, world, asked)
    return payload_text(applied)


def _differs(base_text: str, other_text: str) -> bool:
    """Differs beyond formatting: `SAME`/`FORMATTING` is `False`, anything else — including the
    undecided `None`, which `mechanical` returns for some genuine content differences — is
    `True`. There is no model seat here, so the confirming re-read is the only check on it."""
    verdict = mechanical(base_text, other_text)
    return verdict not in (Verdict.SAME, Verdict.FORMATTING)


def _one_reask(call: tuple[str, str, dict], *, world: Any, applier: Any,
              deps: _Deps, read: Any) -> tuple[bool | None, bool]:
    """`(differs, faulted)` for one captured call, with a confirming re-read.

    `differs` is `None` whenever `faulted` is `True`: a faulted arm measured nothing and must
    not read as "no difference". A faulted arm never reaches `mechanical`, which raises on
    `None`.

    The confirming re-read fires only when the arms appear to differ, and re-reads the world arm
    alone (the memoised base arm cannot be the skew). A difference that survives both reads is
    recorded; one that does not is skew. The comparison is inside the `try` too, since
    `mechanical` can raise on unparseable text or lone surrogates and nothing above catches it.
    """
    base_text = _base_arm(call, deps=deps)
    if base_text is None:
        return None, True
    try:
        world_text = _world_arm(call, world=world, applier=applier, deps=deps, read=read)
        differing = _differs(base_text, world_text)
    except Exception:  # noqa: BLE001 — a refused, faulted or unmeasurable world arm is a faulted re-ask
        return None, True
    if not differing:
        return False, False
    try:
        confirming = _world_arm(call, world=world, applier=applier, deps=deps, read=read)
        return _differs(base_text, confirming), False
    except Exception:  # noqa: BLE001 — the re-read itself faulting is still a faulted re-ask
        return None, True


def _envelope(family: Family) -> tuple[str, str, dict] | None:
    """The discriminator's envelope as a call, or `None` when the manifest carries none."""
    envelope = family.discriminator.get("envelope")
    if not isinstance(envelope, dict):
        return None
    system, verb = envelope.get("system"), envelope.get("verb")
    params = envelope.get("params")
    if not isinstance(system, str) or not isinstance(verb, str) or not isinstance(params, dict):
        return None
    return system, verb, dict(params)


def _rows_of(payload: Any) -> list[dict]:
    """The documents a payload carries, whatever the verb spelled them.

    Recognised: a flat `hits` list, nested `hits.hits`, and tabular `rows`/`values`. Anything
    else contributes no rows ("nothing retrieved"), which never rejects a world on its own.

    Tabular rows may be positional (the ES|QL payload leaves `values` as bare arrays keyed by
    `columns`), so they are bound to column names here; filtering for dicts would drop every
    ES|QL row and silently accept worlds whose difference is unreachable.
    """
    if not isinstance(payload, dict):
        return []
    for field_name in ("hits", "rows", "values", "documents"):
        found = payload.get(field_name)
        if isinstance(found, dict):
            found = found.get("hits")
        if not isinstance(found, list):
            continue
        bound = _bound_rows(found, payload.get("columns"))
        return bound if bound is not None else [r for r in found if isinstance(r, dict)]
    return []


def _bound_rows(rows: list, columns: Any) -> list[dict] | None:
    """Positional rows bound to their column names, or `None` when this is not that shape.

    `None` rather than `[]` so the mapping-shaped fallback still applies. A row whose length
    differs from the header binds what the two share: a truncated row is still a retrieval.
    """
    if not isinstance(columns, list) or not columns:
        return None
    names = [c.get("name") if isinstance(c, dict) else c for c in columns]
    if any(not isinstance(n, str) for n in names):
        return None
    positional = [r for r in rows if isinstance(r, (list, tuple))]
    if not positional:
        return None
    return [dict(zip(names, row, strict=False)) for row in positional]


def _elastic_entries(world: World) -> list[tuple[str, ElasticEntry]]:
    """This world's staged patterns, in a stable order."""
    return sorted(world.overlay.elastic.items())  # lint-shippable: ok — the manifest schema's own field name, owned by `runtime/branch/_family.Overlay`  # noqa: E501


def _injected_counts(world: World, *, rows: Sequence[dict]) -> tuple[int, int]:
    """`(injected_retrieved, injected_present)`.

    `injected_retrieved` is the envelope's own hits on injected documents; `injected_present`
    is the overlay's declared injection size — a size fact, never a reachability one. Kept apart
    so size cannot stand in for reach; neither gates a world on its own.
    """
    retrieved = 0
    present = 0
    for _pattern, entry in _elastic_entries(world):
        if not entry.inject:
            continue
        retrieved += _hit_count(entry, rows)
        present += len(entry.inject)
    return retrieved, present


def _hit_count(entry: ElasticEntry, rows: Sequence[dict]) -> int:
    """How many retrieved rows are one of this entry's injected documents.

    Matched on `_id`, or on the document's body being wholly contained in the row (ids are not
    required by the schema). Model-authored documents are not validated inside, so a
    non-scalar `_id` (unhashable) and an empty document (vacuously matches every row) are
    skipped rather than matched or refused.
    """
    # As strings: `create_index` puts the doc at `str(doc_id)` and the cluster answers `_id` as
    # text, so a YAML `_id: 1` must still match `"1"`.
    ids = {str(doc["_id"]) for doc in entry.inject
           if isinstance(doc.get("_id"), (str, int, float))}
    # Every document's body, `_id` removed — not only id-less ones: the search verb's `hits` come
    # from `_source` alone and carry no `_id`, so the body is often the only witness. Empty
    # bodies are dropped because `all(...)` over nothing is vacuously true.
    bodies = [body for body in
              ({k: v for k, v in doc.items() if k != "_id"} for doc in entry.inject) if body]
    hits = 0
    for row in rows:
        row_id = row.get("_id")
        matched = isinstance(row_id, (str, int, float)) and str(row_id) in ids
        if matched or any(
                all(row.get(k) == v for k, v in body.items()) for body in bodies):
            hits += 1
    return hits


def _patched_visible(world: World, *, rows: Sequence[dict]) -> bool:
    """Does this world's patch table apply to anything the envelope returned?

    Uses the applier's own apply count rather than a second matcher, so "lands" has one meaning.
    """
    if not world.overlay.patches:
        return False
    total = 0
    for _system, table in sorted(world.overlay.patches.items()):
        _payload, applied = apply_patches({"rows": list(rows)}, dict(table))
        total += applied
    return total > 0


def _exclusion_matches(world: World, *, deps: _Deps) -> tuple[int | None, bool, int | None]:
    """How many base documents this world's exclusions remove, out of how many, and whether the
    count failed.

    Counted through the host-side staging door, since `_count` must stay off the model-reachable
    adapter allowlist. A failed count is `None` with the flag set, never `0`: a zero count
    rejects the world, and an outage must not.
    """
    declared = [(pattern, entry) for pattern, entry in _elastic_entries(world)
                if entry.exclude is not None]
    if not declared:
        return None, False, None
    removed = 0
    total = 0
    for pattern, entry in declared:
        try:
            indices = deps.door.resolve(pattern)
        except Exception:  # noqa: BLE001 — an unanswerable count is unknown, never zero
            return None, True, None
        if not indices:
            # No index to count is unknown, not zero: a zero count would reject the world for an
            # exclusion never shown to remove nothing.
            return None, True, None
        for index in indices:
            matched = _counted(deps.door, index, query=entry.exclude)
            held = _counted(deps.door, index)
            if matched is None or held is None:
                return None, True, None
            removed += matched
            total += held
    return removed, False, total


def _counted(door: Any, index: str, *, query: Any = None) -> int | None:
    """One count through the door, or `None` ("not measured") when it could not answer, so
    one failed count doesn't abort a review holding real findings for other worlds."""
    try:
        return int(door.count(index, query=query))
    except Exception:  # noqa: BLE001 — an unanswerable count is "not measured", not a failure
        return None


# ---------------------------------------------------------------------------------------
# inventions and the decision
# ---------------------------------------------------------------------------------------


def _inventions(world: World, *, rows: Sequence[dict], reachability: dict) -> list[str]:
    """What this world asserts that nothing in the capture or the estate holds.

    Recorded only, never a rejection: asserting unseen entities is much of what a
    counterfactual is. For patched entities the capture is the only evidence (the review may not
    ask the adapter new questions). A full-match exclusion — a world that is only its own
    injection — is recorded here too, as implausible but not rejected.
    """
    notes: list[str] = []
    # Scanned per entity with `any(...)` rather than joining the capture (tens of KB per
    # payload) into one string per world.
    for system, table in sorted(world.overlay.patches.items()):
        for entity in sorted(table):
            if not any(entity in str(row.get("payload_text") or "") for row in rows):
                notes.append(
                    f"{system}: entity {entity!r} appears in no captured row and no host-side "
                    "count holds a document for it — this overlay invents it")
    matched = reachability.get("exclusion_matches")
    if isinstance(matched, int) and matched and matched >= _base_total(reachability):
        notes.append(
            f"the exclusion removes all {matched} base documents the count reached, so this "
            "overlay is only its own injection — recorded, not rejected")
    return notes


def _base_total(reachability: dict) -> int:
    """The document total a full-match exclusion is recognised against.

    The unfiltered count over the same indices, so "removes everything" is `matched == total`
    however the predicate is spelled.
    """
    total = reachability.get("base_documents")
    return int(total) if isinstance(total, int) else 0


def _rejection(world: World, *, consistency: dict, reachability: dict) -> str | None:
    """Why this world may not run, or `None`.

    Three reasons only: a contradiction, a patch that applies to nothing the envelope returned,
    and an exclusion that removes no base document. Injection counts and `reachable_by_capture`
    are recorded for later readers but do not reject. Drift, faults, inventions and unanswerable
    counts are recorded and change nothing.
    """
    contradicting = [m["key"] for m in consistency["mismatches"]
                     if m["verdict"] == Verdict.CONTRADICTION.value]
    if contradicting:
        return (f"the replayed answer for {contradicting[0]!r} contradicts the capture, and a "
                "world that contradicts the corpus is not a counterfactual of it")
    matched = reachability["exclusion_matches"]
    if matched == 0 and not reachability["exclusion_count_failed"]:
        return ("this overlay's exclusion matches zero base documents, so its declared "
                "difference removes nothing")
    if not reachability["envelope_ran"]:
        return None
    if world.overlay.patches and not reachability["patched_visible"]:
        return ("this overlay's patches apply to nothing the discriminating envelope returned "
                "— the difference is unreachable")
    return None


def _record(family: Family, *, worlds: dict[str, dict], unreadable: int) -> dict:
    """The whole review document, episode half first.

    `unreadable_capture_rows` is episode-level: unparseable rows are skipped, so the control's
    mismatch set is under-counted by them, and recording the count shows the measurement was
    partial.
    """
    rejected = [wid for wid, result in worlds.items() if result["decision"] == REJECTED]
    reason = None
    if rejected:
        first = worlds[rejected[0]]
        reason = f"world {rejected[0]!r}: {first.get('reason')}"
    return {
        "episode": {
            "episode_id": family.episode_id,
            "decision": REJECTED if rejected else ACCEPTED,
            "outcome": (f"{len(worlds)} worlds reviewed, {len(rejected)} rejected"
                        if rejected else f"{len(worlds)} worlds reviewed, none rejected"),
            "reason": reason,
            "unreadable_capture_rows": unreadable,
        },
        "worlds": worlds,
    }


__all__ = [
    "ACCEPTED",
    "INJECT_SUFFIX",
    "REJECTED",
    "Replay",
    "ReviewError",
    "ScratchLedger",
    "replay_one",
    "review",
    "scratch_ledger",
    "verb_context",
]
