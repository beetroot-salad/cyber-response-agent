"""Review by replay: what the estate says now, against what the capture recorded (#947 M4).

Between staging and the first sibling process there is one gate, and this is it. It answers two
questions per world and writes both answers down.

**Does this world contradict the corpus?** The captured query set is replayed through the
world's own staging, and each answer is compared to the recording. World A — the base, role
`A` — is replayed FIRST, as the CONTROL: the keys it mismatches on are the estate's own drift
between the source run and now, and they are subtracted from every other world's result. What
is left for B and C is a difference the world made. One that is not merely `formatting` is a
contradiction, and one contradiction rejects the whole episode before anything runs.

**Is the difference the world declares observable at all?** The manifest's discriminating
envelope is run in the world; an injection nothing retrieves, a patch that applies to nothing,
and an exclusion predicate that removes no base document are each a world that is not the world
it claims to be. Nothing has run yet, so this is the last moment those cost nothing.

THE SCRATCH LEDGER IS THE LOAD-BEARING PART. The serving path answers from the primed capture
BEFORE it calls any adapter (`estate/registry.py`'s `_base_payload`, C15), so a review run
through the episode's own ledger would read the capture back and compare it with itself — a
green review that proves nothing about the estate. The replay therefore reads through a ledger
whose base file is EMPTY, in a scratch tree outside the episode, and the episode's own `served/`
gains no row for it. Its verb context is host-side over the episode dir with no capture
recorder, so no query row is written anywhere either.

WHAT THIS FRAME NEVER DOES is ask the estate a question of its own beyond the two above. The
review is the last host-side reader before the family runs, and every extra call it makes is a
call the base run never made — so an entity that appears in no captured row and no host-side
count is RECORDED as an invention (O11) rather than chased with another adapter query, and the
exclusion count goes through the staging door, whose `_count` is deliberately absent from the
adapter allowlist (C27).
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from defender._io import read_jsonl_rows, read_jsonl_rows_report, write_guarded
from defender.run_common import DEFENDER_DIR, resolve_runs_base, run_env
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
from .ledger import (
    BASE,
    SERVED_DIRNAME,
    Ledger,
    ServedCall,
    base_file,
    correlation_key_of,
    payload_text,
)
from .staging import INJECT_SUFFIX as _staging_inject_suffix

#: The review's own record, beside the manifest it reviewed. Kept on a REJECTION too: the
#: measurement of a family that did not run is the second thing O4's drift obligation is
#: observed by, and deleting it would leave "we rejected it" as a claim with no reading behind.
REVIEW_NAME = "review.yaml"

#: The suffix staging gives a world's injection index, under its own view name. IMPORTED from
#: the module that constructs the names rather than restated: this module only READS them, and
#: the two "must agree exactly" — a count asked of a name staging did not write answers zero and
#: reads as an unreachable injection, which rejects the world. Re-exported because the review's
#: own consumers name it.
INJECT_SUFFIX = _staging_inject_suffix

#: The two decisions a world or an episode can carry.
ACCEPTED = "accepted"
REJECTED = "rejected"


class ReviewError(Exception):
    """A review that cannot be honestly completed.

    Never raised for what the ESTATE said — a contradiction, an unreachable difference and a
    faulted call are all readings this module records and returns. This class is for the frame
    itself failing: a manifest whose worlds cannot be resolved, a scratch tree that cannot be
    made. The distinction matters because the launcher exits differently on the two: a rejected
    episode is a measurement, and a broken review is not one.
    """


# ---------------------------------------------------------------------------------------
# the replay's own seams
# ---------------------------------------------------------------------------------------


class ScratchLedger(Ledger):
    """A `Ledger` over an EMPTY base, plus the two readings a reviewer needs of one.

    The empty base is the whole point (see the module docstring): with the episode's own primed
    capture underneath, every captured key would answer from the recording and the review would
    agree with itself.

    `base_payload` gains a one-argument spelling because a reviewer holds a KEY — the
    correlation key a capture row carries — where the serving path holds a call. The
    three-argument form is untouched and still the one the replay uses, so the base class's own
    callers keep working through this subclass.
    """

    def base_payload(self, *key: Any) -> str | None:
        """The recorded answer for a key, addressed either way.

        One argument is the request key itself; three are `(system, verb, params)`, which is
        what the serving path holds and what the base class composes a key from.
        """
        if len(key) == 1:
            return self._memo.get(str(key[0]))
        return super().base_payload(*key)

    def base_rows(self) -> Iterator[dict]:
        """Every row in the family tier this ledger reads through — none, by construction.

        Published as a reading rather than left to the caller to open the file, so "the base is
        empty" is a question with one answer rather than a path two readers spell differently.
        """
        yield from read_jsonl_rows(self.base_path)


def scratch_ledger(episode_dir: Path, *, world_label: str = "review",
                   root: Path | None = None) -> ScratchLedger:
    """A ledger for the replay: this world's own rows over a base file that holds nothing.

    OUTSIDE THE EPISODE. `root` is a scratch tree — a fresh temporary directory when the caller
    names none — because the episode's `served/` is the family's recording and the review's
    replay is not part of it. `review_writes_no_query_row` is the negative that pins that, and
    the placement is what makes it true rather than a convention.

    Named after the episode all the same: a leaked scratch tree that says which episode it came
    from is a diagnosable one.
    """
    episode_dir = Path(episode_dir)
    if root is None:
        root = Path(tempfile.mkdtemp(prefix=f"defender-review-{episode_dir.name}-"))
    served = Path(root) / SERVED_DIRNAME
    served.mkdir(  # lint-unguarded-tree-write: ok — a fresh host-made scratch tree under the system temp dir, never a box mount and never the episode's own served/  # noqa: E501
        parents=True, exist_ok=True)
    base = served / base_file(episode_dir).name
    if not base.exists():
        # TOUCHED, not skipped: `Ledger.__post_init__` refuses a missing base, because a world
        # serving without one reads the live estate for every key. An empty file is the honest
        # spelling of "this replay has no recording to answer from" and keeps that refusal
        # meaning what it means for a real run.
        base.write_text(  # lint-unguarded-tree-write: ok — the same fresh host-made scratch tree as the mkdir above; no box mounts it and no model can plant a component in it  # noqa: E501
            "", encoding="utf-8")
    book = ScratchLedger(path=served / f"{world_label}.jsonl", base_path=base)
    if any(book.base_rows()):
        # THE ONE PROPERTY THIS LEDGER EXISTS FOR, checked rather than assumed. A scratch base
        # holding rows is a review pointed at a recording — the episode's own capture, or a
        # scratch tree reused from an earlier attempt — and it would answer every captured key
        # from that recording and agree with itself, green and worthless.
        raise ReviewError(
            f"the replay's base at {book.base_path} holds rows — a review reads through an "
            "EMPTY base so that every captured key reaches the estate; a base with a recording "
            "in it makes the replay agree with itself and proves nothing")
    return book


def verb_context(episode_dir: Path) -> VerbContext:
    """The host-side context the replay's adapter calls run under.

    `run_dir` is the EPISODE dir rather than any run dir, and `capture` is `None`: the replay
    writes no `executed_queries.jsonl` row anywhere, because a review is not a run and a row
    claiming otherwise would put queries no model asked into a table a later reader counts.

    `DEFENDER_RUNS_BASE` IS THE CONFIGURED ROOT, composed here rather than inherited.
    `run_common.run_env` sets it to `run_dir.parent` unconditionally, which was correct for this
    caller only while an episode dir was a direct child of the runs base — and after #947's
    relocation that parent is the EPISODES ROOT, a configured location holding every episode
    and not a runs base at all. Inherited, every adapter subprocess this replay spawns would
    resolve its runs base to that tree.
    """
    episode_dir = Path(episode_dir)
    env = run_env(DEFENDER_DIR, episode_dir)
    env["DEFENDER_RUNS_BASE"] = str(resolve_runs_base())
    return VerbContext(
        defender_dir=DEFENDER_DIR, run_dir=episode_dir, env=env, capture=None)


@dataclass(frozen=True)
class Replay:
    """One replayed call: the payload the world would have been served, and its canonical text.

    Both, because the two readers need different halves — reachability walks the tree, and the
    comparison reads the bytes — and re-dumping one to get the other is how two spellings of
    "the same answer" get compared and found different.
    """

    payload: Any
    text: str


def replay_one(call: tuple[str, str, dict], *, episode_dir: Path, adapters: Any,
               world: Any = None, applier: Any = None, ledger: Any = None,
               ctx: Any = None, captured: str | None = None) -> Replay:
    """Ask one call again, as `world` would have asked it, and hand back what came back.

    THE SERVING PATH'S SHAPE, host-side: stage the call onto the world's corpus, take the base
    answer, then apply the world's difference to it.

    **`captured` IS THE REVIEW'S WHOLE ANSWER, AND IT IS NOT OPTIONAL THERE.** A review does not
    gather evidence: a key the capture already holds is answered from the capture, and the
    adapter is never reached for it. That is a decision, not an optimisation — a review that
    re-asked the estate would be measuring the estate's drift since the source run rather than
    the world's declared difference, and it would be spending a live read per captured key per
    world to do it. With `captured` in hand there is nothing to `restore` either: a captured
    payload is what the SOURCE run was served, so it never carried a world's corpus identity in
    the first place.

    THE ADAPTER ARM SURVIVES FOR THE CALL THE REVIEW ASKS ON PURPOSE — the discriminating
    envelope, which is a question the capture does not hold and which the reachability half
    exists to run. That is the whole of the read surface: everything the capture holds is
    replayed, and the one thing it does not hold is the one thing the review deliberately asks.

    `world is None` is the bare replay: no staging, no patch, nothing to apply.

    THE FORK-6 REFUSAL IS FIRST AND OUTSIDE EVERYTHING, exactly as it is in `serve_one` and in
    `WorldRegistry._served`. This frame is the third spelling of the serve order and it was the
    one without the guard — and it is the spelling that replays the DISCRIMINATING ENVELOPE, the
    one call in this whole module a MODEL authored (`family.discriminator["envelope"]`, which
    the manifest loader type-checks and does not read). Asked above `prepare`, so a world naming
    a sibling's staged view by hand is refused before any stager can rewrite the name into a
    harmless one and before the adapter is reached — which is the case the guard's own docstring
    identifies as the reachable one, because the CONTROL stages nothing and its applier hands
    the parameters straight back.
    """
    system, verb, params = call
    if world is not None:
        refuse_a_foreign_world_view(world, system, verb, params)
    context = ctx if ctx is not None else verb_context(episode_dir)
    book = ledger if ledger is not None else scratch_ledger(episode_dir)
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
        # lint-parse: ok — `Replay.payload` IS the adapter's own untyped answer and is declared
        # `Any`: there is no shape the seven systems share, and the half this frame can promise
        # (the canonical text) is typed and narrowed by `payload_text`.
        return Replay(payload=payload, text=recorded)
    _decision, applied = applier.apply(system, verb, prepared, payload, world, asked)
    # lint-parse: ok — same seam, same reason as the arm above.
    return Replay(payload=applied, text=payload_text(applied))


# ---------------------------------------------------------------------------------------
# the review
# ---------------------------------------------------------------------------------------


def review(family: Family, *, episode_dir: Path, adapters: Any, door: Any,
           invoke: Any, write: Any = None) -> dict:
    """Replay the capture through every world, judge each, and write `review.yaml`.

    THE CONTROL FIRST, always: the rest of the pass is defined against its result, and computing
    a world's mismatches before the drift they are measured against is a comparison with a
    missing term.

    Every dependency is injected. `adapters` is the estate's read side, `door` the host-side
    staging write door (the only thing that may count), and `invoke` the model seam the
    comparator calls at most once per undecided key. None of the three has a default here: this
    frame runs once per episode, from one caller, and a default would be a second opinion about
    which estate an episode was reviewed against.

    `write` is the whole-record write seam (#1007) — `write_guarded` by default, and a caller's
    own wrapper otherwise, so "review.yaml is written exactly once per pass" is observable
    without reaching around it with `monkeypatch.setattr`.
    """
    write = write if write is not None else write_guarded  # lint-default: ok — DI seam owning its own default
    episode_dir = Path(episode_dir)
    rows, unreadable = read_jsonl_rows_report(base_file(episode_dir))
    context = verb_context(episode_dir)
    token = episode_token_for(family.episode_id)
    drifted = frozenset(_capture_drift(rows))
    scratch = Path(tempfile.mkdtemp(prefix=f"defender-review-{episode_dir.name}-"))
    try:
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
        # The scratch tree is the replay's whole write surface, and it is worth exactly nothing
        # once the record is composed: its rows are live reads of a review, not evidence of a
        # run, and leaving them behind would put a tree that looks like an episode's `served/`
        # somewhere no reader expects one.
        shutil.rmtree(scratch, ignore_errors=True)
    record = _record(family, worlds=worlds, unreadable=unreadable)
    # `write_guarded`, not `write_atomic`. They are the same lane — `write_atomic` IS
    # `write_guarded(mode="replace")` — but `write_atomic` is ALSO the marker #719's census
    # reads to find every function that rewrites a queue file wholesale, and that census is one
    # name wide on purpose ("exactly one function under `defender/learning` rewrites a queue
    # file"). A review record is not a queue, and a frame that spells the queue writer's own
    # primitive joins a census it does not belong to.
    write(
        episode_dir / REVIEW_NAME,
        yaml.safe_dump(record, sort_keys=False, allow_unicode=True, default_flow_style=False))
    return record


@dataclass(frozen=True)
class _Deps:
    """One world's collaborators, threaded as a value rather than as six parameters."""

    adapters: Any
    door: Any
    invoke: Any
    ctx: Any
    scratch: Path
    token: str
    #: The keys the CAPTURE itself answers two ways — a fact about the episode, so it is
    #: derived once here rather than per world. Recomputed inside `_consistency` it re-walked
    #: every captured row and re-canonicalised every payload once per world, to rediscover a
    #: value that cannot vary between them.
    drifted: frozenset[str]
    #: Every row `base_file` recorded — M1's own selection pool, read once at `review()` scope
    #: rather than re-read per world.
    captured_rows: Sequence[dict]
    #: M1's base-arm memo (F3, F-A(d)): `(system, verb, canonical(params))` -> canonical text,
    #: at EPISODE scope so a key re-asked by three worlds is read from the un-rewritten estate
    #: exactly once. SUCCESSES ONLY — a faulted read is retried for the next world rather than
    #: poisoning every world after the first (`test_a_faulted_base_arm_is_not_memoised_across_worlds`).
    base_memo: dict[str, str]


def _control_first(family: Family) -> list[World]:
    """The manifest's worlds with the base world at the head.

    ORDER IS A RESULT HERE, not presentation: the control's mismatch set is what every later
    world's is measured against, and the record is written in the order it was computed so a
    reader sees the same sequence the judgment used.
    """
    # THE WORLDS THE LAUNCHER RUNS, and no others. Staging (`cli._run_episode`) and the launch
    # both walk `runnable_worlds`, which drops the `role: null` replicate arm the data model
    # admits so an operator can ASK for one. Walked over `family.worlds` instead, the review
    # judged that arm against a corpus staging never created: its injection index does not
    # exist, `_injected_retrieved` counts zero, `_rejection` calls the difference unreachable,
    # and FORK-14 then ends the whole episode — an opt-in arm making the family unrunnable.
    runnable = runnable_worlds(family)
    base = [w for w in runnable if w.role == BASE_ROLE]
    return base + [w for w in runnable if w.role != BASE_ROLE]


def _review_world(world: World, *, family: Family, episode_dir: Path, rows: Sequence[dict],
                  control: Sequence[str], deps: _Deps) -> dict:
    """One world's whole result: consistency, reachability, inventions and the decision."""
    resumed = resume_world_from(family, world.world_id, episode_dir)
    # NO `patches=`. `WorldApplier.patch_table` prefers the world's OWN overlay whenever the
    # world carries one, and `resumed.overlay` IS `world.overlay` — so a table handed to the
    # constructor here was a second copy the applier never consulted, which is exactly the drift
    # `patch_table`'s docstring exists to prevent. The sibling path (`run.py`) builds it bare.
    applier = WorldApplier()
    ledger = scratch_ledger(episode_dir, world_label=world.world_id, root=deps.scratch)
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

    THE CONTROL'S SET IS SUBTRACTED, not re-derived. A key the base world also mismatches on is
    the estate having moved since the capture — a shared fact about the episode — and charging
    it to a world would reject one for something every world would show. What remains is a
    difference this world made.

    A FAULT IS NEVER A CONTRADICTION and never reaches the comparator. A call that could not be
    replayed for one world and could be for its control is contamination — a staging refusal for
    one arm, an unreadable row for all of them — and classifying it as a corpus contradiction
    would reject a world for the harness. It is recorded, in its own class, and the comparator is
    not asked about bytes nobody got.

    NOTHING HERE REACHES AN ADAPTER. Every key this pass judges is a key the capture holds, and
    each world's answer is its own difference applied to the captured payload. A review does not
    gather evidence: re-asking the estate would measure how far it has moved since the source
    run rather than what the world declares, and it would do it once per captured key per world.
    """
    replayed: list[dict] = []
    mismatches: list[dict] = []
    faults: list[dict] = []
    drift: list[str] = []
    for row in rows:
        # `correlation_key_of`, never `row.get("correlation_key")`: `ServedCall.row()` does not
        # WRITE that column — it is a property — so a column read answered `None` for every row
        # a real `prime_base` produced, every key of the capture folded onto one, and the whole
        # pass read as drift. One derivation, shared with `episode._pair_key`.
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
        # THE COMPARATOR IS DELIBERATELY OUTSIDE THE HANDLER ABOVE. A wrong-seat verdict is not
        # an estate fault; it is the model answering a question this call did not ask, and
        # §7 FORK-9's one abort rule is what ends the episode on it. Filed as a fault it would
        # be a review that recorded "we could not read the answer" and started the family anyway.
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
#: `Verdict` member, because the comparator's vocabulary is what a MODEL may answer and this is
#: a reading the review makes for itself — a member here would be a sixth verdict no seat admits.
DRIFT = object()


def _row_outcome(key: str, captured: str, replayed: str, *, drifted: frozenset[str],
                 control: Sequence[str], is_control: bool, invoke: Any) -> Any:
    """How one replayed row stands to its capture: agreed (`None`), `DRIFT`, or a verdict.

    THE CAPTURE DISAGREEING WITH ITSELF IS DRIFT, and it is the only drift a replay-only review
    can see — which is right, because it is the only drift that happened while the evidence this
    episode reasons over was being written. The source run asked one question twice and was
    answered twice; the estate moved underneath it, and every world inherits that key's ambiguity
    equally. Charged to a world it would reject one for something all three show.

    THE CONTROL NEVER REACHES THE COMPARATOR. It applies nothing, so its replay is the capture
    and any difference it could show is the capture's own — which is drift by definition, and
    spending a model call to have that confirmed would be paying to be told what the bytes
    already say.
    """
    if key in drifted:
        return DRIFT
    verdict = mechanical(captured, replayed)
    if verdict is None and not is_control and key not in control:
        # THE MODEL'S ANSWER IS FOLDED THROUGH THE SAME GATE THE ARITHMETIC'S IS. `compare` can
        # return `same` — it is a member of `REVIEW_SEAT`, and the whole reason the model is
        # asked is that the bytes differ in a way arithmetic could not settle. Returned as a
        # member it was appended to `mismatches` with `verdict: same`, so `review.yaml` reported
        # N mismatches for a world the comparator said agrees, and every reader counting that
        # list read an agreement as a difference.
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

    A key the source run asked more than once, and was served differently each time, is a key
    whose truth moved WHILE the evidence was being gathered. It is a fact about the episode
    rather than about any world, so it is subtracted from every world the way a live control's
    mismatch set used to be — and unlike a live control it costs nothing to observe, because it
    is already written down.

    First-row-wins is the ledger's own rule for which answer a key HAS; this asks the different
    question of whether the rows agree at all, so it compares every later row against the first.
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
# reachability (O3)
# ---------------------------------------------------------------------------------------


def _reachability(world: World, *, family: Family, replay: Any, deps: _Deps,
                  is_control: bool, resumed: Any = None, applier: Any = None) -> dict:
    """Is the difference this world declares observable in this world?

    The envelope is the manifest's own discriminating query, run HERE in the world rather than
    imagined: an injection is reachable if the world's corpus holds it, a patch is visible if it
    applies to something the envelope actually returned, and an exclusion is real if it removes
    at least one base document.

    `envelope_ran` MEANS ROWS CAME BACK. An envelope that faulted or retrieved nothing at all
    measured nothing, and judging a world's difference against it would reject the world for the
    corpus being quiet — the same reading `exclusion_count_failed` gets one field over, where a
    count nobody could ask is recorded as unknown rather than as zero.

    AND `envelope_failed` SAYS WHICH OF THE TWO IT WAS, for the same reason that field exists
    one line further down. A quiet corpus and an envelope that RAISED — an adapter layer nobody
    wired, a confinement refusal, a cluster outage — collapsed onto one `False`, and the record
    a later reader opens could not tell "this world's difference is not observable" from "this
    review measured nothing at all". It does not reject on its own, exactly as an unanswerable
    exclusion count does not: an outage is the harness's, and rejecting a world for one would
    charge it for the estate.

    M1 (#1007): THE CONTROL TAKES NO RE-ASK AT ALL — it declares no difference of its own, so
    there is nothing for the capture's own vocabulary to reach. Every other world's block also
    carries `capture_replays`, `capture_addressed`, `capture_reasks_faulted` and
    `reachable_by_capture`, the three executed facts M1 adds.
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
    retrieved, present = _injected_counts(world, rows=rows, deps=deps)
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


def _addressed(call: tuple[str, str, dict], *, world: World, ctx: Any) -> bool:
    """Does this ONE captured call name a pattern this world stages, or the patched system it
    declares (ledger fork F4, `resolved_by: auto`)?

    THE PATCHED-SYSTEM ARM COUNTS, because it decides which worlds can be withheld: a patch-only
    world stages no such pattern at all, and a `capture_addressed` computed off the pattern
    arm alone would read every one of them as unaddressed — `withheld_reason:
    capture_unaddressed` — and suppress its defender findings under a recorded reason that is
    false.
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
    return pattern is not None and pattern in _addressing_patterns(world)


def _capture_reachability(world: World, *, deps: _Deps, resumed: Any, applier: Any) -> dict:
    """M1: re-ask the capture's own queries, live, and record what the re-ask measured.

    Selection is by `_addressed` alone — a captured row naming a pattern this world stages, or
    naming the system a patch-only world declares. For each selected row: the BASE arm (the
    un-rewritten capture params, through the episode-scope memo) and the WORLD arm (through
    `_world_arm`, which carries this world's staging/patching and the FORK-6 foreign-view
    refusal, and is NEVER memoised — the confirming re-read (H4) has to reach the estate again,
    not a cached answer to the same key). `differs` is confirmed by one back-to-back re-read of
    the WORLD arm before it is recorded — the memoised base arm cannot itself be the skew, so
    only the later arm is re-read.
    """
    selected = [
        (str(row.get("system")), str(row.get("verb")), dict(row.get("params") or {}),
         correlation_key_of(row))
        for row in deps.captured_rows
        if _addressed((str(row.get("system")), str(row.get("verb")), dict(row.get("params") or {})),
                      world=world, ctx=deps.ctx)
    ]
    addressed = bool(selected)
    replays: list[dict] = []
    faulted_count = 0
    any_differs = False
    any_completed = False
    for system, verb, params, key in selected:
        call = (system, verb, params)
        differs, faulted = _one_reask(call, world=resumed, applier=applier, deps=deps)
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
    """M1's base arm: the un-rewritten capture params, read once per episode per key.

    THROUGH `deps.adapters` DIRECTLY — no staging, no world, the same recording read door every
    other adapter read of the review goes through. SUCCESSES ONLY are memoised. A faulted read
    is retried for the next world rather than poisoning every world that follows it in
    `_control_first`'s order.
    """
    system, verb, params = call
    memo_key = json.dumps([system, verb, params], sort_keys=True, default=str)
    cached = deps.base_memo.get(memo_key)
    if cached is not None:
        return cached
    try:
        payload = deps.adapters(system, verb, **params)
    except Exception:  # noqa: BLE001 — an unanswerable base arm is a faulted re-ask, not a raise
        return None
    text = payload_text(payload)
    deps.base_memo[memo_key] = text
    return text


def _world_arm(call: tuple[str, str, dict], *, world: Any, applier: Any, deps: _Deps) -> str:
    """One UNCACHED live read of `call` as this world would answer it.

    Deliberately NOT `replay_one`: that frame's scratch ledger memoises the first answer for a
    given `(system, verb, prepared)` key, which would make H4's confirming re-read a second look
    at the SAME cached bytes rather than a second reach into the estate — exactly the skew this
    re-read exists to catch. The FORK-6 refusal, `prepare`/`apply` and the restore-before-apply
    order are all still here; only the memo is gone.
    """
    system, verb, params = call
    refuse_a_foreign_world_view(world, system, verb, params)
    prepared = applier.prepare(system, verb, dict(params), world, deps.ctx)
    asked = dict(params) if prepared != params else None
    served = deps.adapters(system, verb, **prepared)
    restored = served if asked is None else applier.restore(
        system, verb, served, asked, prepared, deps.ctx)
    _decision, applied = applier.apply(system, verb, prepared, restored, world, asked)
    return payload_text(applied)


def _differs(base_text: str, other_text: str) -> bool:
    """"Differs beyond formatting" — `mechanical`'s own vocabulary, read the way every other
    caller in this module reads it: `SAME`/`FORMATTING` is `False`, everything else (including
    the mechanically UNDECIDED `None` — C29 refuted `mechanical`'s decidability for a genuine
    content difference, pd-5) is `True`. This pass has no model seat to settle `None` further,
    so H4's confirming re-read is the only thing standing between an undecided verdict and a
    recorded fact."""
    verdict = mechanical(base_text, other_text)
    return verdict not in (Verdict.SAME, Verdict.FORMATTING)


def _one_reask(call: tuple[str, str, dict], *, world: Any, applier: Any,
              deps: _Deps) -> tuple[bool | None, bool]:
    """`(differs, faulted)` for one captured call, with H4's confirming re-read.

    `differs` is `None` whenever `faulted` is `True` — a faulted arm measured nothing, so it
    is never recorded as `False` (which would read as "measured, and no difference").

    BOTH SIDES ARE GUARDED BEFORE THE COMPARATOR: `mechanical(None, <text>)` raises an uncaught
    `TypeError`, so a faulted arm — base or world — never reaches it, and never as a quiet
    `differs: false`.

    THE CONFIRMING RE-READ (H4) fires only on the apparently-differing path — the extra read is
    the price of recording a difference, not of every key — and re-reads the WORLD arm alone:
    the memoised base arm cannot itself be the skew (P-D's normalization already removes the
    incidental fields that would make two live reads of an unchanged corpus disagree), so only
    the later arm is asked again. A difference that survives both reads is recorded; one that
    does not is skew, not a fact.
    """
    base_text = _base_arm(call, deps=deps)
    if base_text is None:
        return None, True
    try:
        world_text = _world_arm(call, world=world, applier=applier, deps=deps)
    except Exception:  # noqa: BLE001 — a refused or faulted world arm is a faulted re-ask
        return None, True
    if not _differs(base_text, world_text):
        return False, False
    try:
        confirming = _world_arm(call, world=world, applier=applier, deps=deps)
    except Exception:  # noqa: BLE001 — the re-read itself faulting is still a faulted re-ask
        return None, True
    return _differs(base_text, confirming), False


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

    Three spellings and no guessing beyond them: a flat `hits` list, an engine-shaped nested
    `hits.hits`, and a tabular `rows`/`values`. A payload naming none of them contributes no
    rows, which reads as "nothing was retrieved" — the honest answer for a shape this frame
    cannot count, and one that never rejects a world on its own.

    THE TABULAR SPELLING IS POSITIONAL, and that is not an extra tolerance — it is the ES|QL
    payload, which is the natural discriminating envelope for a staged corpus difference.
    `esql_payload` leaves `values` "AS THE WIRE SENT IT: rows are bare arrays, cell `i` binding
    to `columns[i]`", so an `isinstance(row, dict)` filter over it dropped every row. The whole
    reachability half then measured nothing: `envelope_ran` was False for every ES|QL envelope,
    and `_rejection` returns `None` on that — so a world whose declared difference is genuinely
    unreachable was ACCEPTED and FORK-14 never fired. Bound here, at read time, from the
    `columns` the wire states once, exactly as the payload's own docstring says a reader must.
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

    `None` rather than `[]` for "not tabular", so the mapping-shaped arm above stays the
    fallback rather than being replaced by an empty answer. A row longer or shorter than the
    header binds what the two have in common: a truncated wire row is still evidence of a
    retrieval, and refusing it here would read as "nothing was retrieved".
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


def _injected_counts(world: World, *, rows: Sequence[dict], deps: _Deps) -> tuple[int, int]:
    """`(injected_retrieved, injected_present)` — N4/M9's honest split (#1007).

    THE OLD SINGLE COUNT (`max` of the two) let the door's own size stand in for the envelope's
    reach: whenever the cluster could answer a count at all, the world read reachable — the door
    count IS the injection size, so a world was never truly measured unreachable through this
    field (§7 FORK-7(e)'s consequence). Split, each half means one thing: `injected_retrieved` is
    the ENVELOPE's own hits — what this world's discriminating query actually returned — and
    `injected_present` is the OVERLAY's own declared injection-list length, a SIZE fact,
    never a reachability one and never a door-measured count. `_rejection`'s injection branch
    retires under N4 as vacuous now that neither half alone should gate a world.
    """
    retrieved = 0
    present = 0
    for _pattern, entry in _elastic_entries(world):
        if not entry.inject:
            continue
        retrieved += _hit_count(entry, rows)
        # THE OVERLAY'S OWN DECLARED SIZE — never a door count. "Size is not reach": an overlay
        # can inject a great deal into a corpus the capture never queries, and `injected_present`
        # exists to say so without borrowing the envelope's own measurement to do it.
        present += len(entry.inject)
    return retrieved, present


def _hit_count(entry: ElasticEntry, rows: Sequence[dict]) -> int:
    """How many retrieved rows are one of this entry's injected documents.

    Matched on `_id` where the injected document names one, and otherwise on the document being
    wholly contained in the row: an author who injected a document with no id still declared a
    difference, and refusing to count it would make the id field a requirement no schema states.

    TWO SHAPES A MODEL-AUTHORED DOCUMENT CAN TAKE THAT THIS HAD TO ANSWER FOR. An `_id` that is
    not a scalar is unhashable, and a set comprehension over it raised `TypeError` out of the
    review and aborted the episode — `_parse_elastic_entry` validates that `inject` is a list of
    mappings and nothing about the values inside them. And an EMPTY injected document makes
    `all(...)` vacuously true, so every retrieved row counted as a hit and a world that injected
    nothing at all read as one whose difference is reachable. Neither is refused here — this
    frame counts, it does not judge — they just cannot match anything.
    """
    # AS STRINGS, because that is what the id round-trips as. `create_index` puts the document
    # at `str(doc_id)` in the URL and the cluster answers `_id` as text, so a manifest that
    # spelled `_id: 1` (YAML reads it as `int`) produced `{1}` here and `"1"` on the wire, and
    # `"1" in {1}` is False — the world's whole injection counted zero and `_rejection` called
    # its difference unreachable.
    ids = {str(doc["_id"]) for doc in entry.inject
           if isinstance(doc.get("_id"), (str, int, float))}
    # THE BODY OF EVERY INJECTED DOCUMENT, `_id` REMOVED — not only the id-less ones. The
    # payload this counts against is the SEARCH verb's, and `elastic_adapter` builds its `hits`
    # from `_source` alone, so no retrieved row carries an `_id` at all: the id arm above can
    # only fire for a payload shape that keeps one, and an id-bearing document had no second
    # way to be recognised. Its body is exactly as good a witness, and it is the one the search
    # payload actually holds. An EMPTY body is dropped, because `all(...)` over nothing is
    # vacuously true and would count every retrieved row as a hit.
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

    The APPLY COUNT is the only gate, and it is the applier's own count rather than a second
    matcher written here: a patch that lands nowhere in the payload the discriminator selected
    is a difference the run cannot measure, and a rule about where entities live would be a
    second opinion about what "lands" means.
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

    ASKED THROUGH THE STAGING DOOR. `_count` is deliberately absent from the adapter's read
    allowlist and must stay absent, so the model's dispatch surface cannot ask the cluster to
    count; the door is host-side and is the only thing here that may.

    A FAILED COUNT IS NOT ZERO. `None` with the flag set, never `0`: the rejection this feeds is
    for a predicate that removed nothing, and a predicate nobody could ask about has not been
    shown to remove nothing. Collapsing the two would reject a world for an outage.
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
            # NOTHING TO COUNT IS NOT A COUNT OF ZERO, and the two are the same shape one line
            # further on: `_rejection` refuses a world whose exclusion "matches zero base
            # documents". A declared pattern that resolves to no concrete index — a corpus that
            # is quiet right now, or one the resolver cannot see — has not been SHOWN to remove
            # nothing, so it takes the unknown arm with the rest of the unaskable counts.
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
    """One count through the door, or `None` when the door could not answer.

    The refusal is swallowed HERE and reported as `None` rather than raised, because every
    caller has the same reading for it — "not measured" — and an exception would abort a review
    that has real findings for every other world in hand.
    """
    try:
        return int(door.count(index, query=query))
    except Exception:  # noqa: BLE001 — see docstring: an unanswerable count is not a failure
        return None


# ---------------------------------------------------------------------------------------
# inventions (O11) and the decision
# ---------------------------------------------------------------------------------------


def _inventions(world: World, *, rows: Sequence[dict], reachability: dict) -> list[str]:
    """What this world asserts that nothing in the capture or the estate holds.

    A RECORDING OBLIGATION AND NOTHING MORE. An invention never rejects: a world may assert an
    entity the source run never saw — that is a large part of what a counterfactual IS — and
    rejecting on it would make a cheap string test the judge of what a world is allowed to say.
    What a later reader needs is to see it without re-deriving it.

    The six state systems have no host-side count door, and the review may not ask the adapter a
    question the base run never asked, so for a patched entity the capture is the whole of the
    available evidence. The staged system is where a live count exists, and the full-match
    exclusion is recorded through the same channel: a world that is only its own injection is
    implausible, and implausibility does not reject (§7 FORK-7(a)).
    """
    notes: list[str] = []
    # SCANNED PER ENTITY, never joined. The capture is the whole family's recording — the
    # ledger sizes one payload in tens of kilobytes — and `"\n".join(...)` materialised all of
    # it as one string once per world, including for the control, whose empty patch table means
    # the string is built and never read. `any(... for row in rows)` reads the same rows and
    # allocates nothing, and it stops at the first row that holds the entity.
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

    Read off the same count the exclusion was measured with: the door answers an unfiltered
    count over the same indices, so "removes everything" is `matched == total` rather than a
    guess at the predicate's spelling — a world that spells a full match some other admitted way
    is recorded the same as one that spells it `match_all`.
    """
    total = reachability.get("base_documents")
    return int(total) if isinstance(total, int) else 0


def _rejection(world: World, *, consistency: dict, reachability: dict) -> str | None:
    """Why this world may not run, or `None`.

    THREE REASONS AND NO OTHERS (N4, #1007): a contradiction, a patch that applies to nothing
    the envelope returned, and an exclusion that removes no base document. The FOURTH — an
    injection its own envelope cannot retrieve — RETIRES under N4: `injected_retrieved` (the
    envelope's own hits) and `injected_present` (the overlay's own declared size, never a
    door-measured count) are both honest now, and
    neither alone is a reachability verdict a world should be rejected on, unlike the old single
    count that let the door's size stand in for it. `reachable_by_capture` (M1) is what a later
    reader consults for reachability; this frame no longer rejects on it. Everything else this
    record carries (drift, faults, inventions, an unanswerable count) is a reading that goes in
    the record and changes nothing.
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

    `unreadable_capture_rows` is carried at the EPISODE level because that is what it is about:
    a row nobody could parse is skipped rather than guessed at (§7 FORK-17), and the control's
    mismatch set is then under-counted by exactly those rows. Recorded, a later reader can see
    the measurement was partial; dropped, the review reads as complete.
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
    "REVIEW_NAME",
    "Replay",
    "ReviewError",
    "ScratchLedger",
    "replay_one",
    "review",
    "scratch_ledger",
    "verb_context",
]
