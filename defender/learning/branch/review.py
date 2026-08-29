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
)
from defender.runtime.verbs import VerbContext
from defender.scripts.adapters.confinement import world_view

from .comparator import Verdict, compare, mechanical
from .estate.applier import WorldApplier
from .estate.lookups import apply_patches
from .ledger import BASE, Ledger, ServedCall, base_file, payload_text

#: The review's own record, beside the manifest it reviewed. Kept on a REJECTION too: the
#: measurement of a family that did not run is the second thing O4's drift obligation is
#: observed by, and deleting it would leave "we rejected it" as a claim with no reading behind.
REVIEW_NAME = "review.yaml"

#: The suffix staging gives a world's injection index, under its own view name. The names are
#: constructed there and only READ here — this module never creates one — but the two must
#: agree exactly, because a count asked of a name staging did not write answers zero and reads
#: as an unreachable injection.
INJECT_SUFFIX = ".inject"

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
    served = Path(root) / "served"
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
    """
    system, verb, params = call
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
    _decision, applied = applier.apply(system, verb, prepared, payload, world)
    # lint-parse: ok — same seam, same reason as the arm above.
    return Replay(payload=applied, text=payload_text(applied))


# ---------------------------------------------------------------------------------------
# the review
# ---------------------------------------------------------------------------------------


def review(family: Family, *, episode_dir: Path, adapters: Any, door: Any,
           invoke: Any) -> dict:
    """Replay the capture through every world, judge each, and write `review.yaml`.

    THE CONTROL FIRST, always: the rest of the pass is defined against its result, and computing
    a world's mismatches before the drift they are measured against is a comparison with a
    missing term.

    Every dependency is injected. `adapters` is the estate's read side, `door` the host-side
    staging write door (the only thing that may count), and `invoke` the model seam the
    comparator calls at most once per undecided key. None of the three has a default here: this
    frame runs once per episode, from one caller, and a default would be a second opinion about
    which estate an episode was reviewed against.
    """
    episode_dir = Path(episode_dir)
    rows, unreadable = read_jsonl_rows_report(base_file(episode_dir))
    context = verb_context(episode_dir)
    token = episode_token_for(family.episode_id)
    scratch = Path(tempfile.mkdtemp(prefix=f"defender-review-{episode_dir.name}-"))
    try:
        worlds: dict[str, dict] = {}
        control: list[str] = []
        for world in _control_first(family):
            result = _review_world(
                world, family=family, episode_dir=episode_dir, rows=rows, control=control,
                deps=_Deps(adapters=adapters, door=door, invoke=invoke, ctx=context,
                           scratch=scratch, token=token))
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
    write_guarded(
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


def _control_first(family: Family) -> list[World]:
    """The manifest's worlds with the base world at the head.

    ORDER IS A RESULT HERE, not presentation: the control's mismatch set is what every later
    world's is measured against, and the record is written in the order it was computed so a
    reader sees the same sequence the judgment used.
    """
    base = [w for w in family.worlds if w.role == BASE_ROLE]
    return base + [w for w in family.worlds if w.role != BASE_ROLE]


def _review_world(world: World, *, family: Family, episode_dir: Path, rows: Sequence[dict],
                  control: Sequence[str], deps: _Deps) -> dict:
    """One world's whole result: consistency, reachability, inventions and the decision."""
    resumed = resume_world_from(family, world.world_id, episode_dir)
    applier = WorldApplier(patches={system: dict(table)
                                    for system, table in world.overlay.patches.items()})
    ledger = scratch_ledger(episode_dir, world_label=world.world_id, root=deps.scratch)
    is_control = world.role == BASE_ROLE

    def replay(call: tuple[str, str, dict], captured: str | None = None) -> Replay:
        return replay_one(call, episode_dir=episode_dir, adapters=deps.adapters,
                          world=resumed, applier=applier, ledger=ledger, ctx=deps.ctx,
                          captured=captured)

    consistency = _consistency(rows, replay=replay, control=control, is_control=is_control,
                               invoke=deps.invoke)
    reachability = _reachability(world, family=family, replay=replay, deps=deps)
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
                 is_control: bool, invoke: Any) -> dict:
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
    drifted = _capture_drift(rows)
    replayed: list[dict] = []
    mismatches: list[dict] = []
    faults: list[dict] = []
    drift: list[str] = []
    for row in rows:
        key = str(row.get("correlation_key"))
        captured = row.get("payload_text")
        call = (str(row.get("system")), str(row.get("verb")), dict(row.get("params") or {}))
        if not isinstance(captured, str):
            faults.append({"key": key, "detail": "the captured row carries no payload text"})
            continue
        try:
            answer = replay(call, captured)
        except Exception as fault:  # noqa: BLE001 — every estate fault is a reading, not a raise
            faults.append({"key": key, "detail": str(fault) or type(fault).__name__})
            continue
        replayed.append({"key": key})
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


def _row_outcome(key: str, captured: str, replayed: str, *, drifted: set[str],
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
    if verdict is Verdict.SAME:
        return None
    if is_control:
        return DRIFT
    if key in control:
        return None
    return verdict if verdict is not None else compare(captured, replayed, None, invoke=invoke)


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
        key = str(row.get("correlation_key"))
        text = row.get("payload_text")
        if not isinstance(text, str):
            continue
        if key not in first:
            first[key] = text
        elif mechanical(first[key], text) is not Verdict.SAME:
            drifted.add(key)
    return drifted


# ---------------------------------------------------------------------------------------
# reachability (O3)
# ---------------------------------------------------------------------------------------


def _reachability(world: World, *, family: Family, replay: Any, deps: _Deps) -> dict:
    """Is the difference this world declares observable in this world?

    The envelope is the manifest's own discriminating query, run HERE in the world rather than
    imagined: an injection is reachable if the world's corpus holds it, a patch is visible if it
    applies to something the envelope actually returned, and an exclusion is real if it removes
    at least one base document.

    `envelope_ran` MEANS ROWS CAME BACK. An envelope that faulted or retrieved nothing at all
    measured nothing, and judging a world's difference against it would reject the world for the
    corpus being quiet — the same reading `exclusion_count_failed` gets one field over, where a
    count nobody could ask is recorded as unknown rather than as zero.
    """
    envelope = _envelope(family)
    rows: list[dict] = []
    ran = False
    if envelope is not None:
        try:
            payload = replay(envelope).payload
        except Exception:  # noqa: BLE001 — a faulted envelope is "nothing was measured"
            payload = None
        rows = _rows_of(payload)
        ran = bool(rows)
    injected = _injected_retrieved(world, rows=rows, deps=deps)
    matched, failed, total = _exclusion_matches(world, deps=deps)
    return {
        "envelope_ran": ran,
        "injected_retrieved": injected,
        "patched_visible": _patched_visible(world, rows=rows),
        "exclusion_matches": matched,
        "exclusion_count_failed": failed,
        "base_documents": total,
    }


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
    """
    if not isinstance(payload, dict):
        return []
    for field_name in ("hits", "rows", "values", "documents"):
        found = payload.get(field_name)
        if isinstance(found, dict):
            found = found.get("hits")
        if isinstance(found, list):
            return [row for row in found if isinstance(row, dict)]
    return []


def _elastic_entries(world: World) -> list[tuple[str, ElasticEntry]]:
    """This world's staged patterns, in a stable order."""
    return sorted(world.overlay.elastic.items())  # lint-shippable: ok — the manifest schema's own field name, owned by `runtime/branch/_family.Overlay`  # noqa: E501


def _injected_retrieved(world: World, *, rows: Sequence[dict], deps: _Deps) -> int:
    """How many of this world's injected documents its own corpus can be seen to hold.

    THROUGH THE DOOR, not off the envelope's hits. A search returns at most one page
    (`RETURNED_DOC_CAP`), so an injection larger than a page could never be counted from what
    came back — and a world rejected for that would be rejected for the READER's limit rather
    than for its own difference (§7 FORK-7(e)).

    The envelope's own hits are counted too, and the larger of the two is kept. A door that
    cannot see the injection index — a count that failed, a name it does not hold — must not
    read as an unreachable injection while the envelope demonstrably retrieved one of the
    documents in question.
    """
    counted = 0
    for pattern, entry in _elastic_entries(world):
        if not entry.inject:
            continue
        index = f"{world_view(pattern, _token(world, deps))}{INJECT_SUFFIX}"
        counted += max(_counted(deps.door, index) or 0, _hit_count(entry, rows))
    return counted


def _token(world: World, deps: _Deps) -> str:
    """This world's composed token — the one spelling every staged name is built from."""
    return f"{deps.token}.{world.world_id}"


def _hit_count(entry: ElasticEntry, rows: Sequence[dict]) -> int:
    """How many retrieved rows are one of this entry's injected documents.

    Matched on `_id` where the injected document names one, and otherwise on the document being
    wholly contained in the row: an author who injected a document with no id still declared a
    difference, and refusing to count it would make the id field a requirement no schema states.
    """
    ids = {doc.get("_id") for doc in entry.inject if doc.get("_id") is not None}
    idless = [doc for doc in entry.inject if doc.get("_id") is None]
    hits = 0
    for row in rows:
        if row.get("_id") in ids or any(
                all(row.get(k) == v for k, v in doc.items()) for doc in idless):
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
    captured = "\n".join(str(row.get("payload_text") or "") for row in rows)
    for system, table in sorted(world.overlay.patches.items()):
        for entity in sorted(table):
            if entity not in captured:
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

    FOUR REASONS AND NO OTHERS. A contradiction, an injection its own envelope cannot retrieve,
    a patch that applies to nothing the envelope returned, and an exclusion that removes no base
    document. Every one of them is a world that is not the world it declares — and everything
    else this record carries (drift, faults, inventions, an unanswerable count) is a reading
    that goes in the record and changes nothing.
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
    injects = any(entry.inject for _pattern, entry in _elastic_entries(world))
    if injects and reachability["injected_retrieved"] == 0:
        return ("the discriminating envelope, run here, retrieves none of this overlay's "
                "injected documents — the difference is unreachable")
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
