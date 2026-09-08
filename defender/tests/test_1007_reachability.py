"""#1007 — M1: the review re-asks the capture's own queries and records what it measured.

Three executed facts per non-control world (`capture_replays`, `capture_addressed`,
`reachable_by_capture`), two live reads per re-asked query (the world's staged view and the
un-rewritten base pattern), one memo per episode, and — H4 — one confirming back-to-back
re-read before any difference is recorded.

Every scenario drives the REAL `review.review` composition frame against the injected
`adapters=` / `door=` / `invoke=` seams and reads the record it wrote. `_reachability` is a leg
of that frame and where M1 lands is carried as an OPEN fork (F3); binding at the composition
frame is what keeps these tests independent of that choice.

RED AGAINST HEAD is the expected state.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests import _world_1007 as W


STAGED_ANSWER = {"hits": [{"host": {"name": "web-9"}}]}
BASE_ANSWER = {"hits": [{"host": {"name": "web-1"}}]}


def scene(tmp_path: Path, monkeypatch, *, worlds=None, captured=None) -> tuple[Path, object]:
    """An episode primed with a capture, plus the parsed `Family` the review takes.

    The capture is what M1 re-asks: one row per captured query, keyed on the params the sibling
    was served. A world's overlay declares the staged pattern those params name, which is what
    makes `capture_addressed` true.
    """
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    family_mod = W.mod("runtime.branch._family")
    docs = worlds if worlds is not None else [
        W.base_world(),
        W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}]))),
    ]
    doc = W.family_doc(worlds=docs)
    ep = W.episode(tmp_path, doc=doc, root=root)
    W.base_capture(ep, list(captured if captured is not None else [W.captured_row(key="k1")]))
    return ep, family_mod.parse_family(doc)


def run_review(ep: Path, family, *, adapters=None, door=None, invoke=None):
    review = W.mod("learning.branch.review")
    return review.review(
        family, episode_dir=ep,
        adapters=adapters if adapters is not None else W.FakeAdapters(),
        door=door if door is not None else W.FakeDoor(),
        invoke=invoke if invoke is not None else W.FakeAgent("same"))


def block_of(record: dict, label: str = "b") -> dict:
    return record["worlds"][label]["reachability"]


# ---------------------------------------------------------------------------------------
# The block itself
# ---------------------------------------------------------------------------------------


def test_reachability_block_carries_the_three_executed_facts(tmp_path, monkeypatch):
    """Every non-control world's block carries the three facts M1 executes, and the control's
    does not.

    Observably true: `capture_replays` (one `{key, differs, faulted}` entry per re-asked
    captured query), `capture_addressed` and `reachable_by_capture` are present on world b's
    block, and the base world — which declares no difference — takes no re-ask at all.

    What failure looks like: the block keeps the fields it has today and the three new ones are
    computed nowhere, so every downstream ladder row reads an absent measurement as a measured
    absence.
    """
    ep, family = scene(tmp_path, monkeypatch)

    record = run_review(ep, family, adapters=W.FakeAdapters(
        {("elastic", "query"): BASE_ANSWER},
        by_target={W.world_token("b"): STAGED_ANSWER}))

    block = block_of(record)
    for key in ("capture_replays", "capture_addressed", "reachable_by_capture"):
        assert key in block, f"the reachability block carries no {key!r}: {sorted(block)}"
    assert isinstance(block["capture_replays"], list)
    assert block["capture_replays"], "the block records no re-ask at all"
    entry = block["capture_replays"][0]
    assert set(entry) == {"key", "differs", "faulted"}, f"a replay entry is {entry}"
    assert "capture_replays" not in record["worlds"]["a"]["reachability"], (
        "the control world was re-asked; there is no difference of its own to reach")


def test_reachable_by_capture_true_on_a_differing_reask(tmp_path, monkeypatch):
    """One completed re-ask that answers differently from the base makes the world reachable.

    Observably true: with the world's staged view answering `web-9` and the base pattern
    answering `web-1`, the entry records `differs: true` and the block reads
    `reachable_by_capture: true`.

    What failure looks like: the two arms are read but never compared, or compared with the
    world's own params on both sides, so a genuinely reachable world is recorded as
    unreachable — and its defender findings are then withheld for a difference that WAS there.
    """
    ep, family = scene(tmp_path, monkeypatch)

    record = run_review(ep, family, adapters=W.FakeAdapters(
        {("elastic", "query"): BASE_ANSWER},
        by_target={W.world_token("b"): STAGED_ANSWER}))

    block = block_of(record)
    assert block["reachable_by_capture"] is True, (
        f"reachable_by_capture is {block['reachable_by_capture']!r} with a differing re-ask")
    assert any(e["differs"] is True for e in block["capture_replays"])


def test_reachable_by_capture_false_only_when_one_completed_and_none_differ(
        tmp_path, monkeypatch):
    """`false` requires a completed re-ask. At least one arm ran, and none differed.

    Observably true: with both arms answering the same document, the block reads
    `reachable_by_capture: false` and the entry records `differs: false, faulted: false`.
    `false` is a MEASUREMENT — the corpus was asked and held no difference — which is a
    different fact from "nobody could ask".

    What failure looks like: `false` as the initialiser, so a world whose re-asks all faulted
    is indistinguishable from one that was measured and showed nothing.
    """
    ep, family = scene(tmp_path, monkeypatch)

    record = run_review(ep, family,
                        adapters=W.FakeAdapters({("elastic", "query"): BASE_ANSWER}))

    block = block_of(record)
    assert block["reachable_by_capture"] is False
    assert block["capture_replays"][0]["faulted"] is False
    assert block["capture_replays"][0]["differs"] is False


def test_reachable_by_capture_null_when_no_reask_completed(tmp_path, monkeypatch):
    """`null` ONLY when no re-ask completed — the falsy-but-valid member of this domain.

    Observably true: with every adapter call raising, the block reads
    `reachable_by_capture: None`, `capture_reasks_faulted` counts the faults, and every entry
    reads `faulted: true`.

    What failure looks like: an outage coerced to `false` by an `or` or a truthiness test. The
    ladder then withholds under the wrong reason, and an operator reads "this world showed
    nothing" for a cluster that was down.
    """
    ep, family = scene(tmp_path, monkeypatch)

    record = run_review(ep, family, adapters=W.FakeAdapters(fault=W.Fault(raise_after=0)))

    block = block_of(record)
    assert block["reachable_by_capture"] is None, (
        f"reachable_by_capture is {block['reachable_by_capture']!r} when nothing completed")
    assert block["capture_reasks_faulted"] >= 1
    assert all(e["faulted"] is True for e in block["capture_replays"])


def test_reachability_is_never_derived_from_the_injection_size(tmp_path, monkeypatch):
    """`reachable_by_capture` is a fact about the RE-ASK, never about how much this world
    injected.

    Observably true: a world declaring twenty injected documents, whose re-ask answers exactly
    the base answer, still reads `reachable_by_capture: false` — and `injected_present` reports
    the twenty separately. Size is not reach: an overlay can inject a great deal into a corpus
    the capture never queries.

    What failure looks like: the flag is computed from `injected_retrieved > 0`, which is the
    ENVELOPE's measurement, and a world reachable only by the discriminator is credited with
    being reachable by the capture.
    """
    ep, family = scene(tmp_path, monkeypatch, worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(
            inject=[{"_id": f"i{n}"} for n in range(20)]))),
    ])

    record = run_review(ep, family,
                        adapters=W.FakeAdapters({("elastic", "query"): BASE_ANSWER}))

    block = block_of(record)
    assert block["reachable_by_capture"] is False, (
        "a large injection was read as reach — the flag is derived from the overlay's size")
    assert block["injected_present"] == 20


def test_capture_addressed_false_when_no_captured_query_names_a_staged_pattern(
        tmp_path, monkeypatch):
    """No captured query names this world's staged pattern (or its patched system), so the
    capture never addressed it.

    Observably true: a capture holding only calls against a pattern no world stages sets
    `capture_addressed: false` and takes no re-ask. The patched-system arm COUNTS as addressing
    (ledger F4, resolved at §7), because it decides which worlds can be withheld.

    What failure looks like: `capture_addressed` defaults to true, and a world nobody could
    have asked about is withheld for the wrong reason — or worse, blamed.
    """
    ep, family = scene(tmp_path, monkeypatch,
                       captured=[W.captured_row(key="k1", params={"index": W.ALERTS_PATTERN})])

    record = run_review(ep, family,
                        adapters=W.FakeAdapters({("elastic", "query"): BASE_ANSWER}))

    block = block_of(record)
    assert block["capture_addressed"] is False, (
        "capture_addressed is true for a capture that names no staged pattern")
    assert block["capture_replays"] == []


def test_capture_addressed_true_when_a_captured_query_names_the_patched_system(
        tmp_path, monkeypatch):
    """THE PATCHED-SYSTEM ARM, EXERCISED: a patch-only world the capture queried IS addressed.

    Observably true: a world whose overlay is a `patches` table alone — it stages no elastic
    pattern at all — whose capture holds one call against the PATCHED system reads
    `capture_addressed: true` and takes its re-ask (`capture_replays` names the captured key).
    The captured call carries NO `index`, asserted below, so the staged-pattern arm structurally
    cannot be the reason: the patched system is the only thing that can make this world
    addressed. Ledger fork F4, resolved at §7 (`resolved_by: auto`, taken as recommended):
    `capture_addressed` is true when a captured query names a staged pattern OR the patched
    system, because it decides which worlds can be withheld.
    `test_capture_addressed_false_when_no_captured_query_names_a_staged_pattern` is the control
    on the same field.

    What failure looks like: the pattern arm alone is implemented. Every patch-only world then
    reads `capture_addressed: false`, which the ladder turns into
    `withheld_reason: capture_unaddressed`, which suppresses every `subject: defender` finding
    authored from it and removes it from the `verdict_word` vote — so a family of patch-only
    worlds grades `undecidable` and the loop learns nothing from any of them, silently, under a
    recorded reason ("nobody asked the corpus") that is false.
    """
    patched = W.captured_row("identity", "get-host", key="k1", params={"host": "web-1"},
                             payload={"host": "web-1", "owner": "base-team"})
    assert "index" not in patched["params"], (
        "the isolating control failed — this capture names a pattern, so the staged-pattern arm "
        "could be the reason `capture_addressed` is true and this test would not be about the "
        "patched-system arm at all")
    ep, family = scene(tmp_path, monkeypatch, captured=[patched], worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(patches={"identity": {"web-1": {"owner": "platform"}}})),
    ])

    record = run_review(ep, family, adapters=W.FakeAdapters(
        {("identity", "get-host"): {"host": "web-1", "owner": "base-team"}}))

    block = block_of(record)
    assert block["capture_addressed"] is True, (
        f"capture_addressed is {block['capture_addressed']!r} for a patch-only world whose "
        "capture queried the system it patches — F4's patched-system arm is not implemented, "
        "and every patch-only world is withheld as capture_unaddressed")
    assert [e["key"] for e in block["capture_replays"]] == ["k1"], (
        f"the addressed world took no re-ask: {block['capture_replays']!r} — `capture_addressed` "
        "was set without the measurement it exists to gate")


def test_a_staging_error_counts_as_a_faulted_reask_not_a_quiet_one(tmp_path, monkeypatch):
    """A staging refusal on the world arm is a FAULTED re-ask, never a quiet non-difference.

    Observably true: an adapter that refuses this world's view by name records
    `faulted: true` for that key and increments `capture_reasks_faulted` — it does not record
    `differs: false`.

    What failure looks like: the refusal is caught and the key skipped, so a world whose staged
    view could not be reached at all reads exactly like a world that was reached and held no
    difference — which routes it to the wrong withholding reason and, worse, may leave it
    reading as measured.
    """
    ep, family = scene(tmp_path, monkeypatch)

    record = run_review(ep, family, adapters=W.FakeAdapters(
        {("elastic", "query"): BASE_ANSWER},
        by_target={},
        fault=W.Fault(fail_on=(W.world_token("b"),))))

    block = block_of(record)
    faulted = [e for e in block["capture_replays"] if e["faulted"]]
    assert faulted, f"a refused world arm recorded {block['capture_replays']}"
    assert all(e["differs"] is not False for e in faulted), (
        "a faulted re-ask recorded differs:false — an instrument failure was recorded as a "
        "measurement")
    assert block["capture_reasks_faulted"] >= 1


# ---------------------------------------------------------------------------------------
# The two arms: the base pattern, memoised once per key per episode
# ---------------------------------------------------------------------------------------


def test_the_base_arm_is_read_once_per_key_across_all_worlds(tmp_path, monkeypatch):
    """The un-rewritten base pattern is read ONCE per captured key per episode, however many
    worlds re-ask it.

    Observably true: a three-world family re-asking one captured key issues exactly one base
    read while issuing one world read per world. The memo is at EPISODE scope — that is what
    makes M1's cost linear in the capture rather than in capture x worlds.

    What failure looks like: one base read per world. The bound M1 states is exceeded silently,
    and — worse — the base arm is re-read at three different moments, so the world arms are
    compared against three different base answers.
    """
    ep, family = scene(tmp_path, monkeypatch, worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}]))),
        W.world_doc("c", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i2"}]))),
        W.world_doc("d", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i3"}]))),
    ])
    adapters = W.CountingAdapters({("elastic", "query"): BASE_ANSWER})

    run_review(ep, family, adapters=adapters)

    base_reads = [c for c in adapters.calls
                  if "index" in c[2]
                  and "wv-" not in json.dumps(c[2], sort_keys=True, default=str)]
    assert len(base_reads) == 1, (
        f"the base pattern was read {len(base_reads)} times over three worlds — the memo is "
        "per world rather than per episode")


def test_the_base_arm_never_carries_an_overlay_supplied_param(tmp_path, monkeypatch):
    """The base arm re-asks THE CAPTURE'S OWN params — never a param the overlay supplied.

    Observably true: no base read's params contain the world token or any value the overlay
    introduced; every base read's params are byte-equal to the captured row's own. The base arm
    is the un-rewritten control, and a control carrying the treatment's parameters measures
    nothing.

    What failure looks like: the world's `asked_params` are reused for both arms "because they
    are the same call", and the two arms then read the same staged index — which reports every
    world as unreachable, for every capture, forever.
    """
    ep, family = scene(tmp_path, monkeypatch)
    adapters = W.CountingAdapters({("elastic", "query"): BASE_ANSWER})

    run_review(ep, family, adapters=adapters)

    # Scoped to reads that carry an INDEX: the discriminator's own envelope is an ESQL call
    # with no index param, and it is not a capture re-ask — including it would make this
    # assertion about a read the demand is not about.
    base_reads = [p for _s, _v, p in adapters.calls
                  if "index" in p and "wv-" not in json.dumps(p, sort_keys=True, default=str)]
    assert base_reads, "no base-arm read was issued at all"
    for params in base_reads:
        assert params.get("index") == W.EVENTS_PATTERN, (
            f"the base arm carried {params!r} rather than the capture's own params")


def test_the_world_arm_refuses_a_foreign_world_view(tmp_path, monkeypatch):
    """The world arm may reach THIS world's view and no sibling's.

    Observably true: asking the estate's own refusal — `registry.refuse_a_foreign_world_view` —
    for world b's context about world c's view name raises, and the review's own world arm
    never reaches a sibling's token on the wire.

    What failure looks like: the re-ask is issued with a bare index string and no world
    declaration, so the confinement guard admits whichever `wv-` name the caller composed —
    and one world's measurement is taken against another world's corpus.
    """
    ep, family = scene(tmp_path, monkeypatch, worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}]))),
        W.world_doc("c", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i2"}]))),
    ])
    registry = W.mod("learning.branch.estate.registry")
    adapters = W.CountingAdapters({("elastic", "query"): BASE_ANSWER})

    record = run_review(ep, family, adapters=adapters)

    assert block_of(record)["capture_replays"], (
        "no capture re-ask was issued, so the sweep of world-arm reads below is over an empty "
        "list and proves nothing about what the arm may reach")
    own = W.mod("runtime.branch._family").parse_world(W.world_doc(
        "b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}]))))
    with pytest.raises(W.refusals()):
        registry.refuse_a_foreign_world_view(
            own, "elastic", "query", {"index": f"wv-{W.world_token('c')}-logs"})
    for _s, _v, params in adapters.calls:
        rendered = json.dumps(params, sort_keys=True, default=str)
        if W.world_token("b") in rendered:
            assert W.world_token("c") not in rendered, (
                f"world b's re-ask reached a sibling's view: {params}")


def test_the_world_arm_admits_this_worlds_own_view(tmp_path, monkeypatch):
    """The positive control for the refusal above: a world's OWN view is admitted.

    Observably true: the review's world arm reaches an index carrying world b's own token, and
    the estate's refusal declines to refuse that name for that world. Without this, the
    negative would pass on an arm that reaches nothing at all.

    What failure looks like: the confinement is tightened until no world view is reachable, and
    every re-ask faults — which reads as a cluster outage rather than as a guard that closed.
    """
    ep, family = scene(tmp_path, monkeypatch)
    registry = W.mod("learning.branch.estate.registry")
    adapters = W.CountingAdapters(
        {("elastic", "query"): BASE_ANSWER},
        by_target={W.world_token("b"): STAGED_ANSWER})

    run_review(ep, family, adapters=adapters)

    reached = [p for _s, _v, p in adapters.calls
               if W.world_token("b") in json.dumps(p, sort_keys=True, default=str)]
    assert reached, f"no read reached world b's own view: {adapters.calls}"
    own = W.mod("runtime.branch._family").parse_world(W.world_doc(
        "b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}]))))
    registry.refuse_a_foreign_world_view(
        own, "elastic", "query", {"index": f"wv-{W.world_token('b')}-logs"})


def test_any_reask_fault_records_faulted_and_the_pattern_loop_continues(tmp_path, monkeypatch):
    """One key's fault does not end the loop — the remaining keys are still re-asked.

    Observably true: a capture of three keys where the second faults produces three
    `capture_replays` entries, one of them `faulted: true`, and the third key still carries a
    measurement. The fault class is a real adapter fault (`UpstreamFault`, the class
    `docker_exec_curl` and the adapter bodies actually raise), not an invented one.

    What failure looks like: the exception propagates out of the world's loop, and every key
    after the first fault is silently unmeasured with the block reporting only the keys that
    happened to come before it.
    """
    ep, family = scene(tmp_path, monkeypatch, captured=[
        W.captured_row(key="k1", params={"index": W.EVENTS_PATTERN, "q": "a"}),
        W.captured_row(key="k2", params={"index": W.EVENTS_PATTERN, "q": "boom"}),
        W.captured_row(key="k3", params={"index": W.EVENTS_PATTERN, "q": "c"}),
    ])

    record = run_review(ep, family, adapters=W.FakeAdapters(
        {("elastic", "query"): BASE_ANSWER}, fault=W.Fault(fail_on=("boom",))))

    block = block_of(record)
    keys = [e["key"] for e in block["capture_replays"]]
    assert set(keys) == {"k1", "k2", "k3"}, (
        f"the loop stopped at the fault — only {keys} were measured")
    assert [e["faulted"] for e in block["capture_replays"] if e["key"] == "k2"] == [True]


def test_a_captured_row_whose_pattern_cannot_be_derived_is_never_re_asked(
        tmp_path, monkeypatch):
    """A captured row with no derivable source pattern is not selected for re-ask.

    Observably true: a captured row whose params name no index at all — for which
    `stagers/elastic.py::source_pattern` hands back `None` — produces no `capture_replays`
    entry and no read on either arm, while a sibling row that DOES name one is re-asked.

    What failure looks like: `None` is used as an index. Either the adapter is asked for a
    pattern spelled `None`, or the base and world arms both fall back to a configured default
    and a difference is measured on a query the capture never made.
    """
    ep, family = scene(tmp_path, monkeypatch, captured=[
        W.captured_row(key="k1", params={"index": W.EVENTS_PATTERN}),
        W.captured_row(key="k2", system="host_state", verb="get-host", params={"host": "web-1"}),
    ])
    adapters = W.CountingAdapters({("elastic", "query"): BASE_ANSWER})

    record = run_review(ep, family, adapters=adapters)

    assert [e["key"] for e in block_of(record)["capture_replays"]] == ["k1"], (
        "a row with no derivable pattern was re-asked")
    assert all("None" not in json.dumps(p, default=str) for _s, _v, p in adapters.calls), (
        f"a read was issued for a pattern spelled None: {adapters.calls}")


def test_both_new_reads_go_through_the_recording_read_door_with_the_plain_ctx(
        tmp_path, monkeypatch):
    """Both new reads — M1's base arm and M2's witness — are recorded wherever reads are
    recorded, and both carry the PLAIN ctx.

    Observably true: driving the review issues its base-arm reads through the same recording
    read door every other adapter read goes through, and no base-arm read carries a `world_id`
    declaration. Parity across the two vias is the property: a read that skips the door records
    nothing anywhere, and a base read carrying a world id would let the confinement guard admit
    that world's views for a control read.

    What failure looks like: the base arm reaches `transport.docker_exec_curl` directly for
    speed. The read then happens, costs money and time, and appears in no queries table — the
    same class of invisibility `staged.yaml` is the only record of on the staging door.
    """
    ep, family = scene(tmp_path, monkeypatch)
    adapters = W.CountingAdapters({("elastic", "query"): BASE_ANSWER})

    record = run_review(ep, family, adapters=adapters)

    # THE READS MUST EXIST BEFORE THEIR SHAPE MEANS ANYTHING. Without this the assertion below
    # is satisfied by a pass that issues no capture re-ask at all — the vacuous form of every
    # "and it goes through the right door" demand.
    assert block_of(record)["capture_replays"], (
        "no capture re-ask was issued, so no new read exists to be recorded at a door")
    base_reads = [p for _s, _v, p in adapters.calls
                  if "index" in p and "wv-" not in json.dumps(p, sort_keys=True, default=str)]
    assert base_reads, (
        f"no base-arm read reached the recording adapter seam: {adapters.calls}")
    for params in base_reads:
        assert "world_id" not in params, (
            f"a base-arm read declared a world: {params}")


def test_a_faulted_base_arm_is_not_memoised_across_worlds(tmp_path, monkeypatch):
    """The memo caches SUCCESSES only — a faulted base arm is retried for the next world.

    Observably true: with the base arm failing on its first call and succeeding afterwards, a
    two-world family still measures the second world: the base read is issued twice and world
    c's entry is not `faulted`.

    What failure looks like: the fault is memoised, and one transient cluster hiccup during the
    first world's re-ask marks every remaining world of the episode unmeasurable — an episode
    written off for a blip.
    """
    ep, family = scene(tmp_path, monkeypatch, worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}]))),
        W.world_doc("c", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i2"}]))),
    ])

    class FlakyBase(W.CountingAdapters):
        def __call__(self, system, verb, **params):
            rendered = json.dumps(params, sort_keys=True, default=str)
            # Scoped to reads carrying an INDEX: the discriminator's envelope is an ESQL call
            # with none, and faulting it would end the world for a reason this arm is not about.
            if "index" in params and "wv-" not in rendered:
                self.calls.append((system, verb, dict(params)))
                if len([c for c in self.calls if "index" in c[2] and "wv-" not in
                        json.dumps(c[2], sort_keys=True, default=str)]) == 1:
                    raise W.FakeDoor._upstream_fault("base pattern read failed once")
                return BASE_ANSWER
            return super().__call__(system, verb, **params)

    adapters = FlakyBase(by_target={W.world_token("c"): STAGED_ANSWER})
    record = run_review(ep, family, adapters=adapters)

    base_reads = [c for c in adapters.calls
                  if "index" in c[2]
                  and "wv-" not in json.dumps(c[2], sort_keys=True, default=str)]
    assert len(base_reads) >= 2, (
        "the base arm was read once and its FAULT was memoised for every later world")
    assert not all(e["faulted"] for e in block_of(record, "c")["capture_replays"]), (
        "world c inherited world b's transient base-arm fault")


def test_two_captured_rows_sharing_a_pattern_and_differing_in_params_get_their_own_base_answers(
        tmp_path, monkeypatch):
    """The memo key is the FULL `(source_pattern, params)` tuple, not the pattern alone.

    Observably true: two captured rows against the same index with different query params each
    get their own base read, and each world entry is compared against its own base answer.

    What failure looks like: the memo keys on the pattern, so the second query's world arm is
    compared against the FIRST query's base answer — a difference manufactured (or erased) by
    the cache, on a value nothing downstream can re-derive.
    """
    ep, family = scene(tmp_path, monkeypatch, captured=[
        W.captured_row(key="k1", params={"index": W.EVENTS_PATTERN, "q": "one"}),
        W.captured_row(key="k2", params={"index": W.EVENTS_PATTERN, "q": "two"}),
    ])
    adapters = W.CountingAdapters(
        sequence={'"q": "one"': [BASE_ANSWER], '"q": "two"': [STAGED_ANSWER]})

    run_review(ep, family, adapters=adapters)

    base_reads = [p for _s, _v, p in adapters.calls
                  if "index" in p and "wv-" not in json.dumps(p, sort_keys=True, default=str)]
    assert len(base_reads) == 2, (
        f"two params sharing one pattern issued {len(base_reads)} base reads — the memo key "
        "is the pattern alone, so one query's answer is serving the other")


# ---------------------------------------------------------------------------------------
# H4 — the confirming re-read, and the layer the ladder's safety actually lives in
# ---------------------------------------------------------------------------------------


def test_a_difference_is_recorded_only_after_one_confirming_re_read(tmp_path, monkeypatch):
    """A difference is confirmed by ONE back-to-back re-read before it is recorded.

    Observably true: an arm that answers differently on its first read and identically on its
    second records `differs: false` — the difference did not survive, so it was skew, not a
    fact. The positive control rides in the same test: an arm that differs on BOTH reads
    records `differs: true`.

    What failure looks like: the first comparison is recorded. Time skew between a memoised
    base arm and a later world arm then reads as this world's declared difference, and the
    ladder credits a world for a document that arrived while the review was running.
    """
    ep, family = scene(tmp_path, monkeypatch)
    flapping = W.CountingAdapters(
        {("elastic", "query"): BASE_ANSWER},
        sequence={W.world_token("b"): [STAGED_ANSWER, BASE_ANSWER]})

    record = run_review(ep, family, adapters=flapping)
    assert block_of(record)["capture_replays"][0]["differs"] is False, (
        "a difference that did not survive a back-to-back re-read was recorded as a fact")

    ep2, family2 = scene(tmp_path / "second", monkeypatch)
    steady = W.CountingAdapters(
        {("elastic", "query"): BASE_ANSWER},
        by_target={W.world_token("b"): STAGED_ANSWER})
    record2 = run_review(ep2, family2, adapters=steady)
    assert block_of(record2)["capture_replays"][0]["differs"] is True, (
        "the control failed — a difference that DOES survive two reads was not recorded")


def test_a_non_differing_comparison_takes_no_second_read(tmp_path, monkeypatch):
    """The confirming re-read happens ONLY on the differing path.

    Observably true: when the first comparison is SAME (or FORMATTING), the world arm is read
    exactly once — the extra read is the price of recording a difference, not of every key.
    Its positive control is the test above, where a differing path DOES take a second read.

    What failure looks like: an unconditional double read. M1's stated bound doubles for every
    captured query of every world, on the common path where nothing differs at all.
    """
    ep, family = scene(tmp_path, monkeypatch)
    adapters = W.CountingAdapters({("elastic", "query"): BASE_ANSWER})

    record = run_review(ep, family, adapters=adapters)

    # The positive control for this negative lives one test up, where a DIFFERING path is shown
    # to take its second read. Here the re-ask must have happened at all, or "exactly one read"
    # is satisfied by a pass that re-asked nothing.
    replays = block_of(record)["capture_replays"]
    assert replays, "this drive produced no re-ask at all"
    assert replays[0]["differs"] is False, (
        f"this drive did not produce a completed non-differing re-ask: {replays}")
    world_reads = [p for _s, _v, p in adapters.calls
                   if W.world_token("b") in json.dumps(p, sort_keys=True, default=str)
                   and "index" in p]
    assert len(world_reads) == 1, (
        f"a non-differing key took {len(world_reads)} world reads — the confirming re-read is "
        "unconditional, so every captured query of every world costs two")


def test_a_missing_arm_records_faulted_once_and_never_reaches_the_comparator(
        tmp_path, monkeypatch):
    """A missing side is guarded BEFORE the comparator: `mechanical(None, <text>)` raises an
    uncaught `TypeError`.

    Observably true: with the base arm faulting and the world arm answering, the key records
    `faulted: true` exactly once and the comparator is never invoked with a `None` side — and
    the review completes rather than dying. Executed and probed: `mechanical(None, text)`
    raises out of `_folded`'s `re.sub`, which is neither a `ValueError` nor an
    `AdapterFault` and is in no handler above it.

    What failure looks like: one arm's `None` is passed straight to `mechanical`, and a single
    unreachable base pattern takes down the whole review pass with a bare `TypeError` after
    every other world's reads have already been paid for.
    """
    comparator = W.mod("learning.branch.comparator")
    ep, family = scene(tmp_path, monkeypatch)
    seen: list[tuple] = []

    def watched(a, b):
        seen.append((a, b))
        return comparator.mechanical(a, b)

    record = run_review(ep, family, adapters=W.FakeAdapters(
        by_target={W.world_token("b"): STAGED_ANSWER},
        fault=W.Fault(fail_on=(W.EVENTS_PATTERN,))), invoke=W.FakeAgent("same"))

    block = block_of(record)
    faulted = [e for e in block["capture_replays"] if e["faulted"]]
    assert len(faulted) == 1, f"a missing arm recorded {block['capture_replays']}"
    assert all(a is not None and b is not None for a, b in seen), (
        f"a None side reached the comparator: {seen}")


def test_two_empty_results_are_the_same_answer_and_not_a_difference(tmp_path, monkeypatch):
    """Both arms empty is SAME — an `exclude` world that removed everything shows no difference
    by this instrument.

    Observably true: with both arms answering an empty hit list, `mechanical` reads SAME and
    the entry records `differs: false`. Two empties are two equal answers; calling that a
    difference would credit every world whose corpus is simply quiet.

    What failure looks like: emptiness is treated as "no answer" and routed to the model
    comparator, or worse recorded as an unsettled difference — paying for a model call per
    empty key and manufacturing reach out of silence.
    """
    comparator = W.mod("learning.branch.comparator")
    empty = json.dumps({"hits": []}, sort_keys=True)
    assert comparator.mechanical(empty, empty) == comparator.Verdict.SAME

    ep, family = scene(tmp_path, monkeypatch, worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(
            inject=[], exclude={"match_all": {}}))),
    ])

    record = run_review(ep, family, adapters=W.FakeAdapters({("elastic", "query"): {"hits": []}}))

    block = block_of(record)
    assert block["capture_replays"][0]["differs"] is False
    assert block["reachable_by_capture"] is False


def test_the_search_envelope_the_ledger_sees_carries_no_took_shards_or_document_id(tmp_path):
    """The ladder's safety lives in `elastic_adapter._search`'s normalization, and this pins it.

    Observably true: a REAL raw Elasticsearch response carrying `took`, `_shards` and per-hit
    `_id` — the three fields that move between two identical reads for reasons no world caused
    — reaches the real `query` verb, and the envelope that comes back carries exactly
    `{index, total, returned, sort, truncated, hits}` with only the documents' `_source`.

    This is a real input through the real primitive: the response is written to disk and served
    by a `docker` on the run's own PATH, so the assumption is re-probed on every run rather
    than pinned once. It matters because `mechanical` does NOT protect against incidental
    fields — a genuine content difference and an incidental one both return `None` — so if this
    normalization ever stops, every re-asked key of every world starts reading as a difference.

    What failure looks like: `took` survives into the payload the ledger records, and two live
    reads of one unchanged corpus differ on every single key.
    """
    ea = W.mod("scripts.adapters.elastic_adapter")
    ctx = W.elastic_ctx(tmp_path, response=W.RAW_ES_RESPONSE)

    envelope = ea.query(ctx, native_query="event.action:ssh_login")

    assert set(envelope) == {"index", "total", "returned", "sort", "truncated", "hits"}, (
        f"the envelope carries {sorted(envelope)} — a field the ladder cannot tolerate "
        "survived normalization")
    rendered = json.dumps(envelope, sort_keys=True)
    for incidental in ("took", "_shards", "_id", "_score", "max_score"):
        assert incidental not in rendered, (
            f"{incidental!r} reached the payload the ledger and the comparator see")
    assert envelope["hits"] == [h["_source"] for h in W.RAW_ES_RESPONSE["hits"]["hits"]]
