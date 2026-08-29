"""#947 — review by replay, and the blind comparator (M4, M5, O2, O3, O4, O8, O11).

The review replays the captured query set through a `WorldRegistry` over the staged world,
against a SCRATCH ledger whose base file is empty. That is load-bearing rather than tidy: the
serving path answers from the primed capture before it calls any adapter (C15), so a review run
through the episode's own ledger would read the capture back and agree with itself — a green
review that proves nothing. Its verb context is host-side over the episode dir, and its capture
recorder is absent, so the replay writes no query row anywhere.

**A REVIEW DOES NOT GATHER EVIDENCE** (decided after the spec was written, and recorded here
because the prose above it predates the decision). Every key the capture holds is answered FROM
the capture — each world's replayed answer is its own difference applied to the captured payload
— and no adapter is reached for it. Re-asking the estate would measure how far it has moved
since the source run rather than what the world declares, once per captured key per world. The
one call the review still ASKS is the discriminating envelope, which the capture does not hold
and which the reachability half exists to run; `test_947_an_uncaptured_key_does_reach_the_adapter`
is its positive control.

World A is replayed FIRST as the control, and its mismatch set is drift — under replay-only that
is the drift the capture records against ITSELF, a key the source run asked twice and was
answered twice, which is the only estate movement that happened while this episode's evidence
was being written. For B and C a key that mismatches, is not in the control's set and is not
formatting is a contradiction, and one contradiction rejects. A FAULT is never a contradiction: a
call that could not be replayed for one world and could be for its control is contamination, not
signal.

The comparator is blind by SIGNATURE — two payloads and an axis, nothing else — and mechanical
first: a canonical re-dump answers `same` or `formatting` with no model call at all.

RED against b8a63e66: `learning/branch/review.py` and `learning/branch/comparator.py` do not
exist (X16).
"""
from __future__ import annotations

import json

import pytest

from defender.tests import _triplet_947 as T

TOKEN_B = T.world_token("b")


def _review():
    return T.mod("learning.branch.review")


def _compare():
    return T.mod("learning.branch.comparator")


def _run_review(episode_dir, *, adapters=None, door=None, invoke=None, doc=None, **kw):
    fam = T.mod("runtime.branch._family").parse_family(doc if doc is not None else T.family_doc())
    return _review().review(
        fam, episode_dir=episode_dir, adapters=adapters or T.FakeAdapters(),
        door=door or T.FakeDoor(counts={"logs-000001": 3}), invoke=invoke or T.FakeAgent("same"),
        **kw)


# ---------------------------------------------------------------------------------------
# the replay's own seams
# ---------------------------------------------------------------------------------------


def test_947_review_registry_uses_a_scratch_ledger_with_an_empty_base(tmp_path):
    """The replay registry reads through a scratch ledger whose base file is empty: with the
    episode's own primed capture as its base every captured key would answer from the capture
    and the review would agree with itself, so the review's ledger holds no base rows."""
    ep = T.episode(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1")])
    ledger = _review().scratch_ledger(ep)
    assert ledger.base_payload("k1") is None
    assert not list(ledger.base_rows())


def test_947_review_verb_context_is_host_side_over_the_episode_dir(tmp_path, monkeypatch):
    """The replay's verb context is host-side over the episode dir: its tree is the episode
    directory rather than any run dir, it carries no capture recorder at all, and the environment
    the host composes for it names that directory as the run dir and the CONFIGURED runs base as
    the runs base its adapter subprocesses inherit — never the episode dir's own parent, which
    after §7 round 2 is the EPISODES ROOT, a location that is not a runs base and that no
    runs-base walk may reach."""
    base, _src, root = T.configured_layout(tmp_path, monkeypatch)
    ep = T.episode(tmp_path, root=root)
    ctx = _review().verb_context(ep)
    assert ctx.run_dir == ep
    assert ctx.capture is None
    assert ctx.env["DEFENDER_RUN_DIR"] == str(ep)
    # `run_common.run_env` sets DEFENDER_RUNS_BASE = run_dir.parent unconditionally
    # (`run_common.py:119`), which is F10's precondition — "correct here only because the episode
    # dir is a direct child of the runs base" — and after two relocations that is false. The
    # review COMPOSES the configured runs base instead; inheriting the parent would point every
    # replay subprocess at the tree holding every episode.
    assert ctx.env["DEFENDER_RUNS_BASE"] == str(base)
    assert ctx.env["DEFENDER_RUNS_BASE"] != str(ep.parent), (
        "the replay's subprocesses resolve their runs base to the EPISODES ROOT")


def test_947_review_replay_writes_no_query_row_anywhere(tmp_path):
    """The review's replay writes no query row anywhere: no world ledger gains a row, and no run
    dir is written under the episode at all."""
    ep = T.episode(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1")])
    _run_review(ep)
    assert [p.name for p in (ep / "served").iterdir()] == ["base.jsonl"]
    assert not any(p.name == "executed_queries.jsonl" for p in ep.rglob("*"))


def test_947_review_replays_exactly_the_set_prime_base_read(tmp_path):
    """The review replays exactly the set the primer read — the WHOLE captured recording, not a
    slice at the branch point — so review and prime cannot disagree about which calls exist."""
    ep = T.episode(tmp_path)
    rows = [T.captured_row(key=f"k{i}") for i in range(4)]
    T.base_capture(ep, rows)
    record = _run_review(ep)
    replayed = {m["key"] for w in record["worlds"].values()
                for m in w["consistency"]["replayed"]}
    assert replayed == {r["correlation_key"] for r in rows}


def test_947_no_post_branch_query_reaches_a_real_adapter_unasked(tmp_path):
    """No post-branch query reaches a real adapter body unasked: every captured key is answered
    from the primed recording, so the adapter layer records no call for it — on the review's
    replay and on a sibling's own serving path alike."""
    ep = T.episode(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1")])
    adapters = T.FakeAdapters()
    _run_review(ep, adapters=adapters)
    assert ("elastic", "query") not in adapters.asked


def test_947_an_uncaptured_key_does_reach_the_adapter(tmp_path):
    """The positive control for the unasked-query negative: a key the capture does NOT hold does
    reach the adapter, so the negative above is proof of the memo and not of a channel that
    never carries anything."""
    ep = T.episode(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1")])
    adapters = T.FakeAdapters()
    _review().replay_one(("elastic", "esql", {"query": "FROM logs-* | LIMIT 1"}),
                         episode_dir=ep, adapters=adapters)
    assert ("elastic", "esql") in adapters.asked


# ---------------------------------------------------------------------------------------
# drift, contradiction and the control
# ---------------------------------------------------------------------------------------


def test_947_control_world_is_replayed_first_and_its_mismatches_are_drift(tmp_path):
    """World A is replayed first as the control, and the keys it mismatches on are recorded as
    the episode's drift rather than as anything a world did.

    The drift is IN THE CAPTURE: the source run asked `k1` twice and was served two different
    answers, so the estate moved while the evidence this episode reasons over was being written.
    That is the whole of the drift a replay-only review can see, and it is the only drift that
    can matter — the world A of a replay applies nothing, so it can never differ from the
    capture by itself."""
    ep = T.episode(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1", payload={"hits": [{"_id": "old"}]}),
                        T.captured_row(key="k1", payload={"hits": [{"_id": "new"}]})])
    record = _run_review(ep)
    assert list(record["worlds"])[0] == "a"
    assert record["worlds"]["a"]["consistency"]["control_mismatch_keys"] == ["k1"]


def test_947_mismatch_outside_control_and_not_formatting_is_a_contradiction(tmp_path):
    """A key that mismatches in a world, is not in the control's mismatch set and is not merely
    a formatting difference is recorded as a contradiction, and the world is rejected.

    Driven through the REPLAYED captured value: world B patches `web-1`'s owner, the capture
    holds one answer naming that host, and applying the patch to it produces a payload that
    cannot be true of the same corpus. The capture agrees with itself on `k1`, so the key is not
    in the control's set and the blind comparator is what decides."""
    ep = T.episode(tmp_path)
    T.base_capture(ep, [T.captured_row(
        system="identity", verb="get-user", key="k1",
        payload={"hits": [{"host": "web-1", "owner": "soc"}]})])
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        patches={"identity": {"web-1": {"owner": "platform"}}}))])
    record = _run_review(ep, doc=doc, invoke=T.FakeAgent("contradiction"))
    b = record["worlds"]["b"]
    verdicts = {m["key"]: m["verdict"] for m in b["consistency"]["mismatches"]}
    assert verdicts.get("k1") == "contradiction"
    assert b["decision"] == "rejected"


def test_947_key_that_also_mismatches_in_the_control_does_not_reject(tmp_path):
    """A key that also mismatches in the control is drift and never rejects a world: the same
    key that would be a contradiction on its own is subtracted by the control's own result.

    The fixture is the contradiction test's, plus one thing: the capture answers `k1` twice and
    differently. That alone moves the key into the control's set, and the world whose patch
    would otherwise contradict it is accepted — which is what makes this the subtraction's
    control rather than a second reading of it."""
    ep = T.episode(tmp_path)
    T.base_capture(ep, [
        T.captured_row(system="identity", verb="get-user", key="k1",
                       payload={"hits": [{"host": "web-1", "owner": "soc"}]}),
        T.captured_row(system="identity", verb="get-user", key="k1",
                       payload={"hits": [{"host": "web-1", "owner": "netops"}]}),
    ])
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        patches={"identity": {"web-1": {"owner": "platform"}}}))])
    record = _run_review(ep, doc=doc, invoke=T.FakeAgent(*["contradiction"] * 12))
    assert "k1" in record["worlds"]["a"]["consistency"]["control_mismatch_keys"]
    assert record["worlds"]["b"]["decision"] == "accepted"


def test_947_contradicting_world_is_rejected_before_any_sibling_starts(tmp_path, monkeypatch):
    """A world whose replayed answer contradicts the capture is rejected in the review, before
    any sibling process is started, and the review record names the contradicting key.

    Driven end to end: the SOURCE run carries the captured call, so the launcher's own priming
    is what puts `k1` in the episode's base, and the world the questioner authors patches the
    entity that answer names. Both configured roots point inside `tmp_path`, because
    `episode_dir_for` refuses to invent an episodes root."""
    base, src = T.runs_base(tmp_path)
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(base))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.capture_call(src, system="identity", verb="get-user",
                   payload={"hits": [{"host": "web-1", "owner": "soc"}]})
    spawn = T.FakeSpawn()
    cli = T.mod("learning.branch.cli")
    patched = T.world_doc("b", ov=T.overlay(
        patches={"identity": {"web-1": {"owner": "platform"}}}))
    rc = cli.main([str(src), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
                  spawn=spawn, door=T.FakeDoor(), adapters=T.FakeAdapters(),
                  invoke=T.FakeAgent(*["contradiction"] * 12), preflight=T.no_preflight,
                  questioner=T.FakeAgent(
                      T.family_doc(worlds=[T.base_world(), patched]), patched))
    ep = cli.episode_dir_for(T.EPISODE_ID)
    assert rc != 0
    assert spawn.launches == [], "a sibling started for a rejected episode"
    doc = T.review_doc(ep)
    assert doc["episode"]["decision"] == "rejected"
    assert doc["worlds"]["b"]["decision"] == "rejected"
    named = [m["key"] for m in doc["worlds"]["b"]["consistency"]["mismatches"]]
    assert named, "the review record names no contradicting key"
    assert json.dumps(doc).count(named[0]) >= 1


def test_947_a_fault_shaped_replay_difference_is_recorded_as_a_fault_not_a_contradiction(tmp_path):
    """A replay whose adapter call FAILS for one world but not for its control is recorded as a
    fault: it is never classified as a corpus contradiction, and it never reaches the
    comparator, because a fault-shaped difference is contamination rather than signal."""
    ep = T.episode(tmp_path)
    # A captured ES|QL call the stager cannot retarget: it opens with no `FROM`, so a world that
    # STAGES the event stream refuses to prepare it while the control, which stages nothing,
    # passes it through untouched. One captured row, two arms, and the difference between them
    # is the harness rather than the world — which is exactly what must not be read as a corpus
    # contradiction.
    T.base_capture(ep, [T.captured_row(system="elastic", verb="esql", key="k1",
                                       params={"query": "SHOW INFO"})])
    invoke = T.FakeAgent(*["same"] * 8)
    record = _run_review(ep, invoke=invoke)
    faults = record["worlds"]["b"]["consistency"].get("faults", [])
    assert any(f["key"] == "k1" for f in faults)
    assert not record["worlds"]["b"]["consistency"]["mismatches"]


def test_947_an_unparseable_capture_row_is_skipped_and_counted(tmp_path):
    """A row in the captured recording that does not parse is SKIPPED and counted in the review
    record, never guessed at and never silently dropped: the control's mismatch set would
    otherwise be under-counted by exactly the rows nobody could read."""
    ep = T.episode(tmp_path)
    path = T.base_capture(ep, [T.captured_row(key="k1")])
    path.write_text(path.read_text(encoding="utf-8") + "{not json\n", encoding="utf-8")
    record = _run_review(ep)
    assert record["episode"]["unreadable_capture_rows"] == 1


# ---------------------------------------------------------------------------------------
# reachability (O3)
# ---------------------------------------------------------------------------------------


def test_947_exclusion_matching_zero_base_documents_rejects_the_world(tmp_path):
    """A world whose exclusion predicate matches zero base documents is rejected: its declared
    difference removes nothing, so the world is not the world it claims to be."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor(counts={"logs-000001": 0}, resolves={T.EVENTS_PATTERN: ("logs-000001",)})
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        elastic=T.elastic_overlay(inject=[], exclude={"term": {"process.name": "nc"}})))])
    record = _run_review(ep, doc=doc, door=door)
    assert record["worlds"]["b"]["reachability"]["exclusion_matches"] == 0
    assert record["worlds"]["b"]["decision"] == "rejected"


def test_947_a_failed_exclusion_count_is_not_recorded_as_zero_matches(tmp_path):
    """An exclusion count that ERRORS is not a zero count: it is recorded as a failed count and
    never as `0`, and it never rejects the world on unreachability grounds — the rejection is
    for a predicate that matched zero documents, not for one nobody could ask about."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor(fault=T.Fault(fail_on=("logs-",)),
                      resolves={T.EVENTS_PATTERN: ("logs-000001",)})
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        elastic=T.elastic_overlay(inject=[], exclude={"term": {"process.name": "nc"}})))])
    record = _run_review(ep, doc=doc, door=door)
    reach = record["worlds"]["b"]["reachability"]
    assert reach["exclusion_matches"] != 0
    assert reach["exclusion_count_failed"] is True
    assert "unreachable" not in (record["worlds"]["b"].get("reason") or "")


def test_947_a_full_match_exclusion_is_recorded_not_rejected(tmp_path):
    """An exclusion matching EVERY base document is recorded rather than rejected: a world that
    is only its own injection is an implausible world, and plausibility does not reject. It is
    spelled `match_all`, the clause Elasticsearch actually has for it and the one §7 round 2
    added to the admitted set — without an admissible spelling this world could be recorded here
    and refused at staging, green in the suite and unreachable in production."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor(counts={"logs-000001": 500}, resolves={T.EVENTS_PATTERN: ("logs-000001",)},
                      )
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        elastic=T.elastic_overlay(inject=[{"_id": "i1"}], exclude={"match_all": {}})))])
    record = _run_review(ep, doc=doc, door=door)
    assert record["worlds"]["b"]["reachability"]["exclusion_matches"] == 500
    assert record["worlds"]["b"]["decision"] == "accepted"
    assert any("exclusion" in note for note in record["worlds"]["b"]["inventions"])


def test_947_envelope_retrieving_none_of_its_injection_rejects_the_world(tmp_path):
    """A world whose discriminating envelope, run in that world, retrieves none of its own
    injected documents is rejected: the injection is unreachable, so the difference the world
    declares cannot be observed."""
    ep = T.episode(tmp_path)
    adapters = T.FakeAdapters({("elastic", "esql"): {"hits": [{"_id": "unrelated"}]}})
    record = _run_review(ep, adapters=adapters)
    assert record["worlds"]["b"]["reachability"]["injected_retrieved"] == 0
    assert record["worlds"]["b"]["decision"] == "rejected"


def test_947_zero_apply_count_on_the_envelope_payload_rejects_the_world(tmp_path):
    """A world whose patch applies to nothing in the envelope's payload is rejected: an apply
    count of zero is the only gate on a patched difference, and a patch that never lands is a
    difference the run cannot measure."""
    ep = T.episode(tmp_path)
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        patches={"identity": {"nosuchhost": {"owner": "platform"}}}))])
    adapters = T.FakeAdapters({("elastic", "esql"): {"hits": [{"host": "web-1"}]}})
    record = _run_review(ep, doc=doc, adapters=adapters)
    assert record["worlds"]["b"]["reachability"]["patched_visible"] is False
    assert record["worlds"]["b"]["decision"] == "rejected"


def test_947_review_record_carries_the_full_reachability_block(tmp_path):
    """Every world's review record carries the whole reachability block — whether the envelope
    ran, how many injected documents were retrieved, whether the patch was visible, and how many
    documents the exclusion matched."""
    ep = T.episode(tmp_path)
    record = _run_review(ep)
    for world in record["worlds"].values():
        assert set(world["reachability"]) >= {
            "envelope_ran", "injected_retrieved", "patched_visible", "exclusion_matches"}


def test_947_exclusion_count_goes_through_the_staging_door_not_an_adapter(tmp_path):
    """The exclusion count is asked through the host-side staging door and never through an
    adapter verb: the door records the count call, and the adapter layer records none."""
    ep = T.episode(tmp_path)
    door = T.FakeDoor(counts={"logs-000001": 3}, resolves={T.EVENTS_PATTERN: ("logs-000001",)})
    adapters = T.FakeAdapters()
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        elastic=T.elastic_overlay(inject=[], exclude={"term": {"process.name": "nc"}})))])
    _run_review(ep, doc=doc, door=door, adapters=adapters)
    assert any(c.op == "count" for c in door.calls)
    assert not any(v == "count" for _s, v in adapters.asked)


def test_947_count_endpoint_is_absent_from_the_elastic_adapter_allowlist(tmp_path):
    """The count endpoint is absent from the adapter's read allowlist and stays absent: the
    allowlist is exactly the four read endpoints it already carries, so nothing the model
    dispatches can ask the cluster to count."""
    confinement = T.mod("scripts.adapters.confinement")
    allow = set(confinement.READ_ENDPOINT_ALLOWLIST["elastic"])
    assert allow == {("/*/_search", "POST"), ("/_query", "POST"),
                     ("/_cluster/health", "GET"), ("/api/status", "GET")}


def test_947_the_injection_count_is_asked_through_the_door_not_a_capped_search(tmp_path):
    """The injected-document count is asked through the staging door too, not read off a
    capped search envelope: a search returns at most one page, so an injection larger than a
    page could never be counted from its hits, and a world would be rejected for the reader's
    limit rather than for its own difference."""
    ep = T.episode(tmp_path)
    cap = T.sym("scripts.adapters.elastic_adapter", "RETURNED_DOC_CAP")
    injected = [{"_id": f"i{n}"} for n in range(cap + 1)]
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        elastic=T.elastic_overlay(inject=injected)))])
    door = T.FakeDoor(counts={f"wv-{TOKEN_B}-logs-.inject": cap + 1})
    record = _run_review(ep, doc=doc, door=door)
    assert record["worlds"]["b"]["reachability"]["injected_retrieved"] == cap + 1
    assert record["worlds"]["b"]["decision"] == "accepted"


# ---------------------------------------------------------------------------------------
# the record itself (O4, O11)
# ---------------------------------------------------------------------------------------


def test_947_every_review_record_carries_a_control_result(tmp_path):
    """Every review record carries the control's own result: drift is measured per episode and
    archived, never assumed."""
    ep = T.episode(tmp_path)
    record = _run_review(ep)
    assert "a" in record["worlds"]
    assert "control_mismatch_keys" in record["worlds"]["a"]["consistency"]


def test_947_rejected_episode_keeps_its_review_on_disk(tmp_path):
    """A rejected episode keeps its review record on disk: the measurement of a family that did
    not run is the second thing the drift obligation is observed by."""
    ep = T.episode(tmp_path)
    T.base_capture(ep, [T.captured_row(key="k1", payload={"hits": [{"_id": "d1"}]})])
    adapters = T.FakeAdapters({("elastic", "query"): {"hits": [{"_id": "d1"}]}},
                              by_target={TOKEN_B: {"hits": [{"_id": "planted"}]}})
    _run_review(ep, adapters=adapters, invoke=T.FakeAgent("contradiction"))
    assert (ep / "review.yaml").is_file()
    assert T.review_doc(ep)["episode"]["decision"] == "rejected"


def test_947_an_invented_entity_is_noted_in_the_review_record(tmp_path):
    """An overlay entity for which the capture and a live count both hold zero rows is recorded
    as a note in the review record, per system, so a later reader sees it without re-deriving
    it."""
    ep = T.episode(tmp_path)
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        patches={"identity": {"ghost-9": {"owner": "platform"}}}))])
    record = _run_review(ep, doc=doc, door=T.FakeDoor(counts={}))
    notes = record["worlds"]["b"]["inventions"]
    assert any("ghost-9" in note and "identity" in note for note in notes)


def test_947_an_invention_alone_never_rejects_a_world(tmp_path):
    """An invention alone never rejects a world: the inventions obligation is a RECORDING one,
    and rejecting on it would make a cheap rule the judge of what a world may assert."""
    ep = T.episode(tmp_path)
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b", ov=T.overlay(
        patches={"identity": {"ghost-9": {"owner": "platform"}}},
        elastic=T.elastic_overlay(inject=[{"_id": "i1"}])))])
    adapters = T.FakeAdapters({("elastic", "esql"): {"hits": [{"_id": "i1", "host": "ghost-9"}]}})
    record = _run_review(ep, doc=doc, adapters=adapters)
    assert record["worlds"]["b"]["inventions"]
    assert record["worlds"]["b"]["decision"] == "accepted"


# ---------------------------------------------------------------------------------------
# the comparator (M5, O8)
# ---------------------------------------------------------------------------------------


def test_947_compare_admits_only_two_payloads_and_an_axis():
    """The comparator's blindness is structural: its signature admits two payloads and an axis
    and nothing else — no world label, no trajectory, no disposition, no ledger source."""
    import inspect

    params = list(inspect.signature(_compare().compare).parameters)
    assert params[:3] == ["a", "b", "axis"]
    forbidden = {"world", "world_id", "world_token", "trajectory", "disposition", "role",
                 "source", "seat"}
    assert not forbidden & set(params)


def test_947_the_comparator_prompt_builder_has_no_parameter_for_world_or_disposition():
    """The comparator's prompt builder can carry no identifying argument at all: its parameters
    are the two payloads and the axis, and the prompt it produces from an identifying-looking
    axis carries nothing else that could name which world is which."""
    import inspect

    builder = _compare().build_prompt
    params = set(inspect.signature(builder).parameters)
    assert params <= {"a", "b", "axis"}
    prompt = builder(a='{"x": 1}', b='{"x": 2}', axis="an axis")
    for leak in ("world", "wv-", T.EPISODE_TOKEN, "disposition", "trajectory"):
        assert leak not in prompt


def test_947_comparator_answers_same_or_formatting_without_a_model_call():
    """The comparator answers mechanically first: two payloads whose canonical re-dump is equal
    answer `same`, and two that differ only in key spelling or whitespace answer `formatting` —
    both with no model call at all."""
    agent = T.FakeAgent()
    assert _compare().compare('{"b": 1, "a": 2}', '{"a": 2, "b": 1}', None, invoke=agent) == "same"
    assert _compare().compare('{"host-name": 1}', '{"host_name":  1}', None,
                              invoke=agent) == "formatting"
    assert agent.calls == 0


def test_947_compare_returns_verdict_for_each_seat():
    """ONE verdict type, each seat asserting only its own members: the type carries all five
    members and neither seat narrows it, so nothing structurally prevents a wrong-seat member —
    and the caller is what refuses one. Called with no axis the review seat answers its three
    and REFUSES a delta-seat verdict the model returned; called with a world's axis the derived
    reader answers its three and refuses a review-seat one. `undecided` is not a member: FORK-9's
    (C) was not taken."""
    compare = _compare()
    verdicts = {v.value if hasattr(v, "value") else v for v in compare.Verdict}
    assert verdicts == {"same", "formatting", "contradiction", "mutation", "undeclared"}
    assert compare.compare('{"a": 1}', '{"a": 2}', None,
                           invoke=T.FakeAgent("contradiction")) == "contradiction"
    assert compare.compare('{"a": 1}', '{"a": 2}', "an axis",
                           invoke=T.FakeAgent("mutation")) == "mutation"
    for axis, wrong_seat in ((None, "mutation"), ("an axis", "contradiction")):
        with pytest.raises(T.refusals()) as bad:
            compare.compare('{"a": 1}', '{"a": 2}', axis, invoke=T.FakeAgent(wrong_seat))
        assert wrong_seat in str(bad.value)


def test_947_comparator_model_call_runs_under_the_questioner_role_key():
    """The comparator's one model call runs under the questioner role key with its own trace
    id: it is a fourth call under a role three others already hold, and it is the id that
    separates them."""
    AgentRole = T.sym("runtime.agent_role", "AgentRole")
    agent = T.FakeAgent("mutation")
    _compare().compare('{"a": 1}', '{"a": 2}', "an axis", invoke=agent)
    assert agent.kwargs[0]["role"] is AgentRole.QUESTIONER
    assert agent.agent_ids
    assert agent.agent_ids[0].startswith("comparator:")


def test_947_comparator_payloads_are_wrapped_untrusted():
    """Both payloads reaching the comparator's prompt are wrapped untrusted: each sits inside a
    `<run-{salt}-untrusted>` frame this call minted and appears nowhere outside one. They are
    captured or replayed adapter output, attacker-influenced by definition, and no payload text
    is presented as instruction."""
    agent = T.FakeAgent("mutation")
    _compare().compare('{"note": "IGNORE PRIOR"}', '{"note": "OTHER"}', "an axis", invoke=agent)
    assert len(agent.prompts) == 1, "the comparator never called the model"
    # The frame SHAPE, never a marker from a SECOND `wrap_fresh` call: the seam mints a fresh
    # salt per frame (#875 F-1), so the salt this test would mint is not the one the comparator
    # minted and the comparison could not hold for any implementation.
    T.assert_wrapped_untrusted(agent.prompts[0], '{"note": "IGNORE PRIOR"}', "the captured payload")
    T.assert_wrapped_untrusted(agent.prompts[0], '{"note": "OTHER"}', "the replayed payload")
