"""#1007 — M2's base witness on the staged row, and H1's applied counter.

M2: the serve path takes one extra base-pattern read per staged call and records the outcome on
the staged row itself, so "the sibling was shown the difference" stops being inferred.

H1 (human decision, §7): `apply_patches`' `applied` counter means CONTENT CHANGED, not an
entity-NAME hit. It has THREE independent consumers, each with its own test here — the serve
path's ledger `source`, `_patched_visible` -> `_rejection`'s world-rejection gate, and
`judge/family.py`'s `doctored_answer_served` -> bucket-table selection. 316 existing tests
passed both before and after the executed change with 0 flips, because no existing test drives
an empty or content-identical patch: these three are genuinely new coverage.

RED AGAINST HEAD is the expected state.
"""
from __future__ import annotations

import json
from pathlib import Path


from defender.tests import _world_1007 as W


BASE_PAYLOAD = {"rows": [{"host": "canary-1", "owner": "base-team", "status": "up"}]}


def staged_scene(tmp_path: Path, monkeypatch, *, worlds=None, captured=None):
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


def serve_one_call(ep: Path, family, world_id: str, *, answers=None, tmp_path: Path,
                   index: str = W.EVENTS_PATTERN):
    """Drive the REAL serving registry for one world and hand back `(rows, ctx)`.

    `WorldRegistry` is the frame `_served` lives in and the one a sibling process actually runs.
    The estate under it is a REAL adapters DIRECTORY whose bodies answer from a data table
    (`_world_1007.estate`), because the registry cold-reads that text and checks the grant
    against it at construction — a module-object stand-in never reaches that check, so it would
    not be the shape the seam actually admits.
    """
    registry = W.mod("learning.branch.estate.registry")
    ledger_mod = W.mod("learning.branch.ledger")
    family_mod = W.mod("runtime.branch._family")
    adapters_dir, grant, ctx = W.estate(tmp_path / f"estate-{world_id}", answers=answers)
    world = family_mod.resume_world_from(family, world_id, ep)
    served = ep / "served"
    served.mkdir(parents=True, exist_ok=True)
    path = served / f"{W.world_token(world_id)}.jsonl"
    ledger = ledger_mod.Ledger(path, base_path=served / "base.jsonl")
    reg = registry.WorldRegistry(adapters_dir, grant, world=world, ledger=ledger,
                                 as_of=family.as_of)
    reg.verbs("elastic")["query"](ctx, native_query="event.action:ssh_login", index=index)
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return rows, ctx


# ---------------------------------------------------------------------------------------
# O3/M2 — the witness on the staged row
# ---------------------------------------------------------------------------------------


def test_a_staged_row_carries_differs_from_base_and_a_digest(tmp_path, monkeypatch):
    """A `source: staged` row carries M2's witness pair, and the tool call itself is unchanged.

    Observably true: after one staged serve the ledger row holds `differs_from_base` and
    `base_pattern_digest`, and the payload handed back to the caller is the staged answer
    unmodified. The witness's only outward trace is on the row — the agent's own call is not
    perturbed by it.

    What failure looks like: the extra read's result is folded into the served payload, or the
    fields land on a second row. Either way the sibling is served something the estate did not
    stage, or the pairing every reader does on the first row breaks.
    """
    ep, family = staged_scene(tmp_path, monkeypatch)

    rows, _ctx = serve_one_call(ep, family, "b", tmp_path=tmp_path,
                                answers={"*": BASE_PAYLOAD})

    staged = [r for r in rows if r.get("source") == "staged"]
    assert staged, f"no staged row was written: {rows}"
    assert "differs_from_base" in staged[0], f"the staged row is {sorted(staged[0])}"
    assert "base_pattern_digest" in staged[0]


def test_a_staged_row_equal_to_the_base_answer_is_not_a_difference_shown(
        tmp_path, monkeypatch):
    """A staged answer byte-equal to the base answer is NOT a difference shown.

    Observably true: with the world view and the base pattern answering identically, the staged
    row records `differs_from_base: false` and the grading pass reads `difference_shown: false`
    for that world. This is the whole point of M2: "staged" says the call was retargeted, not
    that anything changed.

    What failure looks like: `source: staged` is read as "shown", which is the inference M2
    exists to replace — and every world whose staging changed nothing is graded as if the
    sibling had been given a difference to notice.
    """
    ep, family = staged_scene(tmp_path, monkeypatch)

    rows, _ctx = serve_one_call(ep, family, "b", tmp_path=tmp_path,
                                answers={"*": BASE_PAYLOAD})

    staged = [r for r in rows if r.get("source") == "staged"]
    assert staged[0]["differs_from_base"] is False, (
        f"an identical staged answer recorded differs_from_base="
        f"{staged[0]['differs_from_base']!r}")


def test_a_patched_row_counts_as_shown_because_its_merged_content_differs(
        tmp_path, monkeypatch):
    """A `patched` row counts as shown BECAUSE its merged content differs — never by
    construction.

    Observably true: a patch that genuinely changes a value serves a payload different from the
    input and the row reads as a difference shown; a name-matching patch whose overlay changes
    nothing serves byte-identical content and does NOT. The by-construction exemption is struck
    (RS-2): `apply_patches` counts an entity-NAME hit today, so `out.update({})` on a
    present-but-empty patch reports `PATCHED` with byte-identical served content — executed and
    refuted, which is exactly why "every patched row showed a difference" is false as written.

    What failure looks like: patched rows are exempted from the witness on the old premise, and
    a world whose patches changed nothing is credited with showing the sibling a difference.
    """
    passthrough, patched, _staged = W.applier_decisions()
    applier_mod = W.mod("learning.branch.estate.applier")
    payload = {"host": "canary-1", "status": "up"}

    changing = applier_mod.WorldApplier().apply(
        "identity", "get-host", {}, dict(payload),
        W.mod("runtime.branch._family").parse_world(W.world_doc(
            "b", ov=W.overlay(patches={"identity": {"canary-1": {"status": "down"}}}))),
        asked=None)
    empty = applier_mod.WorldApplier().apply(
        "identity", "get-host", {}, dict(payload),
        W.mod("runtime.branch._family").parse_world(W.world_doc(
            "c", ov=W.overlay(patches={"identity": {"canary-1": {}}}))),
        asked=None)

    assert changing == (patched, {"host": "canary-1", "status": "down"})
    assert empty[0] == passthrough, (
        f"a name-matching patch that changed nothing reported {empty[0]!r} with content "
        f"{empty[1]!r} — the counter is still counting entity-name hits")


def test_the_base_witness_appends_no_second_ledger_row(tmp_path, monkeypatch):
    """The witness read writes NO second ledger row — the fields ride the staged row.

    Observably true: one staged serve leaves exactly one row for that call in the world's
    ledger. `episode._answers` is first-row-wins, so a witness row would be the FIRST row on a
    captured key and would shadow the staged one for every reader downstream.

    What failure looks like: the witness is recorded as its own row "for the trail". Every
    pairing reader then sees the base answer where the served answer should be, and the whole
    served ledger silently describes a different episode.
    """
    ep, family = staged_scene(tmp_path, monkeypatch)

    rows, _ctx = serve_one_call(ep, family, "b", tmp_path=tmp_path,
                                answers={"*": BASE_PAYLOAD})

    # TWO rows for one served call is the incumbent shape: the FAMILY tier's shared recording
    # (`world_id: null`) that every sibling replays, and this world's own row. A third would be
    # the witness given a row of its own — and because `episode._answers` is first-row-wins, a
    # witness row landing first would shadow the staged one for every reader downstream.
    assert len(rows) == 2, f"one served call wrote {len(rows)} ledger rows: {rows}"
    assert [r["source"] for r in rows][1] == "staged", (
        f"the world's own row is not the second row: {[r['source'] for r in rows]}")
    assert "differs_from_base" in rows[1], (
        "the witness's outcome is not on the staged row, so it went somewhere else")


def test_delta_o_still_classifies_a_staged_key_after_the_witness(tmp_path, monkeypatch):
    """`delta_o` still classifies a staged key exactly as it does today.

    Observably true: with the witness fields on the staged row, `episode.delta_o` returns the
    same classification for that key as it does for the same row without them — the two extra
    keys are additive and no reader keys on the row's key SET.

    What failure looks like: a reader that validates the row shape strictly, or one that pairs
    on a dict comparison, stops recognising staged rows the moment two keys appear on them —
    and every downstream count for the episode silently changes.
    """
    episode_mod = W.mod("learning.branch.episode")
    ep, family = staged_scene(tmp_path, monkeypatch)
    W.write_served(ep, "b", [W.served_row(world="b", differs_from_base=True)])
    with_witness = episode_mod.delta_o(ep)

    W.write_served(ep, "b", [W.served_row(world="b", differs_from_base=None,
                                          base_pattern_digest=None)])
    W.write_served(ep, "b", [{k: v for k, v in W.served_row(world="b").items()
                              if k not in ("differs_from_base", "base_pattern_digest")}])
    without = episode_mod.delta_o(ep)

    assert with_witness == without, (
        f"delta_o classified the same staged key differently with the witness on it: "
        f"{with_witness} != {without}")


def test_the_witness_read_carries_no_world_id(tmp_path, monkeypatch):
    """The witness read goes out on the PLAIN ctx — it declares no world.

    Observably true: the extra base-pattern read the serve path takes carries no `world_id`, so
    the confinement guard admits no world view for it, and it reaches the un-rewritten pattern
    rather than this world's staged one.

    What failure looks like: the witness reuses the serving ctx, which carries the world
    declaration. The "base" arm then reads the world's own staged view, `differs_from_base` is
    false for every world forever, and the field reads as a measurement.
    """
    ep, family = staged_scene(tmp_path, monkeypatch)
    _rows, ctx = serve_one_call(
        ep, family, "b", tmp_path=tmp_path,
        answers={W.world_token("b"): {"rows": [{"host": "x"}]}, "*": BASE_PAYLOAD})

    calls = W.estate_calls(ctx)
    plain = [c for c in calls
             if W.world_token("b") not in json.dumps(c["params"], default=str)]
    assert plain, f"the serve path took no plain-ctx read at all: {calls}"
    for call in plain:
        assert call["world_id"] is None, (
            f"the witness read declared world {call['world_id']!r} — the confinement guard "
            "would then admit that world's own staged views for a control read")


def test_a_faulted_witness_records_null_not_false(tmp_path, monkeypatch):
    """A witness read that faulted records `null`, never `false`.

    Observably true: with the base-pattern read raising, the staged row carries
    `differs_from_base: None`. `false` means the two answers were compared and found equal;
    `null` means the comparison could not be made. Collapsing them charges a world for an
    outage in the estate.

    What failure looks like: a `try/except: differs = False`. Every world served during a
    cluster hiccup then reads as "showed the sibling nothing", and the ladder withholds — or
    blames — on a measurement nobody took.
    """
    ep, family = staged_scene(tmp_path, monkeypatch)

    # The world arm answers and the BASE-PATTERN arm raises: `"*"` catches every read whose
    # index is not this world's view, which is exactly the witness's own read. `__raise__` is
    # the real `UpstreamFault` the shipped adapters raise on a cluster refusal.
    rows, _ctx = serve_one_call(
        ep, family, "b", tmp_path=tmp_path,
        answers={W.world_token("b"): {"rows": [{"host": "x"}]}, "*": "__raise__"})

    staged = [r for r in rows if r.get("source") == "staged"]
    assert staged, f"no staged row was written: {rows}"
    assert staged[0]["differs_from_base"] is None, (
        f"a faulted witness recorded {staged[0]['differs_from_base']!r}")


def test_differs_is_two_live_reads_compared_beyond_formatting(tmp_path, monkeypatch):
    """`differs_from_base` is two LIVE reads compared past formatting — not a shape check.

    Observably true: two payloads that differ only in key order and whitespace record
    `differs_from_base: false` (the comparator reads them as the same answer through
    `mechanical`), while a genuine value change records `true`. The comparison is the
    comparator's own ladder, not a second one written at the serve point.

    What failure looks like: a raw `!=` on the serialised text. Every staged call then records
    a difference, because two independent JSON dumps of one document routinely differ in
    exactly the ways the canonicaliser exists to absorb.
    """
    comparator = W.mod("learning.branch.comparator")
    a = json.dumps({"rows": [{"host": "canary-1", "status": "up"}]}, sort_keys=True)
    b = json.dumps({"rows": [{"status": "up", "host": "canary-1"}]}, indent=2)
    assert comparator.mechanical(a, b) == comparator.Verdict.SAME

    ep, family = staged_scene(tmp_path, monkeypatch)
    rows, _ctx = serve_one_call(
        ep, family, "b", tmp_path=tmp_path,
        answers={W.world_token("b"): json.loads(b), "*": json.loads(a)})

    staged = [r for r in rows if r.get("source") == "staged"]
    assert staged[0]["differs_from_base"] is False, (
        "a formatting-only difference between two live reads was recorded as a difference")


def test_the_control_world_takes_no_base_witness(tmp_path, monkeypatch):
    """The control world takes no witness read at all — it IS the base.

    Observably true: serving a call in the base world issues exactly one adapter read and
    writes no `differs_from_base` field. A witness on the control would compare the base
    pattern against itself, at the cost of one extra live read per captured call of the
    family's own recording.

    What failure looks like: the witness is unconditional. The primed base recording — the one
    every sibling replays — doubles in cost and gains a field that is `false` by construction.
    """
    ep, family = staged_scene(tmp_path, monkeypatch)
    rows, ctx = serve_one_call(ep, family, "a", tmp_path=tmp_path,
                               answers={"*": BASE_PAYLOAD})

    assert len(W.estate_calls(ctx)) == 1, (
        f"the control world took {len(W.estate_calls(ctx))} reads for one call")
    assert all("differs_from_base" not in r for r in rows), (
        f"the control's rows carry a base witness: {rows}")


def test_a_pre_change_staged_row_reads_as_unmeasured_not_as_no_difference(tmp_path):
    """A staged row written BEFORE this change — carrying no `differs_from_base` key at all —
    reads as unmeasured.

    Observably true: the grading pass over a served ledger whose staged row has no witness key
    reports `difference_shown: None` for that world, not `False`. Episodes archived before this
    change are still gradable, and "the field is absent" is a different fact from "the field
    said no".

    What failure looks like: `row.get("differs_from_base", False)`. Every pre-change episode
    then grades as if every staged call had been measured and shown nothing — a whole archive
    silently relabelled.
    """
    episode_mod = W.mod("learning.branch.episode")
    old_row = {k: v for k, v in W.served_row(world="b").items()
               if k not in ("differs_from_base", "base_pattern_digest")}

    shown = episode_mod.difference_shown([old_row])

    assert shown is None, (
        f"a pre-change staged row reads as {shown!r} — an absent field was defaulted to a "
        "measurement")


def test_the_reachability_block_is_written_in_the_one_guarded_whole_record_write(
        tmp_path, monkeypatch):
    """The reachability block rides the ONE guarded whole-record write `review()` already makes.

    Observably true: driving `review` over a three-world family issues exactly one
    `write_guarded` call for `review.yaml`, and the record it wrote carries every world's
    reachability block. The cadence is the incumbent one (executed: one write per episode
    pass), and this change adds no second write.

    What failure looks like: the block is appended per world with its own write. A reader
    opening `review.yaml` mid-pass then sees a partial record, and the file's atomicity — the
    reason it is guarded — is gone.
    """
    guarded = W.mod("_io")
    ep, family = staged_scene(tmp_path, monkeypatch, worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}]))),
        W.world_doc("c", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i2"}]))),
    ])
    review = W.mod("learning.branch.review")
    writer = W.RecordingReader(guarded.write_guarded)

    # `write=` IS PART OF THE CONTRACT, not a convenience: `review()` gives its record write no
    # injection seam today, so "how many times was review.yaml written" is unobservable without
    # one — and the project forbids reaching around it with `monkeypatch.setattr`. A missing
    # seam is pinned as a demand rather than worked around (schema.md, `kind: seam`).
    record = review.review(family, episode_dir=ep, adapters=W.FakeAdapters(),
                           door=W.FakeDoor(), invoke=W.FakeAgent("same"),
                           write=writer)

    review_writes = [c for c in writer.calls if str(c[0][0]).endswith(W.REVIEW_NAME)]
    assert len(review_writes) == 1, (
        f"review.yaml was written {len(review_writes)} times over three worlds")
    for label in ("b", "c"):
        assert "reachability" in record["worlds"][label]


# ---------------------------------------------------------------------------------------
# H1 — the applied counter's three consumers, one test each
# ---------------------------------------------------------------------------------------


def test_a_name_matching_patch_that_changes_no_content_serves_as_passthrough(tmp_path):
    """CONSUMER (i) — the serve path's ledger `source`.

    Observably true: a patch table naming an entity that IS in the payload, whose overlay
    changes no value, serves `PASSTHROUGH` with byte-identical content; a patch that changes a
    value serves `PATCHED`. `applied` counts CONTENT CHANGED, not an entity-name hit.

    Executed and refuted (`c4-noop-patch-reports-patched`): today `apply_patches` counts a name
    match, so `out.update({})` on a present-but-empty patch increments the counter and the
    applier reports `PATCHED` for content that did not move. No existing test drives this case
    — 316 passed both before and after the change was executed on a scratch branch.

    What failure looks like: the ledger's `source` column, which is the one artifact built to
    make wrong rows visible, says a difference was served when none was.
    """
    lookups = W.mod("learning.branch.estate.lookups")
    payload = {"rows": [{"host": "canary-1", "owner": "base-team"}]}

    same_out, same_applied = lookups.apply_patches(payload, {"canary-1": {}})
    equal_out, equal_applied = lookups.apply_patches(
        payload, {"canary-1": {"owner": "base-team"}})
    moved_out, moved_applied = lookups.apply_patches(
        payload, {"canary-1": {"owner": "sib-team"}})

    assert same_applied == 0, (
        f"an empty overlay on a present entity counted {same_applied} applications while "
        f"serving {same_out!r} — the counter is counting entity-name hits")
    assert equal_applied == 0, (
        "a patch writing the value the payload already held counted as an application")
    assert moved_applied == 1, (
        "the positive control failed — a genuine content change did not count")
    assert moved_out["rows"][0]["owner"] == "sib-team", (
        "the positive control failed — the changed value did not reach the served payload")


def test_a_patch_that_changes_no_content_rejects_the_world_and_a_content_changing_one_does_not(
        tmp_path):
    """CONSUMER (ii) — `_patched_visible` feeding `_rejection`'s WORLD-REJECTION gate.

    Observably true: a world whose patch table matches an entity by name while changing no
    content reads `patched_visible: false` and is REJECTED by `_rejection`; a world whose patch
    changes a value reads `patched_visible: true` and is not. This gate ends the whole episode
    before siblings run, so worlds that complete today will be rejected under H1 — an
    operator-visible behaviour change, and arguably this check's own intent.

    What failure looks like: the counter is fixed in the staging path alone. A check named "is
    this world's patch visible" keeps answering by entity-name match, which is the same defect
    #1007 exists to close, one module over.
    """
    review = W.mod("learning.branch.review")
    family_mod = W.mod("runtime.branch._family")
    rows = [{"host": "canary-1", "owner": "base-team"}]
    noop = family_mod.parse_world(W.world_doc(
        "b", ov=W.overlay(patches={"identity": {"canary-1": {}}})))
    moving = family_mod.parse_world(W.world_doc(
        "c", ov=W.overlay(patches={"identity": {"canary-1": {"owner": "sib-team"}}})))

    assert review._patched_visible(noop, rows=rows) is False, (
        "a name-matching patch that changed nothing is still reported visible")
    assert review._patched_visible(moving, rows=rows) is True, (
        "the positive control failed — a genuine patch is not reported visible")

    reachable = W.reachability_block(envelope_ran=True, patched_visible=False,
                                     exclusion_matches=None)
    consistency = {"mismatches": [], "control_mismatch_keys": []}
    assert review._rejection(noop, consistency=consistency, reachability=reachable) is not None, (
        "a world whose patch changes no content was not rejected")
    assert review._rejection(
        moving, consistency=consistency,
        reachability=W.reachability_block(envelope_ran=True, patched_visible=True,
                                          exclusion_matches=None)) is None


def test_a_content_identical_patch_grades_in_the_undoctored_bucket_family(
        tmp_path, monkeypatch):
    """CONSUMER (iii) — `doctored_answer_served` selecting the grading BUCKET TABLE.

    Observably true: a world whose served rows are all `PASSTHROUGH` (because its patch changed
    no content) grades against the UNDOCTORED bucket table — `lead-quality` is reachable for it
    — while an otherwise identical world with a `PATCHED` row grades against the doctored
    table. `doctored = APPLIER_DECISIONS - {PASSTHROUGH}`, so a content-identical
    PATCHED->PASSTHROUGH flip silently reclassifies a graded world into a different bucket
    FAMILY.

    What failure looks like: nothing raises and nothing looks wrong; a world's findings simply
    start coming out of the other table, and the lessons authored from them are about a
    different failure mode than the one that occurred.
    """
    family = W.mod("learning.judge.family")
    applier_mod = W.mod("learning.branch.estate.applier")
    family_mod = W.mod("runtime.branch._family")
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    payload = {"host": "canary-1", "owner": "base-team"}
    noop = W.world_doc("b", ov=W.overlay(patches={"identity": {"canary-1": {}}}))
    moving = W.world_doc("b", ov=W.overlay(
        patches={"identity": {"canary-1": {"owner": "sib-team"}}}))
    grades = {}
    for label, world_doc in (("noop", noop), ("moving", moving)):
        doc = W.family_doc(worlds=[W.base_world(), world_doc])
        ep = W.episode(tmp_path / label, doc=doc, root=root / label)
        W.archived_world(ep, "b")
        # THE `source` COLUMN IS THE APPLIER'S OWN ANSWER, never a literal written here. That is
        # the whole of this consumer: H1 changes which of the two decisions a content-identical
        # patch produces, and a row whose source the test typed in would grade identically
        # before and after the change — which is exactly why 316 existing tests did not flip.
        source, _served = applier_mod.WorldApplier().apply(
            "identity", "get-host", {}, dict(payload),
            family_mod.parse_world(world_doc), asked=None)
        W.write_served(ep, "b", [W.served_row(world="b", source=source)])
        grades[label] = {r["world"]: r for r in family.grade_family(ep, manifest=doc).worlds}["b"]

    assert grades["noop"]["doctored_answer_served"] is False, (
        "a world whose patch changed no content was graded as having served a doctored answer "
        f"(the applier reported {grades['noop'].get('doctored_answer_served')!r}) — the counter "
        "is still counting entity-name hits, one module away from the staging path")
    assert grades["moving"]["doctored_answer_served"] is True, (
        "the control failed — a genuinely patched answer did not select the doctored table")
    assert grades["noop"].get("bucket") != grades["moving"].get("bucket"), (
        f"both graded into {grades['noop'].get('bucket')!r}; the reclassification this "
        "consumer suffers would be invisible, which is exactly how it would ship")
