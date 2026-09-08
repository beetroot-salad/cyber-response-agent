"""#1007 — the judge record, the withholding ladder, and the mechanical world finding.

The demands here are O4/M3's (the ladder that WITHHOLDS a defender finding from a world that
measured nothing) plus demand #0's return-value contract and its round trip. Every test drives
a real entry point — `judge.grade_episode`, `judge.family.grade_family` — against an episode
built on disk; nothing asserts on a fake's canned reply alone.

RED AGAINST HEAD is the expected state: none of the fields these tests name exists yet.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests import _world_1007 as W

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


# ---------------------------------------------------------------------------------------
# The scene: an archived episode with a review record, samples and one graded world.
# ---------------------------------------------------------------------------------------


def graded_episode(tmp_path: Path, monkeypatch, *, worlds=("b",),
                   reachability: dict | None = None,
                   reachability_by_world: dict | None = None,
                   served: dict | None = None,
                   samples: dict | None = None,
                   manifest: dict | None = None) -> Path:
    """One episode dir carrying everything the grading pass reads.

    Built through `_triplet_947`'s own builders so a scenario is a few lines of data: the
    manifest, one archived world dir per label, the review record with its per-world
    reachability block, `samples.yaml`, and one served ledger per world.
    """
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    docs = [W.base_world()] + [
        W.world_doc(label, ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": f"i-{label}"}])))
        for label in worlds]
    ep = W.episode(tmp_path, doc=manifest if manifest is not None else W.family_doc(worlds=docs),
                   root=root)
    for label in worlds:
        W.archived_world(ep, label)
        W.write_served(ep, label, list((served or {}).get(label, [W.served_row(world=label)])))
    blocks = dict(reachability_by_world or {})
    for label in worlds:
        if label not in blocks:
            blocks[label] = reachability if reachability is not None else W.reachability_block(
                capture_replays=[W.replay_entry("k1", differs=True)])
    W.write_review(ep, worlds={
        label: W.reviewed_world(label=label, reachability=blocks[label]) for label in worlds})
    W.write_samples(ep, samples)
    return ep


def grade(ep: Path, *, judge=None, **kw):
    """`judge.grade_episode` through its own injection seams — never a live provider."""
    judge_mod = W.mod("learning.judge")
    return judge_mod.grade_episode(
        ep, judge=judge if judge is not None else W.FakeJudge(W.reply_document()), **kw)


def rows_of(grade_result) -> dict[str, dict]:
    return {row["world"]: row for row in grade_result.worlds}


# ---------------------------------------------------------------------------------------
# Demand #0 — the return value, and the round trip it must survive
# ---------------------------------------------------------------------------------------


def test_grade_episode_returns_extended_record(tmp_path, monkeypatch):
    """`grade_episode` hands back the family-level record CARRYING the new fields, not a record
    a caller has to re-read `judge.yaml` to see.

    Observably true: the returned `EpisodeGrade` exposes the five family-level additions this
    change makes — the family draw's own outcome, the world findings it enqueued, the second
    channel it enqueued them to, the per-world withholding reasons, and the count of worlds
    that measured something — and every per-world row carries the nine new per-world fields.

    What failure looks like: a pass that writes the fields into `judge.yaml` but not onto its
    return value. Every in-process consumer (the launcher's own stamp, `enqueue`) then reads a
    record that is missing exactly the fields this change exists to add, and the only artifact
    that has them is the file on disk.
    """
    ep = graded_episode(tmp_path, monkeypatch)

    result = grade(ep)

    for field in ("family_outcome", "world_findings", "world_enqueued_to",
                  "withheld_worlds", "measuring_worlds"):
        assert hasattr(result, field), (
            f"EpisodeGrade carries no {field!r} — the family-level half of this change reaches "
            "judge.yaml only, so no in-process caller can see it")
    row = rows_of(result)["b"]
    for field in ("reachable_by_capture", "capture_addressed", "withheld_reason",
                  "difference_shown", "world_findings", "capture_reasks_faulted",
                  "injected_retrieved", "injected_present", "sample_unavailable"):
        assert field in row, f"the per-world row carries no {field!r}: {sorted(row)}"


def test_judge_yaml_round_trips_every_new_field(tmp_path, monkeypatch):
    """Every new field written by `_write_judge_yaml` is read back by `_grade_from_document`.

    Observably true: grading an episode twice — the second time off the `judge.yaml` the first
    wrote — yields an equal record. The two sites are hand-written enumerations (C32), which is
    exactly why a field added to the writer and not to the reader is lost silently.

    What failure looks like: the second grade returns a record whose new fields are absent or
    defaulted, so a re-read episode grades as if it had measured nothing — and every reader
    downstream of the re-read path sees a different episode from the one that was graded.
    """
    ep = graded_episode(tmp_path, monkeypatch)

    first = grade(ep)
    second = grade(ep)          # the existing-record path: reads judge.yaml, does not re-draw

    assert (ep / W.JUDGE_NAME).is_file(), "the pass wrote no judge.yaml to round-trip"
    assert rows_of(second) == rows_of(first), (
        "a per-world field written to judge.yaml did not survive the re-read — "
        f"{rows_of(first)} != {rows_of(second)}")
    for field in ("family_outcome", "world_findings", "world_enqueued_to",
                  "withheld_worlds", "measuring_worlds", "verdict_word"):
        assert getattr(second, field) == getattr(first, field), (
            f"{field!r} is written to judge.yaml and not read back off it")


# ---------------------------------------------------------------------------------------
# O4/M3 — the ladder
# ---------------------------------------------------------------------------------------


def test_a_reachable_world_that_showed_nothing_still_enqueues_lead_set(tmp_path, monkeypatch):
    """A world whose difference WAS reachable, and whose sibling still asked nothing, is a real
    defender finding — the ladder withholds nothing here.

    Observably true: with `reachable_by_capture: true` and a served ledger holding no row on the
    holding system, the defender lane enqueues its `lead-set` finding exactly as today and the
    row carries no `withheld_reason`.

    What failure looks like: a ladder that withholds on any world that queried nothing. That
    turns the change from "stop blaming the defender for an unmeasurable world" into "stop
    grading the defender at all", and the finding this whole loop exists to produce disappears.
    """
    ep = graded_episode(tmp_path, monkeypatch,
                        reachability=W.reachability_block(
                            reachable_by_capture=True,
                            capture_replays=[W.replay_entry("k1", differs=True)]),
                        served={"b": []})

    result = grade(ep, judge=W.FakeJudge(W.reply_document(findings=[W.finding()])))

    row = rows_of(result)["b"]
    assert row.get("withheld_reason") is None, (
        f"a reachable world's defender finding was withheld for {row.get('withheld_reason')!r} "
        "— the ladder is withholding on 'queried nothing' rather than on 'measured nothing'")
    assert "b" not in set(result.withheld_worlds)


def test_a_measured_nothing_world_withholds_its_defender_findings(tmp_path, monkeypatch):
    """A world that measured nothing produces no defender finding — the finding is RECORDED
    with its reason, never enqueued.

    Observably true: with `reachable_by_capture: false` (the re-asks completed and none
    differed), the world's row carries `withheld_reason: measured_nothing`, the world is in
    `withheld_worlds`, and no `subject: defender` row reaches the findings queue for it.

    What failure looks like: the finding is enqueued anyway. The defender is then blamed for
    not noticing a difference that was not observable — O4's own falsifier, and the reason this
    ladder exists.
    """
    paths = W.loop_paths(tmp_path)
    ep = graded_episode(tmp_path, monkeypatch,
                        reachability=W.reachability_block(
                            reachable_by_capture=False,
                            capture_replays=[W.replay_entry("k1", differs=False)]))

    result = grade(ep, judge=W.FakeJudge(W.reply_document(findings=[W.finding()])),
                   queue_dir=paths.pending_dir)

    row = rows_of(result)["b"]
    assert row["withheld_reason"] == "measured_nothing", (
        f"withheld_reason is {row.get('withheld_reason')!r}")
    assert "b" in set(result.withheld_worlds)
    assert [r for r in W.queue_rows(paths.findings)
            if r.get("subject") == W.SUBJECT_DEFENDER] == [], (
        "a defender finding for a world that measured nothing reached the queue")


def test_withheld_reason_is_capture_unaddressed_when_nothing_names_the_corpus(
        tmp_path, monkeypatch):
    """A world whose capture never named a staged pattern is withheld as `capture_unaddressed`,
    which is a DIFFERENT answer from `measured_nothing`.

    Observably true: `capture_addressed: false` puts `capture_unaddressed` on the row. The two
    reasons must stay distinguishable — one says the corpus was asked and held no difference,
    the other says nobody asked it — and an operator repairs them differently.

    What failure looks like: both collapse onto one reason, and the record can no longer say
    whether the questioner staged the wrong corpus or the world genuinely showed nothing.
    """
    ep = graded_episode(tmp_path, monkeypatch,
                        reachability=W.reachability_block(
                            capture_addressed=False, reachable_by_capture=None,
                            capture_replays=[]))

    row = rows_of(grade(ep))["b"]

    assert row["withheld_reason"] == "capture_unaddressed", (
        f"withheld_reason is {row.get('withheld_reason')!r}, not capture_unaddressed")


def test_withheld_reason_is_reachability_unmeasured_when_every_reask_faulted(
        tmp_path, monkeypatch):
    """Every re-ask faulted, so nothing was measured about reachability at all — the reason
    names the INSTRUMENT, never the world.

    Observably true: with every `capture_replays` entry `faulted: true` and
    `reachable_by_capture: null`, the row reads `reachability_unmeasured`.

    What failure looks like: an outage is recorded as `measured_nothing`, which charges the
    world for the harness — the same conflation `exclusion_count_failed` already exists one
    field over to prevent.
    """
    ep = graded_episode(tmp_path, monkeypatch,
                        reachability=W.reachability_block(
                            reachable_by_capture=None, capture_reasks_faulted=2,
                            capture_replays=[W.replay_entry("k1", differs=None, faulted=True),
                                             W.replay_entry("k2", differs=None, faulted=True)]))

    row = rows_of(grade(ep))["b"]

    assert row["withheld_reason"] == "reachability_unmeasured", (
        f"withheld_reason is {row.get('withheld_reason')!r}; a faulted instrument is not a "
        "world that showed nothing")


def test_a_withheld_world_does_not_vote_in_verdict_word(tmp_path, monkeypatch):
    """The episode's word is computed over MEASURING worlds only.

    Observably true: an episode with two worlds — one measuring and disagreeing with its
    declared disposition, one withheld — takes its word from the measuring world alone, and
    `measuring_worlds` names exactly that one. A withheld world is excluded exactly as an
    ungradable one already is.

    What failure looks like: the withheld world votes, and an episode is called `survived`
    because a world nobody could measure disagreed with its own label.
    """
    ep = graded_episode(
        tmp_path, monkeypatch, worlds=("b", "c"),
        reachability_by_world={
            "b": W.reachability_block(reachable_by_capture=True,
                                      capture_replays=[W.replay_entry("k1", differs=True)]),
            "c": W.reachability_block(reachable_by_capture=False,
                                      capture_replays=[W.replay_entry("k1", differs=False)]),
        })

    result = grade(ep)

    assert set(result.measuring_worlds) == {"b"}, (
        f"measuring_worlds is {sorted(result.measuring_worlds)} — a withheld world is voting")
    assert "c" in set(result.withheld_worlds)


def test_verdict_word_is_undecidable_when_no_world_measured(tmp_path, monkeypatch):
    """No world measured anything, so the episode has no word to say.

    Observably true: every world withheld gives `verdict_word == "undecidable"` and an empty
    `measuring_worlds`. `undecidable` is the falsy-but-valid member of this domain — it must be
    reachable by the ladder, not only by an empty manifest.

    What failure looks like: the pass answers `caught` because zero disagreements were found
    among zero measured worlds — a vacuous truth reported as a result.
    """
    ep = graded_episode(tmp_path, monkeypatch, worlds=("b", "c"),
                        reachability=W.reachability_block(
                            reachable_by_capture=False,
                            capture_replays=[W.replay_entry("k1", differs=False)]))

    result = grade(ep)

    assert result.verdict_word == "undecidable", (
        f"verdict_word is {result.verdict_word!r} over zero measuring worlds")
    assert list(result.measuring_worlds) == []


@pytest.mark.parametrize("kind", ["inject", "exclude", "patch"])
def test_unreachable_difference_fires_for_inject_exclude_and_patch_alike(
        tmp_path, monkeypatch, kind):
    """The mechanical world finding fires on ANY declared difference the capture could not
    reach — not only on an injection.

    Observably true: a world declaring an injection, an exclusion or a patch, each with
    `reachable_by_capture: false`, mints one `subject: world` finding whose bucket is
    `unreachable-difference`. The three overlay halves are three spellings of one claim ("this
    world differs"), and a check written for one of them silently exempts the other two.

    What failure looks like: only the inject arm fires, so a patch-only world that measured
    nothing is graded as if it had declared nothing — the exact shape C4's refutation showed is
    already reachable on the applier side.
    """
    ov = {
        "inject": W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}])),
        "exclude": W.overlay(elastic=W.elastic_overlay(inject=[], exclude={"match_all": {}})),
        "patch": W.overlay(patches={"identity": {"web-1": {"owner": "sib-team"}}}),
    }[kind]
    manifest = W.family_doc(worlds=[W.base_world(), W.world_doc("b", ov=ov)])
    ep = graded_episode(tmp_path, monkeypatch, manifest=manifest,
                        reachability=W.reachability_block(
                            reachable_by_capture=False,
                            capture_replays=[W.replay_entry("k1", differs=False)]))

    result = grade(ep)

    buckets = [f["bucket"] for f in rows_of(result)["b"]["world_findings"]]
    assert W.MECHANICAL_WORLD_BUCKET in buckets, (
        f"a {kind} world whose difference was unreachable minted {buckets} — the mechanical "
        "world finding is scoped to one overlay half")


def test_unreachable_difference_fires_even_with_no_row_on_the_holding_system(
        tmp_path, monkeypatch):
    """Ladder row 1 does not gate row 4: a world the sibling never queried still gets its
    mechanical WORLD finding.

    Observably true: an empty served ledger (no row on the holding system) plus
    `reachable_by_capture: false` still mints `unreachable-difference` about the world, while
    the DEFENDER finding is withheld. The two lanes answer different questions and the world
    lane must not inherit the defender lane's gate.

    What failure looks like: the world finding is suppressed with the defender one, so the
    questioner corpus never learns about the worlds that are hardest to reach — precisely the
    ones it most needs to learn from.
    """
    ep = graded_episode(tmp_path, monkeypatch, served={"b": []},
                        reachability=W.reachability_block(
                            reachable_by_capture=False,
                            capture_replays=[W.replay_entry("k1", differs=False)]))

    row = rows_of(grade(ep))["b"]

    assert [f["bucket"] for f in row["world_findings"]] == [W.MECHANICAL_WORLD_BUCKET], (
        f"world_findings is {row.get('world_findings')!r} with no row on the holding system")


def test_agreed_without_difference_is_a_trial_outcome_not_a_world_finding(
        tmp_path, monkeypatch):
    """`agreed-without-difference` lands on the world's ROW as a trial outcome; it is not a
    finding anybody authors a lesson from.

    Observably true: a world whose sibling agreed with the control while no difference was
    shown carries `agreed_without_difference: true` on its row, and mints NO world finding
    under that name. The positive control rides with it — the same drive DOES mint the
    mechanical `unreachable-difference` finding — so this is a fact about routing, not about a
    pass that produced nothing at all.

    What failure looks like: the trial outcome is enqueued as a finding, and the questioner
    corpus fills with rows saying nothing happened.
    """
    ep = graded_episode(tmp_path, monkeypatch,
                        served={"b": [W.served_row(world="b", differs_from_base=False)]},
                        reachability=W.reachability_block(
                            reachable_by_capture=False,
                            capture_replays=[W.replay_entry("k1", differs=False)]))

    row = rows_of(grade(ep))["b"]

    assert row.get("agreed_without_difference") is True, (
        "the trial outcome is not on the row")
    buckets = [f["bucket"] for f in row["world_findings"]]
    assert "agreed-without-difference" not in buckets, (
        f"the trial outcome was minted as a world finding: {buckets}")
    assert W.MECHANICAL_WORLD_BUCKET in buckets, (
        "the positive control failed — this drive minted no world finding at all, so the "
        "absence asserted above proves nothing")


def test_removing_the_flag_leaves_no_orphan_in_the_committed_spec_corpus(tmp_path):
    """Removing `agreed-without-evidence` settles its THIRD consumer — the committed spec
    corpus the CI ratchet checks — not just the two in code.

    Observably true: after this change no `agreed-without-evidence` string survives in
    `defender/learning/judge/family.py`, in either of the two #921 suites that name it
    (`test_921_family_buckets.py`, `test_921_family_facts.py`), or in
    `spec-flow/specs/spec_graph_921-family-judge.yaml`. The last is the one the design's own
    sweep missed (correction C-B): the committed graph binds the flag as a domain member and
    records an R4 discharge against it, so removing it orphans a coverage row and a mechanical
    discharge in a corpus a ratchet reads.

    Each holder is asserted to EXIST before it is read, which is not bookkeeping and is not
    hypothetical: this test named `tests/e2e/test_921_family_buckets.py`, which is not where
    that suite lives, so one third of its census read no file at all and passed on nothing —
    and the existence check is what found it. The corrected census gained a FOURTH holder
    (`test_921_family_facts.py`) the wrong path had been hiding.

    What failure looks like: the code drops the flag, the spec corpus keeps binding it, and the
    graph checker fails on a repository the change left inconsistent — a red CI whose cause is
    two directories from the diff.
    """
    repo = Path(__file__).resolve().parents[2]
    holders = [
        repo / "defender" / "learning" / "judge" / "family.py",
        repo / "defender" / "tests" / "test_921_family_buckets.py",
        repo / "defender" / "tests" / "test_921_family_facts.py",
        repo / "spec-flow" / "specs" / "spec_graph_921-family-judge.yaml",
    ]
    missing = [p for p in holders if not p.is_file()]
    assert missing == [], (
        f"{[str(p.relative_to(repo)) for p in missing]} do not exist, so the absence below is a "
        "fact about a file nobody read — this is the whole failure mode of a string check: it "
        "is green when the channel it looks through is not there")
    present = [p for p in holders if "agreed-without-evidence" in p.read_text(encoding="utf-8")]

    assert present == [], (
        "these still bind the removed family flag: "
        f"{[str(p.relative_to(repo)) for p in present]} — the last one is the committed spec "
        "corpus, whose orphaned domain member and R4 discharge row the CI ratchet reads")


def test_reachable_by_sibling_only_leaves_the_defender_ladder_unchanged(tmp_path, monkeypatch):
    """A difference the SIBLING was shown, that the capture's own re-ask could not reach, still
    grades the defender exactly as today.

    Observably true: `difference_shown: true` on the served row with
    `reachable_by_capture: false` withholds nothing — the defender was shown the difference at
    serve time, which is the fact the defender is answerable for. Row 3 is consulted before row
    4 and the ladder stops there.

    What failure looks like: the re-ask's verdict overrides the serve-time witness, and a
    defender that WAS shown a difference and missed it is excused because a later live read
    could not reproduce it.
    """
    ep = graded_episode(tmp_path, monkeypatch,
                        served={"b": [W.served_row(world="b", differs_from_base=True)]},
                        reachability=W.reachability_block(
                            reachable_by_capture=False,
                            capture_replays=[W.replay_entry("k1", differs=False)]))

    row = rows_of(grade(ep))["b"]

    assert row.get("withheld_reason") is None, (
        f"a world the sibling was demonstrably shown was withheld for "
        f"{row.get('withheld_reason')!r} — row 4 is overriding row 3")
    assert row["difference_shown"] is True


def test_grade_family_reads_the_review_record_once_through_the_guarded_reader(
        tmp_path, monkeypatch):
    """The mechanical pass reads `review.yaml` ONCE per episode, through the guarded reader.

    Observably true: driving `grade_family` over a three-world episode with a counting reader
    injected records exactly one read of the review record, whatever the world count. The
    episode dir is a tree a box can reach, so two reads are two documents with no guarantee
    they agree — the same hand-over `render` already takes for the manifest.

    What failure looks like: one read per world. A three-world family then grades against up to
    three different review records, and the disagreement is invisible in the output.
    """
    ep = graded_episode(tmp_path, monkeypatch, worlds=("b", "c", "d"))
    family = W.mod("learning.judge.family")
    reader = W.RecordingReader(W.read_yaml)

    family.grade_family(ep, review_reader=reader)

    assert reader.count == 1, (
        f"the review record was read {reader.count} times over three worlds — the pass "
        "re-reads a tree a box can write, once per world")


def test_a_withheld_world_is_still_drawn_and_still_yields_world_findings(
        tmp_path, monkeypatch):
    """Withholding a world's DEFENDER findings does not skip the world's model draw.

    Observably true: a world withheld as `measured_nothing` is still rendered and still drawn —
    the judge is asked about it, its prompt is composed, and its `subject: world` findings
    stand. The withholding is about the DEFENDER lane alone.

    What failure looks like: the pass short-circuits the whole world, and the questioner never
    hears about the worlds that failed to measure — which is precisely the population its
    corpus exists to learn from.
    """
    reply = W.reply_document(findings=[W.world_finding(bucket="an-unlisted-world-bucket")])
    judge = W.FakeJudge(reply)
    ep = graded_episode(tmp_path, monkeypatch,
                        reachability=W.reachability_block(
                            reachable_by_capture=False,
                            capture_replays=[W.replay_entry("k1", differs=False)]))

    result = grade(ep, judge=judge)

    assert any(a.startswith("judge:") and "family" not in a for a in judge.agent_ids), (
        f"the withheld world was never drawn: agent ids {judge.agent_ids}")
    buckets = [f["bucket"] for f in rows_of(result)["b"]["world_findings"]]
    assert "an-unlisted-world-bucket" in buckets, (
        f"the withheld world's own model-drawn world findings were dropped: {buckets}")


def test_a_non_boolean_reachable_by_capture_reads_as_unmeasured(tmp_path, monkeypatch):
    """A `reachable_by_capture` that is not a boolean is UNMEASURED, never coerced to false.

    Observably true: the string `"false"` on the record (a YAML quoting accident, a hand-edited
    episode) grades as `reachability_unmeasured`, not as a world that measured nothing. The
    field is `bool|null` and every other value is outside its domain.

    What failure looks like: `if not block["reachable_by_capture"]` — under which the string
    `"false"` is TRUTHY and the world reads as reachable, while an empty string reads as
    measured-and-nothing-found. Both are answers the record never carried.
    """
    ep = graded_episode(tmp_path, monkeypatch,
                        reachability=W.reachability_block(
                            reachable_by_capture="false",
                            capture_replays=[W.replay_entry("k1", differs=False)]))

    row = rows_of(grade(ep))["b"]

    assert row["withheld_reason"] == "reachability_unmeasured", (
        f"a string 'false' graded as {row.get('withheld_reason')!r} — the value was coerced "
        "rather than read as outside the field's domain")


def test_an_absent_reachability_block_withholds_and_never_mints_unreachable_difference(
        tmp_path, monkeypatch):
    """No reachability block for the graded world is UNMEASURED — never "unreachable".

    Observably true: a review record whose world entry carries no `reachability` key withholds
    the defender finding as `reachability_unmeasured` AND mints no `unreachable-difference`
    world finding. The negative half is the load-bearing one: an absent measurement is not
    evidence that the difference was unreachable.

    What failure looks like: `block.get("reachable_by_capture")` returns `None`, `None` is
    falsy, and the pass accuses the world of an unreachable difference on the strength of a
    measurement nobody took.
    """
    ep = graded_episode(tmp_path, monkeypatch)
    doc = W.read_yaml(ep / W.REVIEW_NAME)
    doc["worlds"]["b"].pop("reachability")
    W.write_yaml(ep / W.REVIEW_NAME, doc)

    row = rows_of(grade(ep))["b"]

    assert row["withheld_reason"] == "reachability_unmeasured"
    assert [f["bucket"] for f in row["world_findings"]] == [], (
        f"an absent block minted {row.get('world_findings')!r} — a missing measurement was "
        "read as a measured absence")


def test_a_label_present_in_only_one_artifact_reads_as_an_absent_block(tmp_path, monkeypatch):
    """When the manifest and the review record disagree about the world set, a world named by
    only one of them has NO block — it is not silently matched to a sibling's.

    Observably true: a manifest declaring `b` and `c` against a review record carrying only `b`
    grades `c` as `reachability_unmeasured`, and `b` keeps its own block unchanged.

    What failure looks like: an index-based join (`review["worlds"][i]`) pairs `c` with `b`'s
    block, and `c` is graded against a measurement taken of a different world.
    """
    ep = graded_episode(tmp_path, monkeypatch, worlds=("b", "c"))
    doc = W.read_yaml(ep / W.REVIEW_NAME)
    doc["worlds"].pop("c")
    W.write_yaml(ep / W.REVIEW_NAME, doc)

    rows = rows_of(grade(ep))

    assert rows["c"]["withheld_reason"] == "reachability_unmeasured", (
        f"world c grades as {rows['c'].get('withheld_reason')!r} off a record that says "
        "nothing about it")
    assert rows["b"].get("withheld_reason") is None


def test_a_mechanical_world_finding_is_told_from_a_model_drawn_one_by_provenance(
        tmp_path, monkeypatch):
    """Two findings can carry the SAME world bucket on the same world; only `provenance` tells
    them apart.

    Observably true: an episode where the mechanical pass mints `unreachable-difference` and
    the model draws a finding with the same string yields two rows on the questioner channel,
    one `provenance: mechanical` and one `provenance: model`. The vocabulary is open (G-3), so
    the bucket cannot carry uniqueness and readers key on provenance instead.

    What failure looks like: the two are deduplicated on `(world, bucket)`, and the model's own
    reading of the world is silently discarded whenever it agrees with the arithmetic.
    """
    paths = W.loop_paths(tmp_path)
    judge = W.FakeJudge(W.reply_document(
        findings=[W.world_finding(bucket=W.MECHANICAL_WORLD_BUCKET)]))
    ep = graded_episode(tmp_path, monkeypatch,
                        reachability=W.reachability_block(
                            reachable_by_capture=False,
                            capture_replays=[W.replay_entry("k1", differs=False)]))

    grade(ep, judge=judge, queue_dir=paths.pending_dir)

    rows = [r for r in W.queue_rows(W.questioner_channel(paths))
            if r.get("type") == W.MECHANICAL_WORLD_BUCKET]
    assert sorted(r["provenance"] for r in rows) == ["mechanical", "model"], (
        f"the two same-bucket findings collapsed to {rows} — the open vocabulary means the "
        "bucket cannot tell an arithmetic finding from a drawn one")


def test_an_episode_killed_before_the_sibling_ran_withholds_with_episode_incomplete(
        tmp_path, monkeypatch):
    """An episode that died before any sibling served a single call is WITHHELD, not blamed.

    Observably true: with no served row anywhere in the episode — not merely none on the
    holding system — every world's row reads `withheld_reason: episode_incomplete` and no
    defender finding is enqueued. Without this cell an episode killed before step 5 is
    indistinguishable from a defender that queried nothing, and the defender is falsely accused
    at O4's own falsifier.

    What failure looks like: `lead-set` findings for every world of an episode nobody finished,
    authored into the defender corpus as lessons about an investigation that never ran.
    """
    paths = W.loop_paths(tmp_path)
    ep = graded_episode(tmp_path, monkeypatch, worlds=("b", "c"), served={"b": [], "c": []})

    result = grade(ep, judge=W.FakeJudge(W.reply_document(findings=[W.finding()])),
                   queue_dir=paths.pending_dir)

    for label, row in rows_of(result).items():
        assert row["withheld_reason"] == "episode_incomplete", (
            f"world {label} reads {row.get('withheld_reason')!r} on an episode with no served "
            "row at all")
    assert [r for r in W.queue_rows(paths.findings)
            if r.get("subject") == W.SUBJECT_DEFENDER] == [], (
        "an unfinished episode still accused the defender")


def test_the_reachability_facts_stay_on_the_record_when_the_world_is_later_rejected(
        tmp_path, monkeypatch):
    """A world rejected on some OTHER ground keeps the reachability facts the review measured.

    Observably true: driving the real `review.review` over a world that contradicts the capture
    (a rejection reason that has nothing to do with reachability) still leaves that world's
    `capture_replays`, `capture_addressed` and `reachable_by_capture` on `review.yaml`.

    What failure looks like: the rejection path returns early and the facts are never written,
    so the record cannot say whether the world was also unreachable — and the operator
    debugging a rejected episode is one measurement short for no reason.
    """
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    review = W.mod("learning.branch.review")
    family_mod = W.mod("runtime.branch._family")
    doc = W.family_doc(worlds=[
        W.base_world(),
        W.world_doc("b", ov=W.overlay(patches={"identity": {"web-1": {"owner": "sib"}}}))])
    ep = W.episode(tmp_path, doc=doc, root=root)
    W.base_capture(ep, [W.captured_row(key="k1")])
    adapters = W.FakeAdapters({("elastic", "query"): {"hits": [{"_id": "other"}]}})

    review.review(family_mod.parse_family(doc), episode_dir=ep, adapters=adapters,
                  door=W.FakeDoor(), invoke=W.FakeAgent("contradiction"))

    block = W.review_doc(ep)["worlds"]["b"]["reachability"]
    for key in ("capture_replays", "capture_addressed", "reachable_by_capture"):
        assert key in block, (
            f"a rejected world's record carries no {key!r}: {sorted(block)}")


def test_an_incomplete_capture_replay_entry_is_never_a_completed_non_differing_reask(
        tmp_path, monkeypatch):
    """A `capture_replays` entry missing one of its three keys is UNMEASURED, never a completed
    non-differing re-ask.

    Observably true: an entry carrying only `{key, differs}` — no `faulted` — or only
    `{key, faulted}` grades as `reachability_unmeasured` with `reachable_by_capture: null`, not
    as `false`. `false` means at least one re-ask COMPLETED and none differed; an entry that
    cannot say whether it faulted has not established that.

    What failure looks like: `entry.get("faulted")` returns `None`, `None` is falsy, and an
    incomplete entry is counted as a completed non-differing re-ask — which turns a partial
    measurement into a verdict against the world, in the direction that withholds.
    """
    for shape in ({"key": "k1", "differs": False}, {"key": "k1", "faulted": False},
                  {"differs": False, "faulted": False}):
        ep = graded_episode(
            tmp_path / f"case-{len(shape)}-{sorted(shape)[0]}", monkeypatch,
            reachability=W.reachability_block(reachable_by_capture=None,
                                              capture_replays=[dict(shape)]))

        row = rows_of(grade(ep))["b"]

        assert row["withheld_reason"] == "reachability_unmeasured", (
            f"the incomplete replay entry {shape} graded as {row.get('withheld_reason')!r} — "
            "a missing key was read as a completed measurement")
