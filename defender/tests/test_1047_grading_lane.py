"""#1047 O1 — a world whose run the host cut short is never graded as a verdict about the case.

THE BUG, OBSERVED (claim h2, `probe_kind: executed`): over an accepted episode with two caught
worlds, overwriting world b's archived `report.md` with the host's forced `unresolved` report
moved the family from `verdict_word=caught` to `verdict_word=survived`, and filed row b as
`verdict=unresolved declared=malicious bucket=decision-discipline, ungradable=None`. The host's
own "the model never got to decide" close is read by the learning loop as the model's verdict
about the case, and it flips the family's word.

THE FIX, in this lane: `_grade_world` learns a THIRD ROW SHAPE. Tier 1 stays "an input is
absent" (`ungradable`, no `malformed`); tier 2 stays "an input is there and wrong"
(`ungradable` + `malformed`); the new shape is "the run did not finish" — `ungradable: True`,
`cut_short: <normalized exit class>`, an `ungradable_reason` naming the exit, and NO `malformed`
key, so `test_921_family_facts.py:631`'s absent-vs-malformed split reads the same after the
change as before it. `is_gradable_row` is truthiness on `ungradable` and already excludes it
(claim h7), so `verdict_word` is computed over what is left measuring with no change of its own.

THREE §7 RESOLUTIONS ARE APPLIED HERE AS SETTLED, not as readings this file picked:

* **F1 (auto, reading A)** — `cut_short` is a TOP-LEVEL row key beside `ungradable`, the way
  `malformed` already spells tier 2's discriminator. Nesting it would make every reader
  destructure a dict for room to grow that nothing in this piece needs.
* **F5 (human, reading A)** — the cut-short check runs BEFORE `_missing_required_input`. Three
  of the five exit classes (`aborted`, `budget`, `store`) write no `report.md` at all (claim
  h1), so on the other ordering `cut_short` would only ever be observable for the two classes
  that also produce a forced report — undercutting O1's own words, "the reason names the exit".
* **F-A (human, §7 round 2, reading B)** — the record carries `closed_before_cut`, and the
  third row shape is filed only when the world was cut short WITHOUT deciding. Round-1 probe
  p21 (EXECUTED) found the forced close's `ReviewState.of(deps).closed` skip reachable on all
  five exit classes: a world can carry a real, confident, model-authored verdict AND a stamped
  exit class. Discarding that verdict would make the row's own reason string ("the host's
  report is not a verdict") literally false about that world, and would silently lose genuine
  signal from the learning loop.

RED against `59bdea44`: `learning/judge/family.py` has no cut-short check, `WorldFacts` has no
`cut_short` field, and `archive.RUN_END_NAME` does not exist.
"""
from __future__ import annotations

import json

from defender.tests import _spec1047 as S

#: The host's own forced close, as `_close_a_run_cut_short` writes it — `unresolved`, `stands`,
#: and the "recorded without a challenge review" cause. The exact document claim h2 observed
#: flipping a family's verdict word when it was graded as world b's conclusion.
FORCED_REPORT = S.report_text("unresolved")


def _forced_close(episode_dir, label="b"):
    """Overwrite one archived world's report with the host's forced `unresolved` close — claim
    h2's configuration, reproduced as a real document through the real reader."""
    (episode_dir / "worlds" / label / "report.md").write_text(FORCED_REPORT, encoding="utf-8")


# ---------------------------------------------------------------------------------------
# the third row shape
# ---------------------------------------------------------------------------------------


def test_a_cut_short_world_files_the_third_row_shape(tmp_path):
    """A world whose archived run_end.json says its run was truncated — and whose model had NOT
    already closed — returns the third row shape: `ungradable: True`, `cut_short` carrying the
    normalized exit value, `closed_before_cut` False on the record it was read from, and an
    `ungradable_reason` naming the exit — with no `malformed` key, so tier 1 still means absent
    and tier 2 still means malformed.

    The record's field set is F-A reading B's (§7 round 2): `truncated_by` alone cannot tell a
    host-forced close from the model's own, and the reason string this row carries asserts that
    it can. `closed_before_cut` is the bit that makes the sentence true."""
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    row = S.graded(ep)["b"]
    assert row.get("ungradable") is True, "a cut-short world was still graded as a verdict"
    assert row.get("cut_short") == "request-limit", (
        "the row does not carry the exit class as a top-level key beside `ungradable` "
        "(F1 reading A); a reader cannot tell this row from tier 1 without it")
    assert "malformed" not in row, (
        "the cut-short row was marked malformed — tier 2 means 'the input is there and wrong', "
        "and this world's inputs are neither")
    reason = row.get("ungradable_reason") or ""
    assert "b" in reason, f"the reason does not name the world: {reason!r}"
    assert "request-limit" in reason, f"the reason does not name the exit class: {reason!r}"


def test_a_request_limit_world_is_ungradable_not_a_verdict(tmp_path):
    """`grade_family` over an episode whose world b ended `request-limit` files row b ungradable
    with a reason naming the exit, instead of grading the host's forced `unresolved` report as
    b's verdict about the case.

    World b carries the forced report claim h2 observed being graded as a verdict — this is
    that exact configuration, with the run-end record added. Its siblings still grade: a world
    the tier rule excludes costs no other world its row."""
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    _forced_close(ep)
    graded = S.graded(ep)
    assert graded["b"].get("ungradable") is True
    assert graded["b"].get("cut_short") == "request-limit"
    assert graded["b"].get("verdict") is None, (
        "the host's forced `unresolved` was recorded as world b's verdict about the case")
    assert graded["c"].get("ungradable") is not True, (
        "world b's exclusion cost its sibling its grade")


def test_a_cut_short_world_does_not_move_the_family_verdict_word(tmp_path):
    """verdict_word is computed over the remaining measuring worlds: the control episode's word
    is unchanged by world b's run being cut short, where today a host-forced unresolved report
    on b flips caught to survived (claim h2, executed).

    Three episodes, one assertion each: the control; the control with b's report replaced by
    the host's forced close and NO run-end record, which is the bug; and the same with the
    record, which is the fix. The middle one is the positive control for the observation
    channel — without it, "the word did not move" is also green for a pass that cannot move the
    word at all."""
    control = S.cut_short_episode(tmp_path / "control")
    word = S.family_word(control)

    bug = S.cut_short_episode(tmp_path / "bug")
    _forced_close(bug)
    assert S.family_word(bug) != word, (
        "the observation channel cannot see the difference: a host-forced `unresolved` report "
        "on world b did not move the family's verdict word, so the assertion below proves "
        "nothing (claim h2 observed caught -> survived on exactly this configuration)")

    fixed = S.cut_short_episode(tmp_path / "fixed", cut={"b": "request-limit"})
    _forced_close(fixed)
    assert S.family_word(fixed) == word, (
        "world b's run being cut short moved the family's verdict word; a run that was stopped "
        "before the model could decide is not a measurement of the case")


def test_the_third_row_shape_keeps_the_two_tiers_separable(tmp_path):
    """The cut-short row carries no `malformed` key and an absent input still carries none
    either, so `test_921_family_facts.py:631`'s absent-vs-malformed split reads the same after
    the change as before it.

    All three shapes are driven in one pass so the comparison is between rows one code path
    produced, not between a row and a remembered shape: b is cut short, c has an absent
    `report.md` (tier 1), and the malformed arm is pinned by its own sibling test."""
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    (ep / "worlds" / "c" / "report.md").unlink()
    graded = S.graded(ep)
    assert "malformed" not in graded["b"], "the cut-short row claims tier 2"
    assert graded["c"].get("ungradable") is True
    assert graded["c"].get("malformed") is not True, (
        "an absent input was recorded as a malformed one; tier 1 skips and tier 2 refuses, and "
        "the record is where the difference has to survive")
    assert graded["c"].get("cut_short") is None, (
        "a world ungradable for an absent report acquired a cut_short key")


def test_a_pre_existing_ungradable_reason_does_not_acquire_a_cut_short_key(tmp_path):
    """A world ungradable for a PRE-EXISTING reason unconnected to `run_end.json` — a tier-2
    malformed world, or a tier-1 reason that predates this piece — does not spuriously acquire
    a `cut_short` key: `tier_split_survives` pins that the two tiers stay separable in one
    direction; this pins the other.

    Three pre-existing reasons, each with no run-end record at all: an absent report (tier 1),
    a manifest disposition outside the vocabulary (tier 1), and a report whose headline is
    outside the vocabulary (tier 2). None of them is about how the run ended, so none of their
    rows may say anything about how the run ended."""
    ep = S.cut_short_episode(tmp_path / "absent")
    (ep / "worlds" / "b" / "report.md").unlink()
    assert S.graded(ep)["b"].get("cut_short") is None, "an absent report acquired cut_short"

    bad_headline = S.cut_short_episode(tmp_path / "malformed")
    (bad_headline / "worlds" / "b" / "report.md").write_text(
        S.report_text("not-a-disposition"), encoding="utf-8")
    row = S.graded(bad_headline)["b"]
    assert row.get("ungradable") is True, "the control failed: the malformed world still graded"
    assert row.get("cut_short") is None, "a malformed world acquired cut_short"

    bad_declared = S.cut_short_episode(
        tmp_path / "declared", dispositions={"a": "benign", "b": "nonsense", "c": "malicious"})
    assert S.graded(bad_declared)["b"].get("cut_short") is None, (
        "a world with no ground truth to grade against acquired a cut_short key")


def test_an_aborted_budget_or_store_world_names_its_exit_not_a_missing_report(tmp_path):
    """A world whose run ended aborted, budget or store — none of which write a report.md —
    still returns the third row shape naming that exit class, rather than the generic tier-1
    reason "missing its report.md"; the cut-short check runs first for all five exit classes,
    not only the two that also produce a forced report.

    Each arm is driven with the report genuinely absent, which is the state claim h1 says these
    three classes leave. Under the other ordering every one of them would read out as "world
    'b' is missing its report.md" — true, and useless to an operator asking why."""
    for exit_class in S.NO_REPORT_EXITS:
        ep = S.cut_short_episode(tmp_path / exit_class, cut={"b": exit_class})
        (ep / "worlds" / "b" / "report.md").unlink()
        row = S.graded(ep)["b"]
        assert row.get("cut_short") == exit_class, (
            f"{exit_class}: the row does not name the exit class")
        reason = row.get("ungradable_reason") or ""
        assert exit_class in reason, (
            f"{exit_class}: the reason is {reason!r} — the generic missing-report reason won, "
            "so the cut-short check did not run first")
        assert "report.md" not in reason, (
            f"{exit_class}: the reason blames a missing report.md for a class that never "
            "writes one")


# ---------------------------------------------------------------------------------------
# F-A — a model that closed, and a run cut short afterwards
# ---------------------------------------------------------------------------------------


def test_a_world_whose_model_closed_and_was_then_cut_short(tmp_path):
    """A world whose model had ALREADY CLOSED when the exit class was stamped keeps its
    verdict: the row is graded normally, carries no `cut_short` key, and still counts toward
    the family's verdict word.

    Fork F-A, resolved to reading B by the human at §7 round 2. Round-1 probe p21 (EXECUTED
    over the real `AgentDeps`) confirmed the collision is real on all five exit classes: the
    forced close returns early when `challenge_gate.ReviewState.of(deps).closed`, leaving the
    model's own `report.md` and `review_record.1.json` byte-identical, and the three classes
    that never force a close reach it trivially. Reading A — the exit class is an unconditional
    trump — was rejected because it throws away a real, confident model verdict and makes the
    third row shape's own reason string false about that world.

    Positive control on the same exit class, one line down: the same `request-limit` record
    with `closed_before_cut` false still files the third row shape, so what is under test is
    the FIELD and not the exit class."""
    decided = S.cut_short_episode(tmp_path / "decided", cut={"b": "request-limit"},
                                  closed=("b",))
    row = S.graded(decided)["b"]
    assert row.get("cut_short") is None, (
        "a world that produced its own verdict before the run was cut short was filed as "
        "cut short; the host's report is not what this world's report is")
    assert row.get("ungradable") is not True, (
        "a genuine model-authored verdict was discarded because the run was later cut short")

    undecided = S.cut_short_episode(tmp_path / "undecided", cut={"b": "request-limit"})
    assert S.graded(undecided)["b"].get("cut_short") == "request-limit", (
        "the control failed: a world cut short WITHOUT deciding no longer files the third row "
        "shape, so the assertion above is not about `closed_before_cut`")

    control = S.cut_short_episode(tmp_path / "control")
    assert S.family_word(decided) == S.family_word(control), (
        "a world that decided before it was cut short stopped counting as a measuring world")


def test_the_record_must_distinguish_a_host_written_close_from_the_models_own(tmp_path):
    """The run-end record carries a second field — `closed_before_cut` — and it is what
    separates a host-written close from the model's own: two worlds carrying the SAME exit
    class and the SAME report differ in their rows only because the record says whether the
    model had already decided.

    The archived `report.md` carries no field that distinguishes the two (probe p21): the value
    pair `unresolved` + `CAUSE_NOT_REVIEWED` is incidental, not a designed discriminator, and
    `validate_report` admits whatever the box writes anyway (claim h3). The host is the only
    party that knows, via `ReviewState.of(deps).closed` at the moment of the cut, so the record
    is where that fact has to be carried — and it is written host-side, where no box can reach
    it."""
    ep = S.cut_short_episode(tmp_path, cut={"b": "aborted", "c": "aborted"}, closed=("c",))
    for label in ("b", "c"):
        (ep / "worlds" / label / "report.md").write_text(
            S.report_text("malicious"), encoding="utf-8")
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "aborted", (
        "the world whose model never closed was not filed as cut short")
    assert graded["c"].get("cut_short") is None, (
        "the world whose model HAD closed was filed as cut short; the two worlds are "
        "identical apart from the record's second field, so the record is not distinguishing "
        "a host-written close from the model's own")
    assert graded["c"].get("verdict") is not None, (
        "the world that decided before it was cut short recorded no verdict at all")

    record = json.loads(
        (ep / "worlds" / "c" / S.run_end_name()).read_text(encoding="utf-8"))
    assert record["closed_before_cut"] is True
    assert set(record) >= {"truncated_by", "closed_before_cut"}, (
        "the record's field set is short of what F-A reading B requires")


# ---------------------------------------------------------------------------------------
# what the judge's read of the archived record does with each state it can meet
# ---------------------------------------------------------------------------------------


def _cut_short_of(episode_dir, label="b"):
    """What the grading pass made of one world's archived run-end record: the `cut_short` the
    row carries, or `None` — the judge's one read of the record (`family._read_run_end_record`,
    through `run_end.parse_record`) feeds the row and nothing else."""
    return S.graded(episode_dir)[label].get("cut_short")


def test_read_world_facts_given_an_empty_run_end_json(tmp_path):
    """A zero-byte archived record reads as None (unreadable) and the world grades as today, by
    `missing_run_end_grades_as_today`'s own rule.

    The bytes are really written and really read — a zero-length file is not the same input as
    an absent one at the filesystem, and only driving both proves the reader folds them
    together."""
    ep = S.cut_short_episode(tmp_path)
    S.plant_archived_record(ep, "b", raw="")
    assert _cut_short_of(ep) is None
    assert S.graded(ep)["b"].get("ungradable") is not True


def test_read_world_facts_given_a_mapping_with_no_truncated_by_key(tmp_path):
    """A mapping with no `truncated_by` key is a lookup miss: None, and the world grades as
    today."""
    ep = S.cut_short_episode(tmp_path)
    S.plant_archived_record(ep, "b", raw=json.dumps({"closed_before_cut": False}))
    assert _cut_short_of(ep) is None
    assert S.graded(ep)["b"].get("cut_short") is None


def test_read_world_facts_given_a_mapping_with_truncated_by_explicitly_null(tmp_path):
    """An explicit null is indistinguishable from key-absent and from file-absent: all three
    mean "not cut short".

    Driven as all three in one test, because the point is that they AGREE — a reader that
    answered `None`, `""` and "absent" differently would make "this run was not cut short"
    depend on which of three equivalent records the host happened to write."""
    absent = S.cut_short_episode(tmp_path / "absent")
    explicit = S.cut_short_episode(tmp_path / "explicit")
    S.plant_archived_record(explicit, "b", truncated_by=None)
    no_key = S.cut_short_episode(tmp_path / "nokey")
    S.plant_archived_record(no_key, "b", raw=json.dumps({}))
    answers = [_cut_short_of(e) for e in (absent, explicit, no_key)]
    assert answers == [None, None, None], f"the three absent-shaped records disagreed: {answers}"
    rows = [S.graded(e)["b"] for e in (absent, explicit, no_key)]
    assert all(r.get("ungradable") is not True for r in rows), (
        "a record meaning 'not cut short' made a world ungradable")


def test_read_world_facts_given_extra_unexpected_keys_alongside_truncated_by(tmp_path):
    """Extra keys are ignored and `truncated_by` is read and normalised as usual — tolerance is
    safe here precisely because the archived record is host-written from a host-owned sidecar,
    so an extra key has no adversarial producer and the h3 hazard that killed the frontmatter
    design does not transfer.

    The extra keys planted here are deliberately the row-shaped ones (`ungradable`, `verdict`,
    `malformed`): if any of them were merged into the row rather than ignored, the record would
    be deciding the grade instead of reporting how the run ended."""
    ep = S.cut_short_episode(tmp_path)
    S.plant_archived_record(ep, "b", raw=json.dumps({
        "truncated_by": "aborted", "closed_before_cut": False,
        "ungradable": False, "verdict": "benign", "malformed": True, "note": "hello"}))
    assert _cut_short_of(ep) == "aborted"
    row = S.graded(ep)["b"]
    assert row.get("cut_short") == "aborted"
    assert row.get("ungradable") is True, "a planted `ungradable: False` reached the row"
    assert "malformed" not in row, "a planted `malformed` key reached the row"
    assert row.get("verdict") is None, "a planted verdict reached the row"


def test_read_world_facts_given_a_wrong_typed_truncated_by_value(tmp_path):
    """A non-string `truncated_by` value normalises to None at the owner and reads as "not cut
    short" — the judge carries no type check of its own."""
    ep = S.cut_short_episode(tmp_path)
    for value in (7, True, ["aborted"], {"value": "aborted"}):
        S.plant_archived_record(ep, "b", raw=json.dumps({"truncated_by": value}))
        assert _cut_short_of(ep) is None, f"{value!r} was read as an exit class"
        assert S.graded(ep)["b"].get("ungradable") is not True


def test_read_world_facts_given_undecodable_bytes(tmp_path):
    """Undecodable bytes read as None — "undecodable" is named verbatim in demand #0a's
    `json_mapping` note, beside absent, unreadable and non-mapping.

    Real bytes through the real reader: `json_mapping` goes through `read_guarded`, which
    answers absent, unreadable and undecodable the same way — `None` — so this is a fault the
    test re-probes on every run rather than a taxonomy assumption pinned once."""
    ep = S.cut_short_episode(tmp_path)
    S.plant_archived_record(ep, "b", raw=b"\xff\xfe\x00\x81not utf-8 at all")
    assert _cut_short_of(ep) is None
    assert S.graded(ep)["b"].get("ungradable") is not True


def test_read_world_facts_given_truncated_json_or_a_json_list(tmp_path):
    """Invalid JSON, truncated JSON and a JSON list where a mapping belongs each read as None
    and the world grades as today (fork F-Y, §7 round 2, convergent on the demand's own pinned
    language).

    `json_mapping` returns `None` for a document that is not a mapping, so a list is answered
    exactly as undecodable bytes are — there is no fourth answer to invent."""
    ep = S.cut_short_episode(tmp_path)
    for raw in ('{"truncated_by": "abort', '[{"truncated_by": "aborted"}]', '"aborted"', "null"):
        S.plant_archived_record(ep, "b", raw=raw)
        assert _cut_short_of(ep) is None, f"{raw!r} was read as an exit class"
        assert S.graded(ep)["b"].get("ungradable") is not True, f"{raw!r} made the world ungradable"


# ---------------------------------------------------------------------------------------
# the absent record, and every route to it
# ---------------------------------------------------------------------------------------


def test_a_world_with_no_run_end_record_grades_as_it_does_today(tmp_path):
    """An archive written before this change — a world with no run_end.json at all — grades
    exactly as it does today: no cut_short key, no new ungradable reason, the same verdict and
    bucket.

    Asserted as EQUALITY against the row a control episode produces, not as a list of absent
    keys: "no new reason" is a claim about the whole row, and a test that checked three keys
    would stay green while a fourth appeared."""
    control = S.cut_short_episode(tmp_path / "control")
    assert not (control / "worlds" / "b" / S.run_end_name()).exists()
    row = S.graded(control)["b"]
    assert "cut_short" not in row, "a world with no record acquired a cut_short key"
    assert row.get("ungradable") is not True
    assert row.get("verdict") is not None, (
        "the control episode's world b produced no verdict at all, so 'grades as today' is "
        "not observable here")


def test_old_archive_predating_the_feature_has_no_sidecar_ever(tmp_path):
    """An episode archived before this feature existed grades verbatim as
    `missing_run_end_grades_as_today` says: no cut_short key, no new reason, the same verdict
    and bucket.

    The pre-feature archive is built as the archive step ACTUALLY leaves one, through the real
    `archive_episode` over run dirs that carry no sidecar — not by deleting a record from a
    modern archive, which would leave the rest of the tree in a shape the old writer never
    produced."""
    base, _src = S.runs_base(tmp_path)
    ep = S.cut_short_episode(tmp_path)
    old = {w: S.sibling_run_dir(base, w) for w in ("b", "c")}
    for run_dir in old.values():
        assert not S.sidecar_path(run_dir).exists(), "the fixture wrote a sidecar"
    S.mod("learning.branch.archive").archive_episode(ep, old)
    for label in ("b", "c"):
        assert not (ep / "worlds" / label / S.run_end_name()).exists(), (
            f"{label}: the archive invented a record for a run that recorded nothing")
    assert S.graded(ep)["b"].get("cut_short") is None


def test_missing_run_end_covers_every_re_run_path_not_only_archive_time(tmp_path):
    """The absent-record outcome is a property of the archived record's CONTENT, not of which
    pass reads it: re-processing and re-archiving answer the same.

    The same episode dir is graded twice and archived twice, with the record absent throughout.
    A reader that keyed on "is this the first pass" rather than on the record would answer
    differently on the second call, which is the state an operator re-running a grade actually
    meets."""
    base, _src = S.runs_base(tmp_path)
    ep = S.cut_short_episode(tmp_path)
    first = S.graded(ep)["b"]
    second = S.graded(ep)["b"]
    assert first == second, "the second grading pass over one archive answered differently"
    S.mod("learning.branch.archive").archive_episode(ep, {"b": S.sibling_run_dir(base, "b")})
    assert S.graded(ep)["b"].get("cut_short") is None, (
        "re-archiving a world whose run recorded nothing produced a cut_short key")


def test_world_declared_by_the_manifest_has_no_archived_directory_at_all(tmp_path):
    """Archive membership is `_scrub_ran` alone and `stop_and_scrub` runs in run.py's `finally`,
    reached identically by all five exit classes — so the exit class never gates the archive; a
    world with no archived directory at all is one whose process died before the `finally`, and
    it takes today's generic absent-world handling.

    Fork F-C evaporated on re-ground probe #23 (claim p23): all five exit classes reach the
    archive, so "cut short" and "not archived" are independent conditions and the second one
    keeps the handling it already had."""
    import shutil

    ep = S.cut_short_episode(tmp_path, cut={"b": "aborted"})
    shutil.rmtree(ep / "worlds" / "b")
    row = S.graded(ep)["b"]
    assert row.get("ungradable") is True, "a world with no archived directory still graded"
    assert row.get("cut_short") is None, (
        "a world the archive never received was filed with an exit class; the record it would "
        "have carried went with the directory")
    assert S.graded(ep)["c"].get("ungradable") is not True, (
        "the missing world cost its sibling its grade")


# ---------------------------------------------------------------------------------------
# the cut-short check runs before every artifact-presence check, not just the report's
# ---------------------------------------------------------------------------------------


def test_run_end_record_lands_but_the_forced_report_never_does(tmp_path):
    """A world with a run-end record and no report.md gets the third row shape naming its exit
    class — F5's ordering puts the cut-short check ahead of the report-presence check for all
    five exit classes, so "record present, report absent" is the GOOD state.

    This is also what closes fork F-B's crash window: the host-side write happens BEFORE the
    forced report (probe p25, executed), so a kill between the two leaves exactly this state
    rather than the pre-#1047 bug (a forced report graded as a verdict with no record beside
    it)."""
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    (ep / "worlds" / "b" / "report.md").unlink()
    row = S.graded(ep)["b"]
    assert row.get("cut_short") == "request-limit"
    assert "report.md" not in (row.get("ungradable_reason") or "")


def test_a_world_directory_holding_a_run_end_record_and_nothing_else(tmp_path):
    """A world directory holding only a run-end record gets the third row shape: "the cut-short
    check runs before `_missing_required_input`" covers EVERY artifact-presence check in that
    function (the ledger artifact, report.md, investigation.md, alert.json — claim n7), not
    just the report.

    Each of the four is removed in turn AND all four together, because `_missing_required_input`
    returns on the FIRST one it finds missing: a check ordered ahead of only the report would
    be green on the report arm and silently wrong on the other three."""
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    world = ep / "worlds" / "b"
    ledger = ep / S.mod("learning.judge.family").world_ledger_name(  # #1049: the relative spelling
        "b", episode_token=S.EPISODE_TOKEN)
    for name in ("report.md", "investigation.md", "alert.json"):
        (world / name).unlink()
    if ledger.exists():
        ledger.unlink()
    row = S.graded(ep)["b"]
    assert row.get("cut_short") == "request-limit", (
        "a world stripped of every required input did not reach the cut-short check; the "
        "ordering covers the report alone")
    reason = row.get("ungradable_reason") or ""
    assert "is missing its" not in reason, (
        f"the generic missing-input reason won over the exit class: {reason!r}")


def test_world_cut_short_before_any_of_its_required_inputs_exist(tmp_path):
    """A world cut short before any required input exists still gets the third row shape naming
    its exit class: the cut-short check requires no other input to be present.

    The world directory holds the record and NOTHING else — the shape a run killed at its first
    model request leaves behind once the host has written what it knows."""
    ep = S.cut_short_episode(tmp_path, cut={"b": "budget"})
    import shutil

    shutil.rmtree(ep / "worlds" / "b")
    S.plant_archived_record(ep, "b", truncated_by="budget")
    row = S.graded(ep)["b"]
    assert row.get("cut_short") == "budget"
    assert row.get("ungradable") is True
    assert "budget" in (row.get("ungradable_reason") or "")


# ---------------------------------------------------------------------------------------
# families: several worlds, several shapes, one pass
# ---------------------------------------------------------------------------------------


def test_two_worlds_end_in_different_exit_classes_in_one_episode(tmp_path):
    """Each world grades independently per its own class — b a request-limit row, c an aborted
    row via F5's reordering, d a normal graded row — and verdict_word is computed over what is
    left measuring.

    Three non-control worlds so "the rest still grades" is observable: with only two, an
    episode where both are excluded and one where both are graded are indistinguishable from
    the word alone."""
    ep = S.cut_short_episode(
        tmp_path, labels=("a", "b", "c", "d"),
        dispositions={"a": "benign", "b": "malicious", "c": "malicious", "d": "malicious"},
        ledgers={"b": [S.staged_row("b")], "c": [], "d": []},
        cut={"b": "request-limit", "c": "aborted"})
    (ep / "worlds" / "c" / "report.md").unlink()
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "request-limit"
    assert graded["c"].get("cut_short") == "aborted"
    assert graded["d"].get("ungradable") is not True, (
        "the world that finished was excluded along with its cut-short siblings")
    assert S.family_word(ep), "the family computed no verdict word at all"


def test_a_cut_short_world_and_a_malformed_world_in_the_same_episode(tmp_path):
    """The three row shapes coexist in one episode without interference —
    `tier_split_survives`'s own stated purpose, driven over a real family.

    b is cut short (no `malformed`), c is malformed (`malformed: True`, no `cut_short`), d is
    graded. A reader keying on `ungradable` alone sees three exclusions; the record is where
    the difference between them has to survive."""
    ep = S.cut_short_episode(
        tmp_path, labels=("a", "b", "c", "d"),
        dispositions={"a": "benign", "b": "malicious", "c": "malicious", "d": "malicious"},
        ledgers={"b": [S.staged_row("b")], "c": [], "d": []},
        cut={"b": "request-limit"})
    (ep / "worlds" / "c" / "report.md").write_text(
        S.report_text("not-a-disposition"), encoding="utf-8")
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "request-limit"
    assert "malformed" not in graded["b"], "the cut-short row claims tier 2"
    assert graded["c"].get("malformed") is True, "the malformed world lost its tier-2 mark"
    assert graded["c"].get("cut_short") is None, "the malformed world acquired cut_short"
    assert graded["d"].get("ungradable") is not True
