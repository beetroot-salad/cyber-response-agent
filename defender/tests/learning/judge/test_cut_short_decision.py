"""#1047 — the ticket lane decides per exit class, from a source the box cannot write.

#1047 — a world whose run the host cut short is never graded as a verdict about the case.

#1047 — no box-writable file is an input to the cut-short decision: the negative universals,
each with a positive control.
"""
from __future__ import annotations

import json
from pathlib import Path

from defender.tests.support.shared.filesystem import _spec1047 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.shared._locations_1210 import location_path
from defender.records._episode_handle import Episode


# one arm per exit class


def test_an_aborted_run_leaves_its_ticket_open_with_the_escalation(tmp_path):
    run_dir = S.closed_run_dir(tmp_path, report=False)
    fake = S.record_ticket(run_dir, truncated_by="aborted", closed_before_cut=False)

    assert fake.records == [], (
        "an aborted run recorded a verdict")
    assert len(fake.notes) == 1, f"the aborted arm made {len(fake.notes)} note calls, not one"
    note = fake.notes[0]
    assert note.method == "POST"
    assert note.key == S.CASE_KEY, (
        f"the note addressed ticket {note.key!r}, not the one the alert named ({S.CASE_KEY!r})")
    body = note.text().lower()
    assert "aborted" in body, f"the note does not name the exit class: {note.text()!r}"
    assert "escalate" in body, (
        f"the note does not carry the escalation ask: {note.text()!r}")


def test_a_request_limit_run_records_unresolved(tmp_path):
    """A run whose exit class is `request-limit` records `unresolved` off the host's forced report
    — a comment proposing it, for a person to close on; never a transition."""
    run_dir = S.closed_run_dir(tmp_path, disposition="unresolved")
    fake = S.record_ticket(run_dir, truncated_by="request-limit")
    assert fake.transitions == [], "the request-limit arm transitioned the ticket"
    assert len(fake.records) == 1, "the request-limit arm made no record"
    assert "unresolved" in fake.records[0].text()
    assert fake.notes == [], "the request-limit arm also raised an escalation note"
    assert (S.receipt(run_dir) or {}).get("ok") is True


def test_a_budget_kill_leaves_its_ticket_open_and_makes_no_call(tmp_path):
    """The missing report is itself the escalation, so the budget arm makes no call."""
    for report in (False, True):
        run_dir = S.closed_run_dir(tmp_path / f"report-{report}", report=report)
        fake = S.record_ticket(run_dir, truncated_by="budget")
        assert fake.calls == [], (
            f"report={report}: the budget arm made calls: {fake.calls}")
        assert S.receipt(run_dir) is None, "the budget arm wrote a receipt for a call it never made"


def test_a_run_that_was_not_cut_short_still_records_off_its_report(tmp_path):
    run_dir = S.closed_run_dir(tmp_path, disposition="malicious")
    fake = S.record_ticket(run_dir, truncated_by=None)
    assert fake.transitions == []
    assert len(fake.records) == 1
    assert "malicious" in fake.records[0].text()
    assert fake.notes == []
    assert (S.receipt(run_dir) or {}).get("ok") is True


def test_an_exit_class_the_table_does_not_name_takes_the_report_driven_fallback(tmp_path):
    assert "dead-end" in S.vocabulary(), (
        "control: `dead-end` is not in the vocabulary")
    run_dir = S.closed_run_dir(tmp_path, disposition="malicious")
    unmapped = S.record_ticket(run_dir, truncated_by="dead-end")
    baseline = S.record_ticket(run_dir, truncated_by=None)
    assert len(unmapped.records) == 1, "an unmapped exit class made no record at all"
    assert unmapped.records[0].body == baseline.records[0].body, (
        "an unmapped exit class recorded the ticket differently from a run with no exit class")
    assert unmapped.notes == []


def test_a_run_with_no_exit_class_and_no_usable_report_records_that_and_proposes_nothing(
        tmp_path):
    for name, write in (
        ("absent", None),
        ("no-frontmatter", "just some prose, no headline anywhere\n"),
        ("bad-headline", S.report_text("not-a-disposition")),
    ):
        run_dir = S.closed_run_dir(tmp_path / name, report=False)
        if write is not None:
            (run_dir / "report.md").write_text(write, encoding="utf-8")
        fake = S.record_ticket(run_dir, truncated_by=None)
        assert fake.transitions == [], f"{name}: an unusable report still closed the ticket"
        assert len(fake.records) == 1, f"{name}: an unusable report left the ticket in silence"
        assert S.UNREADABLE_MARK in fake.records[0].text(), (
            f"{name}: the record proposes something off a report that yields no disposition")
        for word in S.sym("_vocab", "DISPOSITION_VALUES"):
            assert word not in fake.records[0].text().lower(), (
                f"{name}: an unreadable report's record names a disposition ({word!r})")
        assert (S.receipt(run_dir) or {}).get("ok") is True


# the exit class and a genuine model verdict, together


def test_a_ticket_for_a_run_that_closed_and_was_then_cut_short(tmp_path):
    run_dir = S.closed_run_dir(tmp_path, disposition="malicious")
    decided = S.record_ticket(run_dir, truncated_by="aborted", closed_before_cut=True)
    assert len(decided.records) == 1, (
        "a run that reached its own confident close recorded nothing; the model decided, "
        "and the exit class arrived afterwards")
    assert "malicious" in decided.records[0].text(), (
        "the record proposes something other than the model's own verdict")
    assert decided.notes == [], (
        "an escalation note was raised about a case that actually concluded")

    undecided = S.record_ticket(run_dir, truncated_by="aborted", closed_before_cut=False)
    control_failed = (
        "the control failed: the same run dir with `closed_before_cut=False` no longer takes "
        "the aborted arm, so the assertions above are not about that field")
    assert undecided.records == [], control_failed
    assert len(undecided.notes) == 1, control_failed


def test_a_forced_close_set_exit_whose_own_forced_close_failed_leaves_the_ticket_open_with_the_escalation(
        tmp_path):
    for exit_class in S.FORCED_CLOSE_SET:
        run_dir = S.closed_run_dir(tmp_path / exit_class, report=False)
        fake = S.record_ticket(run_dir, truncated_by=exit_class)
        assert fake.records == [], (
            f"{exit_class}: `unresolved` was recorded with no report to record it off")
        assert len(fake.notes) == 1, (
            f"{exit_class}: a run whose forced close failed left the ticket open in silence")
        assert exit_class in fake.notes[0].text()

        decided = S.closed_run_dir(tmp_path / f"{exit_class}-decided", report=False)
        both = S.record_ticket(decided, truncated_by=exit_class, closed_before_cut=True)
        assert both.records == [], (
            f"{exit_class}: a run that had closed but left no report.md still recorded a verdict")
        assert len(both.notes) == 1, (
            f"{exit_class}: `closed_before_cut=True` swallowed the escalation of a failed "
            "forced close")
        assert exit_class in both.notes[0].text()


def test_a_failed_note_call_never_breaks_the_run_and_is_recorded_in_the_receipt(tmp_path):
    """A note call that fails is swallowed — the run never breaks over it — and the outcome is
    written into `ticket_write.json` either way."""
    ok_dir = S.closed_run_dir(tmp_path / "ok", report=False)
    S.record_ticket(ok_dir, truncated_by="aborted")
    ok = S.receipt(ok_dir)
    assert ok is not None, "a successful note call left no receipt at all"
    assert ok.get("ok") is True, f"a successful note call was recorded as a failure: {ok!r}"
    assert ok.get("status") != "closed", (
        f"the receipt claims the ticket closed on the leave-open arm: {ok!r}")

    bad_dir = S.closed_run_dir(tmp_path / "bad", report=False)
    S.record_ticket(bad_dir, ticket=S.FakeTicketSystem(status=None), truncated_by="aborted")
    bad = S.receipt(bad_dir)
    assert bad is not None, "a failed note call left no receipt; the operator cannot see it"
    assert bad.get("ok") is False, f"a failed note call was recorded as a success: {bad!r}"


# nothing inside the run dir is an input to the decision


def test_no_planted_file_under_the_run_dir_changes_which_comment_record_case_ticket_makes_for_any_exit_class(
        tmp_path):
    for exit_class in (*S.vocabulary(), None):
        clean = S.closed_run_dir(tmp_path / f"clean-{exit_class}", disposition="unresolved")
        salted = S.closed_run_dir(tmp_path / f"salted-{exit_class}", disposition="unresolved")
        S.salt_run_dir(salted, value="request-limit")
        (salted / "report.md").write_text(S.report_text("unresolved"), encoding="utf-8")
        a = S.record_ticket(clean, truncated_by=exit_class)
        b = S.record_ticket(salted, truncated_by=exit_class)
        assert [(c.path.split("/")[-1], c.body) for c in a.calls] == \
               [(c.path.split("/")[-1], c.body) for c in b.calls], (
            f"{exit_class}: a planted file changed what the ticket lane did")


def test_a_forged_session_store_pointer_file_is_never_consulted_by_the_ticket_lane_for_any_exit_class(
        tmp_path):
    in_folder_name = "session_store_pointer.json"

    def addresses(run_dir: Path) -> dict[str, Path]:
        sidecar = S.sym("records", "RunPaths")(run_dir).session_pointer()
        assert sidecar.parent == run_dir.parent, (
            f"the case pointer is not a sidecar beside the run dir: {sidecar}")
        return {"in-folder": run_dir / in_folder_name, "sidecar": sidecar}

    forgeries = {
        "other-case": json.dumps({"case_id": "someone-elses-case", "session_id": "sid"}),
        "not-json": "{{{ not json at all",
        "empty": "",
    }
    for exit_class in (*S.vocabulary(), None):
        control = S.record_ticket(
            S.closed_run_dir(tmp_path / f"control-{exit_class}", disposition="unresolved"),
            truncated_by=exit_class)
        for where in ("in-folder", "sidecar"):
            for name, content in forgeries.items():
                run_dir = S.closed_run_dir(tmp_path / f"{where}-{name}-{exit_class}",
                                           disposition="unresolved")
                addresses(run_dir)[where].write_text(content, encoding="utf-8")
                fake = S.record_ticket(run_dir, truncated_by=exit_class)
                assert [c.path.split("/")[-1] for c in fake.calls] == \
                       [c.path.split("/")[-1] for c in control.calls], (
                    f"{exit_class}/{where}/{name}: a forged case pointer moved the ticket lane")

    for where in ("in-folder", "sidecar"):
        dangling = S.closed_run_dir(tmp_path / f"dangling-{where}", disposition="unresolved")
        addresses(dangling)[where].symlink_to(tmp_path / "nowhere.json")
        assert len(S.record_ticket(dangling, truncated_by="request-limit").records) == 1, (
            f"a dangling symlink at the case pointer's {where} address stopped the ticket lane, "
            "so something is reading it")


def test_a_forged_ticket_write_receipt_claiming_prior_closure_does_not_suppress_the_real_record_or_note_call(
        tmp_path):
    for exit_class, expect in (("request-limit", "records"), ("aborted", "notes")):
        run_dir = S.closed_run_dir(tmp_path / exit_class, disposition="unresolved",
                                   report=expect == "records")
        # The receipt sits beside the run dir; forge it at its name there.
        S.receipt_path(run_dir).write_text(
            json.dumps({"key": run_dir.name, "status": "closed", "ok": True,
                        "url": "http://tickets.test/tickets/forged"}), encoding="utf-8")
        fake = S.record_ticket(run_dir, truncated_by=exit_class)
        assert len(getattr(fake, expect)) == 1, (
            f"{exit_class}: a forged receipt claiming the ticket was already closed suppressed "
            "the real call")


# the host never transitions; the store's `closed` is a person's word (#767)


def test_no_exit_class_transitions_the_ticket(tmp_path):
    """For EVERY exit class, with and without a report, and whether or not the model had closed,
    the lane makes no transition call: the only writes are comments."""
    seen_writes = 0
    for exit_class in (*S.vocabulary(), None):
        for report in (False, True):
            for closed in (False, True):
                run_dir = S.closed_run_dir(
                    tmp_path / f"{exit_class}-{report}-{closed}", report=report)
                fake = S.record_ticket(run_dir, truncated_by=exit_class,
                                       closed_before_cut=closed)
                assert fake.transitions == [], (
                    f"{exit_class}/report={report}/closed_before_cut={closed}: the host "
                    f"transitioned the ticket: {[c.path for c in fake.transitions]}")
                assert all(c.is_comment for c in fake.writes), (
                    f"{exit_class}: a write that is neither a comment nor a transition: "
                    f"{[c.path for c in fake.writes]}")
                seen_writes += len(fake.writes)
    assert seen_writes, "the control failed: no drive wrote anything, so the census is empty"


#: The host's forced close as `_close_a_run_cut_short` leaves it: an `unresolved` report.
FORCED_REPORT = S.report_text("unresolved")


def _forced_close(episode_dir):
    """Overwrite world b's archived report with the host's forced `unresolved` close."""
    (episode_dir / "worlds" / T.world_id(episode_dir, "b") / "report.md").write_text(FORCED_REPORT, encoding="utf-8")


# the third row shape


def test_a_cut_short_world_files_the_third_row_shape(tmp_path):
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    row = S.graded(ep)["b"]
    assert row.get("ungradable") is True, "a cut-short world was still graded as a verdict"
    assert row.get("cut_short") == "request-limit", (
        "the row does not carry the exit class as a top-level key beside `ungradable`")
    assert "malformed" not in row, "the cut-short row was marked malformed"
    reason = row.get("ungradable_reason") or ""
    assert "b" in reason, f"the reason does not name the world: {reason!r}"
    assert "request-limit" in reason, f"the reason does not name the exit class: {reason!r}"


def test_a_cut_short_world_does_not_reach_the_family_call_as_a_verdict(tmp_path):
    control = S.family_view(S.cut_short_episode(tmp_path / "control"))
    assert "verdict='malicious'" in control["b"], control

    bug_ep = S.cut_short_episode(tmp_path / "bug")
    _forced_close(bug_ep)
    bug = S.family_view(bug_ep)
    assert "verdict='unresolved'" in bug["b"], (
        f"a host-forced `unresolved` report on world b did not reach the family call: {bug}")

    fixed_ep = S.cut_short_episode(tmp_path / "fixed", cut={"b": "request-limit"})
    _forced_close(fixed_ep)
    judge = S.scripted_judge()
    assert S.graded(fixed_ep, judge=judge)["b"].get("verdict") is None
    assert S.judge_calls_for(judge, "b", episode_dir=fixed_ep) == [], (
        "world b's run was cut short and still bought a world call")
    fixed = S.family_view(fixed_ep)
    assert fixed["b"] == "NOT JUDGED", (
        f"the family call was shown cut-short world b's forced close as a verdict: {fixed['b']!r}")
    assert fixed["c"] == control["c"], "world b's cut moved what the family is shown of world c"


def test_the_third_row_shape_keeps_the_two_tiers_separable(tmp_path):
    ep = S.cut_short_episode(tmp_path, cut={"b": "request-limit"})
    (ep / "worlds" / T.world_id(ep, "c") / "report.md").unlink()
    graded = S.graded(ep)
    assert "malformed" not in graded["b"], "the cut-short row claims tier 2"
    assert graded["c"].get("ungradable") is True
    assert graded["c"].get("malformed") is not True, (
        "an absent input was recorded as a malformed one")
    assert graded["c"].get("cut_short") is None, (
        "a world ungradable for an absent report acquired a cut_short key")


def test_an_aborted_budget_or_store_world_names_its_exit_not_a_missing_report(tmp_path):
    for exit_class in S.NO_REPORT_EXITS:
        ep = S.cut_short_episode(tmp_path / exit_class, cut={"b": exit_class})
        (ep / "worlds" / T.world_id(ep, "b") / "report.md").unlink()
        row = S.graded(ep)["b"]
        assert row.get("cut_short") == exit_class, (
            f"{exit_class}: the row does not name the exit class")
        reason = row.get("ungradable_reason") or ""
        assert exit_class in reason, (
            f"{exit_class}: the generic missing-report reason won: {reason!r}")
        assert "report.md" not in reason, (
            f"{exit_class}: the reason blames a missing report.md for a class that never "
            "writes one")


# a model that closed, and a run cut short afterwards


def test_a_world_whose_model_closed_and_was_then_cut_short(tmp_path):
    decided = S.cut_short_episode(tmp_path / "decided", cut={"b": "request-limit"},
                                  closed=("b",))
    row = S.graded(decided)["b"]
    assert row.get("cut_short") is None, (
        "a world that produced its own verdict before the run was cut short was filed as "
        "cut short")
    assert row.get("ungradable") is not True, (
        "a genuine model-authored verdict was discarded because the run was later cut short")

    undecided = S.cut_short_episode(tmp_path / "undecided", cut={"b": "request-limit"})
    assert S.graded(undecided)["b"].get("cut_short") == "request-limit", (
        "control: a world cut short without deciding did not file the third row shape")

    control = S.cut_short_episode(tmp_path / "control")
    assert S.family_view(decided) == S.family_view(control), (
        "a world that decided before it was cut short stopped counting as a measuring world")


def test_the_record_must_distinguish_a_host_written_close_from_the_models_own(tmp_path):
    ep = S.cut_short_episode(tmp_path, cut={"b": "aborted", "c": "aborted"}, closed=("c",))
    for label in ("b", "c"):
        (ep / "worlds" / T.world_id(ep, label) / "report.md").write_text(
            S.report_text("malicious"), encoding="utf-8")
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "aborted", (
        "the world whose model never closed was not filed as cut short")
    assert graded["c"].get("cut_short") is None, (
        "the world whose model had closed was filed as cut short")
    assert graded["c"].get("verdict") is not None, (
        "the world that decided before it was cut short recorded no verdict at all")

    record = json.loads(
        (ep / "worlds" / T.world_id(ep, "c") / S.run_end_name()).read_text(encoding="utf-8"))
    assert record["closed_before_cut"] is True
    assert set(record) >= {"truncated_by", "closed_before_cut"}, (
        f"the record lacks `truncated_by` or `closed_before_cut`: {sorted(record)}")


# what the judge's read of the archived record does with each state it can meet


def _cut_short_of(episode_dir):
    """The `cut_short` world b's graded row carries, or `None`: the judge's one read of the
    run-end record (`family._read_run_end_record`) feeds the row and nothing else."""
    return S.graded(episode_dir)["b"].get("cut_short")


def test_read_world_facts_given_a_mapping_with_truncated_by_explicitly_null(tmp_path):
    """An explicit null is indistinguishable from key-absent and from file-absent: all three mean
    "not cut short"."""
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


def test_read_world_facts_given_a_wrong_typed_truncated_by_value(tmp_path):
    """A non-string `truncated_by` value normalises to None at the owner and reads as "not cut
    short" — the judge carries no type check of its own."""
    ep = S.cut_short_episode(tmp_path)
    for value in (7, True, ["aborted"], {"value": "aborted"}):
        S.plant_archived_record(ep, "b", raw=json.dumps({"truncated_by": value}))
        assert _cut_short_of(ep) is None, f"{value!r} was read as an exit class"
        assert S.graded(ep)["b"].get("ungradable") is not True


def test_read_world_facts_given_truncated_json_or_a_json_list(tmp_path):
    ep = S.cut_short_episode(tmp_path)
    for raw in ("", '{"truncated_by": "abort', '[{"truncated_by": "aborted"}]', '"aborted"',
                "null"):
        S.plant_archived_record(ep, "b", raw=raw)
        assert _cut_short_of(ep) is None, f"{raw!r} was read as an exit class"
        assert S.graded(ep)["b"].get("ungradable") is not True, f"{raw!r} made the world ungradable"


# families: several worlds, several shapes, one pass


def test_a_cut_short_world_and_a_malformed_world_in_the_same_episode(tmp_path):
    """The three row shapes coexist in one episode without interference."""
    ep = S.cut_short_episode(
        tmp_path, labels=("a", "b", "c", "d"),
        dispositions={"a": "benign", "b": "malicious", "c": "malicious", "d": "malicious"},
        ledgers={"b": [S.staged_row("b")], "c": [], "d": []},
        cut={"b": "request-limit"})
    (ep / "worlds" / T.world_id(ep, "c") / "report.md").write_text(
        S.report_text("not-a-disposition"), encoding="utf-8")
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "request-limit"
    assert "malformed" not in graded["b"], "the cut-short row claims tier 2"
    assert graded["c"].get("malformed") is True, "the malformed world lost its tier-2 mark"
    assert graded["c"].get("cut_short") is None, "the malformed world acquired cut_short"
    assert graded["d"].get("ungradable") is not True


def _rows_and_word(episode_dir):
    """One pass over one episode: every row, plus what the family-scope call was shown of each
    world."""
    return S.graded_with_view(episode_dir)


# the universal, as one test over every surface


def test_no_file_a_box_can_write_is_an_input_to_was_this_run_cut_short(tmp_path):
    archive = S.mod("learning.branch.archive")

    control_base, _src = location_path(S.runs_base)(tmp_path / "control-base")
    control_ep = S.cut_short_episode(tmp_path / "control")
    with Episode.open(control_ep) as episode:
        archive.archive_episode(
            episode, {T.world_id(episode.dir, label): path for label, path in ({label: S.sibling_run_dir(control_base, label) for label in ("b", "c")}).items()})
    control_rows, control_word = _rows_and_word(control_ep)

    forged_base, _src = location_path(S.runs_base)(tmp_path / "forged-base")
    forged_ep = S.cut_short_episode(tmp_path / "forged")
    forged_dirs = {label: S.sibling_run_dir(forged_base, label) for label in ("b", "c")}
    for run_dir in forged_dirs.values():
        S.salt_run_dir(run_dir, value="request-limit")
    with Episode.open(forged_ep) as episode:
        archive.archive_episode(episode, {T.world_id(episode.dir, label): path for label, path in forged_dirs.items()})
    forged_rows, forged_word = _rows_and_word(forged_ep)
    assert forged_rows == control_rows, (
        "a forgery planted in a box-writable file moved the grade")
    assert forged_word == control_word, "a forgery moved the family's verdict word"
    for label in ("b", "c"):
        assert not (forged_ep / "worlds" / T.world_id(forged_ep, label) / S.run_end_name()).exists(), (
            f"{label}: a box-written file became the archived run-end record; the record is "
            "not in the copy list and no run dir entry is an input to it")

    honest = S.cut_short_episode(tmp_path / "honest", cut={"b": "request-limit"})
    assert S.graded(honest)["b"].get("cut_short") == "request-limit", (
        "control: a host-written record does not move the grade either")

    control_ticket = S.record_ticket(
        S.closed_run_dir(tmp_path / "ticket-clean", disposition="benign"), truncated_by=None)
    salted = S.closed_run_dir(tmp_path / "ticket-salted", disposition="benign")
    S.salt_run_dir(salted, value="aborted")
    (salted / "report.md").write_text(S.report_text("benign"), encoding="utf-8")
    forged_ticket = S.record_ticket(salted, truncated_by=None)
    assert [(c.path.split("/")[-1], c.body) for c in forged_ticket.calls] == \
           [(c.path.split("/")[-1], c.body) for c in control_ticket.calls], (
        "a forgery under the run dir moved what the ticket lane did")


def test_every_box_writable_artifact_carrying_a_truncated_by_looking_value_leaves_the_grade_unmoved(
        tmp_path):
    """One planted name at a time, so a failure names the file that moved the grade."""
    archive = S.mod("learning.branch.archive")
    control_base, _src = location_path(S.runs_base)(tmp_path / "control-base")
    control_ep = S.cut_short_episode(tmp_path / "control")
    with Episode.open(control_ep) as episode:
        archive.archive_episode(episode, {T.world_id(episode.dir, 'b'): S.sibling_run_dir(control_base, 'b')})
    control_rows, control_word = _rows_and_word(control_ep)
    for i, name in enumerate(S.FORGEABLE_NAMES):
        base, _src = location_path(S.runs_base)(tmp_path / f"base-{i}")
        ep = S.cut_short_episode(tmp_path / f"forged-{i}-{name.replace('/', '_')}")
        run_dir = S.sibling_run_dir(base, "b")
        (run_dir / name).write_text(
            json.dumps(S.record_doc("request-limit")), encoding="utf-8")
        with Episode.open(ep) as episode:
            archive.archive_episode(episode, {T.world_id(episode.dir, 'b'): run_dir})
        assert not (ep / "worlds" / T.world_id(ep, "b") / S.run_end_name()).exists(), (
            f"{name}: a box-written file became the archived run-end record")
        seen_rows, seen_word = _rows_and_word(ep)
        assert seen_rows == control_rows, f"{name}: a planted value moved the grade"
        assert seen_word == control_word, f"{name}: a planted value moved the verdict word"

    honest = S.cut_short_episode(tmp_path / "honest", cut={"b": "request-limit"})
    assert S.graded(honest)["b"].get("cut_short") == "request-limit", (
        "control: a host-written record does not move the grade")


def test_a_file_named_like_the_archived_run_end_record_planted_anywhere_under_the_run_dir_does_not_reach_the_grade(
        tmp_path):
    """The archive copies only the host-side sidecar, which is outside the run dir."""
    base, _src = location_path(S.runs_base)(tmp_path)
    ep = S.cut_short_episode(tmp_path)
    run_dir = S.sibling_run_dir(base, "b")
    S.plant_sidecar(run_dir, truncated_by="aborted")
    forged = json.dumps(S.record_doc("request-limit"))
    (run_dir / S.run_end_name()).write_text(forged, encoding="utf-8")
    (run_dir / "gather_raw" / S.run_end_name()).write_text(forged, encoding="utf-8")
    nested = run_dir / "gather_raw" / "l-001"
    nested.mkdir(parents=True, exist_ok=True)
    (nested / S.run_end_name()).write_text(forged, encoding="utf-8")
    with Episode.open(ep) as episode:
        S.mod("learning.branch.archive").archive_episode(episode, {T.world_id(episode.dir, 'b'): run_dir})
    archived = json.loads(
        (ep / "worlds" / T.world_id(ep, "b") / S.run_end_name()).read_text(encoding="utf-8"))
    assert archived == S.record_doc("aborted"), (
        f"a plant under the run dir reached the archived record: {archived!r}")
    assert S.graded(ep)["b"].get("cut_short") == "aborted"


# report frontmatter — the surface the first design would have trusted


def _frontmatter_row(tmp_path, name, extra=None):
    """One episode whose world b carries a planted `report.md`, graded."""
    ep = S.cut_short_episode(tmp_path / name)
    S.plant_frontmatter(ep / "worlds" / T.world_id(ep, "b"), extra=extra or "")
    return _rows_and_word(ep)


def test_grading_given_a_planted_truncated_by_frontmatter_line_with_a_valid_value(tmp_path):
    """A `truncated_by:` line spliced into world b's report frontmatter, which the report
    validator admits, changes nothing for any vocabulary member."""
    control_rows, control_word = _rows_and_word(S.cut_short_episode(tmp_path / "control"))
    for member in S.vocabulary():
        rows, word = _frontmatter_row(tmp_path, f"valid-{member}",
                                      extra=f"truncated_by: {member}\n")
        assert rows == control_rows, f"{member}: a planted valid member moved the grade"
        assert word == control_word, f"{member}: a planted valid member moved the word"


# the owner's input channel, and whose world a record is about


def test_no_box_writable_files_content_is_ever_fed_as_the_value_argument_to_the_exit_class_normalizer(
        tmp_path):
    """No box-writable file's content is ever the value argument to the owner: the two sources are
    the archived record (from a host sidecar) and the in-process summary."""
    base, _src = location_path(S.runs_base)(tmp_path)
    archive = S.mod("learning.branch.archive")

    # site 1 — the archive
    clean_ep, forged_ep = S.episode(tmp_path / "clean"), S.episode(tmp_path / "forged")
    clean_dir, forged_dir = S.sibling_run_dir(base, "b"), S.sibling_run_dir(base, "c")
    S.plant_sidecar(clean_dir, truncated_by="aborted")
    S.plant_sidecar(forged_dir, truncated_by="aborted")
    S.salt_run_dir(forged_dir, value="request-limit")
    with Episode.open(clean_ep) as episode:
        archive.archive_episode(episode, {T.world_id(episode.dir, 'b'): clean_dir})
    with Episode.open(forged_ep) as episode:
        archive.archive_episode(episode, {T.world_id(episode.dir, 'b'): forged_dir})
    assert (clean_ep / "worlds" / T.world_id(clean_ep, "b") / S.run_end_name()).read_text(encoding="utf-8") == \
           (forged_ep / "worlds" / T.world_id(forged_ep, "b") / S.run_end_name()).read_text(encoding="utf-8"), (
        "the archive's record changed when box-written content changed")

    judge_base, _src = location_path(S.runs_base)(tmp_path / "judge-base")
    clean_grade = S.cut_short_episode(tmp_path / "judge-clean")
    forged_grade = S.cut_short_episode(tmp_path / "judge-forged")
    clean_world, forged_world = (S.sibling_run_dir(judge_base, "jb"),
                                 S.sibling_run_dir(judge_base, "jc"))
    S.plant_sidecar(clean_world, truncated_by="aborted")
    S.plant_sidecar(forged_world, truncated_by="aborted")
    S.salt_run_dir(forged_world, value="request-limit")
    with Episode.open(clean_grade) as episode:
        archive.archive_episode(episode, {T.world_id(episode.dir, 'b'): clean_world})
    with Episode.open(forged_grade) as episode:
        archive.archive_episode(episode, {T.world_id(episode.dir, 'b'): forged_world})
    assert S.graded(forged_grade)["b"].get("cut_short") == \
           S.graded(clean_grade)["b"].get("cut_short") == "aborted"

    # site 3 — the ticket lane
    clean_run = S.closed_run_dir(tmp_path / "ticket-clean", disposition="unresolved")
    forged_run = S.closed_run_dir(tmp_path / "ticket-forged", disposition="unresolved")
    S.salt_run_dir(forged_run, value="request-limit")
    (forged_run / "report.md").write_text(S.report_text("unresolved"), encoding="utf-8")
    a = S.record_ticket(clean_run, truncated_by="aborted")
    b = S.record_ticket(forged_run, truncated_by="aborted")
    assert [c.path.split("/")[-1] for c in a.calls] == [c.path.split("/")[-1] for c in b.calls]


def test_no_world_can_move_another_worlds_cut_short_row(tmp_path):
    base, _src = location_path(S.runs_base)(tmp_path)
    ep = S.cut_short_episode(tmp_path)
    b_dir, c_dir = S.sibling_run_dir(base, "b"), S.sibling_run_dir(base, "c")
    S.plant_sidecar(b_dir, truncated_by="request-limit")
    S.plant_sidecar(c_dir, truncated_by=None)
    # b claims to answer for c, on both channels it has: a file in its own run dir naming c,
    # and a sidecar written at the path c's run dir would derive.
    (b_dir / S.run_end_name()).write_text(
        json.dumps({"world": "c", "label": "c", "run_id": c_dir.name,
                    "truncated_by": "aborted"}), encoding="utf-8")
    (b_dir / f"{c_dir.name}.forged.json").write_text(
        json.dumps(S.record_doc("aborted")), encoding="utf-8")
    with Episode.open(ep) as episode:
        S.mod("learning.branch.archive").archive_episode(episode, {T.world_id(episode.dir, 'b'): b_dir, T.world_id(episode.dir, 'c'): c_dir})
    records = {label: json.loads(
        (ep / "worlds" / T.world_id(ep, label) / S.run_end_name()).read_text(encoding="utf-8"))
        for label in ("b", "c")}
    assert records["b"]["truncated_by"] == "request-limit"
    assert records["c"]["truncated_by"] is None, (
        "world b's plant reached world c's record; the two records must land at distinct, "
        "non-interfering paths")
    graded = S.graded(ep)
    assert graded["b"].get("cut_short") == "request-limit"
    assert graded["c"].get("cut_short") is None, "world b moved world c's row"
