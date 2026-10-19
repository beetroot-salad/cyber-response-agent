"""#1047 O2 — the ticket lane decides per exit class, from a source the box cannot write."""
from __future__ import annotations

import json
from pathlib import Path

from defender.tests import _spec1047 as S


# one arm per exit class


def test_an_aborted_run_leaves_its_ticket_open_with_the_escalation(tmp_path):
    run_dir = S.closed_run_dir(tmp_path, report=False)
    opened = S.open_ticket(run_dir)
    fake = S.record_ticket(run_dir, truncated_by="aborted", closed_before_cut=False)

    assert fake.records == [], (
        "an aborted run recorded a verdict; the environment was unreachable, so nothing "
        "about the case was settled and there is nothing to propose to a person")
    assert len(fake.notes) == 1, f"the aborted arm made {len(fake.notes)} note calls, not one"
    note = fake.notes[0]
    assert note.method == "POST"
    assert note.key == opened.calls[0].body["key"], (
        f"the note addressed ticket {note.key!r} while the open leg wrote "
        f"{opened.calls[0].body['key']!r} — two namespaces, so the note lands on no ticket")
    body = note.text().lower()
    assert "aborted" in body, f"the note does not name the exit class: {note.text()!r}"
    assert "escalate" in body, (
        f"the note does not carry the escalation ask: {note.text()!r} — leaving the ticket "
        "open without one is silence, not an escalation")


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
    """A run killed by the budget leaves its ticket open and makes no call at all — the missing
    report IS the escalation, and that stays true once the lane keys on the exit class."""
    for report in (False, True):
        run_dir = S.closed_run_dir(tmp_path / f"report-{report}", report=report)
        fake = S.record_ticket(run_dir, truncated_by="budget")
        assert fake.calls == [], (
            f"report={report}: the budget arm made {fake.calls} — it must make no call at all")
        assert S.receipt(run_dir) is None, "the budget arm wrote a receipt for a call it never made"


def test_a_run_that_was_not_cut_short_still_records_off_its_report(tmp_path):
    """A run with no exit class recorded records its ticket from the report — the ordinary
    completed run is untouched by this change."""
    run_dir = S.closed_run_dir(tmp_path, disposition="malicious")
    fake = S.record_ticket(run_dir, truncated_by=None)
    assert fake.transitions == []
    assert len(fake.records) == 1
    assert "malicious" in fake.records[0].text()
    assert fake.notes == []
    assert (S.receipt(run_dir) or {}).get("ok") is True


def test_an_exit_class_the_table_does_not_name_takes_the_report_driven_fallback(tmp_path):
    assert "dead-end" in S.vocabulary(), (
        "the control failed: `dead-end` left the vocabulary, so this no longer tests a real "
        "member with no arm in the table")
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


# F-A — the exit class and a genuine model verdict, together


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
            f"{exit_class}: a run that had closed but left no report.md still recorded a "
            "verdict — off what? F-A's deferral has no verdict on disk to defer to here, and "
            "inventing the payload is what F-K refuses")
        assert len(both.notes) == 1, (
            f"{exit_class}: `closed_before_cut=True` swallowed F-K's escalation on a run whose "
            "own forced close failed, leaving the ticket open in silence")
        assert exit_class in both.notes[0].text()


def test_a_failed_note_call_never_breaks_the_run_and_is_recorded_in_the_receipt(tmp_path):
    """A note call that fails is swallowed — the run never breaks over it — and the outcome is
    written into `ticket_write.json` either way (fork F-L, auto, §7 round 2)."""
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
        sidecar = S.sym("run_repository", "RunPaths")(run_dir).session_pointer()
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
        # #1107 moved the receipt beside the run dir; forged at its name there.
        S.receipt_path(run_dir).write_text(
            json.dumps({"key": run_dir.name, "status": "closed", "ok": True,
                        "url": "http://tickets.test/tickets/forged"}), encoding="utf-8")
        fake = S.record_ticket(run_dir, truncated_by=exit_class)
        assert len(getattr(fake, expect)) == 1, (
            f"{exit_class}: a forged receipt claiming the ticket was already closed suppressed "
            "the real call")


# #767 O1 — the host never transitions; the store's `closed` is a person's word


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
                    f"transitioned the ticket — {[c.path for c in fake.transitions]}")
                assert all(c.is_comment for c in fake.writes), (
                    f"{exit_class}: a write that is neither a comment nor a transition: "
                    f"{[c.path for c in fake.writes]}")
                seen_writes += len(fake.writes)
    assert seen_writes, "the control failed: no drive wrote anything, so the census is empty"
