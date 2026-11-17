"""#767/#1359 — the host records its investigation as one comment on the ticket the alert names
(`record_case_ticket`, a stand-in for the credential proxy in front of the store)."""
from __future__ import annotations

import json
import re

import pytest

from defender import _vocab
from defender.investigation import ticket_writer
from defender.tests.storage.verdict_1534 import _spec1534 as V
from defender.tests.support.storage import _readers1534 as R
from defender.tests.support.runtime.engine._spec767 import (
    ALERT,
    ALERT_MAPPING,
    CASE_KEY,
    CASE_RECORD_RELPATH,
    COMMENTS_SUFFIX,
    ELLIPSIS,
    host_cause,
    narrative_of,
    NO_NOTES,
    TICKET_BASE,
    TICKETS_PATH,
    TRANSITIONS_SUFFIX,
    WIRE_BOUND_BYTES,
    FakeStore,
    case_record_doc,
    current_settings,
    make_run,
    receipt,
    receipt_path,
    record,
    use_case_record,
)
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

STANDALONE_FENCE = re.compile(r"(?m)^---\s*$")
WARNING = "WARNING defender.investigation.ticket_writer"
COMMENT_PATH = f"{TICKETS_PATH}/{CASE_KEY}{COMMENTS_SUFFIX}"
M_URL_BASE = TICKET_BASE


def _store(tmp_path, **kw) -> FakeStore:
    """A store whose proxy stand-in lives under a fresh folder (one per call)."""
    n = len(list(tmp_path.glob("store-*")))
    return FakeStore(tmp_path / f"store-{n}", **kw)


def _setup(monkeypatch, tmp_path, doc=None):
    return use_case_record(monkeypatch, tmp_path / "dfn", doc)


def test_767_record_posts_one_comment_on_the_alerts_ticket_and_receipts(tmp_path, monkeypatch):
    """One comment POST on the alert's ticket key, no read first, no transition, no create; the
    receipt is keyed on the ticket. O1, O5, O7."""
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path)
    ok_store = _store(tmp_path)
    assert record(run_dir, ok_store) is None, "the post-step returns a value some caller reads"
    assert [(c.method, c.path) for c in ok_store.calls] == [("POST", COMMENT_PATH)], (
        "the leg's calls must be its one comment POST, keyed on the alert's ticket")
    assert not ok_store.paths(TRANSITIONS_SUFFIX), "the host transitioned the case"
    assert run_dir.name != CASE_KEY, "the fixture does not separate the run id from the ticket key"

    good = receipt(run_dir)
    assert set(good) == {"key", "status", "url", "ok", "reason"}, good
    assert (good["key"], good["status"], good["ok"], good["reason"]) == (
        CASE_KEY, ticket_writer.RECEIPT_COMMENTED, True, None), good
    assert good["url"].endswith(f"{TICKETS_PATH}/{CASE_KEY}"), good

    failed_dir = make_run(tmp_path, name="20260917t000001z-sshd")
    record(failed_dir, _store(tmp_path, answers=[S.timed_out()]))
    bad = receipt(failed_dir)
    # The write timed out after it may have reached the store and the read-back timed out too (#1374).
    assert (bad["key"], bad["ok"], bad["status"]) == (CASE_KEY, False, ticket_writer.RECEIPT_UNKNOWN), bad


def test_767_the_comment_is_the_templates_body_under_the_agent_tag(tmp_path, monkeypatch):
    """The wire body is the tenant template rendered from disposition, the record's cause sentence and the rendered
    ceiling and baseline lines; no entries render the no-notes marker; the placeholder sentence is gone. O7, OD15."""
    _setup(monkeypatch, tmp_path)
    ceiling, baseline = R.ceiling_entry("The account is a decommissioned service identity."), R.baseline_entry()
    run_dir = make_run(tmp_path, ceiling=(ceiling,), baselines=(baseline,))
    store = _store(tmp_path)
    record(run_dir, store)
    body = store.comment_body()
    assert body.startswith(f"benign — {host_cause()}\n\n"), body
    assert narrative_of(ceiling) in body, body
    assert narrative_of(baseline) in body, body
    assert "Disposition recorded by the close gate" not in body, "the placeholder sentence is still rendered (OD15)"
    payload = store.only_comment()
    assert set(payload) == {"author", "body"}, sorted(payload)
    assert isinstance(payload["author"], str), payload
    assert payload["author"].strip(), payload

    empty = _store(tmp_path)
    record(make_run(tmp_path, name="run-empty", body=""), empty)
    assert empty.comment_body() == f"benign — {host_cause()}\n\n{NO_NOTES}"


def test_767_case_id_in_the_template_is_the_run_folder_not_the_ticket(tmp_path, monkeypatch):
    """`{case_id}` renders the run folder name while the request goes to the ticket key. r3 Data."""
    _setup(monkeypatch, tmp_path, case_record_doc(body="run {case_id} / {disposition}"))
    run_dir = make_run(tmp_path)
    store = _store(tmp_path)
    record(run_dir, store)
    assert store.comment_body() == f"run {run_dir.name} / benign"
    assert [c.path for c in store.calls] == [COMMENT_PATH]


def test_767_signature_in_the_template_is_the_runs_recorded_signature(tmp_path, monkeypatch):
    """`{signature}` renders the signature recorded at run start from the alert ("5710"), not the
    ticket key or the run folder, with the run's alert as the only source. D-14, O7."""
    _setup(monkeypatch, tmp_path, case_record_doc(body="sig={signature} / {disposition}"))
    run_dir = make_run(tmp_path)
    assert ALERT["rule"]["id"] == "5710", "fixture: the alert's rule id is the expected signature"
    store = _store(tmp_path)
    record(run_dir, store)
    assert store.comment_body() == "sig=5710 / benign"
    assert [c.path for c in store.calls] == [COMMENT_PATH]

    other = make_run(tmp_path, name="run-other-sig",
                     alert={**ALERT, "rule": {**ALERT["rule"], "id": "R-9001"}})
    other_store = _store(tmp_path)
    record(other, other_store)
    assert other_store.comment_body() == "sig=R-9001 / benign", (
        "the signature does not follow the run's own record (control)")


def test_767_summary_and_event_time_placeholders_are_accepted_and_render_as_today(
        tmp_path, monkeypatch):
    """`{summary}` and `{event_time}` stay valid comment placeholders (a template naming them is
    not a template fault) and render as the base comment renderer does: base
    `case_record_to_comment` hands the context neither, so both render empty, whether or not the
    alert carries them. Control: the sibling placeholders render. D-14, O7."""
    _setup(monkeypatch, tmp_path, case_record_doc(body="[{summary}][{event_time}] {disposition}"))
    assert ALERT["rule"]["description"], "fixture: the alert carries a summary"
    assert ALERT["timestamp"], "fixture: the alert carries an event time"
    present = _store(tmp_path)
    record(make_run(tmp_path), present)
    assert present.comment_body() == "[][] benign", present.wire_body()
    absent_alert = {k: v for k, v in ALERT.items() if k != "timestamp"}
    absent_alert["rule"] = {"id": ALERT["rule"]["id"]}
    absent = _store(tmp_path)
    run_dir = make_run(tmp_path, name="run-absent-facts", alert=absent_alert)
    record(run_dir, absent)
    assert absent.comment_body() == "[][] benign", absent.wire_body()
    assert receipt(run_dir)["status"] == ticket_writer.RECEIPT_COMMENTED, receipt(run_dir)


@pytest.mark.parametrize(("why", "rule"), [
    ("no rule id in the alert", {"description": "sshd: Attempt to login using a non-existent user"}),
    ("a rule id the signature rule refuses", {"id": "R 5710", "description": "x"}),
])
def test_767_signature_is_unknown_when_the_record_has_none(tmp_path, monkeypatch, why, rule):
    """A run whose record holds no signature renders `unknown` in `{signature}` and still comments
    on the ticket. D-14, O7."""
    _setup(monkeypatch, tmp_path, case_record_doc(body="sig={signature} / {disposition}"))
    control = _store(tmp_path)
    record(make_run(tmp_path, name="run-with-sig"), control)
    assert control.comment_body() == "sig=5710 / benign", "control: a recorded signature renders"

    run_dir = make_run(tmp_path, name="run-without-sig", alert={**ALERT, "rule": rule})
    store = _store(tmp_path)
    record(run_dir, store)
    assert store.comment_body() == "sig=unknown / benign", why
    assert [c.path for c in store.calls] == [COMMENT_PATH]


def test_767_no_host_payload_sets_a_verdict_or_opens_a_case(tmp_path, monkeypatch, capsys):
    """Across a whole run the store sees one POST to the comment path: no create, no transition,
    no status or resolution. O1, H1."""
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path)
    store = _store(tmp_path)
    record(run_dir, store)

    assert [(c.method, c.path) for c in store.calls] == [("POST", COMMENT_PATH)]
    assert TICKETS_PATH not in [c.path for c in store.calls], "a ticket was created"
    for call in store.writes():
        body = call.body if isinstance(call.body, dict) else {}
        assert not ({"resolution", "status", "labels", "summary"} & set(body)), body
    assert "closed" not in json.dumps(receipt(run_dir)), "the receipt carries a status word"
    assert "released" not in capsys.readouterr().err


@pytest.mark.parametrize("key", [
    None, "", ".", "..", "...", "a/b", "a\\b", "a;b", "a b", "a\tb", "a\nb", "a\x0bb", "é-1",
    "a\x00b", "K" * 129])
def test_767_a_key_the_alert_cannot_name_makes_no_call_and_says_so(tmp_path, monkeypatch, key):
    """An absent, empty, dot-only, separator-, whitespace-, control-, non-ASCII- or over-long key
    records no key: no call, an error receipt with an empty key. O5, r4 Data."""
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path, alert={k: v for k, v in ALERT.items() if k != "alert_id"}
                       if key is None else {**ALERT, "alert_id": key})
    store = _store(tmp_path)
    assert record(run_dir, store) is None
    assert store.calls == [], f"a call was made for the key {key!r}"
    got = receipt(run_dir)
    assert (got["key"], got["status"], got["ok"], got["url"]) == ("", "error", False, None), got
    assert "names no ticket" in got["reason"], got

    control = _store(tmp_path)
    record(make_run(tmp_path, name="run-control"), control)
    assert [c.path for c in control.calls] == [COMMENT_PATH], "positive control: a valid key posts"


def test_767_a_key_is_sent_as_one_path_segment(tmp_path, monkeypatch):
    """A key with URL-special characters (none the front door refuses) reaches the store as one
    percent-encoded segment. P3."""
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path, alert={**ALERT, "alert_id": "C-1?x=y#z%2F"})
    store = _store(tmp_path)
    record(run_dir, store)
    assert [c.path for c in store.calls] == ["/tickets/C-1%3Fx%3Dy%23z%252F/comments"]
    assert receipt(run_dir)["key"] == "C-1?x=y#z%2F"


@pytest.mark.parametrize("disposition", _vocab.DISPOSITION_VALUES)
def test_767_comment_first_line_is_the_records_disposition_and_cause_sentence(tmp_path, monkeypatch, disposition):
    """Every member of `DISPOSITION_VALUES`: the first line is its disposition and its cause's sentence, then the narrative. O7."""
    from defender.records import closing as C

    _setup(monkeypatch, tmp_path)
    entry = R.ceiling_entry("model notes")
    run_dir = make_run(tmp_path, name=f"run-{disposition}", disposition=disposition, ceiling=(entry,))
    store = _store(tmp_path)
    record(run_dir, store)
    first, blank, rest = store.comment_body().split("\n", 2)
    cause = R.valid_fields(disposition)["cause"]
    assert first == f"{disposition} — {C.CAUSE_SENTENCES[cause]}", f"first line is {first!r}"
    assert blank == "", "the host line and the narrative are not separated by a blank line"
    assert rest.strip() == narrative_of(entry)


def test_767_a_run_that_never_closed_says_so_and_a_decoy_report_changes_nothing(tmp_path, monkeypatch):
    """`NeverClosed` comments with the fixed sentence and no narrative; a contrary `report.md` beside it is not read. O7."""
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path, name="run-never", closed=False)
    (run_dir / "report.md").write_text("---\ndisposition: malicious\n---\nDECOY\n", encoding="utf-8")  # lint-run-records: ok — a decoy the bridge must not read
    store = _store(tmp_path)
    record(run_dir, store)
    body = store.comment_body()
    assert "No disposition was recorded for this case: the investigation did not close." in body, body
    assert "DECOY" not in body, body
    assert "malicious" not in body, body
    assert NO_NOTES not in body, "the ordinary branch's marker was rendered instead"

    no_pointer = tmp_path / fixture_uuid("run-no-pointer")
    no_pointer.mkdir()
    plant_alert(no_pointer, ALERT, mapping=ALERT_MAPPING)
    bare = _store(tmp_path)
    record(no_pointer, bare)
    assert bare.comment_body() == body, "no pointer is `NeverClosed` too"


@pytest.mark.parametrize("fault", R.TWO_KINDS + ("recorded-before-1534",))
def test_767_a_record_that_cannot_be_looked_up_posts_nothing_and_leaves_an_error_receipt(
        tmp_path, monkeypatch, capsys, fault):
    """`CouldNotLook`: no comment, a warning, an `error` receipt carrying the kind's wording and never the detail. O7, OD8."""
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path, name=f"run-{fault}", fault=fault)
    store = _store(tmp_path)
    record(run_dir, store)
    assert store.calls == [], "a comment was posted for a run whose record could not be looked up"
    got = receipt(run_dir)
    assert (got["status"], got["ok"]) == ("error", False), got
    assert R.names_only(fault, got["reason"] or ""), got
    assert str(tmp_path) not in json.dumps(got), "the lookup's detail (a path) reached the receipt"
    assert "WARN" in capsys.readouterr().err

    control = _store(tmp_path)
    record(make_run(tmp_path, name="run-control"), control)
    assert [c.path for c in control.calls] == [COMMENT_PATH], "positive control: a record posts"


def test_767_the_summary_is_not_in_the_comment(tmp_path, monkeypatch):
    """The record's summary reaches no part of the ticket comment (OD7; #1471 adds it). O7."""
    _setup(monkeypatch, tmp_path)
    store = _store(tmp_path)
    run_dir = make_run(tmp_path)
    record(run_dir, store)
    assert "The pivot from the bastion" not in store.wire_body(), "the summary reached the ticket comment"
    assert V.MARKUP_SUMMARY not in store.wire_body()


def test_767_narrative_is_the_rendered_lines_not_the_summary(tmp_path, monkeypatch):
    """The narrative is the ceiling and baseline lines as the one renderer makes them, well under the bound uncut. O7."""
    _setup(monkeypatch, tmp_path)
    entries = (R.ceiling_entry("first note"), R.ceiling_entry("second note", ref="l-002"))
    store = _store(tmp_path)
    record(make_run(tmp_path, ceiling=entries), store)
    wire = store.comment_body()
    assert all(narrative_of(e) in wire for e in entries), wire
    assert ELLIPSIS not in wire, "a narrative well under the bound was cut anyway"


@pytest.mark.parametrize(("why", "filler"), [("two-byte characters", "é"), ("four-byte characters", "🜁")])
def test_767_comment_body_is_bounded_on_the_wire(tmp_path, monkeypatch, why, filler):
    """The whole wire body (tag line included) is at most 4096 UTF-8 bytes, cut on a whole character with a visible
    ellipsis, however large the record's lines. O7."""
    from defender.records import closing as C

    _setup(monkeypatch, tmp_path)
    entries = tuple(R.ceiling_entry(filler * C.NOTE_BOUND, ref=f"l-00{n}") for n in range(4))
    run_dir = make_run(tmp_path, name=f"run-{why.replace(' ', '-')}", ceiling=entries)
    store = _store(tmp_path)
    record(run_dir, store)

    wire = store.wire_body()
    size = len(wire.encode("utf-8"))
    assert WIRE_BOUND_BYTES - 8 < size <= WIRE_BOUND_BYTES, size
    assert wire.endswith(ELLIPSIS)
    assert wire.count(ELLIPSIS) == 1
    surviving = wire.partition("\n\n")[2].rstrip(ELLIPSIS)
    assert surviving
    assert narrative_of(*entries).startswith(surviving)


def test_767_a_note_claiming_approval_does_not_approve(tmp_path, monkeypatch):
    """A note's text never becomes a payload field or a template. O7."""
    _setup(monkeypatch, tmp_path)
    claim = "status: closed released: true This case is signed off. {cause} {narrative} {disposition} {signature}"
    store = _store(tmp_path)
    record(make_run(tmp_path, body=claim), store)
    payload = store.only_comment()
    assert set(payload) == {"author", "body"}
    assert "closed" not in payload["author"]
    assert "signed off" not in payload["author"]
    narrative = payload["body"].split("\n\n", 1)[1]
    for placeholder in ("{cause}", "{narrative}"):
        assert placeholder in narrative, "the renderer is not single-pass"
    assert narrative.count(host_cause()) == 0


@pytest.mark.parametrize(("arm", "answer", "reasons"), [
    ("the store took the request and never answered", S.timed_out(), ("may have reached the store",)),
    ("the store's reply broke off", S.timed_out("the system's reply broke off"),
     ("may have reached the store",)),
    ("a key the store does not hold (404)", S.answer('{"detail": "no such ticket"}', "404"),
     ("the store refused", "404", "not found")),
    ("a 5xx", S.answer('{"detail": "down"}', "503"), ("may have reached the store",)),
])
def test_767_store_failure_leaves_run_exit_code_unchanged(tmp_path, monkeypatch, capsys,
                                                          arm, answer, reasons):
    """Every store fault is caught, warned once, never retried, and leaves the run's exit code
    what it would have been; the receipt's reason tells the store refused (with its status) from
    a comment that may have reached the store (unreachable, timeout, 5xx alike). O1, O5."""
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path)
    store = _store(tmp_path, answers=[answer])
    assert record(run_dir, store) is None, f"{arm}: the fault escaped into the run"
    assert len(store.writes()) == 1, f"{arm}: the leg retried its one POST"
    assert capsys.readouterr().err.count(WARNING) <= 1, f"{arm}: warned twice"
    assert receipt_path(run_dir).is_file(), f"{arm}: no receipt was written"
    assert receipt(run_dir)["url"] is None, f"{arm}: an error receipt carries a link (D-10)"
    reason = receipt(run_dir)["reason"].lower()
    for words in reasons:
        assert words in reason, f"{arm}: the reason lacks {words!r}: {reason!r}"


def test_767_unreachable_store_loses_the_record_not_the_run(tmp_path, monkeypatch):
    _setup(monkeypatch, tmp_path)
    lost = make_run(tmp_path, name="run-unreachable")
    assert record(lost, _store(tmp_path, answers=[S.timed_out()])) is None
    assert receipt(lost)["ok"] is False
    assert "may have reached the store" in receipt(lost)["reason"], receipt(lost)

    unconfigured = make_run(tmp_path, name="run-unconfigured")
    no_config = _store(tmp_path)
    assert record(unconfigured, no_config, config=None) is None
    assert no_config.calls == [], "a run with no case-system config still reached the store"
    got = receipt(unconfigured)
    assert (got["ok"], got["url"], got["key"]) == (False, None, CASE_KEY), got
    assert "system ticket settings" in got["reason"], got  # #1366 DC6: the record, not the retired file

    reachable = _store(tmp_path)
    kept = make_run(tmp_path, name="run-reachable")
    assert record(kept, reachable) is None
    assert reachable.comment_payloads, "the control never posted"
    assert receipt(kept)["ok"] is True


def test_767_failed_write_leaves_no_capture_record(tmp_path, monkeypatch, capsys):
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path)
    before = {p.name for p in run_dir.iterdir()}
    record(run_dir, _store(tmp_path, answers=[S.timed_out()]))
    assert {p.name for p in run_dir.iterdir()} - before == set()
    assert not (run_dir / "executed_queries.jsonl").exists()
    assert not (run_dir / "gather_raw").exists()
    assert WARNING in capsys.readouterr().err
    assert receipt(run_dir)["ok"] is False


def test_767_receipt_io_failure_warns_and_keeps_the_exit_code(tmp_path, monkeypatch, capsys):
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path)
    receipt_path(run_dir).mkdir()
    store = _store(tmp_path)
    assert record(run_dir, store) is None, "a receipt IO failure escaped into the run"
    assert store.comment_payloads, "the comment was skipped because of the receipt"
    assert WARNING in capsys.readouterr().err, "the IO failure was silent"


@pytest.mark.parametrize("answer", ['{"id": 1}', "", "created", "<html>not json", "[]"])
def test_767_any_2xx_is_success_whatever_its_body(tmp_path, monkeypatch, answer):
    """A 2xx answer whose body is not a JSON object is still a posted comment: a `commented`
    receipt with the ticket's link. O3, O5, D-8."""
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path)
    store = _store(tmp_path, answers=[S.answer(answer, "201")])
    record(run_dir, store)
    got = receipt(run_dir)
    assert (got["key"], got["status"], got["ok"]) == (CASE_KEY, "commented", True), got
    assert got["url"] == f"{M_URL_BASE}/tickets/{CASE_KEY}", got


@pytest.mark.parametrize(("why", "body", "kw"), [
    ("a stray `{` in comment.body", "{disposition} — {cause} {", {}),
    ("a positional `{0}` in comment.body", "{0}", {}),
    ("an attribute path in comment.body", "{narrative.x}", {}),
    ("a placeholder the context cannot fill", "{no_such_key}", {}),
    ("a bad template, on the aborted arm", "{0}", {"truncated_by": "aborted"}),
])
def test_767_a_template_fault_refuses_with_a_receipt(tmp_path, monkeypatch, capsys, why, body, kw):
    """A comment template that cannot render sends nothing and says so, naming the case record (#1366 DC6: the record's
    locator, not a file), on every arm that meant to call out. O5."""
    _setup(monkeypatch, tmp_path, case_record_doc(body=body))
    run_dir = make_run(tmp_path)
    store = _store(tmp_path)
    assert record(run_dir, store, **kw) is None, f"{why}: the leg raised into the run"
    assert store.calls == [], f"{why}: something was sent off a broken template"
    got = receipt(run_dir)
    assert (got["ok"], got["status"]) == (False, "error"), got
    assert "the case record" in got["reason"], got
    err = capsys.readouterr().err
    assert "WARN" in err, err
    assert "raised, ignored" not in err, err


def test_767_the_template_is_the_case_record_files_not_the_checkouts(tmp_path, monkeypatch):
    """Editing `comment.body` in the tenant's case-record file changes the wire body. O7."""
    _setup(monkeypatch, tmp_path, case_record_doc(body="{cause}//{narrative}"))
    store = _store(tmp_path)
    from defender.records import closing as C

    entry = R.ceiling_entry("the model's own notes")
    record(make_run(tmp_path, cause=C.CAUSE_STORY_SETTLED, ceiling=(entry,)), store)
    assert store.comment_body() == f"{host_cause()}//{narrative_of(entry)}"
    assert current_settings().joinpath(CASE_RECORD_RELPATH).is_file()
