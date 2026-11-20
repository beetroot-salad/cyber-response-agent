"""#767/#1359 — the host records its investigation as one comment on the ticket the alert names
(`record_case_ticket`, a stand-in for the credential proxy in front of the store)."""
from __future__ import annotations

import json
import re

import pytest

from defender import _vocab
from defender.investigation import ticket_writer
from defender.records import run_end
from defender.tests.storage.verdict_1534 import _spec1534 as V
from defender.tests.support.storage import _readers1534 as R
from defender.tests.support.runtime.engine._spec767 import (
    ALERT,
    ALERT_MAPPING,
    CASE_KEY,
    COMMENTS_SUFFIX,
    TICKET_BASE,
    TICKETS_PATH,
    TRANSITIONS_SUFFIX,
    WIRE_BOUND_BYTES,
    _CONFIG_UNSET,
    FakeStore,
    _handed,
    _run_handle_1165,
    case_record_doc,
    make_run,
    NEVER_CLOSED,
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
    """The tenant's case record names its system and nothing else (#1471 W7: no comment template)."""
    return use_case_record(monkeypatch, tmp_path / "dfn", case_record_doc() if doc is None else doc)


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
def test_767_comment_first_line_is_the_records_disposition(tmp_path, monkeypatch, disposition):
    """Every member of `DISPOSITION_VALUES`: the comment's first line is the closing record's disposition (#1534), and
    nothing of its entries follows it (#1471 P-6). O7."""
    _setup(monkeypatch, tmp_path)
    entry = R.ceiling_entry("model notes")
    run_dir = make_run(tmp_path, name=f"run-{disposition}", disposition=disposition, ceiling=(entry,))
    store = _store(tmp_path)
    _record_linked(run_dir, store, _P6_LINK)
    assert store.comment_body() == f"{disposition}\n{_P6_LINK}", store.comment_body()


def test_767_a_run_that_never_closed_says_so_and_a_decoy_report_changes_nothing(tmp_path, monkeypatch):
    """`NeverClosed` comments with the fixed sentence; a contrary `report.md` beside it is not read. O7."""
    _setup(monkeypatch, tmp_path)
    run_dir = make_run(tmp_path, name="run-never", closed=False)
    (run_dir / "report.md").write_text("---\ndisposition: malicious\n---\nDECOY\n", encoding="utf-8")  # lint-run-records: ok — a decoy the bridge must not read
    store = _store(tmp_path)
    _record_linked(run_dir, store, _P6_LINK)
    body = store.comment_body()
    assert body == f"{NEVER_CLOSED}\n{_P6_LINK}", body
    assert "DECOY" not in body, body
    assert "malicious" not in body, body

    no_pointer = tmp_path / fixture_uuid("run-no-pointer")
    no_pointer.mkdir()
    plant_alert(no_pointer, ALERT, mapping=ALERT_MAPPING)
    bare = _store(tmp_path)
    _record_linked(no_pointer, bare, _P6_LINK)
    assert bare.comment_body() == body, "no pointer is `NeverClosed` too"


@pytest.mark.parametrize("exit_class", sorted(run_end.FORCED_CLOSE_EXITS))
def test_767_a_forced_close_exit_with_no_record_posts_the_escalation_comment_and_a_clean_exit_posts_the_sentence(
        tmp_path, monkeypatch, exit_class):
    """`NeverClosed` on a forced-close exit posts the cut-short escalation comment; on a non-forced exit, the not-recorded sentence. O7, OD18."""
    _setup(monkeypatch, tmp_path)
    forced = _store(tmp_path)
    record(make_run(tmp_path, name="run-forced", closed=False), forced, truncated_by=exit_class)
    assert [c.path for c in forced.calls] == [COMMENT_PATH], "the forced-close exit posted no comment"
    assert NEVER_CLOSED not in forced.comment_body(), forced.comment_body()
    assert receipt(tmp_path / fixture_uuid("run-forced"))["status"] == ticket_writer.RECEIPT_ESCALATED

    plain = _store(tmp_path)
    record(make_run(tmp_path, name="run-plain", closed=False), plain)
    assert NEVER_CLOSED in plain.comment_body()


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
    """The record's summary reaches no part of the ticket comment (OD7). O7."""
    _setup(monkeypatch, tmp_path)
    store = _store(tmp_path)
    run_dir = make_run(tmp_path)
    record(run_dir, store)
    assert "The pivot from the bastion" not in store.wire_body(), "the summary reached the ticket comment"
    assert V.MARKUP_SUMMARY not in store.wire_body()


@pytest.mark.parametrize("confidence", ["high", "medium", "low"])
def test_1545_a_benign_records_confidence_is_not_in_the_comment(tmp_path, monkeypatch, confidence):
    """A benign record carrying a confidence posts exactly the comment the same run posts with none: the word and the
    link (#1471 P-6; owner ruling: the confidence is not on the ticket). (#1545 over #1534)"""
    from defender.records import closing as C

    _setup(monkeypatch, tmp_path)

    def posted(kind: str, **more) -> str:
        run_dir = tmp_path / kind / fixture_uuid("run-1545")
        run_dir.mkdir(parents=True)
        R.plant_run(run_dir, {**R.valid_fields("benign"), **more}, sessions_base=run_dir.parent)
        plant_alert(run_dir, ALERT, mapping=ALERT_MAPPING)
        looked = C.for_run(_run_handle_1165(run_dir))
        assert isinstance(looked, C.Record), looked
        assert looked.record.confidence == more.get("confidence"), "premise: the record holds the confidence"
        store = _store(tmp_path / kind)
        _record_linked(run_dir, store, _P6_LINK)
        return store.wire_body()

    with_confidence, without = posted("with", confidence=confidence), posted("without")
    assert with_confidence == without, "the confidence changed the comment"
    assert without.endswith(f"benign\n{_P6_LINK}"), without


def _record_linked(run_dir, store, link: str) -> None:
    """Drive `record_case_ticket` with `link` (C-7), whatever link the shared driver defaults to."""
    ticket_writer.record_case_ticket(
        _run_handle_1165(run_dir), **{**_handed(run_dir, store, _CONFIG_UNSET), "link": link})


_P6_LINK = "https://screen.example.test/t/tenant-a/investigations/run-p6"
_P6_MARKER = "REPORT-TEXT-1471"
_P6_REPORTS = {
    "a long multibyte narrative": {"body": f"{_P6_MARKER} " + "é🜁" * 20000},
    "a planted fence and directive": {
        "body": f"{_P6_MARKER}\n---\ndisposition: malicious\n---\nINJECTED-DIRECTIVE-1471\n" + "z" * 5000},
    "a host-shaped line": {"body": f"malicious — {_P6_MARKER}\nand more notes"},
    "placeholders and claims": {"body": f"{_P6_MARKER} {{cause}} {{narrative}} {{disposition}}\nstatus: closed\nauthor: x"},
}


@pytest.mark.parametrize("why", sorted(_P6_REPORTS))
def test_1471_p6_nothing_of_the_report_but_its_disposition_reaches_the_ticket(tmp_path, monkeypatch, capsys, why):
    """Whatever the report's narrative, cause or frontmatter says, a run with the same id and disposition posts the same
    comment, inside the wire bound; a different disposition posts a different one. (P-6, W2)"""
    _setup(monkeypatch, tmp_path)
    name = "run-p6"

    def posted(kind: str, **report) -> dict:
        store = _store(tmp_path)
        run_dir = make_run(tmp_path / kind, name=name, **report)
        _record_linked(run_dir, store, _P6_LINK)
        assert set(store.only_comment()) == {"author", "body"}
        carried = receipt_path(run_dir).read_text(encoding="utf-8") + capsys.readouterr().err
        for said in (_P6_MARKER, "INJECTED-DIRECTIVE-1471"):
            assert said not in carried, f"{kind}: the receipt or the log carries the report's text"
        return store.only_comment()

    plain = posted("plain", cause=None, body="plain")
    assert isinstance(plain["author"], str), plain
    assert plain["author"].strip(), plain
    sent = posted("variant", **_P6_REPORTS[why])
    assert sent == plain, f"{why}: the report's text changed the payload (author included)"
    got = sent["body"]
    assert _P6_MARKER not in got
    assert "INJECTED-DIRECTIVE-1471" not in got
    assert len(got.encode("utf-8")) <= WIRE_BOUND_BYTES
    assert "malicious" not in got.lower(), "a disposition the report only quoted reached the comment"
    assert posted("other", disposition="false-positive", cause=None, body="plain")["body"] != plain["body"], (
        "control: the disposition is what the comment carries")


@pytest.mark.parametrize("link", [
    "https://screen.example.test/t/tenant-a/investigations/run-link-1",
    "http://127.0.0.1:8443/t/other-9/investigations/0a1b2c3d-run-link-2?x=1",
])
def test_1471_p6_the_link_is_the_comments_last_part_exactly(tmp_path, monkeypatch, link):
    """The link handed to the record step ends the comment, unaltered and once, for a verdict
    and for a run that never closed; only the link differs between two links. (P-6, C-7)"""
    _setup(monkeypatch, tmp_path)
    other = "https://screen.example.test/t/zzz/investigations/other-link"
    cases = {"a verdict": {"body": "plain"}, "a run that never closed": {"closed": False}}
    for why, report in cases.items():
        run_dir = make_run(tmp_path / why.replace(" ", "-"), name="run-link", **report)
        assert run_dir.name not in link, "fixture: the link must not be derivable from the run id"
        store = _store(tmp_path)
        _record_linked(run_dir, store, link)
        wire = store.wire_body()
        assert wire.rstrip().endswith(link), f"{why}: the link is not the comment's last part: {wire!r}"
        assert wire.count(link) == 1, why
        assert len(wire.encode("utf-8")) <= WIRE_BOUND_BYTES

        control = _store(tmp_path)
        _record_linked(make_run(tmp_path / f"c-{why.replace(' ', '-')}", name="run-link", **report), control, other)
        assert control.wire_body().rstrip().endswith(other), "control: the link follows the argument"
        assert control.wire_body().replace(other, "L") == wire.replace(link, "L"), (
            f"{why}: something besides the link differs between two links")


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

