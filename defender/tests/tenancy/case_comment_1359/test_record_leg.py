"""#1359 the record leg comments on the ticket the alert names, through the case system's adapter
(through the credential proxy, #1391 O1), driven through `run.main` with the real writer. Here: O1, O5, O7 end to end."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, ensure_d9_tenant
from defender.tests.support.shared.contracts._spec1077 import fixture_run
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S


def _world(tmp_path: Path, *, key: str | None = C.TICKET_KEY, **kw: Any) -> tuple[Path, Path, Path]:
    ensure_d9_tenant()
    root = current_data_root()
    folder = C.plant_case_tenant(root, **kw)
    case = kw.get("case_system")
    systems = S.settings_of(folder) / "systems"
    if case and not (systems / case / "access.yaml").exists():
        # A planted case system is reached through the proxy like any other (#1391 r5 O-S3):
        # it declares the ticket store's access, comment route included.
        (systems / case).mkdir(parents=True, exist_ok=True)
        (systems / case / "access.yaml").write_bytes((systems / "ticket" / "access.yaml").read_bytes())
    return root, folder, C.plant_alert(tmp_path / "in", key=key)


def _signer() -> Any:
    """A signer that signs anything: run start mints the run's tokens for the proxied systems."""
    from defender.tests.integrations.credential_proxy_1163._harness import FakeSigner

    return FakeSigner()


def _shim(tmp_path: Path, monkeypatch, *answers: dict[str, Any]) -> S.ProxyStandIn:
    """The credential proxy's stand-in (the case store is behind it), installed for the run."""
    return S.ProxyStandIn(tmp_path / "proxy", list(answers) or [S.answer('{"id": 1}', "201")]
                          ).install(monkeypatch)


def _run(tmp_path: Path, root: Path, alert: Path, *, summary: dict[str, Any] | None = None,
         before: Any = None, page: bool = False) -> tuple[int | None, Any, Path]:
    rec = C.CaseRunRecorder(tmp_path / "runs" / "r1359", summary=summary, before_lifecycle=before)
    seams = {} if page else {"visualize": rec.visualize}
    rc, refused = S.drive_run(S.run_argv(alert, root, update_ticket=True), rec, signer=_signer(), **seams)
    return rc, refused, rec.run_dir_at


def test_o1_one_comment_on_the_alert_named_ticket_and_no_call_at_run_start(tmp_path, monkeypatch):
    """The store receives one comment POST on the alert's key and nothing else; none before the lifecycle.
    O1, O5."""
    root, _folder, alert = _world(tmp_path)
    shim = _shim(tmp_path, monkeypatch)
    at_start: list[int] = []
    rc, refused, run_dir = _run(tmp_path, root, alert,
                                before=lambda _d: at_start.append(len(shim.requests())))

    assert refused is None, refused
    assert rc == 0, rc
    assert at_start == [0], f"the store was called at run start: {shim.requests()}"
    calls = shim.requests()
    assert len(calls) == 1, f"expected one store call, got {calls}"
    assert calls[0]["method"] == "POST", calls[0]
    assert calls[0]["path"].endswith(f"/tickets/{C.TICKET_KEY}/comments"), calls[0]
    got = S.receipt(run_dir)
    assert got is not None, "no receipt"
    assert set(got) == C.RECEIPT_KEYS, got
    assert (got["key"], got["status"], got["ok"]) == (C.TICKET_KEY, C.COMMENTED, True), got


def test_o1_a_store_that_does_not_know_the_key_leaves_a_not_found_receipt(tmp_path, monkeypatch):
    """A 404 on the comment leaves an error receipt naming "not found" and the key. O1, O5."""
    root, _folder, alert = _world(tmp_path)
    shim = _shim(tmp_path, monkeypatch, S.answer(json.dumps({"detail": "no such ticket"}), "404"))
    rc, refused, run_dir = _run(tmp_path, root, alert)

    assert refused is None, refused
    assert len(C.comment_calls(shim)) == 1, f"positive control: the comment was sent: {shim.requests()}"
    got = S.receipt(run_dir)
    assert got is not None, "no receipt"
    assert (got["key"], got["status"], got["ok"]) == (C.TICKET_KEY, C.ERROR, False), got
    assert got["url"] is None, f"an error receipt after a call carries a link (D-10): {got}"
    assert C.REASON_NOT_FOUND in (got.get("reason") or "").lower(), got


def test_o5_an_alert_naming_no_ticket_is_an_empty_key_receipt_the_page_shows(tmp_path, monkeypatch):
    """No case_key: no call, receipt key "" with the reason, and the page shows the reason, not "receipt unreadable".
    O5, flow step 3."""
    root, _folder, alert = _world(tmp_path, key=None)
    shim = _shim(tmp_path, monkeypatch)
    rc, refused, run_dir = _run(tmp_path, root, alert, page=True)

    assert refused is None, refused
    assert rc == 0, rc
    assert shim.requests() == [], f"a call was made with no key: {shim.requests()}"
    got = S.receipt(run_dir)
    assert got is not None, "no receipt"
    assert set(got) == C.RECEIPT_KEYS, got
    assert (got["key"], got["status"], got["ok"], got["url"]) == ("", C.ERROR, False, None), got
    reason = got.get("reason") or ""
    assert C.REASON_NO_KEY in reason, got
    page = S.page_html(run_dir)
    assert page, "positive control: the page rendered"
    assert html.escape(reason) in page or reason in page, "the page does not show the reason"
    assert S.RECEIPT_UNREADABLE not in page


def test_run_start_bad_case_settings_make_no_call_and_name_the_file(tmp_path, monkeypatch):
    """A case system whose settings fail its check: no store call, the run goes on, the receipt names the settings file.
    Run-start flow, O5."""
    root, folder, alert = _world(tmp_path)
    S.set_key(folder, "ticket", "TICKET_TIMEOUT_SEC", "ten")
    shim = _shim(tmp_path, monkeypatch)
    rc, refused, run_dir = _run(tmp_path, root, alert)

    assert refused is None, refused
    assert rc == 0, rc
    assert shim.requests() == [], shim.requests()
    got = S.receipt(run_dir)
    assert got is not None, "no receipt"
    assert (got["key"], got["status"], got["ok"]) == (C.TICKET_KEY, C.ERROR, False), got
    assert "config.env" in (got.get("reason") or ""), got
    for host in (str(folder), str(folder.resolve()), str(root), str(root.resolve())):
        assert host not in got["reason"], f"the reason carries the host path {host}: {got['reason']!r}"


def test_o7_a_forced_close_escalates_and_the_posted_comments_row_is_keyed_on_the_ticket(
        tmp_path, monkeypatch):
    """An aborted run escalates on the alert's key; the posted-comments row is keyed by the ticket
    key (not the run folder), its body tagged with the run. O7, r3 Data."""
    root, _folder, alert = _world(tmp_path)
    shim = _shim(tmp_path, monkeypatch)
    rc, refused, run_dir = _run(tmp_path, root, alert, summary={
        "output": "spec1359", "requests": 0, "truncated_by": "aborted", "closed_before_cut": False})

    assert refused is None, refused
    assert len(C.comment_calls(shim)) == 1, shim.requests()
    got = S.receipt(run_dir)
    assert got is not None, "no receipt"
    assert (got["key"], got["status"]) == (C.TICKET_KEY, C.ESCALATED), got
    posted = S.mod("tenancy.case_ticket").read_posted_comments(fixture_run(run_dir))
    assert [k for k, _ in posted] == [C.TICKET_KEY], posted
    assert run_dir.name not in [k for k, _ in posted]
    tag = S.mod("tenancy.case_ticket").agent_comment_tag(run_dir.name)
    assert posted[0][1].startswith(tag), posted


@pytest.mark.parametrize(("truncated_by", "closed_before_cut", "expected"), [
    (None, False, C.COMMENTED),
    ("aborted", False, C.ESCALATED),
    ("request-limit", False, C.ESCALATED),
    ("retry-exhausted", False, C.ESCALATED),
    ("budget", True, C.COMMENTED),
    ("budget", False, None),
    ("store", False, None),
    ("provider-down", False, None),
])
def test_o7_exit_class_decides_whether_the_run_comments(tmp_path, monkeypatch, truncated_by,
                                                        closed_before_cut, expected):
    """Which exit classes comment, escalate or stay silent is unchanged: silent means no call and
    no receipt. O7."""
    root, _folder, alert = _world(tmp_path)
    shim = _shim(tmp_path, monkeypatch)
    rc, refused, run_dir = _run(tmp_path, root, alert, summary={
        "output": "spec1359", "requests": 0, "truncated_by": truncated_by,
        "closed_before_cut": closed_before_cut})

    # A run whose model provider stayed down exits 4 (`run.PROVIDER_DOWN_EXIT`): that status is
    # the run's own and unrelated to the record leg, which is silent for it.
    assert (refused, rc) == (None, 4 if truncated_by == "provider-down" else 0)
    got = S.receipt(run_dir)
    if expected is None:
        assert shim.requests() == [], f"a silent exit class called the store: {shim.requests()}"
        assert got is None, f"a silent exit class left a receipt: {got}"
    else:
        assert len(C.comment_calls(shim)) == 1, shim.requests()
        assert got is not None, "no receipt"
        assert (got["key"], got["status"], got["ok"]) == (C.TICKET_KEY, expected, True), got


def test_o1_a_failed_comment_adds_no_posted_comments_row(tmp_path, monkeypatch):
    """A refused comment leaves no posted-comments row, a sent one leaves exactly one. O7, #1255."""
    root, _folder, alert = _world(tmp_path)
    _shim(tmp_path, monkeypatch, S.answer(json.dumps({"detail": "no such ticket"}), "404"))
    _rc, _refused, failed = _run(tmp_path, root, alert)
    assert S.mod("tenancy.case_ticket").read_posted_comments(fixture_run(failed)) == []

    _shim(tmp_path, monkeypatch)
    _rc, _refused, sent = _run(tmp_path / "again", root, alert)
    assert len(S.mod("tenancy.case_ticket").read_posted_comments(fixture_run(sent))) == 1


def test_o5_a_redirect_is_the_store_refusing_not_a_comment(tmp_path, monkeypatch):
    """A 302 on the comment is not a 2xx: an error receipt carrying the status and no
    posted-comments row, so no world is later served a comment the store never stored. Control:
    a 201 comments. O5, #1392 review."""
    root, _folder, alert = _world(tmp_path)
    _shim(tmp_path, monkeypatch, S.answer("", "302"))
    _rc, refused, run_dir = _run(tmp_path, root, alert)
    assert refused is None, refused
    got = S.receipt(run_dir)
    assert got is not None, "no receipt"
    assert (got["status"], got["ok"], got["url"]) == (C.ERROR, False, None), got
    assert "302" in (got.get("reason") or ""), got
    assert S.mod("tenancy.case_ticket").read_posted_comments(fixture_run(run_dir)) == []

    _shim(tmp_path, monkeypatch)
    _rc, _refused, sent = _run(tmp_path / "again", root, alert)
    assert S.receipt(sent)["status"] == C.COMMENTED, S.receipt(sent)


CRASHING_CASE_ADAPTER = (
    "def check_settings(tenant):\n"
    "    raise RuntimeError(f'cannot judge {tenant.agent_root}')\n\n\n"
    "def add_case_comment(ctx, *, key, body):\n    return None\n\n\n"
    "VERBS = {}\n")


def test_run_start_a_crashing_case_check_is_a_receipt_that_names_no_host_root(tmp_path, monkeypatch):
    """A case adapter whose settings check crashes with a host path in its text: the run goes on,
    no store call, and the error receipt names the data root as `<data root>`, never the path —
    the run start judgement's own redaction. #1392 review."""
    import shutil

    from defender.systems.verbs import read_roster

    root, _folder, alert = _world(tmp_path, case_system="casesys")
    tree = tmp_path / "tree" / "defender"
    shutil.copytree(S.DEFENDER / "integrations", tree / "integrations",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (tree / "integrations" / "casesys_adapter.py").write_text(CRASHING_CASE_ADAPTER, encoding="utf-8")
    shim = _shim(tmp_path, monkeypatch)
    rec = C.CaseRunRecorder(tmp_path / "runs" / "r1359")
    rc, refused = S.drive_run(S.run_argv(alert, root, update_ticket=True), rec, signer=_signer(),
                              visualize=rec.visualize,
                              roster=read_roster(tree / "integrations"))

    assert (refused, rc) == (None, 0), (refused, rc)
    assert shim.requests() == [], shim.requests()
    got = S.receipt(rec.run_dir_at)
    assert got is not None, "no receipt"
    reason = got.get("reason") or ""
    assert (got["status"], got["ok"]) == (C.ERROR, False), got
    assert "RuntimeError" in reason, "positive control: the check's crash reached the receipt"
    for host in (str(root), str(root.resolve())):
        assert host not in reason, f"the receipt carries the host path {host}: {reason!r}"


# ======================================================================================
# #1374: a comment whose answer was lost after it may have reached the store is read back once.
# ======================================================================================

def _read_backs(shim: S.ProxyStandIn) -> list[dict[str, Any]]:
    """The requests that read the case back: a GET of the ticket itself."""
    return [r for r in shim.requests()
            if r["method"] == "GET" and r["path"].endswith(f"/tickets/{C.TICKET_KEY}")]


def _ticket(*bodies: str) -> dict[str, Any]:
    """The lab store's ticket read (`GET /tickets/<key>`): the ticket with every comment."""
    return S.answer(json.dumps({
        "key": C.TICKET_KEY, "status": "open",
        "comments": [{"author": "someone", "body": b} for b in bodies]}), "200")


def _tag(tmp_path: Path) -> str:
    """This run's tag line, known before the run: `_run`'s recorder names the run folder, and the
    folder's name is the run id."""
    run_dir = C.CaseRunRecorder(tmp_path / "runs" / "r1359").run_dir_at
    return S.mod("tenancy.case_ticket").agent_comment_tag(run_dir.name)


OTHER_RUN = "[defender agent comment, run 00000000-0000-4000-8000-000000000000]"


@pytest.mark.parametrize(("label", "read", "status", "ok", "rows"), [
    ("found", lambda ours: _ticket("an analyst's note", f"{ours}\nthe verdict"),
     C.COMMENTED, True, 1),
    ("absent", lambda ours: _ticket("an analyst's note", f"{OTHER_RUN}\nan earlier run's verdict"),
     C.UNKNOWN, False, 0),
    ("read fails", lambda ours: S.timed_out(), C.UNKNOWN, False, 0),
    ("no comment list", lambda ours: S.answer(json.dumps({"key": C.TICKET_KEY}), "200"),
     C.UNKNOWN, False, 0),
    ("an entry it cannot read", lambda ours: S.answer(json.dumps({"comments": [
        {"author": "someone", "body": "a note"}, {"author": "someone", "text": "changed shape"},
    ]}), "200"), C.UNKNOWN, False, 0),
    ("found beside an entry it cannot read", lambda ours: S.answer(json.dumps({"comments": [
        {"author": "someone", "text": "changed shape"}, {"author": "someone", "body": f"{ours}\nthe verdict"},
    ]}), "200"), C.COMMENTED, True, 1),
])
def test_1374_a_lost_answer_is_settled_by_one_read_back(
        tmp_path, monkeypatch, label, read, status, ok, rows):
    """The comment POST times out after it may have reached the store (the proxy says so): the host
    reads the ticket back once and decides from this run's tag line (P3) — found is the success
    receipt with the link and the comment recorded (O2); anything else, absent included (r4), is
    `unknown` naming the ticket and the tag to look for, and never claims the store could not be
    reached (O4). One write, one read (P4)."""
    root, _folder, alert = _world(tmp_path)
    ours = _tag(tmp_path)
    shim = _shim(tmp_path, monkeypatch, S.timed_out(), read(ours))
    _rc, refused, run_dir = _run(tmp_path, root, alert)
    assert refused is None, refused
    assert ours == S.mod("tenancy.case_ticket").agent_comment_tag(run_dir.name), "not this run's tag"
    argvs = shim.requests()
    assert len(C.comment_calls(shim)) == 1, (label, argvs)
    assert len(_read_backs(shim)) == 1, (label, argvs)
    got = S.receipt(run_dir)
    assert got is not None, f"[{label}] no receipt"
    assert (got["status"], got["ok"]) == (status, ok), (label, got)
    posted = S.mod("tenancy.case_ticket").read_posted_comments(fixture_run(run_dir))
    assert len(posted) == rows, (label, posted)
    reason = got.get("reason") or ""
    if status == C.COMMENTED:
        assert (got["url"] or "").endswith(f"/tickets/{C.TICKET_KEY}"), got
        assert got["reason"] is None, got
        assert posted[0][1].startswith(ours), posted
    else:
        assert got["url"] is None, got
        assert "may have reached the store" in reason, (label, reason)
        assert "could not be reached" not in reason, (label, reason)
    if label == "absent":
        assert "no comment from this run" in reason, reason
        assert "not posted" not in reason, f"a late commit can still land (T1): {reason}"
    if label == "no comment list":
        assert "no comment list" in reason, reason
    if status == C.UNKNOWN:
        assert C.TICKET_KEY in reason, reason
        assert ours in reason, reason


@pytest.mark.parametrize(("label", "write"), [
    ("never sent", S.never_connected()),
    ("store refused", S.answer(json.dumps({"detail": "no such ticket"}), "404")),
])
def test_1374_a_write_that_did_not_reach_or_was_refused_is_not_read_back(
        tmp_path, monkeypatch, label, write):
    """A write proven never sent (the proxy never connected) or one the store answered is
    decided as before: an error receipt and no read-back (O5, O6). The read the shim would
    answer next holds this run's comment, so a read-back would show as a success."""
    root, _folder, alert = _world(tmp_path)
    shim = _shim(tmp_path, monkeypatch, write, _ticket(f"{_tag(tmp_path)}\nthe verdict"))
    _rc, refused, run_dir = _run(tmp_path, root, alert)
    assert refused is None, refused
    assert _read_backs(shim) == [], (label, shim.requests())
    got = S.receipt(run_dir)
    assert (got["status"], got["ok"]) == (C.ERROR, False), (label, got)


def _case_adapter(tmp_path: Path, read_back: str | None, *, write_raises: str = "TransportFault('the reply was cut')") -> Any:
    """A checkout copy whose `casesys` adapter loses the comment's answer after it may have
    reached the store, with `read_back` as its read-back source (None: it has none)."""
    import shutil

    from defender.systems.verbs import read_roster

    tree = tmp_path / "tree" / "defender"
    shutil.copytree(S.DEFENDER / "integrations", tree / "integrations",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (tree / "integrations" / "casesys_adapter.py").write_text(
        "from defender.kit.faults import ConfigFault, TransportFault, UpstreamFault\n\n\n"
        "def check_settings(tenant):\n    return None\n\n\n"
        f"def {C.COMMENT_ACTION}(ctx, *, key, body):\n"
        f"    raise {write_raises}\n\n\n"
        + (read_back or "") + "\n\nVERBS = {}\n", encoding="utf-8")
    return read_roster(tree / "integrations")


@pytest.mark.parametrize(("label", "read_back", "why"), [
    ("no read-back", None, "cannot read the case back"),
    ("read-back crashes",
     f"def {C.READBACK_ACTION}(ctx, *, key):\n    raise RuntimeError('odd reply')\n",
     "RuntimeError"),
    ("read-back answers no comments",
     f"def {C.READBACK_ACTION}(ctx, *, key):\n    return 'yes'\n",
     "TypeError"),
    ("the proxy fails the read",
     f"def {C.READBACK_ACTION}(ctx, *, key):\n"
     "    fault = TransportFault('proxy down')\n    fault.proxy_own = True\n    raise fault\n",
     "the credential proxy failed: proxy down"),
    ("the proxy refuses the read",
     f"def {C.READBACK_ACTION}(ctx, *, key):\n"
     "    fault = ConfigFault('token expired')\n    fault.proxy_own = True\n    raise fault\n",
     "the credential proxy refused the call: token expired"),
])
def test_1374_an_unsettled_outcome_is_unknown_and_not_recorded(tmp_path, monkeypatch, label,
                                                                read_back, why):
    """A connector with no read-back, or one whose read-back raises anything at all, leaves the
    outcome unsettled: an `unknown` receipt (not ok, no link) naming the ticket and the tag to
    look for, and no posted-comments row (O4, D2)."""
    root, _folder, alert = _world(tmp_path, case_system="casesys")
    _shim(tmp_path, monkeypatch)
    rec = C.CaseRunRecorder(tmp_path / "runs" / "r1359")
    rc, refused = S.drive_run(S.run_argv(alert, root, update_ticket=True), rec, signer=_signer(),
                              visualize=rec.visualize, roster=_case_adapter(tmp_path, read_back))
    assert (refused, rc) == (None, 0), (refused, rc)
    got = S.receipt(rec.run_dir_at)
    assert got is not None, f"[{label}] no receipt"
    assert (got["status"], got["ok"], got["url"]) == (C.UNKNOWN, False, None), (label, got)
    reason = got.get("reason") or ""
    assert why in reason, (label, reason)
    assert C.TICKET_KEY in reason, (label, reason)
    assert _tag(tmp_path) in reason, (label, reason)
    assert S.mod("tenancy.case_ticket").read_posted_comments(fixture_run(rec.run_dir_at)) == []


def _read_answering(texts: str) -> str:
    return (f"def {C.READBACK_ACTION}(ctx, *, key):\n"
            "    from defender.kit.verbs import CaseComments\n"
            f"    return CaseComments(texts={texts}, link='http://store/t')\n")


@pytest.mark.parametrize(("label", "text", "status", "rows"), [
    ("found", "{tag}\nthe verdict", C.COMMENTED, 1),
    ("none", "a note", C.UNKNOWN, 0),
    ("the tag quoted in a sentence is not ours", "see {tag} above", C.UNKNOWN, 0),
])
def test_1374_the_host_decides_from_what_the_connector_read(
        tmp_path, monkeypatch, label, text, status, rows):
    """The connector only reads; the host applies the rules, so every connector inherits them. A
    comment whose own line is this run's tag is a success (P3). A read can only prove a comment is
    there, so no such comment is `unknown` however much was read (r4)."""
    root, _folder, alert = _world(tmp_path, case_system="casesys")
    _shim(tmp_path, monkeypatch)
    tag = _tag(tmp_path)
    texts = repr((text.replace("{tag}", tag),))
    rec = C.CaseRunRecorder(tmp_path / "runs" / "r1359")
    rc, refused = S.drive_run(S.run_argv(alert, root, update_ticket=True), rec, signer=_signer(),
                              visualize=rec.visualize,
                              roster=_case_adapter(tmp_path, _read_answering(texts)))
    assert (refused, rc) == (None, 0), (refused, rc)
    got = S.receipt(rec.run_dir_at)
    assert got is not None, label
    assert got["status"] == status, (label, got)
    assert got["url"] == ("http://store/t" if rows else None), (label, got)
    posted = S.mod("tenancy.case_ticket").read_posted_comments(fixture_run(rec.run_dir_at))
    assert len(posted) == rows, (label, posted)


@pytest.mark.parametrize(("raises", "status"), [
    ("TransportFault('y' * 5000)", C.UNKNOWN),
    ("UpstreamFault('y' * 5000, status=422)", C.ERROR),
], ids=["may-have-landed", "refused"])
def test_1374_a_write_fault_reaches_the_receipt_cut_short(tmp_path, monkeypatch, raises, status):
    """A write fault's detail can carry the store's whole reply too, whichever receipt it ends in."""
    root, _folder, alert = _world(tmp_path, case_system="casesys")
    _shim(tmp_path, monkeypatch)
    rec = C.CaseRunRecorder(tmp_path / "runs" / "r1359")
    S.drive_run(S.run_argv(alert, root, update_ticket=True), rec, signer=_signer(), visualize=rec.visualize,
                roster=_case_adapter(tmp_path, None, write_raises=raises))
    got = S.receipt(rec.run_dir_at)
    assert got["status"] == status, got
    assert "y" * 100 in got["reason"], "positive control: the detail reached the receipt"
    assert "y" * 1000 not in got["reason"], len(got["reason"])


# Retired by #1391 O1: `test_1374_a_docker_exit_1_may_have_sent_so_it_is_read_back` pinned how a
# docker exit decided "may have reached the store". The proxy says so itself (`sent`); a write that
# may have reached is read back (`test_1374_a_lost_answer_is_settled_by_one_read_back` above).


def test_1374_a_read_fault_reaches_the_receipt_cut_short(tmp_path, monkeypatch):
    """A failed read's detail can carry the store's whole reply (other people's comments): the
    receipt holds a bounded part of it, and still names the ticket and the tag."""
    root, _folder, alert = _world(tmp_path, case_system="casesys")
    _shim(tmp_path, monkeypatch)
    long = f"def {C.READBACK_ACTION}(ctx, *, key):\n    raise TransportFault('x' * 5000)\n"
    rec = C.CaseRunRecorder(tmp_path / "runs" / "r1359")
    S.drive_run(S.run_argv(alert, root, update_ticket=True), rec, signer=_signer(), visualize=rec.visualize,
                roster=_case_adapter(tmp_path, long))
    got = S.receipt(rec.run_dir_at)
    assert got["status"] == C.UNKNOWN, got
    assert "x" * 100 in got["reason"], "positive control: the detail reached the receipt"
    assert "x" * 1000 not in got["reason"], len(got["reason"])
    assert _tag(tmp_path) in got["reason"], got


def test_1374_the_page_tells_unknown_from_error_by_its_words(tmp_path):
    """The run page's ticket line says the receipt's status and reason, so `unknown` reads
    differently from `error`; it is not ok, so it never looks like a success (r4)."""
    from defender.presentation import visualize_run

    lines = {}
    for status, ok in ((C.COMMENTED, True), (C.ERROR, False), (C.UNKNOWN, False)):
        run_dir = tmp_path / status / "run"
        run_dir.mkdir(parents=True)
        S.receipt_path(run_dir).write_text(json.dumps(
            {"key": "SOC-1", "status": status, "url": None, "ok": ok, "reason": f"why {status}"}),
            encoding="utf-8")
        lines[status] = visualize_run.render_ticket_line(run_dir)
    for status, line in lines.items():
        assert f"\u2014 {status} \u2014" in line, line
        assert f"why {status}" in line, line
    assert "ticket-ok" in lines[C.COMMENTED], lines
    assert "ticket-ok" not in lines[C.UNKNOWN], lines
