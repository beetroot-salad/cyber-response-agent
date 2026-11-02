"""#1359 the record leg comments on the ticket the alert names, through the case system's adapter
(docker route), driven through `run.main` with the real writer."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, ensure_d9_tenant
from defender.tests.support.shared.contracts._spec1077 import fixture_run
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S


def _world(tmp_path: Path, *, key: str | None = C.TICKET_KEY, **kw: Any) -> tuple[Path, Path, Path]:
    ensure_d9_tenant()
    root = current_data_root()
    folder = C.plant_case_tenant(root, **kw)
    return root, folder, C.plant_alert(tmp_path / "in", key=key)


def _shim(tmp_path: Path, monkeypatch, *answers: dict[str, Any]) -> S.DockerShim:
    shim = S.DockerShim(tmp_path / "docker", list(answers) or [S.answer('{"id": 1}', "201")])
    monkeypatch.setenv("PATH", shim.path_value())
    return shim


def _run(tmp_path: Path, root: Path, alert: Path, *, summary: dict[str, Any] | None = None,
         before: Any = None, page: bool = False) -> tuple[int | None, Any, Path]:
    rec = C.CaseRunRecorder(tmp_path / "runs" / "r1359", summary=summary, before_lifecycle=before)
    seams = {} if page else {"visualize": rec.visualize}
    rc, refused = S.drive_run(S.run_argv(alert, root, update_ticket=True), rec, **seams)
    return rc, refused, rec.run_dir_at


def test_o1_one_comment_on_the_alert_named_ticket_and_no_call_at_run_start(tmp_path, monkeypatch):
    """The store receives one comment POST on the alert's key and nothing else; none before the lifecycle.
    O1, O5."""
    root, _folder, alert = _world(tmp_path)
    shim = _shim(tmp_path, monkeypatch)
    at_start: list[int] = []
    rc, refused, run_dir = _run(tmp_path, root, alert,
                                before=lambda _d: at_start.append(len(shim.calls())))

    assert refused is None, refused
    assert rc == 0, rc
    assert at_start == [0], f"the store was called at run start: {shim.calls()}"
    calls = [c["argv"] for c in shim.calls()]
    assert len(calls) == 1, f"expected one store call, got {calls}"
    assert "POST" in calls[0], calls[0]
    assert (S.curl_url(calls[0]) or "").endswith(f"/tickets/{C.TICKET_KEY}/comments"), calls[0]
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
    assert len(C.comment_calls(shim)) == 1, f"positive control: the comment was sent: {shim.calls()}"
    got = S.receipt(run_dir)
    assert got is not None, "no receipt"
    assert (got["key"], got["status"], got["ok"]) == (C.TICKET_KEY, C.ERROR, False), got
    assert C.PROVISIONAL_REASON_NOT_FOUND in (got.get("reason") or "").lower(), got


def test_o5_an_alert_naming_no_ticket_is_an_empty_key_receipt_the_page_shows(tmp_path, monkeypatch):
    """No case_key: no call, receipt key "" with the reason, and the page shows the reason, not "receipt unreadable".
    O5, flow step 3."""
    root, _folder, alert = _world(tmp_path, key=None)
    shim = _shim(tmp_path, monkeypatch)
    rc, refused, run_dir = _run(tmp_path, root, alert, page=True)

    assert refused is None, refused
    assert rc == 0, rc
    assert shim.calls() == [], f"a call was made with no key: {shim.calls()}"
    got = S.receipt(run_dir)
    assert got is not None, "no receipt"
    assert set(got) == C.RECEIPT_KEYS, got
    assert (got["key"], got["status"], got["ok"], got["url"]) == ("", C.ERROR, False, None), got
    reason = got.get("reason") or ""
    assert C.PROVISIONAL_REASON_NO_KEY in reason, got
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
    assert shim.calls() == [], shim.calls()
    got = S.receipt(run_dir)
    assert got is not None, "no receipt"
    assert (got["key"], got["status"], got["ok"]) == (C.TICKET_KEY, C.ERROR, False), got
    assert "config.env" in (got.get("reason") or ""), got


def test_o7_exit_class_and_posted_comments_record_key_on_the_ticket_key(tmp_path, monkeypatch):
    """A cut-short run escalates on the alert's key; the posted-comments row is keyed by the ticket key,
    its body tagged with the run. O7."""
    root, _folder, alert = _world(tmp_path)
    shim = _shim(tmp_path, monkeypatch)
    rc, refused, run_dir = _run(tmp_path, root, alert, summary={
        "output": "spec1359", "requests": 0, "truncated_by": "budget", "closed_before_cut": False})

    assert refused is None, refused
    assert len(C.comment_calls(shim)) == 1, shim.calls()
    got = S.receipt(run_dir)
    assert got is not None, "no receipt"
    assert (got["key"], got["status"]) == (C.TICKET_KEY, C.ESCALATED), got
    posted = S.mod("tenancy.case_ticket").read_posted_comments(fixture_run(run_dir))
    assert [k for k, _ in posted] == [C.TICKET_KEY], posted
    tag = S.mod("tenancy.case_ticket").agent_comment_tag(run_dir.name)
    assert posted[0][1].startswith(tag), posted
