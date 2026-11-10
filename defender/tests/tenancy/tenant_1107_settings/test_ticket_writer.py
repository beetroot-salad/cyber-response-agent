"""Ticket writer record step: error receipts, redaction, atomic receipt write, env handed through."""
from __future__ import annotations

import html
import json
import logging
from pathlib import Path
from typing import Any


from defender.records import RunPaths
from defender.records import run_end
from defender.investigation import ticket_writer
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, ensure_d9_tenant
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.support.shared._fixture_uuid import fixture_uuid

TW_LOGGER = ticket_writer.__name__
MARKER = "tw1107"


#: The ticket the planted alert names (`S.plant_alert`'s `alert_id`, mapped to `case_key`).
KEY = "a-1107"
CASE = "ticket"
CASE_RECORD = "case-record.yaml"


def _world(tmp_path: Path, *, marker: str = MARKER, name: str = "tenants",
           **plant_kw: Any) -> tuple[Path, Path, Path]:
    """The data-root row, a complete tenant under this test's data root (the one `run.py` reads;
    a second call replaces the first's knowledge whole), and an alert. Returns (data root,
    knowledge folder, alert)."""
    ensure_d9_tenant()
    root = current_data_root()
    folder = S.plant(root, marker=marker, **plant_kw)
    alert = S.plant_alert(tmp_path / f"alert-{name}", alert_id=KEY)
    return root, folder, alert


def _shim(tmp_path: Path, monkeypatch, *answers: dict[str, Any], name: str = "proxy"
          ) -> S.ProxyStandIn:
    """The credential proxy's stand-in, installed as the address every run here reaches (the case
    store is behind it, #1391 O1)."""
    return S.ProxyStandIn(tmp_path / name, list(answers) or None).install(monkeypatch)


def _run(tmp_path: Path, root: Path, alert: Path, *, run_id: str = "r1107",
         summary: dict[str, Any] | None = None, page: bool = False, before: Any = None,
         update_ticket: bool = True) -> tuple[int | None, Any, Path, S.RunRecorder]:
    """`run.main` over one alert with the real ticket writer. `page=True` leaves the real renderer
    in place; otherwise the recorder's `visualize` stands in. Returns (rc, refusal, run dir,
    recorder)."""
    from defender.tests.integrations.credential_proxy_1163._harness import FakeSigner

    rec = S.RunRecorder(tmp_path / "runs" / run_id, summary=summary, before_lifecycle=before)
    seams: dict[str, Any] = {"signer": FakeSigner()}
    if not page:
        seams["visualize"] = rec.visualize
    rc, refused = S.drive_run(
        S.run_argv(alert, root, update_ticket=update_ticket), rec, **seams)
    return rc, refused, rec.run_dir_at, rec


def _summary(truncated_by: str | None = None) -> dict[str, Any]:
    return {"output": "spec1107", "requests": 0, "truncated_by": truncated_by,
            "closed_before_cut": False}


def _host_paths(folder: Path, root: Path) -> set[str]:
    """The tenant's host settings path and the data root, as given and resolved."""
    settings = S.settings_of(folder)
    return {str(settings), str(settings.resolve()), str(root), str(root.resolve())}


def _warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and r.name == TW_LOGGER]


def _ticket_line_near(page: str, reason: str, *others: str, window: int = 1500) -> bool:
    """Does the page carry `reason` with every one of `others` within `window` chars of it —
    one ticket line, whatever its markup."""
    for needle in {html.escape(reason), reason}:
        at = page.find(needle)
        while at >= 0:
            around = page[max(0, at - window): at + len(needle) + window]
            if all(html.escape(o) in around or o in around for o in others):
                return True
            at = page.find(needle, at + 1)
    return False


def _post_calls(proxy: S.ProxyStandIn) -> list[dict[str, Any]]:
    return [r for r in proxy.requests() if r["method"] == "POST"]


# Retired by #1391 O1: `test_d_writer_context_from_run` checked the environment of the docker child
# the record step forked. The step forks nothing now; it sends to the credential proxy.


def test_o6_missing_config_receipt(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    root_ok, _folder_ok, alert_ok = _world(tmp_path, name="tenants-ok")
    _shim(tmp_path, monkeypatch, *S.store_answers_ok())
    rc_present, refused_present, _dir, _rec = _run(tmp_path, root_ok, alert_ok,
                                                   run_id="r-present", page=True)
    assert refused_present is None, f"the control run was refused: {refused_present}"

    root, folder, alert = _world(tmp_path, name="tenants-missing")
    S.config_path(folder, CASE).unlink()
    caplog.clear()
    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id="r-missing", page=True)
    assert refused is None, f"the run was refused over a ticket-config problem: {refused}"
    page = S.page_html(run_dir)
    assert page, "the run page did not render"
    got = S.receipt(run_dir)
    assert got is not None, "no ticket_write.json for a tenant with no config.env for its case system"
    assert got.get("ok") is False, got
    assert got.get("status") == "error", got
    assert "url" in got, f"url must be null with no config: {got}"
    assert got["url"] is None, f"url must be null with no config: {got}"
    reason = got.get("reason")
    assert isinstance(reason, str), f"no reason on the receipt: {got}"
    assert reason.strip(), f"no reason on the receipt: {got}"
    assert S.settings_pointer() in reason, (
        f"the reason does not name the settings through SETTINGS_POINTER: {reason!r}")
    assert _warnings(caplog), "the missing config logged no warning"
    assert _ticket_line_near(page, reason, got["key"], "error"), (
        "the run page shows no ticket line with the receipt's key, status and reason")
    assert rc == rc_present, (
        f"a ticket-config failure changed the exit code: {rc} vs {rc_present} with the config")


def test_o6_bad_config_receipt(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    _shim(tmp_path, monkeypatch)
    arms = {
        "missing-key": ("TICKET_KEY_PATTERN", lambda f: S.drop_key(
            f, CASE, "TICKET_KEY_PATTERN")),
        "non-digit-timeout": ("TICKET_TIMEOUT_SEC", lambda f: S.set_key(
            f, CASE, "TICKET_TIMEOUT_SEC", "ten")),
    }
    for arm, (bad_key, spoil) in arms.items():
        root, folder, alert = _world(tmp_path, name=f"tenants-{arm}")
        spoil(folder)
        caplog.clear()
        rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=f"r-{arm}")
        assert refused is None, f"{arm}: rc={rc} refused={refused}"
        assert rc == 0, f"{arm}: rc={rc} refused={refused}"
        got = S.receipt(run_dir)
        assert got is not None, f"{arm}: no ticket_write.json for a bad case-system config"
        assert got.get("ok") is False, f"{arm}: {got}"
        assert got.get("status") == "error", f"{arm}: {got}"
        assert "url" in got, f"{arm}: url must be null: {got}"
        assert got["url"] is None, f"{arm}: url must be null: {got}"
        reason = got.get("reason") or ""
        assert bad_key in reason, f"{arm}: the reason does not name {bad_key}: {reason!r}"
        assert S.settings_pointer() in reason, (
            f"{arm}: the reason does not name the settings through SETTINGS_POINTER: {reason!r}")
        assert _warnings(caplog), f"{arm}: no warning logged"


def test_o5_no_case_record_file_leaves_a_receipt_naming_it(tmp_path, monkeypatch):
    """A tenant with no case record (the planter's `case_system=None` seeds none: `R.NO_CASE`; or one still holding
    `systems/case-history/`, which nothing reads) run with `--update-ticket`: no call, an error receipt saying there is
    no case record, no silent ignore. The retired file is not named (#1366 O9, DC6: the case record is a database row,
    nothing reads `case-record.yaml`). O2, O5."""
    shim = _shim(tmp_path, monkeypatch, *S.store_answers_ok())
    for arm in ("none", "legacy-folder"):
        root, folder, alert = _world(tmp_path, name=arm, case_system=None)
        if arm == "legacy-folder":
            legacy = S.settings_of(folder) / "systems" / "case-history"
            legacy.mkdir(parents=True)
            (legacy / "mapping.yaml").write_text("open:\n  status: open\ncomment:\n  body: x\n",
                                                 encoding="utf-8")
        rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=f"r-{arm}")
        assert refused is None, f"{arm}: rc={rc} refused={refused}"
        assert rc == 0, f"{arm}: rc={rc}"
        got = S.receipt(run_dir)
        assert got is not None, f"{arm}: no receipt for --update-ticket with no case-record file"
        assert (got["status"], got["ok"]) == ("error", False), got
        assert "case record" in (got.get("reason") or "").replace("-", " ").lower(), got
        for host in _host_paths(folder, root):
            assert host not in got["reason"], f"{arm}: the reason carries {host}: {got['reason']!r}"
    assert not _post_calls(shim), "a call was made for a tenant with no case system"

    root, _folder, alert = _world(tmp_path, name="no-flag", case_system=None)
    _rc, _ref, run_dir, _rec = _run(tmp_path, root, alert, run_id="r-no-flag", update_ticket=False)
    assert not S.receipt_path(run_dir).exists(), "a run without --update-ticket wrote a receipt"


def _comment_argv(proxy: S.ProxyStandIn) -> dict[str, Any]:
    (request,) = _post_calls(proxy)
    return request


def _sent_body(request: dict[str, Any]) -> str:
    return json.dumps(request["body"])


def _with_report(run_dir: Path) -> None:
    """A readable report: the comment template renders over it (without one the fixed
    unreadable-report sentence is sent in its place)."""
    from defender.tests.support.runtime.engine._spec767 import write_report

    write_report(run_dir)


def test_o8_edits_to_the_case_settings_after_run_start_change_nothing_the_comment_carries(
        tmp_path, monkeypatch):
    """Editing the tenant's case-record.yaml or the system's config.env under the data root during
    a run changes nothing the comment carries; control: the body planted before start is sent. D-18."""
    edited_body = "EDITED-BODY {disposition}"
    control_shim = _shim(tmp_path, monkeypatch, *S.store_answers_ok(), name="proxy-control")
    root, _folder, alert = _world(tmp_path, name="control", case_body=edited_body)
    _run(tmp_path, root, alert, run_id="r-control", before=_with_report)
    assert "EDITED-BODY" in _sent_body(_comment_argv(control_shim)), "control: the body is read"

    shim = _shim(tmp_path, monkeypatch, *S.store_answers_ok(), name="proxy-edited")
    root, folder, alert = _world(tmp_path, name="edited")

    def edit_during_the_run(run_dir: Path) -> None:
        _with_report(run_dir)
        S.case_record_path(folder).write_text(
            f'system: "cmdb"\ncomment:\n  body: "{edited_body}"\n', encoding="utf-8")
        (S.settings_of(folder) / "systems" / CASE / "access.yaml").write_text(
            S.T1106.access_text(MARKER, CASE, base="http://edited-host.invalid:9"),
            encoding="utf-8")

    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id="r-edited",
                                      before=edit_during_the_run)
    assert refused is None, f"rc={rc} refused={refused}"
    assert rc == 0, f"rc={rc} refused={refused}"
    argv = _comment_argv(shim)
    assert argv["url"] == f"http://ticket-{MARKER}:8080/tickets/{KEY}/comments", argv
    assert "EDITED-BODY" not in _sent_body(argv), "an edit made during the run reached the comment"
    got = S.receipt(run_dir)
    assert got is not None
    assert (got["status"], got["ok"]) == ("commented", True), got


def test_o6_transport_fault_receipt(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    # The proxy reports the store took the request and never answered: no status.
    _shim(tmp_path, monkeypatch, S.timed_out("ticket store did not answer in time"))
    root, _folder, alert = _world(tmp_path)
    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id="r-transport")
    assert refused is None, f"rc={rc} refused={refused}"
    assert rc == 0, f"rc={rc} refused={refused}"
    got = S.receipt(run_dir)
    assert got is not None, "no ticket_write.json for a transport fault"
    assert got.get("ok") is False, got
    # #1374: a request that may have reached the store settles nothing. The proxy's own detail stays
    # in the reason.
    assert got.get("status") == "unknown", got
    assert got.get("url") is None, got
    reason = got.get("reason") or ""
    assert reason.strip(), f"no reason on the transport-fault receipt: {got}"
    assert "may have reached the store" in reason, reason
    assert "did not answer in time" in reason, reason
    assert _warnings(caplog), "a transport fault logged no warning"


def test_o6_budget_cut_missing_config_no_receipt(tmp_path, monkeypatch):
    _shim(tmp_path, monkeypatch)
    root, folder, alert = _world(tmp_path)
    S.config_path(folder, CASE).unlink()
    # The control, same tenant, same missing config: an aborted run DOES write the error receipt,
    # so the channel below can see a receipt when one is written.
    _rc, _ref, aborted_dir, _rec = _run(
        tmp_path, root, alert, run_id="r-aborted",
        summary=_summary(run_end.TRUNCATED_BY_ABORTED))
    assert S.receipt(aborted_dir) is not None, (
        "the control failed: an aborted run with the config missing wrote no receipt")
    for cut in (run_end.TRUNCATED_BY_BUDGET, run_end.TRUNCATED_BY_STORE):
        rc, refused, run_dir, _rec = _run(
            tmp_path, root, alert, run_id=f"r-{cut}", summary=_summary(cut))
        assert refused is None, f"{cut}: rc={rc} refused={refused}"
        assert rc == 0, f"{cut}: rc={rc} refused={refused}"
        path = S.receipt_path(run_dir)
        assert not path.exists(), f"a run cut by {cut} with no verdict wrote {path.name}: {path.read_text()!r}"
        assert not path.is_symlink(), f"a run cut by {cut} with no verdict wrote {path.name}: {path.read_text()!r}"


def test_o6_aborted_missing_config_receipt(tmp_path, monkeypatch):
    _shim(tmp_path, monkeypatch)
    root, folder, alert = _world(tmp_path)
    S.config_path(folder, CASE).unlink()
    rc, refused, run_dir, _rec = _run(
        tmp_path, root, alert, run_id="r-aborted",
        summary=_summary(run_end.TRUNCATED_BY_ABORTED))
    assert refused is None, f"rc={rc} refused={refused}"
    assert rc == 0, f"rc={rc} refused={refused}"
    got = S.receipt(run_dir)
    assert got is not None, "an aborted run with the config missing wrote no receipt"
    assert got.get("ok") is False, got
    assert got.get("status") == "error", got
    assert "url" in got, f"url must be null with no config: {got}"
    assert got["url"] is None, f"url must be null with no config: {got}"
    assert (got.get("reason") or "").strip(), f"no reason: {got}"


def test_o5_run_start_makes_no_call_and_writes_no_receipt_on_any_path(tmp_path, monkeypatch):
    """Whatever run start finds wrong with the case settings it neither calls the store nor leaves
    a receipt: the record leg is the only source of one. O1, O5, run-start flow."""
    for arm in ("ok", "missing-config", "bad-config", "bad-case-record", "no-key", "transport"):
        answers = [S.timed_out()] if arm == "transport" else S.store_answers_ok()
        shim = _shim(tmp_path, monkeypatch, *answers, name=f"proxy-{arm}")
        root, folder, alert = _world(tmp_path, name=f"tenants-{arm}")
        if arm == "missing-config":
            S.config_path(folder, CASE).unlink()
        elif arm == "bad-config":
            S.set_key(folder, CASE, "TICKET_TIMEOUT_SEC", "ten")
        elif arm == "bad-case-record":
            S.case_record_path(folder).write_text("- not\n- a mapping\n", encoding="utf-8")
        elif arm == "no-key":
            alert = _alert_without_key(tmp_path / f"alert-nokey-{arm}")
        seen: list[tuple[int, bool]] = []

        def at_start(run_dir: Path, shim=shim, seen=seen) -> None:
            seen.append((len(shim.requests()), S.receipt_path(run_dir).exists()))

        rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=f"r-start-{arm}",
                                          before=at_start)
        assert refused is None, f"{arm}: rc={rc} refused={refused}"
        assert seen == [(0, False)], f"{arm}: at the lifecycle, (store calls, receipt) = {seen}"
        got = S.receipt(run_dir)
        assert got is not None, f"{arm}: the record leg left no receipt"
        assert got["ok"] is (arm == "ok"), f"{arm}: {got}"


def _alert_without_key(where: Path) -> Path:
    """An alert whose id field (the mapped `case_key`) is absent."""
    where.mkdir(parents=True, exist_ok=True)
    path = where / "alert.json"
    path.write_text(json.dumps({"rule": {"id": "r-1107", "description": "spec 1107"},
                                "timestamp": "2026-09-28T00:00:00Z"}), encoding="utf-8")
    return path


def test_store_answers_the_record_step_with_an_http_error(tmp_path, monkeypatch, caplog):
    """An HTTP 4xx or 5xx from the store on the record step is a transport fault: ticket_write.json
    with ok false and a reason, a warning log line, a page line, and the exit code unchanged. A 4xx
    is the store refusing (`error`); a 5xx may follow a store that took the comment, so the case is
    read back once (#1374) and, the read meeting the same 5xx, the receipt is `unknown`."""
    caplog.set_level(logging.INFO)
    root, _folder, alert = _world(tmp_path)
    _shim(tmp_path, monkeypatch, *S.store_answers_ok(), name="proxy-ok")
    rc_ok, refused_ok, ok_dir, _rec = _run(tmp_path, root, alert, run_id="r-ok", page=True)
    assert refused_ok is None, refused_ok
    control = S.receipt(ok_dir)
    assert control is not None, f"the control failed: a 2xx record step wrote {control}"
    assert control.get("ok") is True, f"the control failed: a 2xx record step wrote {control}"
    for status, words in (("403", ("the store refused", "403")),
                          ("422", ("the store refused", "422")),
                          ("404", ("the store refused", "404", "not found")),
                          ("500", ("may have reached the store",)),
                          ("503", ("may have reached the store",))):
        run_id = f"r-http-{status}"
        shim = _shim(tmp_path, monkeypatch,
                     S.answer(json.dumps({"detail": f"store said {status}"}), status),
                     name=f"proxy-{status}")
        caplog.clear()
        rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=run_id, page=True)
        assert refused is None, f"HTTP {status}: refused {refused}"
        assert len(_post_calls(shim)) == 1, (
            f"HTTP {status}: positive control, the comment was sent once")
        page = S.page_html(run_dir)
        assert page, f"HTTP {status}: the run page did not render"
        got = S.receipt(run_dir)
        assert got is not None, f"HTTP {status}: {got}"
        expected = "unknown" if status.startswith("5") else "error"
        assert (got.get("key"), got.get("status"), got.get("ok")) == (KEY, expected, False), got
        assert got.get("url") is None, f"HTTP {status}: an error receipt carries a link: {got}"
        reason = (got.get("reason") or "")
        assert all(w in reason.lower() for w in words), f"HTTP {status}: reason {reason!r}"
        assert _warnings(caplog), f"HTTP {status}: no warning logged"
        assert _ticket_line_near(page, reason, got["key"]), (
            f"HTTP {status}: the run page shows no ticket line for the failed record")
        assert rc == rc_ok, f"HTTP {status} changed the exit code: {rc} vs {rc_ok}"


def test_s7_nf23_reason_is_the_redacted_fault_text(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    _shim(tmp_path, monkeypatch)
    root, folder, alert = _world(tmp_path, name="tenants-bad")
    S.drop_key(folder, CASE, "TICKET_KEY_PATTERN")
    caplog.clear()
    _rc, _ref, run_dir, _rec = _run(tmp_path, root, alert, run_id="r-bad")
    got = S.receipt(run_dir)
    assert got is not None, f"no reason: {got}"
    assert (got.get("reason") or "").strip(), f"no reason: {got}"
    reason = got["reason"]
    warned = _warnings(caplog)
    assert any(reason in w for w in warned), (
        f"no warning line carries the receipt's reason {reason!r}: {warned}")
    for host in _host_paths(folder, root):
        assert host not in reason, f"the reason carries {host}: {reason!r}"
        for w in warned:
            assert host not in w, f"a warning line carries the host path {host}: {w!r}"

    # A person has already closed the case: the store holds it `closed`, and every answer it
    # gives says so. The writer never asks, so the record lands as on any case (#1221).
    root2, _folder2, alert2 = _world(tmp_path, name="tenants-closed")
    run_id = "r-closed"
    shim2 = _shim(tmp_path, monkeypatch, *S.store_answers_ok(), name="proxy-closed")
    _rc2, _ref2, run_dir2, _rec2 = _run(tmp_path, root2, alert2, run_id=run_id)
    recorded = S.receipt(run_dir2)
    assert recorded is not None, "a closed case's record wrote no receipt"
    assert (recorded.get("status"), recorded.get("ok"), recorded.get("reason")) == (
        ticket_writer.RECEIPT_COMMENTED, True, None), (
        f"a case the store holds closed was not recorded like any other: {recorded}")
    methods = [r["method"] for r in shim2.requests()]
    assert "GET" not in methods, f"the writer read the case back: {methods}"
    comments = [r for r in _post_calls(shim2) if r["path"].endswith("/comments")]
    assert len(comments) == 1, f"expected one comment POST, saw {len(comments)}: {methods}"


def test_s7_nf24_receipt_write_failure_is_harmless(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    root, _folder, alert = _world(tmp_path)

    # A directory squatting the receipt's name: a real input the guarded replace cannot write
    # over. The record step itself succeeds against the store.
    _shim(tmp_path, monkeypatch, *S.store_answers_ok(), name="proxy-squat")

    def squat(run_dir: Path) -> None:
        S.receipt_path(run_dir).mkdir()

    caplog.clear()
    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id="r-squat", before=squat)
    assert refused is None, f"a receipt write failure changed the run: {rc} {refused}"
    assert rc == 0, f"a receipt write failure changed the run: {rc} {refused}"
    assert S.receipt_path(run_dir).is_dir(), "the squatting directory was removed or replaced"
    warned = [w for w in _warnings(caplog)
              if "receipt" in w.lower() or RunPaths(run_dir).ticket_write.name in w]
    assert warned, f"the failed receipt write was not logged as a warning: {_warnings(caplog)}"


def test_s7_mf12_no_receipt_branch_clears_stale_receipt(tmp_path, monkeypatch):
    _shim(tmp_path, monkeypatch)
    root, _folder, alert = _world(tmp_path)
    forged = {"key": "FORGED-KEY-1107", "status": "commented", "url": "http://forged.invalid/x",
              "ok": True, "reason": "forged-reason-1107"}
    target = tmp_path / "outside-target.json"
    target_bytes = json.dumps(forged).encode("utf-8")
    target.write_bytes(target_bytes)
    planted: list[str] = []

    def plant_file(run_dir: Path) -> None:
        S.receipt_path(run_dir).write_text(json.dumps(forged), encoding="utf-8")
        planted.append("file" if S.receipt_path(run_dir).is_file() else "")

    def plant_link(run_dir: Path) -> None:
        S.receipt_path(run_dir).symlink_to(target)
        planted.append("link" if S.receipt_path(run_dir).is_symlink() else "")

    for arm, kind, before in (("forged", "file", plant_file), ("symlink", "link", plant_link)):
        rc, refused, run_dir, _rec = _run(
            tmp_path, root, alert, run_id=f"r-{arm}", page=True, before=before,
            summary=_summary(run_end.TRUNCATED_BY_BUDGET))
        assert refused is None, f"{arm}: rc={rc} refused={refused}"
        assert rc == 0, f"{arm}: rc={rc} refused={refused}"
        page = S.page_html(run_dir)
        assert page, f"{arm}: the run page did not render"
        # The plant was in place when the run reached its ticket lane.
        assert planted, f"{arm}: the plant was not in place: {planted}"
        assert planted[-1] == kind, f"{arm}: the plant was not in place: {planted}"
        path = S.receipt_path(run_dir)
        assert not path.exists(), f"{arm}: a budget-cut run left {path.name} behind"
        assert not path.is_symlink(), f"{arm}: a budget-cut run left {path.name} behind"
        for marker in ("FORGED-KEY-1107", "forged-reason-1107", "forged.invalid"):
            assert marker not in page, f"{arm}: the page shows the planted receipt ({marker})"
    assert target.read_bytes() == target_bytes, "the unlink followed the link into its target"


def test_o1_ticket_writer_ignores_env(tmp_path, monkeypatch):
    """With TICKET_URL_BASE exported, the record step's request URL and the receipt's url are
    the tenant's declared base."""
    exported = "http://exported-ticket-1107:1"
    monkeypatch.setenv("TICKET_URL_BASE", exported)
    run_id = "r-o1"
    shim = _shim(tmp_path, monkeypatch, *S.store_answers_ok())
    root, _folder, alert = _world(tmp_path)
    rc, refused, run_dir, _rec = _run(tmp_path, root, alert, run_id=run_id)
    assert refused is None, f"rc={rc} refused={refused}"
    assert rc == 0, f"rc={rc} refused={refused}"
    calls = shim.requests()
    assert calls, "the record step reached the store through no request"
    file_base = f"http://ticket-{MARKER}:8080"
    for call in calls:
        assert call["url"].startswith(file_base), (
            f"the record step addressed {call['url']!r}, not the tenant file's {file_base}")
        assert exported not in json.dumps(call), call
    got = S.receipt(run_dir)
    assert got is not None, f"the receipt's url is not the tenant file's: {got}"
    assert str(got.get("url") or "").startswith(file_base), f"the receipt's url is not the tenant file's: {got}"


def test_s60_ticket_write_fs_atomic_replace(tmp_path, monkeypatch):
    root, folder, alert = _world(tmp_path)
    # The run folder is rebuilt below from this id, so it is the canonical UUID the recorder uses.
    run_id = fixture_uuid("r-atomic")
    _shim(tmp_path, monkeypatch, *S.store_answers_ok())
    _run(tmp_path, root, alert, run_id=run_id)
    run_dir = tmp_path / "runs" / run_id
    path = S.receipt_path(run_dir)
    assert path.is_file(), "the first record step wrote no receipt"
    old_bytes = path.read_bytes()
    assert json.loads(old_bytes).get("ok") is True, f"the first record step failed: {old_bytes!r}"
    old_inode = path.stat().st_ino
    # A reader holding the file open across the next write.
    with path.open("rb") as reader:
        S.config_path(folder, CASE).unlink()
        _run(tmp_path, root, alert, run_id=run_id)
        held = reader.read()
    assert held == old_bytes, "the second write changed the bytes under an open reader (in place)"
    json.loads(held.decode("utf-8"))
    after = json.loads(path.read_bytes().decode("utf-8"))
    # The second record step (the missing config's error receipt) did write: the last attempt wins.
    assert after.get("status") == "error", f"the second (error) receipt did not land: {after}"
    assert after.get("ok") is False, f"the second (error) receipt did not land: {after}"
    assert path.stat().st_ino != old_inode, (
        "the second receipt was not written by a replace — the same inode was rewritten")
    leftovers = sorted(p.name for p in run_dir.iterdir()
                       if p.name != path.name and "ticket_write" in p.name)
    assert not leftovers, f"a staged receipt was left beside the real one: {leftovers}"


def test_s7_f6_run_env_handed_to_the_correlation_lead(tmp_path, monkeypatch):
    """The driver hands the run's env to the correlation lead: with a marker variable in that
    env, the lead's backend child receives it."""
    marker_var, marker_value = "SPEC1107_RUN_ENV_MARKER", "run-env-marker-7c1"
    monkeypatch.setenv(marker_var, marker_value)

    from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as FD

    lead = FD.run_alert(tmp_path / "lz-run", tenant=FD.plant_tenant(),
                        leads={FD.L3: [FD.query("elastic", "alerts", {"native_query": "*"}),
                                       FD.text(FD.DEFAULT_CORRELATION_SUMMARY)]})
    assert lead.backend.rec.calls, "the correlation lead issued no backend call"
    shell_env = dict(lead.backend.rec.calls[0].ctx.env)
    assert shell_env.get(marker_var) == marker_value, (
        "the correlation lead's backend call was not handed the run env's marker")


# Retired by #1391 O1: `test_s7_f6_run_env_handed_to_the_ticket_writer` checked the environment of
# the docker child the writer forked. The writer forks nothing now; it sends to the credential proxy.
