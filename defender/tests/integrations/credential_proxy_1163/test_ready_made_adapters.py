"""#1359 the ready-made Jira and ServiceNow adapters comment through the real credential proxy
with no code written (O6, r4 "Ready-made adapters"; DC-4, DC-11, R3).

Not testable here (design-level exclusion): O6's `/connect` prose (the maintainer picks the
system, gives its address and credential, names the alert field). The tenant files `/connect`
leaves are planted instead (`_ready_made1359.files_for`). Vendor request shapes are from vendor
docs where they exist; Jira's success status and ServiceNow's link form are unconfirmed and are
not pinned (a Jira success is tried as 200 and 201; a ServiceNow link is only `None`)."""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, unquote

import pytest

from defender.kit.faults import ConfigFault, TransportFault, UpstreamFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _ready_made1359 as R
from defender.tests.integrations.credential_proxy_1163._ready_made1359 import (
    BODY, JIRA_NO, JIRA_YES, SERVICENOW, VENDORS, Vendor)
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C

KEY = C.TICKET_KEY
#: Every punctuation/alphanumeric character a `case_key` may hold (P3: printable ASCII, no `/`,
#: `\`, whitespace): the whole class, not a hand-picked list.
#: `;` is left out (D-1): the proxy refuses it in any path, so P3's key shape refuses it at the
#: front door too and such a key never reaches an adapter (`alert_front_door_1222/test_case_key_fact.py`).
KEY_CHARS = [chr(c) for c in range(0x21, 0x7F) if chr(c) not in "/\\;"]
BY_ID = {v.id: v for v in VENDORS}
vendors = pytest.mark.parametrize("vendor", VENDORS, ids=lambda v: v.id)


def _lines(v: Vendor, request_body: str) -> list[str]:
    """The comment text the request carried, one entry per line/paragraph, whatever the shape."""
    doc = json.loads(request_body)
    if v is JIRA_NO:
        return [_paragraph_text(p) for p in doc["body"]["content"]]
    return str(doc["body" if v is JIRA_YES else "work_notes"]).split("\n")


def _paragraph_text(node: dict[str, Any]) -> str:
    return "".join(n.get("text", "") for n in node.get("content") or [] if n.get("type") == "text")


@pytest.mark.parametrize("system", R.SYSTEMS)
def test_o6_the_adapter_declares_no_verbs_and_exports_the_comment_action(system, checkout_roster):
    """`jira` and `servicenow` are on the roster with `VERBS = {}`, `add_case_comment` and `check_settings`. O6, r4."""
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

    module = S.mod("systems.verbs").fresh_adapter_module(checkout_roster, system)
    assert module.VERBS == {}, "a ready-made adapter grants the agent nothing"
    assert callable(module.add_case_comment)
    assert callable(module.check_settings)


def test_o6_jira_cloud_comment_is_an_adf_document_with_a_paragraph_per_line(
        tmp_path, data_root, checkout_roster):
    """JIRA_SERVICE_DESK=no: POST rest/api/3/issue/{key}/comment, ADF body, one paragraph per line, text intact. O6."""
    with R.planted(tmp_path, data_root, JIRA_NO) as rig:
        link = rig.comment(checkout_roster, KEY)
        (seen,) = rig.sent()

    assert (seen.method, seen.path.split("?")[0]) == ("POST", "/jira" + JIRA_NO.route(KEY))
    doc = json.loads(seen.body)["body"]
    assert (doc["type"], doc["version"]) == ("doc", 1), doc
    assert [p["type"] for p in doc["content"]] == ["paragraph"] * len(doc["content"]), doc
    assert [t for t in _lines(JIRA_NO, seen.body) if t] == [ln for ln in BODY.split("\n") if ln]
    assert link == f"{JIRA_NO.declared_base(rig.up)}/browse/{KEY}"


def test_o6_jira_service_desk_comment_is_an_internal_plain_text_body(
        tmp_path, data_root, checkout_roster):
    """JIRA_SERVICE_DESK=yes: POST rest/servicedeskapi/request/{key}/comment with exactly {body, public: false}. O6, P4."""
    with R.planted(tmp_path, data_root, JIRA_YES) as rig:
        link = rig.comment(checkout_roster, KEY)
        (seen,) = rig.sent()

    assert (seen.method, seen.path.split("?")[0]) == ("POST", "/jira" + JIRA_YES.route(KEY))
    assert json.loads(seen.body) == {"body": BODY, "public": False}
    assert link == f"{JIRA_YES.declared_base(rig.up)}/browse/{KEY}"


def test_o6_servicenow_comment_is_a_work_note_and_nothing_else(
        tmp_path, data_root, checkout_roster):
    """PATCH api/now/table/{table}/{sys_id} with exactly {"work_notes": body} (no comments, no other field); link None. O6, R3, P4."""
    with R.planted(tmp_path, data_root, SERVICENOW) as rig:
        link = rig.comment(checkout_roster, C.TICKET_KEY.lower())
        (seen,) = rig.sent()

    assert (seen.method, seen.path.split("?")[0]) == (
        "PATCH", "/sn" + SERVICENOW.route(C.TICKET_KEY.lower()))
    assert json.loads(seen.body) == {"work_notes": BODY}
    assert link is None


@vendors
def test_o6_the_key_is_one_path_segment_whatever_its_characters(
        vendor, tmp_path, data_root, checkout_roster):
    """Every key the alert can name (printable ASCII but `/`, `\\`, whitespace; up to 128) reaches the store as one path segment. O6, P3."""
    keys = [f"{c}K{c}" for c in KEY_CHARS] + ["K" + "x" * 127]
    failures: list[str] = []
    with R.planted(tmp_path, data_root, vendor) as rig:
        for key in keys:
            try:
                rig.comment(checkout_roster, key)
            except Exception as exc:  # noqa: BLE001 — any refusal of a legal key is the finding
                failures.append(f"{key!r}: {type(exc).__name__} {exc}")
        seen = rig.sent()

    assert not failures, failures
    assert len(seen) == len(keys), "a key was not sent exactly once"
    for key, s in zip(keys, seen, strict=True):
        raw = s.path.split("?", 1)[0]
        want = vendor.base_path + vendor.route(key)
        if (s.method, unquote(raw), raw.count("/")) != (vendor.method, want, want.count("/")):
            failures.append(f"{key!r}: sent {s.method} {s.path}")
    assert not failures, failures


@vendors
def test_o6_the_credential_is_added_by_the_proxy_never_by_the_adapter(
        vendor, tmp_path, data_root, checkout_roster):
    """The request the adapter hands the proxy carries no credential; the upstream gets the stored one. O6, P2."""
    with R.planted(tmp_path, data_root, vendor) as rig:
        rig.comment(checkout_roster, KEY)
        (seen,) = rig.sent()
        (built,) = rig.tap.bodies

    asked = json.loads(built)
    assert (asked["system"], asked["method"]) == (vendor.system, vendor.method), asked
    assert not {h.lower() for h in asked.get("headers") or {}} & {"authorization", "cookie"}, asked
    assert R.USER not in built.decode(), "credential in the adapter's request"
    assert R.PASSWORD not in built.decode(), "credential in the adapter's request"
    assert seen.header("Authorization") == R.BASIC_AUTH


def _config(system: str, extra: str, *, docker: bool = False) -> str:
    p = A.prefix_of(system)
    if not docker:
        return A.env_text(system, extra=extra)
    return (f'{p}_TRANSPORT="docker-exec"\n{p}_URL_BASE="http://{system}.invalid:8080"\n'
            f'{p}_BASTION_HOST="bastion"\n{p}_TIMEOUT_SEC="5"\n{p}_DOCKER_CONTEXT="ctx-{system}"\n{extra}')


_JIRA, _SN = 'JIRA_SERVICE_DESK="{}"\n', 'SERVICENOW_TABLE="{}"\n'
CHECKS = [
    # (id, vendor, config.env text, access.yaml present, usable)
    pytest.param(JIRA_NO, _config("jira", _JIRA.format("no")), True, True, id="jira-no-control"),
    pytest.param(JIRA_NO, _config("jira", _JIRA.format("yes")), True, True, id="jira-yes-control"),
    pytest.param(SERVICENOW, _config("servicenow", _SN.format("incident")), True, True,
                 id="servicenow-control"),
    pytest.param(SERVICENOW, _config("servicenow", _SN.format(R.TABLE)), True, True,
                 id="servicenow-other-table-control"),
    pytest.param(JIRA_NO, _config("jira", ""), True, False, id="jira-service-desk-missing"),
    pytest.param(SERVICENOW, _config("servicenow", ""), True, False, id="servicenow-table-missing"),
    *[pytest.param(JIRA_NO, _config("jira", _JIRA.format(v)), True, False, id=f"jira-service-desk-{v or 'blank'}")
      for v in ("maybe", "true", "1", "", "YES", "No")],  # D-2: lowercase yes|no only
    *[pytest.param(SERVICENOW, _config("servicenow", _SN.format(v)), True, False,
                   id=f"servicenow-table-{n}")
      # #1366 C1: the table is a segment of the declared comment route, so `*` and `\` are the settings fault too
      for n, v in (("slash", "incident/x"), ("space", "a b"), ("query", "x?y=1"), ("blank", ""),
                   ("star", "inc*"), ("lone-star", "*"), ("backslash", "a\\b"))],
    pytest.param(JIRA_NO, _config("jira", _JIRA.format("no"), docker=True), False, False,
                 id="jira-docker-exec"),
    pytest.param(SERVICENOW, _config("servicenow", _SN.format("incident"), docker=True), False,
                 False, id="servicenow-docker-exec"),
    # The same docker-exec configs WITH an access.yaml present, so the refusal is the transport's
    # (r4: http-proxy only), not a missing declaration.
    pytest.param(JIRA_NO, _config("jira", _JIRA.format("no"), docker=True), True, False,
                 id="jira-docker-exec-with-access"),
    pytest.param(SERVICENOW, _config("servicenow", _SN.format("incident"), docker=True), True,
                 False, id="servicenow-docker-exec-with-access"),
]


@pytest.mark.parametrize(("vendor", "env", "access", "usable"), CHECKS)
def test_o6_check_settings_accepts_a_complete_http_proxy_config_and_refuses_the_rest(
        vendor, env, access, usable, tmp_path, data_root, checkout_roster):
    """Required keys have no defaults (JIRA_SERVICE_DESK yes|no, SERVICENOW_TABLE); another transport is refused. O6, DC-4."""
    with R.planted(tmp_path, data_root, vendor, env=env, access=access) as rig:
        module, record = rig.module(checkout_roster), rig.record()
        if usable:
            assert module.check_settings(record) is None
        else:
            with pytest.raises(ConfigFault):
                module.check_settings(record)


RECEIPT_CASES = [
    pytest.param(JIRA_NO, 200, id="jira-no-200"), pytest.param(JIRA_NO, 201, id="jira-no-201"),
    pytest.param(JIRA_YES, 200, id="jira-yes-200"), pytest.param(JIRA_YES, 201, id="jira-yes-201"),
    pytest.param(SERVICENOW, 200, id="servicenow-200"),
]


@pytest.mark.parametrize(("vendor", "status"), RECEIPT_CASES)
def test_o6_the_comment_reaches_the_store_through_the_record_leg_and_the_receipt_says_so(
        vendor, status, tmp_path, data_root):
    """A tenant planted as /connect leaves it: one request on the key, receipt `commented` with the adapter's link. O6, O1."""
    with R.planted(tmp_path, data_root, vendor, leg=True) as rig:
        rig.reply(KEY, status, {"id": "10001"})
        receipt = rig.leg("run")
        seen = rig.sent()
        base = vendor.declared_base(rig.up)

    assert receipt is not None, "no receipt"
    assert (receipt["key"], receipt["status"], receipt["ok"]) == (KEY, C.COMMENTED, True), receipt
    assert receipt.get("url") == vendor.link(base, KEY), receipt
    assert [(s.method, s.path.split("?")[0]) for s in seen] == [
        (vendor.method, vendor.base_path + vendor.route(KEY))]
    lines = _lines(vendor, seen[0].body)
    assert any(" \u2014 " in ln for ln in lines), (
        f"the case-record template's body did not reach the store: {lines}")


@vendors
def test_o6_a_ticket_the_store_does_not_know_leaves_a_not_found_receipt(
        vendor, tmp_path, data_root):
    """A 404 on the key is an error receipt saying not found (ServiceNow also names sys_id); a known key still comments. O6, O1, O5."""
    missing = "C1359-9999" if vendor.system == "jira" else "0" * 32
    with R.planted(tmp_path, data_root, vendor, leg=True) as rig:
        rig.reply(KEY, 200, {"id": "1"})
        rig.reply(missing, 404, {"errorMessages": ["not there"], "error": {"message": "No Record found"}})
        known = rig.leg("known", key=KEY)
        gone = rig.leg("gone", key=missing)
        paths = [s.path.split("?")[0] for s in rig.sent()]

    assert known is not None, "no receipt"
    assert gone is not None, "no receipt"
    assert (known["status"], known["ok"]) == (C.COMMENTED, True), known
    assert (gone["key"], gone["status"], gone["ok"]) == (missing, C.ERROR, False), gone
    reason = gone.get("reason") or ""
    assert C.REASON_NOT_FOUND in reason.lower(), gone
    if vendor is SERVICENOW:
        assert "sys_id" in reason, gone
    assert paths == [vendor.base_path + vendor.route(k) for k in (KEY, missing)]


def test_1363_servicenow_not_found_re_raise_keeps_the_system_origin(tmp_path, data_root, checkout_roster):
    """ServiceNow's 404 is re-raised as a fresh `UpstreamFault` naming sys_id; it carries the origin
    `system` and is not the proxy's own, like the 404 it came from. #1363 B2, G26."""
    from defender.kit.faults import UpstreamFault

    missing = "0" * 32
    with R.planted(tmp_path, data_root, SERVICENOW) as rig:
        rig.reply(missing, 404, {"error": {"message": "No Record found"}})
        with pytest.raises(UpstreamFault) as raised:
            rig.comment(checkout_roster, missing)

    assert "sys_id" in raised.value.detail, "positive control: this is the re-raised fault"
    assert (raised.value.status, getattr(raised.value, "origin", None), raised.value.proxy_own) == (404, "system", False)


# ======================================================================================
# #1374: the ready-made adapters read a case's comments, for the host's read-back.
# ======================================================================================

JOURNAL_PATH = "/sn/api/now/table/sys_journal_field"
OK_HEADERS = {"Content-Type": "application/json"}
readers = pytest.mark.parametrize("vendor", VENDORS, ids=lambda v: v.id)


def _serve(rig: Any, vendor: Vendor, page: Any, status: int = 200) -> None:
    """`page` as the answer to `vendor`'s read of `KEY`."""
    path = JOURNAL_PATH if vendor is SERVICENOW else vendor.base_path + vendor.route(KEY)
    rig.up.replies[path] = (status, OK_HEADERS, json.dumps(page).encode())


def _adf_comment(*paragraphs: list[dict[str, Any]]) -> dict[str, Any]:
    return {"id": "1", "body": {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": p} for p in paragraphs]}}


def _text(value: str) -> dict[str, Any]:
    return {"type": "text", "text": value}


def _page(vendor: Vendor, *texts: str) -> dict[str, Any]:
    """A page holding `texts` as `vendor` sends comments."""
    if vendor is JIRA_NO:
        return {"startAt": 0, "maxResults": 100, "total": len(texts), "comments": [
            _adf_comment(*[[_text(line)] if line else [] for line in t.split("\n")]) for t in texts]}
    if vendor is JIRA_YES:
        return {"start": 0, "limit": 100, "size": len(texts), "isLastPage": True,
                "values": [{"id": "1", "body": t} for t in texts]}
    return {"result": [{"value": t} for t in texts]}


@readers
def test_1374_the_read_is_one_get_that_returns_each_comment_as_text(
        vendor, tmp_path, data_root, checkout_roster):
    """One GET with the bounded page the vendor's API takes, newest first where it can sort, and
    each comment as text with its line breaks; never a write. Jira's link is the issue's."""
    with R.planted(tmp_path, data_root, vendor) as rig:
        _serve(rig, vendor, _page(vendor, "a note", "[tag]\nthe verdict"))
        got = rig.read(checkout_roster, KEY)
        (seen,) = rig.sent()
        base = vendor.declared_base(rig.up)

    assert seen.method == "GET", seen
    path, _, query = seen.path.partition("?")
    asked = {k: v[0] for k, v in parse_qs(query).items()}
    if vendor is JIRA_NO:
        assert path == "/jira" + vendor.route(KEY)
        assert asked == {"startAt": "0", "maxResults": "100", "orderBy": "-created"}, asked
    elif vendor is JIRA_YES:
        assert path == "/jira" + vendor.route(KEY)
        assert asked == {"start": "0", "limit": "100"}, asked
    else:
        assert path == JOURNAL_PATH
        assert asked == {
            "sysparm_query": f"element_id={KEY}^element=work_notes^ORDERBYDESCsys_created_on",
            "sysparm_fields": "value", "sysparm_limit": "100"}, asked
    assert got.texts == ("a note", "[tag]\nthe verdict"), got
    assert got.link == vendor.link(base, KEY), got


def test_1374_jira_cloud_reads_its_document_format_as_lines(tmp_path, data_root, checkout_roster):
    """Paragraphs and hard breaks are line breaks, text split by marks rejoins, and a nested block
    keeps its text: the tag line stays a line whatever the store did to the rest."""
    comment = _adf_comment(
        [_text("[defender "), {**_text("agent]"), "marks": [{"type": "strong"}]}],
        [_text("first"), {"type": "hardBreak"}, _text("second")], [])
    comment["body"]["content"].append({"type": "bulletList", "content": [
        {"type": "listItem", "content": [{"type": "paragraph", "content": [_text("item")]}]}]})
    with R.planted(tmp_path, data_root, JIRA_NO) as rig:
        _serve(rig, JIRA_NO, {"startAt": 0, "total": 1, "comments": [comment]})
        got = rig.read(checkout_roster, KEY)
    (text,) = got.texts
    assert text.splitlines() == ["[defender agent]", "first", "second", "", "item"], text


@pytest.mark.parametrize(("vendor", "page"), [
    (JIRA_NO, {"startAt": 0}), (JIRA_YES, {"start": 0}), (SERVICENOW, {}),
], ids=["cloud", "desk", "journal"])
def test_1374_a_reply_with_no_comment_list_raises(vendor, page, tmp_path, data_root, checkout_roster):
    """A reply that is not a list of comments at all is a failed read, so it is reported as one."""
    with R.planted(tmp_path, data_root, vendor) as rig:
        _serve(rig, vendor, page)
        with pytest.raises(TransportFault):
            rig.read(checkout_roster, KEY)


@pytest.mark.parametrize(("vendor", "page"), [
    (JIRA_NO, {"comments": [{"id": "1", "body": "plain"}, {"id": "2"}, "not a comment",
                            _adf_comment([_text("good")])]}),
    (JIRA_YES, {"values": [{"id": "1", "body": {"x": 1}}, {"id": "2"}, "not a comment",
                           {"id": "3", "body": "good"}]}),
    (SERVICENOW, {"result": [{"value": None}, {}, "not a note", {"value": "good"}]}),
], ids=["cloud", "desk", "journal"])
def test_1374_a_comment_it_cannot_read_is_left_out(vendor, page, tmp_path, data_root, checkout_roster):
    """One unreadable comment from anyone must not hide this run's comment. Leaving it out cannot
    cause a wrong outcome, because a read only ever proves a comment is there (r4)."""
    with R.planted(tmp_path, data_root, vendor) as rig:
        _serve(rig, vendor, page)
        got = rig.read(checkout_roster, KEY)
    assert got.texts == ("good",), got


def test_1374_a_damaged_document_keeps_the_lines_it_can_read(tmp_path, data_root, checkout_roster):
    """Damage inside a Jira document costs only the damaged part."""
    body = {"type": "doc", "content": [
        {"type": "paragraph", "content": [{"type": "text"}]},
        {"type": "paragraph", "content": [_text("good")]},
        {"type": "panel", "content": 5},
        "not a node"]}
    with R.planted(tmp_path, data_root, JIRA_NO) as rig:
        _serve(rig, JIRA_NO, {"comments": [{"id": "1", "body": body}]})
        got = rig.read(checkout_roster, KEY)
    (text,) = got.texts
    assert "good" in text.splitlines(), text


@readers
def test_1374_a_refused_read_raises(vendor, tmp_path, data_root, checkout_roster):
    """A 403 on the read (ServiceNow's journal is often closed to integration accounts) is a fault."""
    with R.planted(tmp_path, data_root, vendor) as rig:
        _serve(rig, vendor, {"error": "no"}, status=403)
        with pytest.raises(UpstreamFault) as raised:
            rig.read(checkout_roster, KEY)
    assert raised.value.status == 403, raised.value


def test_1374_a_servicenow_key_cannot_reshape_the_journal_query(tmp_path, data_root, checkout_roster):
    """The key goes into an encoded query there, where `^` starts a new condition, so a key holding
    it is refused before any request: nothing else's work notes can be read as this case's."""
    with R.planted(tmp_path, data_root, SERVICENOW) as rig:
        with pytest.raises(TransportFault):
            rig.read(checkout_roster, "abc^NQactive=true")
        assert rig.sent() == []


def _lost_write_then(rig: Any, vendor: Vendor, read: Any) -> None:
    """The write answers 503, so it may have landed; the read answers `read`."""
    path = vendor.base_path + vendor.route(KEY)
    write_lost = (503, OK_HEADERS, b'{"error": "busy"}')
    answer = (200, OK_HEADERS, json.dumps(read).encode())
    if vendor is SERVICENOW:
        rig.up.replies[path] = write_lost
        rig.up.replies[JOURNAL_PATH] = answer
    else:
        rig.up.replies[path] = lambda seen: write_lost if seen.method == vendor.method else answer


@pytest.mark.parametrize(("vendor", "found", "status"), [
    (JIRA_NO, True, C.COMMENTED), (JIRA_NO, False, C.UNKNOWN),
    (JIRA_YES, True, C.COMMENTED), (JIRA_YES, False, C.UNKNOWN),
    (SERVICENOW, True, C.COMMENTED), (SERVICENOW, False, C.UNKNOWN),
], ids=["cloud-found", "cloud-absent", "desk-found", "desk-absent", "journal-found", "journal-none"])
def test_1374_a_lost_answer_is_settled_through_the_real_proxy(
        vendor, found, status, tmp_path, data_root):
    """The record leg on a write that may have landed: one write and one read through the real
    proxy with the write-back token, settled from this run's tag line. None found is `unknown` on
    every vendor: a read cannot prove a comment will not appear (r4)."""
    from defender.tenancy.case_ticket import agent_comment_tag

    with R.planted(tmp_path, data_root, vendor, leg=True) as rig:
        tag = agent_comment_tag(C.CaseRunRecorder(tmp_path / "run").run_dir_at.name)
        _lost_write_then(rig, vendor, _page(vendor, "a note", *([f"{tag}\nverdict"] if found else [])))
        receipt = rig.leg("run")
        methods = [s.method for s in rig.sent()]
        base = vendor.declared_base(rig.up)

    assert receipt is not None, "no receipt"
    assert receipt["status"] == status, receipt
    assert methods == [vendor.method, "GET"], methods
    assert receipt["url"] == (vendor.link(base, KEY) if found else None), receipt
