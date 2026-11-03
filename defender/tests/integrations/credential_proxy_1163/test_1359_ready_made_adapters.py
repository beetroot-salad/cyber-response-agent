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
from urllib.parse import unquote

import pytest

from defender.kit.faults import ConfigFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _ready_made1359 as R
from defender.tests.integrations.credential_proxy_1163._ready_made1359 import (
    BODY, JIRA_NO, JIRA_YES, SERVICENOW, VENDORS, Vendor)
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C

KEY = C.TICKET_KEY
#: Every punctuation/alphanumeric character a `case_key` may hold (P3: printable ASCII, no `/`,
#: `\`, whitespace): the whole class, not a hand-picked list.
#: `;` is left out (D-1): the proxy refuses it in any path, so P3's key shape refuses it at the
#: front door too and such a key never reaches an adapter (`alert_front_door_1222/test_1359_case_key_fact.py`).
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
      for n, v in (("slash", "incident/x"), ("space", "a b"), ("query", "x?y=1"), ("blank", ""))],
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
