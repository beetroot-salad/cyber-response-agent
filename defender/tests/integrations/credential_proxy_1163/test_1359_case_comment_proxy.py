"""#1359 the record leg reaches an `http-proxy` case system through the shared transport with
the host's write-back token; the ready-made Jira and ServiceNow adapters comment with no code
written; run start mints the write-back token for the system the case-record file names."""
from __future__ import annotations

import json
from typing import Any

from defender.box import run_env
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163.test_run_start_tokens import (
    TABLE, RunAtHandedRecorder, _records)
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, published_tenant

#: Marks every vendor request-shape assumption (design "Readiness": unverified against vendor docs).
VENDOR_SHAPE_UNVERIFIED = True

STORE = "/store"
COMMENT_PATH = f"{STORE}/tickets/{C.TICKET_KEY}/comments"
KEY_PATTERN = f'TICKET_KEY_PATTERN="{C.MARKER.upper()}-[0-9]+"\n'

# Jira Cloud REST v3 (VENDOR_SHAPE_UNVERIFIED): POST rest/api/3/issue/{key}/comment, body in
# Atlassian Document Format.
JIRA_BASE = "/jira"
JIRA_WRITE = ("POST", "/rest/api/3/issue/*/comment")
# ServiceNow Table API (VENDOR_SHAPE_UNVERIFIED): PATCH api/now/table/incident/{sys_id} with
# `work_notes`; the case key is assumed to BE the record's sys_id.
SN_BASE = "/sn"
SN_TABLE = "incident"
SN_WRITE = ("PATCH", f"/api/now/table/{SN_TABLE}/*")
SN_SYS_ID = "9d385017c611228701d22104cc95c371"


def _files(system: str, decl: str, *, env_extra: str = "") -> dict[str, str]:
    files = A.system_files(system, decl, env_extra=env_extra)
    files[f"settings/{C.PROVISIONAL_CASE_RECORD_REL}"] = C.case_record_text(system)
    files["settings/alert-mapping.yaml"] = C.alert_mapping_text()
    return files


def _comment(tmp_path, t, url: str, tok: str, *, key: str = C.TICKET_KEY,
             shim: S.DockerShim | None = None) -> dict[str, Any] | None:
    """The record leg at run end over a run whose record names `key`; returns the receipt."""
    rec = C.CaseRunRecorder(tmp_path / "run")
    run = rec.materialize(C.plant_alert(tmp_path / "in", key=key))
    env = run_env(DEFENDER, rec.run_dir_at)
    if shim is not None:
        env = shim.env(env)
    C.record_leg()(run, tenant=T.run_record(t), defender_dir=DEFENDER, env=env,
                   request_token=tok, proxy_url=url)
    return S.receipt(rec.run_dir_at)


def test_o3_o4_the_comment_goes_through_the_proxy_with_the_write_token_only(tmp_path, data_root):
    """rw token: one POST on the key, credential added by the proxy, no docker. r token: nothing sent, a proxy refusal.
    O3, O4."""
    shim = S.DockerShim(tmp_path / "shim")
    with H.upstream() as up:
        decl = H.declaration(up.url + STORE, writes=(("POST", "/tickets/*/comments"),))
        files = _files("ticket", decl, env_extra=KEY_PATTERN)
        with published_tenant(tmp_path / "forge", root=data_root, files=files) as t:
            up.replies[COMMENT_PATH] = (201, {}, json.dumps({"id": 1}).encode())
            store = H.FakeStore({(t.tenant_id, "ticket"): T.static_set()})
            with A.proxy_for(t, store) as (url, _tap):
                ok = _comment(tmp_path / "rw", t, url, T.token(t.tenant_id, {("ticket", "rw")}),
                              shim=shim)
                sent = len(up.seen)
                refused = _comment(tmp_path / "r", t, url, T.token(t.tenant_id, {("ticket", "r")}))

    assert ok is not None, "no receipt"
    assert (ok["key"], ok["status"], ok["ok"]) == (C.TICKET_KEY, C.COMMENTED, True), ok
    assert [(s.method, s.path) for s in up.seen[:sent]] == [("POST", COMMENT_PATH)]
    assert up.seen[0].header("Authorization") == f"Bearer {H.CANARY_KEY}"
    assert shim.calls() == []
    assert len(up.seen) == sent, "a read token wrote through the proxy"
    assert refused is not None, "no receipt"
    assert (refused["status"], refused["ok"]) == (C.ERROR, False), refused
    assert "proxy" in (refused.get("reason") or "").lower(), refused


def _vendor_comment(tmp_path, data_root, checkout_roster, system: str, base: str,
                    write: tuple[str, str], key: str, reply_path: str) -> tuple[Any, list[H.Seen]]:
    """A tenant with `system` planted as /connect would leave it (config.env, access.yaml with
    one write route, case-record file, case_key mapping); its adapter's check, then one comment."""
    with H.upstream() as up:
        decl = H.declaration(up.url + base, writes=(write,))
        with published_tenant(tmp_path / "forge", root=data_root, files=_files(system, decl)) as t:
            up.replies[reply_path] = (200, {"Content-Type": "application/json"}, b"{}")
            module = S.mod("systems.verbs").fresh_adapter_module(checkout_roster, system)
            assert module.check_settings(T.run_record(t)) is None
            assert getattr(module, "VERBS", None) == {}, "a ready-made adapter declares no verbs"
            store = H.FakeStore({(t.tenant_id, system): T.static_set()})
            with A.proxy_for(t, store) as (url, _tap):
                receipt = _comment(tmp_path, t, url, T.token(t.tenant_id, {(system, "rw")}), key=key)
        return receipt, list(up.seen)


def test_o6_ready_made_jira_adapter_posts_an_adf_comment(tmp_path, data_root, checkout_roster):
    """A Jira case system configured with no code comments on the key in Jira's document format. O6, P1."""
    path = f"{JIRA_BASE}/rest/api/3/issue/{C.TICKET_KEY}/comment"
    receipt, seen = _vendor_comment(tmp_path, data_root, checkout_roster, C.PROVISIONAL_JIRA_SYSTEM,
                                    JIRA_BASE, JIRA_WRITE, C.TICKET_KEY, path)
    assert receipt is not None, "no receipt"
    assert receipt["ok"] is True, receipt
    assert [(s.method, s.path) for s in seen] == [("POST", path)]
    body = json.loads(seen[0].body)["body"]
    assert (body.get("type"), body.get("version")) == ("doc", 1), body
    texts = [n.get("text", "") for n in _walk(body) if n.get("type") == "text"]
    assert any(t.strip() for t in texts), f"the document carries no text: {body}"


def _walk(node: Any) -> list[dict[str, Any]]:
    """Every ADF node under `node`, itself included."""
    if not isinstance(node, dict):
        return []
    out = [node]
    for child in node.get("content") or []:
        out += _walk(child)
    return out


def test_o6_ready_made_servicenow_adapter_writes_a_work_note(tmp_path, data_root, checkout_roster):
    """A ServiceNow case system configured with no code writes the comment as an internal work note. O6, P4."""
    path = f"{SN_BASE}/api/now/table/{SN_TABLE}/{SN_SYS_ID}"
    receipt, seen = _vendor_comment(tmp_path, data_root, checkout_roster,
                                    C.PROVISIONAL_SERVICENOW_SYSTEM, SN_BASE, SN_WRITE, SN_SYS_ID, path)
    assert receipt is not None, "no receipt"
    assert receipt["ok"] is True, receipt
    assert [(s.method, s.path.split("?")[0]) for s in seen] == [("PATCH", path)]
    doc = json.loads(seen[0].body)
    assert isinstance(doc.get("work_notes"), str), doc
    assert doc["work_notes"].strip(), doc
    assert "comments" not in doc, f"a customer-visible comment was written: {doc}"


class _RecordOnly:
    """`run.main`'s writer seam with the record leg only (no open leg exists): records its keywords."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def record_case_ticket(self, run: Any, **kw: Any) -> None:
        self.calls.append(kw)


def test_run_start_mints_the_write_back_token_for_the_named_case_system(tmp_path, data_root):
    """With the case-record file naming an http-proxy `ticket`, the one write-back token grants rw on `ticket`
    and the record leg gets it. Run-start flow, P2."""
    configs = dict(S.config_texts(C.MARKER))
    configs["ticket"] = A.env_text("ticket", extra=KEY_PATTERN)
    folder = C.plant_case_tenant(data_root, configs=configs, table=TABLE)
    for rel, text in H.access_files("ticket", H.declaration(
            "http://x.invalid/api", writes=(("POST", "/tickets/*/comments"),))).items():
        (folder / rel).parent.mkdir(parents=True, exist_ok=True)
        (folder / rel).write_text(text, encoding="utf-8")
    signer = A.MarkedSigner()
    writer = _RecordOnly()
    rec = RunAtHandedRecorder(tmp_path / "run")
    rc, refused = S.drive_run(
        S.run_argv(C.plant_alert(tmp_path / "in"), data_root, update_ticket=True), rec,
        ticket_writer=writer, proxy_url="http://proxy.invalid", signer=signer,
        directory=_records(data_root, tmp_path)[0].directory)

    assert (rc, refused) == (0, None)
    assert [A.grant_of(A.claims_of_payload(p)) for p in signer.payloads] == [[("ticket", "rw")]]
    (kw,) = writer.calls
    assert kw.get("request_token"), kw
