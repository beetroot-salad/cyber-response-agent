"""#1359 the record leg reaches an `http-proxy` case system through the shared transport with
the job lane's write-back token (a pass naming the ticket, X1); the ready-made Jira and ServiceNow adapters comment
with no code written. (The operator run's own write-back mint is gone with `--update-ticket`, W7.)"""
from __future__ import annotations

import json
from typing import Any

from defender.box import run_env

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, published_tenant
from defender.tests.support.runtime.engine._spec767 import ticket_link_for

STORE = "/store"
COMMENT_PATH = f"{STORE}/tickets/{C.TICKET_KEY}/comments"
KEY_PATTERN = f'TICKET_KEY_PATTERN="{C.MARKER.upper()}-[0-9]+"\n'


def _files(system: str, decl: str, *, env_extra: str = "") -> dict[str, str]:
    files = A.system_files(system, decl, env_extra=env_extra)
    files[f"settings/{C.CASE_RECORD_REL}"] = C.case_record_text(system)
    return files


def _comment(tmp_path, t, url: str, tok: str, *, key: str = C.TICKET_KEY,
             shim: S.DockerShim | None = None) -> dict[str, Any] | None:
    """The record leg at run end over a run whose record names `key`; returns the receipt."""
    rec = C.CaseRunRecorder(tmp_path / "run")
    run = rec.materialize(C.plant_alert(tmp_path / "in", key=key))
    env = run_env(DEFENDER, rec.run_dir_at)
    if shim is not None:
        env = shim.env(env)
    record = T.run_record(t)
    C.record_leg()(run, tenant=record, defender_dir=DEFENDER, env=env, case=T1106.case_for(record),
                   request_token=tok, proxy_url=url, link=ticket_link_for(rec.run_dir_at))
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
                ok = _comment(tmp_path / "rw", t, url, T.token(t.tenant_id, {("ticket", "rw", C.TICKET_KEY)}),
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


def test_o5_a_write_the_store_took_is_a_comment_whatever_the_proxy_made_of_its_reply(tmp_path, data_root):
    """A 201 whose reply is over the proxy's size cap is still the store taking the comment:
    `commented`, never "the store refused (HTTP 200)". The host never reads a write's reply.
    Control: the same store's 404 is a refusal. O5, #1392 review."""
    with H.upstream() as up:
        decl = H.declaration(up.url + STORE, writes=(("POST", "/tickets/*/comments"),))
        files = _files("ticket", decl, env_extra=KEY_PATTERN)
        with published_tenant(tmp_path / "forge", root=data_root, files=files) as t:
            store = H.FakeStore({(t.tenant_id, "ticket"): T.static_set()})
            tok = T.token(t.tenant_id, {("ticket", "rw", C.TICKET_KEY)})
            with A.proxy_for(t, store, max_response_bytes=64) as (url, _tap):
                up.replies[COMMENT_PATH] = (201, {}, json.dumps({"id": 1, "body": "x" * 4096}).encode())
                took = _comment(tmp_path / "took", t, url, tok)
                up.replies[COMMENT_PATH] = (404, {}, json.dumps({"detail": "no such ticket"}).encode())
                lost = _comment(tmp_path / "lost", t, url, tok)

    assert took is not None, "no receipt for the accepted write"
    assert lost is not None, "no receipt for the refused write"
    assert (took["status"], took["ok"]) == (C.COMMENTED, True), took
    assert (lost["status"], lost["ok"]) == (C.ERROR, False), lost
    assert "404" in (lost.get("reason") or ""), lost
