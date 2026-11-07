"""#1359 the record leg reaches an `http-proxy` case system through the shared transport with
the host's write-back token; the ready-made Jira and ServiceNow adapters comment with no code
written; run start mints the write-back token for the system the case-record file names."""
from __future__ import annotations

import json
from typing import Any

from defender.box import run_env
from defender.kit.faults import ConfigFault, TransportFault

import pytest
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163.test_run_start_tokens import (
    TABLE, RunAtHandedRecorder, _records)
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S
from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, published_tenant

STORE = "/store"
COMMENT_PATH = f"{STORE}/tickets/{C.TICKET_KEY}/comments"
KEY_PATTERN = f'TICKET_KEY_PATTERN="{C.MARKER.upper()}-[0-9]+"\n'

# Jira Cloud (r4 Adapters); its request shapes are slice C's, in test_ready_made_adapters.py.
JIRA_WRITE = ("POST", "/rest/api/3/issue/*/comment")


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


def test_o5_a_write_the_store_took_is_a_comment_whatever_the_proxy_made_of_its_reply(tmp_path, data_root):
    """A 201 whose reply is over the proxy's size cap is still the store taking the comment:
    `commented`, never "the store refused (HTTP 200)". The host never reads a write's reply.
    Control: the same store's 404 is a refusal. O5, #1392 review."""
    with H.upstream() as up:
        decl = H.declaration(up.url + STORE, writes=(("POST", "/tickets/*/comments"),))
        files = _files("ticket", decl, env_extra=KEY_PATTERN)
        with published_tenant(tmp_path / "forge", root=data_root, files=files) as t:
            store = H.FakeStore({(t.tenant_id, "ticket"): T.static_set()})
            tok = T.token(t.tenant_id, {("ticket", "rw")})
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


class _RecordOnly:
    """`run.main`'s writer seam after #1359: `record_case_ticket` and `clear_receipt` only (an open
    leg would fail the run's call)."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def clear_receipt(self, run: Any, **kw: Any) -> None:
        pass

    def record_case_ticket(self, run: Any, **kw: Any) -> None:
        self.calls.append(kw)


#: Per case system: its config.env extra keys and its one declared comment route (r4 Adapters).
CASES = {
    C.CASE_SYSTEM_TICKET: (KEY_PATTERN, ("POST", "/tickets/*/comments")),
    C.JIRA_SYSTEM: ('JIRA_SERVICE_DESK="no"\n', JIRA_WRITE),
}


def _case_tenant(data_root, system: str, *, extra: str | None = None, **kw: Any):
    """The playground tenant with `system` on `http-proxy` (its declaration holding its one write
    route) and a case-record file naming it; `extra` replaces the system's config.env keys."""
    env_extra, write = CASES[system]
    configs = dict(S.config_texts(C.MARKER))
    configs[system] = A.env_text(system, extra=env_extra if extra is None else extra)
    folder = C.plant_case_tenant(data_root, case_system=system, configs=configs, table=TABLE, **kw)
    for rel, text in H.access_files(system, H.declaration("http://x.invalid/api", writes=(write,))).items():
        (folder / rel).parent.mkdir(parents=True, exist_ok=True)
        (folder / rel).write_text(text, encoding="utf-8")
    return folder


def _drive_real_leg(tmp_path, data_root, *, no_generation: bool = False, **seams: Any):
    """`run.main --update-ticket` with the REAL writer (the leg reaches only an unreachable proxy
    address); returns (recorder, rc, refused). `no_generation` withholds the shared fixture's
    default live generation (and so its sign login, #1391 _proxied1391)."""
    rec = RunAtHandedRecorder(tmp_path / "run")
    argv = S.run_argv(C.plant_alert(tmp_path / "in"), data_root, update_ticket=True)
    if no_generation:
        seams["directory"] = directory_for_argv(argv, generations=())
    rc, refused = S.drive_run(
        argv, rec, visualize=rec.visualize, proxy_url="http://127.0.0.1:9", **seams)
    return rec, rc, refused


@pytest.mark.parametrize("system", list(CASES))
def test_the_record_leg_gets_a_write_back_token_for_the_named_case_system(tmp_path, data_root, system):
    """With the case-record file naming an http-proxy system (`ticket` or another), the one
    write-back token (minted at the record leg, D-9 corrected) grants rw on that system only and the leg gets it. P2."""
    _case_tenant(data_root, system)
    signer = A.MarkedSigner()
    writer = _RecordOnly()
    rec = RunAtHandedRecorder(tmp_path / "run")
    rc, refused = S.drive_run(
        S.run_argv(C.plant_alert(tmp_path / "in"), data_root, update_ticket=True), rec,
        ticket_writer=writer, proxy_url="http://proxy.invalid", signer=signer,
        directory=_records(data_root, tmp_path)[0].directory)

    assert (rc, refused) == (0, None)
    assert [A.grant_of(A.claims_of_payload(p)) for p in signer.payloads] == [[(system, "rw")]]
    (kw,) = writer.calls
    assert kw.get("request_token"), kw


def test_no_write_back_token_is_minted_for_a_tenant_with_no_case_file(tmp_path, data_root):
    """No case-record file: nothing is minted for any system, and the run goes on. D-9 corrected."""
    _case_tenant(data_root, C.CASE_SYSTEM_TICKET)
    (S.settings_of(data_root / S.PLAYGROUND_ID / "knowledge") / C.CASE_RECORD_REL).unlink()
    signer = A.MarkedSigner()
    writer = _RecordOnly()
    rec = RunAtHandedRecorder(tmp_path / "run")
    rc, refused = S.drive_run(
        S.run_argv(C.plant_alert(tmp_path / "in"), data_root, update_ticket=True), rec,
        ticket_writer=writer, proxy_url="http://proxy.invalid", signer=signer,
        directory=_records(data_root, tmp_path)[0].directory)

    assert (rc, refused) == (0, None)
    assert signer.payloads == []
    assert [kw.get("request_token") for kw in writer.calls] == [None]


@pytest.mark.parametrize("arm", ["no sign login", "signer config fault", "signer transport fault"])
def test_r4_no_signing_access_mints_nothing_the_run_goes_on_and_the_leg_says_so(
        tmp_path, data_root, arm):
    """With no signing access (no sign login, or a signer fault) nothing is minted, the run goes on and the
    receipt says so; no store is reached. R4, D-11."""
    _case_tenant(data_root, C.CASE_SYSTEM_TICKET)
    witness = A.MarkedSigner()  # would mint if asked: the no-login arm must never ask
    seams: dict[str, Any] = {"no_generation": True, "signer": witness}  # no live generation: no sign login (R4)
    if arm != "no sign login":
        seams = {"signer": A.RaisingSigner(ConfigFault("OpenBao is sealed") if "config" in arm
                                           else TransportFault("OpenBao is unreachable")),
                 "directory": _records(data_root, tmp_path)[0].directory}
    with H.upstream() as up:
        rec, rc, refused = _drive_real_leg(tmp_path, data_root, **seams)
    assert (rc, refused) == (0, None), "the run was refused instead of going on"
    assert rec.lifecycle_calls, "the run never investigated"
    got = S.receipt(rec.run_dir_at)
    assert got is not None, "no receipt"
    assert (got["key"], got["status"], got["ok"]) == (C.TICKET_KEY, C.ERROR, False), got
    assert got["url"] is None, got
    assert "write-back token" in got["reason"], got
    assert up.seen == []
    if arm == "no sign login":
        assert witness.payloads == [], "a mint was attempted with no sign login"


@pytest.mark.parametrize("spoil", ["bad config.env", "bad case-record file"])
def test_run_start_judges_the_case_settings_before_the_mint(tmp_path, data_root, spoil):
    """Bad case settings are reported as such (the file named), never as a missing token or a
    proxy refusal, and nothing is signed. Run-start flow, O5."""
    folder = _case_tenant(data_root, C.CASE_SYSTEM_TICKET)
    if spoil == "bad config.env":
        S.set_key(folder, C.CASE_SYSTEM_TICKET, "TICKET_TIMEOUT_SEC", "ten")
        named = "systems/ticket/config.env"
    else:
        S.case_record_path(folder).write_text("- not\n- a mapping\n", encoding="utf-8")
        named = C.CASE_RECORD_REL
    signer = A.MarkedSigner()
    rec, rc, refused = _drive_real_leg(
        tmp_path, data_root, signer=signer, directory=_records(data_root, tmp_path)[0].directory)

    assert (rc, refused) == (0, None)
    assert signer.payloads == [], "a token was minted for a case system whose settings are wrong"
    got = S.receipt(rec.run_dir_at)
    assert got is not None, "no receipt"
    assert named in got["reason"], got
    assert got["url"] is None, got
    assert "write-back token" not in got["reason"], got
    assert "proxy refused" not in got["reason"], got
