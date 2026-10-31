"""#1163 run start signs the run's request tokens in the run process: a read token over the
granted `http-proxy` systems, and a write-back token at each ticket leg when the ticket system is
`http-proxy`. Driven through `run.main` and its injection seams."""
from __future__ import annotations

import logging
import time
from typing import Any

import pytest

from defender.hooks.budget_enforcer import DEFAULT_LIMITS
from defender.kit.faults import ConfigFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163._target import proxy
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

TABLE = """\
dispositions:
  cmdb:
    get-host: {roles: [gather]}
    health-check: {roles: [gather]}
  identity:
    get-user: {roles: [gather]}
    health-check: {roles: [gather]}
"""
BUDGET = DEFAULT_LIMITS["wall_clock_timeout"] + DEFAULT_LIMITS["grace_seconds"]
#: The read token outlives the wall-clock budget plus grace by this fixed margin (r6 A15).
MARGIN = 300
#: The seconds between the test's clock and the run's stamp of its start.
CLOCK_TOLERANCE = 60


class TicketRecorder:
    """The `ticket_writer` seam of `run.main`: records each leg's keyword arguments."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def open_case_ticket(self, run: Any, **kw: Any) -> None:
        self.calls.append(("open", kw))

    def record_case_ticket(self, run: Any, **kw: Any) -> None:
        self.calls.append(("record", kw))

    def leg(self, name: str) -> dict[str, Any]:
        (kw,) = [k for n, k in self.calls if n == name]
        return kw


def _plant(data_root, *, proxy: tuple[str, ...]):
    """The playground tenant with each system of `proxy` on `http-proxy` (declaration planted
    beside its config.env)."""
    configs = dict(S.config_texts("t1163"))
    for system in proxy:
        configs[system] = A.env_text(system)
    folder = S.plant(data_root, configs=configs, table=TABLE)
    for system in proxy:
        for rel, text in H.access_files(system, H.declaration("http://x.invalid/api")).items():
            (folder / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / rel).write_text(text, encoding="utf-8")


def _drive(tmp_path, data_root, *, signer=None, ticket=True, **seams):
    """Drive `run.main`; with no `signer` none is injected (the production signing path)."""
    rec, tickets = S.RunRecorder(tmp_path / "run"), TicketRecorder()
    alert = S.plant_alert(tmp_path / "in")
    started = time.time()
    if signer is not None:
        seams["signer"] = signer
    try:
        rc, refused = S.drive_run(
            S.run_argv(alert, data_root, update_ticket=ticket), rec, ticket_writer=tickets,
            proxy_url="http://proxy.invalid", **seams)
    except ConfigFault as fault:
        rc, refused = None, fault
    return rec, tickets, rc, refused, started


def _claims_of_token(signer: H.FakeSigner, token: str) -> dict[str, Any]:
    (n,) = [i for i in range(1, len(signer.payloads) + 1) if f"{A.SIGNATURE_CANARY}-{i}" in token]
    return A.claims_of_payload(signer.payloads[n - 1])


def test_r1_run_start_signs_a_read_token_and_a_write_back_token_per_leg(
        tmp_path, data_root, caplog):
    """Read grant names only http-proxy systems; `rw` on the ticket system only, minted at each
    leg; expiry is budget + grace + 300 s; no token reaches disk or log. O8, O10, O4, A7, A15."""
    caplog.set_level(logging.DEBUG)
    _plant(data_root, proxy=("identity", "case-history"))
    signer = A.MarkedSigner()
    rec, tickets, rc, refused, started = _drive(tmp_path, data_root, signer=signer)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    run_id = rec.run_dir_at.name
    claims = [A.claims_of_payload(p) for p in signer.payloads]
    assert len(claims) == 3, "one read token, one write-back token per ticket leg"
    by_grant = sorted(claims, key=lambda c: A.grant_of(c))
    write_back, read = by_grant[:2], by_grant[2]
    assert A.grant_of(read) == [("identity", "r")], "the cmdb (docker-exec) system is not granted"
    assert [A.grant_of(c) for c in write_back] == [[("case-history", "rw")]] * 2
    for c in claims:
        assert (c["tenant"], c["investigation"]) == (S.PLAYGROUND_ID, run_id)
    lifetime = read["exp"] - started
    assert BUDGET + MARGIN - 1 <= lifetime <= BUDGET + MARGIN + CLOCK_TOLERANCE, lifetime
    for c in write_back:
        assert c["exp"] > started

    open_tok, record_tok = tickets.leg("open")["request_token"], tickets.leg(
        "record")["request_token"]
    assert open_tok != record_tok
    assert A.grant_of(_claims_of_token(signer, open_tok)) == [("case-history", "rw")]
    assert A.grant_of(_claims_of_token(signer, record_tok)) == [("case-history", "rw")]

    (life,) = rec.lifecycle_calls
    for held in (life["tenant"], life["run"], life["systems"]):
        assert A.SIGNATURE_CANARY not in repr(held), "a token shows in a repr (O10)"
    assert A.SIGNATURE_CANARY not in caplog.text
    on_disk = A.text_of(data_root, tmp_path)
    assert A.SIGNATURE_CANARY not in on_disk, "a token reached a file: run state, record or log"
    assert run_id in on_disk, "positive control: the files the run wrote are read"
    assert "run_dir=" in caplog.text, "positive control: the log channel is read"


def test_r2_a_docker_exec_ticket_system_gets_no_write_back_token(tmp_path, data_root):
    """Only the identity system is `http-proxy`: one read token, and neither ticket leg is
    handed a token. A7."""
    _plant(data_root, proxy=("identity",))
    signer = A.MarkedSigner()
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, signer=signer)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    assert [A.grant_of(A.claims_of_payload(p)) for p in signer.payloads] == [[("identity", "r")]]
    assert tickets.leg("open").get("request_token") is None
    assert tickets.leg("record").get("request_token") is None


def test_r3_a_run_with_no_http_proxy_system_never_contacts_the_signer(tmp_path, data_root):
    """No system is `http-proxy`: nothing is signed even by a sealed OpenBao, so existing
    replays need none. A7."""
    _plant(data_root, proxy=())
    signer = A.RaisingSigner(ConfigFault("OpenBao is sealed"))
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, signer=signer)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    assert signer.asked == 0
    assert tickets.leg("open").get("request_token") is None
    assert rec.lifecycle_calls, "positive control: the run reached its lifecycle"


ROLE, SECRET = "role-1163-own", "secret-1163-own"
DECOY_ROLE, DECOY_SECRET = "role-1163-decoy", "secret-1163-decoy"
DECOY_TENANT = "t1163-decoy"


SEALED = {"sealed on login": {"sealed": "login"}, "sealed on sign": {"sealed": "sign"},
          "unreachable": {"unreachable": True}}


@pytest.mark.parametrize("ticket", [False, True])
@pytest.mark.parametrize("fault", list(SEALED))
def test_r4_a_sealed_or_unreachable_openbao_refuses_run_start_when_a_token_is_needed(
        tmp_path, data_root, ticket, fault):
    """The production signing path against an OpenBao answering 503 sealed (on login or sign)
    or not at all: `ConfigFault` before the lifecycle, nothing signed. The control is R3. A7."""
    _plant(data_root, proxy=("identity",))
    A.bind_issuer(data_root, S.PLAYGROUND_ID, tmp_path / "operator", role_id=ROLE, secret_id=SECRET)
    bao = A.OpenBaoStandIn({ROLE: SECRET}, **SEALED[fault])
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, ticket=ticket, issuer_transport=bao)

    assert bao.requests, "positive control: OpenBao was asked for a token"
    assert rc is None
    assert isinstance(refused, ConfigFault), refused
    assert "lifecycle" not in rec.order
    assert bao.signs == []
    assert tickets.calls == []


def test_r5_the_signing_login_is_never_taken_from_the_environment(
        tmp_path, data_root, monkeypatch):
    """With login material only in the process environment and no signer or issuer config
    file, run start refuses and nothing is sent to the address the environment names; a run's
    children still get no login variable. A1."""
    from defender.box import run_env
    from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER

    _plant(data_root, proxy=("identity",))
    with H.upstream() as vault:
        for name, value in (("VAULT_ADDR", vault.url), ("BAO_ADDR", vault.url),
                            ("VAULT_TOKEN", "env-login-1163"), ("BAO_TOKEN", "env-login-1163"),
                            ("DEFENDER_BAO_TOKEN", "env-login-1163"),
                            ("ROLE_ID", "env-role-1163"), ("SECRET_ID", "env-secret-1163")):
            monkeypatch.setenv(name, value)
        rec = S.RunRecorder(tmp_path / "run")
        alert = S.plant_alert(tmp_path / "in")
        try:
            rc, refused = S.drive_run(S.run_argv(alert, data_root), rec,
                                      proxy_url="http://proxy.invalid")
        except ConfigFault as fault:
            rc, refused = None, fault
        env = run_env(DEFENDER, tmp_path / "run")

    assert rc is None, "run start proceeded without an issuer config"
    assert refused is not None, "run start proceeded without an issuer config"
    assert vault.seen == [], "the environment's address was used"
    assert "lifecycle" not in rec.order
    assert not [k for k in env if k in ("VAULT_TOKEN", "BAO_TOKEN", "DEFENDER_BAO_TOKEN",
                                        "ROLE_ID", "SECRET_ID")]
    assert env["DEFENDER_RUN_DIR"], "positive control: the run env was built"


def test_r6_run_start_signs_with_the_tenants_own_issuer_login_and_key(tmp_path, data_root):
    """No injected signer: the read token is signed through OpenBao with the login of the
    tenant's own issuer config and its own transit key, not another bound tenant's. A11, A1."""
    _plant(data_root, proxy=("identity",))
    A.bind_issuer(data_root, S.PLAYGROUND_ID, tmp_path / "operator", role_id=ROLE, secret_id=SECRET)
    # A second tenant on the same data root, bound with its own issuer config: a run that read
    # the wrong row's login, or the wrong key, would be caught.
    S.plant(data_root, DECOY_TENANT)
    A.bind_issuer(data_root, DECOY_TENANT, tmp_path / "operator", role_id=DECOY_ROLE,
                  secret_id=DECOY_SECRET)
    bao = A.OpenBaoStandIn({ROLE: SECRET, DECOY_ROLE: DECOY_SECRET})
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, ticket=False, issuer_transport=bao)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    assert bao.logins == [(ROLE, SECRET)], "login with the tenant's own config alone"
    (sign,) = bao.signs
    assert bao.role_of(sign) == ROLE
    assert sign.key == proxy().transit_key_for(S.PLAYGROUND_ID), "the tenant's own transit key (A11)"
    assert sign.key != proxy().transit_key_for(DECOY_TENANT)
    claims = A.claims_of_payload(sign.payload)
    assert (claims["tenant"], A.grant_of(claims)) == (S.PLAYGROUND_ID, [("identity", "r")])
    assert rec.lifecycle_calls, "positive control: the run went on to its lifecycle"


def _no_binding(data_root, tmp_path):
    return None


def _binding_with_file_absent(data_root, tmp_path):
    A.bind_issuer(data_root, S.PLAYGROUND_ID, tmp_path / "operator", role_id=ROLE,
                  secret_id=SECRET).unlink()


@pytest.mark.parametrize("setup", [_no_binding, _binding_with_file_absent],
                         ids=["no forge binding", "issuer config file absent"])
def test_r7_an_http_proxy_tenant_with_no_usable_issuer_config_refuses_run_start(
        tmp_path, data_root, setup):
    """No forge binding, or a binding whose issuer config file is absent: `ConfigFault` before
    the lifecycle and no login. The control is R6. A11."""
    _plant(data_root, proxy=("identity",))
    setup(data_root, tmp_path)
    bao = A.OpenBaoStandIn({ROLE: SECRET})
    rec, tickets, rc, refused, _ = _drive(tmp_path, data_root, issuer_transport=bao)

    assert rc is None
    assert isinstance(refused, ConfigFault), refused
    assert bao.logins == []
    assert bao.signs == []
    assert "lifecycle" not in rec.order
    assert tickets.calls == []
