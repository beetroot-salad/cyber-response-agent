"""#1163 run side, run start: the write-back token's lifetime, the request token's absence from
every repr, and the signing login taken from the issuer file alone. Driven through `run.main`."""
from __future__ import annotations

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import test_run_start_tokens as R
from defender.tests.integrations.credential_proxy_1163._target import (
    RUN_STATE_ACCESS_ATTR, request_access_type)
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S


def test_w1_each_write_back_token_expires_within_the_runs_own_ceiling(tmp_path, data_root):
    """Both ticket legs' `rw` tokens expire after the run began and no later than the run's own
    ceiling (budget + grace + margin + clock tolerance): a ticket leg cannot outlive its run.
    A7, A15, O8."""
    R._plant(data_root, proxy=("identity", "case-history"))
    signer = A.MarkedSigner()
    rec, tickets, rc, refused, started = R._drive(tmp_path, data_root, signer=signer)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    claims = [A.claims_of_payload(p) for p in signer.payloads]
    write_back = [c for c in claims if A.grant_of(c) == [("case-history", "rw")]]
    assert len(write_back) == 2, "one write-back token per ticket leg"
    for c in write_back:
        assert started < c["exp"] <= started + R.BUDGET + R.MARGIN + R.CLOCK_TOLERANCE, (
            c["exp"] - started)
    assert tickets.leg("open")["request_token"], "positive control: the legs were handed tokens"


def test_w2_the_runs_request_access_shows_no_token_in_any_repr(tmp_path, data_root):
    """Through the real run, no repr or str of anything the run hands its lifecycle (the access,
    the run state holding it, every argument) shows the request token; the address shows. O10, A7."""
    R._plant(data_root, proxy=("identity",))
    signer = A.MarkedSigner()
    rec, _tickets, rc, refused, _ = R._drive(tmp_path, data_root, signer=signer, ticket=False)

    assert refused is None, (rc, refused)
    (life,) = rec.lifecycle_calls
    access_type = request_access_type()
    (access,) = [v for v in life.values() if isinstance(v, access_type)]
    assert A.SIGNATURE_CANARY in access.token, "positive control: the access holds the signed token"

    shown: list[str] = []
    for held in life.values():
        shown += [repr(held), str(held)]
        if hasattr(held, "__dict__") and held is not access:  # the access holds the token itself
            shown.append(repr(vars(held)))
    run = life["run"]
    snapshot = getattr(run, RUN_STATE_ACCESS_ATTR, None)
    shown += [repr(snapshot), repr([snapshot])]
    for text in shown:
        assert A.SIGNATURE_CANARY not in text, "the request token shows in a repr (O10)"
    assert any("proxy.invalid" in text for text in shown), "positive control: the address shows"


ROLE, SECRET = "role-1163-file", "secret-1163-file"
DECOY_ROLE, DECOY_SECRET = "role-1163-env", "secret-1163-env"
DECOY_ADDRESS = "https://decoy-vault.invalid:8200"
FILE_HOST = "openbao.test"  # the host `A.bind_issuer` writes into the issuer client config


class HostRecordingBao(A.OpenBaoStandIn):
    """The OpenBao stand-in that also records the host of each request."""

    def __init__(self, *args, **kw) -> None:
        super().__init__(*args, **kw)
        self.hosts: list[str] = []

    def _handle(self, request):
        self.hosts.append(request.url.host)
        return super()._handle(request)


def test_w3_the_signing_login_and_address_come_from_the_issuer_file_not_the_environment(
        tmp_path, data_root, monkeypatch):
    """With the issuer config file valid and decoy login variables set, the login and sign go
    to the file's address with the file's pair. A1, P-4."""
    R._plant(data_root, proxy=("identity",))
    A.bind_issuer(data_root, S.PLAYGROUND_ID, tmp_path / "operator", role_id=ROLE,
                  secret_id=SECRET)
    for name, value in (("VAULT_ADDR", DECOY_ADDRESS), ("BAO_ADDR", DECOY_ADDRESS),
                        ("ROLE_ID", DECOY_ROLE), ("SECRET_ID", DECOY_SECRET)):
        monkeypatch.setenv(name, value)
    bao = HostRecordingBao({ROLE: SECRET, DECOY_ROLE: DECOY_SECRET})
    rec, _tickets, rc, refused, _ = R._drive(tmp_path, data_root, ticket=False,
                                             issuer_transport=bao)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    assert bao.logins == [(ROLE, SECRET)], "login with the file's pair alone"
    assert len(bao.signs) == 1, "positive control: the read token was signed"
    assert set(bao.hosts) == {FILE_HOST}, bao.hosts
