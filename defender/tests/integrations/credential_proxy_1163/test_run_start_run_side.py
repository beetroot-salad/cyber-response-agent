"""#1163 run side, run start: the write-back token's lifetime, the request token's absence from
every repr, and the signing login taken from the issuer file alone. Driven through `run.main`."""
from __future__ import annotations

import time

from defender.investigation.run_state import RunState
from defender.kit.access import RequestAccess
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import test_run_start_tokens as R
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

#: The longest a write-back token may outlive the leg that minted it (O10 #1163 hole 9), and the
#: seconds of clock slack between this test and the run's stamp.
LEG_LIFETIME = 3600
CLOCK_SLACK = 60


def test_w1_each_write_back_token_expires_within_the_hour_of_its_ticket_leg(
        tmp_path, data_root):
    """Both ticket legs' `rw` tokens expire after the run began and no later than an hour past
    the end of the run. A7, O8."""
    R._plant(data_root, proxy=("identity", "case-history"))
    signer = A.MarkedSigner()
    rec, tickets, rc, refused, started = R._drive(tmp_path, data_root, signer=signer)
    finished = time.time()

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    claims = [A.claims_of_payload(p) for p in signer.payloads]
    write_back = [c for c in claims if A.grant_of(c) == [("case-history", "rw")]]
    assert len(write_back) == 2, "one write-back token per ticket leg"
    for c in write_back:
        assert started < c["exp"] <= finished + LEG_LIFETIME + CLOCK_SLACK, c["exp"] - finished
    assert tickets.leg("open")["request_token"], "positive control: the legs were handed tokens"


def test_w2_the_runs_request_access_shows_no_token_in_any_repr(tmp_path, data_root):
    """The proxy address and read token the run hands its lifecycle show the address but not the
    token in a repr, and neither does the run state holding it. O10, A7."""
    R._plant(data_root, proxy=("identity",))
    signer = A.MarkedSigner()
    rec, _tickets, rc, refused, _ = R._drive(tmp_path, data_root, signer=signer, ticket=False)

    assert refused is None, (rc, refused)
    (life,) = rec.lifecycle_calls
    (access,) = [v for v in life.values() if isinstance(v, RequestAccess)]
    assert A.SIGNATURE_CANARY in access.token, "positive control: the access holds the signed token"
    state = RunState(tmp_path / "state", "w2")
    state.access = access
    assert state.access is access
    for shown in (repr(access), str(access), repr([access]), repr(vars(state))):
        assert A.SIGNATURE_CANARY not in shown, "the request token shows in a repr (O10)"
    assert "proxy.invalid" in repr(access), "positive control: the repr shows the address"
    assert "proxy.invalid" in repr(vars(state)), "positive control: the state's fields are read"


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
