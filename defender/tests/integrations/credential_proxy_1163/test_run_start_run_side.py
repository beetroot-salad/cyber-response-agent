"""#1163 run side, run start: the write-back token's lifetime, the request token's absence from
every repr, and the signing login taken from the tenant's sign generation alone. Driven through `run.main`."""
from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import test_run_start_tokens as R
from defender.tests.integrations.credential_proxy_1163._target import (
    RUN_STATE_ACCESS_ATTR, request_access_type)
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S


def test_w1_each_write_back_token_expires_within_the_runs_own_ceiling(tmp_path, data_root):
    """Both ticket legs' `rw` tokens expire after the run began and within a token's lifetime
    (plus clock tolerance). A7, O8, r7 A20."""
    R._plant(data_root, proxy=("identity", "case-history"))
    signer = A.MarkedSigner()
    rec, tickets, rc, refused, started = R._drive(tmp_path, data_root, signer=signer)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    claims = [A.claims_of_payload(p) for p in signer.payloads]
    write_back = [c for c in claims if A.grant_of(c) == [("case-history", "rw")]]
    assert len(write_back) == 2, "one write-back token per ticket leg"
    for c in write_back:
        assert started < c["exp"] <= started + R.TOKEN_SEC + R.CLOCK_TOLERANCE, (
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
    assert A.SIGNATURE_CANARY in access.token(), "positive control: the access signs the token"

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


ROLE, SECRET = "role-1163-sign", "secret-1163-sign"
DELIVERY_ROLE, DELIVERY_SECRET = "role-1163-delivery", "secret-1163-delivery"
DECOY_ROLE, DECOY_SECRET = "role-1163-env", "secret-1163-env"
DECOY_ADDRESS = "https://decoy-vault.invalid:8200"


class HostRecordingBao(A.OpenBaoStandIn):
    """The OpenBao stand-in that also records the host of each request."""

    def __init__(self, *args, **kw) -> None:
        super().__init__(*args, **kw)
        self.hosts: list[str] = []
        self.origins: list[tuple[str, str, int | None]] = []

    def _handle(self, request):
        self.hosts.append(request.url.host)
        self.origins.append((request.url.scheme, request.url.host, request.url.port))
        return super()._handle(request)


def test_w3_the_signing_login_comes_from_the_sign_generation_not_the_environment_or_delivery(
        tmp_path, data_root, monkeypatch):
    """With decoy login variables set and the delivery secret file unreadable, the login and
    sign go to the deployment's address with the sign pair alone. A24, A24', A1."""
    from defender.configuration.issuer import DEPLOYMENT_ISSUER

    R._plant(data_root, proxy=("identity",))
    fields = A.generation(S.PLAYGROUND_ID, tmp_path / "secrets", sign_role_id=ROLE,
                          sign_secret=SECRET, role_id=DELIVERY_ROLE, delivery_secret=DELIVERY_SECRET,
                          delivery_file=False)
    fields["host_secret_file"].mkdir()  # the delivery file cannot be read; the signer never reads it
    records = A.Records(data_root, {S.PLAYGROUND_ID: [fields]})
    for name, value in (("VAULT_ADDR", DECOY_ADDRESS), ("BAO_ADDR", DECOY_ADDRESS),
                        ("ROLE_ID", DECOY_ROLE), ("SECRET_ID", DECOY_SECRET)):
        monkeypatch.setenv(name, value)
    bao = HostRecordingBao({ROLE: SECRET, DECOY_ROLE: DECOY_SECRET, DELIVERY_ROLE: DELIVERY_SECRET})
    rec, _tickets, rc, refused, _ = R._drive(tmp_path, data_root, ticket=False,
                                             issuer_transport=bao, directory=records.directory)

    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    R.read_access(rec).token()
    assert bao.logins == [(ROLE, SECRET)], "login with the sign pair alone"
    assert len(bao.signs) == 1, "positive control: the read token was signed"
    assert set(bao.hosts) == {urlsplit(DEPLOYMENT_ISSUER.openbao_url).hostname}, bao.hosts
    deployment = httpx.URL(DEPLOYMENT_ISSUER.openbao_url)
    assert set(bao.origins) == {(deployment.scheme, deployment.host, deployment.port)}, bao.origins
    assert deployment.scheme == "https", "positive control: the deployment's address is https"
    assert {s.mount for s in bao.signs} == {"transit"}, "the fixed transit mount (A25)"
