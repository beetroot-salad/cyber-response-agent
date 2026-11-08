"""#1163 learning preflight reaches an `http-proxy` system through the proxy with a read grant on
the source run's http-proxy systems (H12), and a working-tree base that differs from `current`
is refused by the proxy with nothing sent outside the merged declaration (A3). Pre-flight reads
live only a call the source run's capture holds no answer for (#1385 H6), so the idp call here is a
captured failure."""
from __future__ import annotations

import json
import time
from urllib.parse import urlencode

import pytest

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import ACCESS_FILE, proxy
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.learning.oracle.live_contracts.test_1224_preflight_and_outcome import (
    _capture_row,
)
from defender.tests.tenancy.tenant_1108_p4._support import default_secrets_dir, published_tenant

pytestmark = pytest.mark.e2e

API = "/api"
# bound pending design amendment (preflight token lifetime)
#: Longest a preflight read token may live (one pass of live reads), and the clock slack.
PREFLIGHT_LIFETIME = 3600
CLOCK_TOLERANCE = 60
ROLE, SECRET = "role-1163-learning", "secret-1163-learning"
DELIVERY_ROLE, DELIVERY_SECRET = "role-1163-delivery", "secret-1163-delivery"
FIXTURE_SYSTEMS = ("identity", "ticket", "host-state", "threat-intel", "change-mgmt",
                   "elastic", "cmdb")
#: `idp` is a tenant-only name: no product allowlist knows it (A6). Its `query` goes through the
#: shared transport; its other verbs answer locally.
IDP_ADAPTER = '''\
from defender.kit import transport
from defender.kit.verbs import VerbContext, verb


def check_settings(*_a, **_k):
    return None


@verb()
def query(ctx: VerbContext, *, q: str = "*", start: str = "", end: str = "",
          limit: int = 50) -> dict:
    config = transport.load_config(ctx, "idp", "IDP")
    return transport.http_get(ctx, config, "/events", system="idp", params={"q": q})


@verb()
def lookup(ctx: VerbContext, *, entity: str) -> dict:
    return {}


@verb()
def health_check(ctx: VerbContext) -> dict:
    return {}


@verb(verb_class="rw")
def isolate(ctx: VerbContext, *, host: str) -> dict:
    return {}


VERBS = {"query": query, "lookup": lookup, "health-check": health_check, "isolate": isolate}
'''


def _preflight(tmp_path, monkeypatch, data_root, *, working_tree_edit: bool, env_url: str | None = None,  # noqa: PLR0913
               proxy_address: bool = True):
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    if env_url is not None:  # operator OpenBao/Vault login material in the launcher's environment
        for name, value in (("VAULT_ADDR", env_url), ("BAO_ADDR", env_url),
                            ("VAULT_TOKEN", "env-token-1163"), ("BAO_TOKEN", "env-token-1163")):
            monkeypatch.setenv(name, value)
    est = S.estate(tmp_path)
    (est.adapters / "idp_adapter.py").write_text(IDP_ADAPTER, encoding="utf-8")
    idp = [c for c in S.default_calls() if c.system == "idp"][0]
    # Every call answers with the idp rows, so the one scripted submission is true of all three
    # (calibrating edr or siem-x against another system's rows would fail the family). The idp
    # call is a captured failure, so it has no recording and pre-flight reads it live (H6).
    calls = [S.Call(c.system, c.verb, c.params, idp.payload) for c in S.default_calls()
             if c.system != "idp"]

    def capture_idp_failure(src) -> None:
        _capture_row(src, system="idp", verb=idp.verb, params=idp.params, seq=60, exit_code=1,
                     payload={"error": "upstream said no"})

    with H.upstream() as merged, H.upstream() as wt:
        merged.replies[f"{API}/events"] = (200, {"Content-Type": "application/json"},
                                           json.dumps(idp.payload).encode())
        files = {"settings/verb-grants.yaml": est.table(),
                 **{f"settings/systems/{s}/config.env": None for s in FIXTURE_SYSTEMS},
                 **A.system_files("idp", H.declaration(merged.url + API)),
                 # Another http-proxy system the source run never called: the grant must not reach it.
                 **A.system_files("crm", H.declaration(merged.url + "/crm"))}
        with published_tenant(tmp_path / "forge", root=data_root, tenant_id=S.FIXTURE_TENANT,
                              files=files) as t:
            if working_tree_edit:  # an unmerged edit in the clone's working tree (C28, C34)
                (t.clone / ACCESS_FILE.format(system="idp")).write_text(
                    H.declaration(wt.url + API), encoding="utf-8")
            # The launcher signs in-process with the live generation's sign login, read from the
            # episode's records it passes in as `directory=` (A24); the delivery file is absent
            # (the signer never reads it). No signer is injected, the OpenBao stand-in is the transport.
            fields = A.generation(S.FIXTURE_TENANT, default_secrets_dir(t), sign_role_id=ROLE,
                                  sign_secret=SECRET, role_id=DELIVERY_ROLE,
                                  delivery_secret=DELIVERY_SECRET, delivery_file=False)
            records = t.directory_with(generations=[fields])
            bao, tap_holder = A.OpenBaoStandIn({ROLE: SECRET, DELIVERY_ROLE: DELIVERY_SECRET}), {}
            store = H.FakeStore({(S.FIXTURE_TENANT, "idp"): T.static_set()})
            # No second records read inside learning (A24): one through the environment's
            # database would meet an unreachable server, not a records source.
            monkeypatch.setenv("DEFENDER_DATABASE_DSN",
                               "postgresql://poison:poison@127.0.0.1:1/poisoned1163")
            with A.proxy_for(t, store) as (url, tap):
                tap_holder["tap"] = tap
                run = S.launch(tmp_path, est, calls=calls, oracle=S.oracle(
                    then=S.submit(idp.payload, S.EMPTY_CLAIM)),
                    verifier=S.passing_verifier(), issuer_transport=bao, proxy_url=url if proxy_address else None,
                    directory=records, after_source=capture_idp_failure)
        outcome = S.read_outcome(run.ep)
    return run, outcome, bao, tap_holder["tap"], merged, wt


def test_p1_preflight_reads_idp_through_the_proxy_with_a_read_grant_on_http_proxy_systems(
        tmp_path, monkeypatch, data_root):
    """Control: served by the merged base, read grant on idp alone, signed with the live
    generation's sign login (from the episode's records) and the tenant's key; no token in
    children. H12, A7, A11, A24, O10."""
    run, outcome, bao, tap, merged, wt = _preflight(
        tmp_path, monkeypatch, data_root, working_tree_edit=False)
    finished = time.time()
    assert run.rc == 0, run.message
    idp_call = [c for c in S.default_calls() if c.system == "idp"][0]
    assert merged.paths() == [f"{API}/events?{urlencode({'q': idp_call.params['q']})}"]
    assert merged.seen[0].headers.get("Authorization") == f"Bearer {H.CANARY_KEY}"
    assert bao.logins == [(ROLE, SECRET)], "the live generation's sign login, not its delivery login"
    (sign,) = bao.signs
    assert bao.role_of(sign) == ROLE
    assert sign.key == proxy().transit_key_for(S.FIXTURE_TENANT), "the tenant's own transit key (A11)"
    claims = A.claims_of_payload(sign.payload)
    assert (claims["tenant"], A.grant_of(claims)) == (S.FIXTURE_TENANT, [("idp", "r")])
    (source_run,) = (p for p in (data_root / S.FIXTURE_TENANT / "runs").iterdir() if p.is_dir())
    assert claims["investigation"] == source_run.name, "the token names the source run"
    assert claims["exp"] <= finished + PREFLIGHT_LIFETIME + CLOCK_TOLERANCE, "an unbounded token"
    assert claims["exp"] > finished, "positive control: the expiry is a time still to come"
    assert tap.tokens
    assert all(A.SIGNATURE_CANARY in tok for tok in tap.tokens)
    assert "drift" not in outcome
    assert wt.seen == []
    # O10: curators and the author carry no token or signature in argv or env.
    assert run.spawn.launches, "positive control: children were spawned"
    for launch in run.spawn.launches:
        assert A.SIGNATURE_CANARY not in " ".join(launch["argv"])
        assert A.SIGNATURE_CANARY not in "\n".join(f"{k}={v}" for k, v in launch["env"].items())
        assert not [t for t in tap.tokens if t in " ".join(launch["argv"]) + str(launch["env"])]


def test_p1b_preflight_signs_with_the_sign_login_whatever_the_environment_holds(
        tmp_path, monkeypatch, data_root):
    """Operator OpenBao/Vault tokens and addresses in the environment: pre-flight still signs its read
    token with the live generation's sign login through its issuer transport; the environment's
    address sees nothing. A1/A24 (the signing login is never taken from the environment)."""
    with H.upstream() as canary:
        run, _outcome, bao, tap, _merged, _wt = _preflight(
            tmp_path, monkeypatch, data_root, working_tree_edit=False, env_url=canary.url)
    assert run.rc == 0, run.message
    assert canary.seen == [], "the environment's address was used"
    assert bao.logins == [(ROLE, SECRET)]
    assert len(bao.signs) == 1
    assert set(bao.origins) == {A.deployment_origin()}, "the sign login and sign went to the deployment's address (A1)"
    assert tap.tokens
    assert all(A.SIGNATURE_CANARY in tok for tok in tap.tokens)


def test_p2_a_working_tree_base_that_differs_from_current_is_refused_and_sent_nowhere(
        tmp_path, monkeypatch, data_root):
    """The proxy refuses the working tree's base (it applies `current`); the idp call's live read
    fails without making a world unservable, and neither upstream is reached. A3, O2."""
    run, outcome, bao, tap, merged, wt = _preflight(
        tmp_path, monkeypatch, data_root, working_tree_edit=True)
    assert outcome is not None, run.message  # the outcome is written before any sibling
    assert outcome["unservable_worlds"] == [], "the failed live read made a world unservable"
    assert tap.tokens, "positive control: the proxy was asked"
    assert merged.seen == []
    assert wt.seen == []


def test_p3_preflight_with_no_proxy_address_is_refused_once_and_contacts_no_openbao(tmp_path, monkeypatch, data_root):
    """With no credential proxy address (none handed, none in the environment), pre-flight is REFUSED naming the missing
    setting, as run start refuses, before any OpenBao login or sign and before any replayed call. A20, A24', H12."""
    from defender.kit.access import PROXY_URL_ENV
    monkeypatch.delenv(PROXY_URL_ENV, raising=False)
    run, outcome, bao, tap, merged, _wt = _preflight(tmp_path, monkeypatch, data_root, working_tree_edit=False,
                                                     proxy_address=False)
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", outcome
    assert PROXY_URL_ENV in outcome["reason"], outcome["reason"]
    assert (bao.logins, bao.signs) == ([], [])
    assert tap.tokens == []
    assert merged.seen == []
