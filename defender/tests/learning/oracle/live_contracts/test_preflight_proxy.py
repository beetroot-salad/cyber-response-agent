"""#1163 learning preflight reaches an `http-proxy` system through the proxy with the run's read grant
(#1363 O2, D5: every granted, declared system not judged down), signing as a run does (#1363 O1), and a working-tree base that differs from `current`
is refused by the proxy with nothing sent outside the merged declaration (A3). Pre-flight reads
live only a call the source run's capture holds no answer for (#1385 H6), so the idp call here is a
captured failure."""
from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import pytest

from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import ACCESS_FILE, proxy
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.learning.oracle.live_contracts.test_preflight_and_outcome import (
    _capture_row,
)
from defender.tests.tenancy.tenant_1108_p4._support import default_secrets_dir, published_tenant

pytestmark = pytest.mark.e2e

API = "/api"
#: The clock slack between the test's clock and the pass's.
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
    return transport.request(ctx, "idp", "GET", "/events", query={"q": q},
                             timeout_sec=transport.timeout_of(config))


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


#: A granted, declared system whose adapter's settings check fails: judged down, so outside the
#: run's read grant (#1363 O2, D5).
HR_DOWN_ADAPTER = IDP_ADAPTER.replace(
    "def check_settings(*_a, **_k):\n    return None\n",
    "def check_settings(*_a, **_k):\n    raise faults.ConfigFault(\"HR_TIMEOUT_SEC is not set\")\n",
).replace("from defender.kit import transport\n", "from defender.kit import faults, transport\n")
#: #1363 O1: a request token's life, and the life a held one must have left to be reused.
TOKEN_SEC, REUSE_MARGIN_SEC = 600, 60
assert "ConfigFault" in HR_DOWN_ADAPTER, "the down adapter's check must raise"


class Clock:
    """The pass's holder clock (seconds since the epoch), moved only by the test. It starts at real
    time, so every token it dates is still unexpired at the real proxy."""

    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now


@dataclass
class Rig:
    est: S.Estate
    calls: list
    idp: S.Call
    t: Any
    records: Any
    bao: A.OpenBaoStandIn
    store: H.FakeStore
    merged: H.Upstream
    wt: H.Upstream
    after_source: Any


@contextlib.contextmanager
def rig(tmp_path, monkeypatch, data_root, *, working_tree_edit: bool = False,  # noqa: PLR0913
        env_url: str | None = None, credential_set: bool = True) -> Iterator[Rig]:
    """The fixture tenant with `idp` and `crm` (granted, declared, never called by the source run)
    on the credential proxy, `hr` granted and declared but judged down, and the OpenBao stand-in
    that signs with the live generation's sign login. Yields before any launch."""
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    if env_url is not None:  # operator OpenBao/Vault login material in the launcher's environment
        for name, value in (("VAULT_ADDR", env_url), ("BAO_ADDR", env_url),
                            ("VAULT_TOKEN", "env-token-1163"), ("BAO_TOKEN", "env-token-1163")):
            monkeypatch.setenv(name, value)
    est = S.estate(tmp_path, systems=(*S.SYSTEMS, "crm", "hr"))
    (est.adapters / "idp_adapter.py").write_text(IDP_ADAPTER, encoding="utf-8")
    (est.adapters / "hr_adapter.py").write_text(HR_DOWN_ADAPTER, encoding="utf-8")
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
                 # host-state reads no key, so it ships no config.env to remove (#1391 r5 O-S1).
                 **{f"settings/systems/{s}/config.env": None for s in FIXTURE_SYSTEMS
                    if s != "host-state"},
                 **A.system_files("idp", H.declaration(merged.url + API)),
                 # Granted for gather and declared, never called by the source run: the run's read
                 # grant reaches it (D5), H12's "systems the replayed calls reach" did not.
                 **A.system_files("crm", H.declaration(merged.url + "/crm")),
                 **A.system_files("hr", H.declaration(merged.url + "/hr"))}
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
            bao = A.OpenBaoStandIn({ROLE: SECRET, DELIVERY_ROLE: DELIVERY_SECRET})
            store = H.FakeStore({(S.FIXTURE_TENANT, "idp"): T.static_set()} if credential_set else {})
            # No second records read inside learning (A24): one through the environment's
            # database would meet an unreachable server, not a records source.
            monkeypatch.setenv("DEFENDER_DATABASE_DSN",
                               "postgresql://poison:poison@127.0.0.1:1/poisoned1163")
            yield Rig(est=est, calls=calls, idp=idp, t=t, records=records, bao=bao, store=store,
                      merged=merged, wt=wt, after_source=capture_idp_failure)


def _preflight(tmp_path, monkeypatch, data_root, *, working_tree_edit: bool = False,  # noqa: PLR0913
               env_url: str | None = None, proxy_address: bool = True, oracle: Any = None,
               unreachable_proxy: bool = False, credential_set: bool = True,
               on_read: Any = None, **seams: Any):
    """One launch through pre-flight over `rig`. `on_read(rig)` runs as the merged upstream serves
    each idp read; `unreachable_proxy` hands the launcher an address nothing listens at."""
    with rig(tmp_path, monkeypatch, data_root, working_tree_edit=working_tree_edit, env_url=env_url,
             credential_set=credential_set) as r:
        if on_read is not None:
            body = r.merged.replies[f"{API}/events"]

            def reply(_seen):
                on_read(r)
                return body
            r.merged.replies[f"{API}/events"] = reply
        with A.proxy_for(r.t, r.store) as (url, tap):
            address = (f"http://127.0.0.1:{H.free_port()}" if unreachable_proxy
                       else url if proxy_address else None)
            run = S.launch(tmp_path, r.est, calls=r.calls, oracle=oracle if oracle is not None else S.oracle(
                then=S.submit(r.idp.payload, S.EMPTY_CLAIM)),
                verifier=S.passing_verifier(), issuer_transport=r.bao, proxy_url=address,
                directory=r.records, after_source=r.after_source, **seams)
        outcome = S.read_outcome(run.ep)
    return run, outcome, r.bao, tap, r.merged, r.wt


def test_p1_preflight_reads_idp_through_the_proxy_with_the_runs_read_grant(
        tmp_path, monkeypatch, data_root):
    """Served by the merged base; the token grants `r` on every granted, declared system not judged
    down (crm too, never called; not hr), lives one run token's life, and is signed with the live
    generation's sign login and the tenant's key; no token in children. #1363 O1, O2/D5; A7, A11, A24, O10."""
    asked = time.time()
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
    assert (claims["tenant"], A.grant_of(claims)) == (S.FIXTURE_TENANT, [("crm", "r"), ("idp", "r")]), (
        "the run's read grant: crm (granted, declared, never called) in; hr (judged down) out")
    (source_run,) = (p for p in (data_root / S.FIXTURE_TENANT / "runs").iterdir() if p.is_dir())
    assert claims["investigation"] == source_run.name, "the token names the source run"
    assert asked + TOKEN_SEC - 1 <= claims["exp"] <= finished + TOKEN_SEC + CLOCK_TOLERANCE, (
        "a pre-flight token lives a run token's life (O1)", claims["exp"] - asked)
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
    assert bao.signs, "positive control: a token was signed"
    assert {bao.role_of(sign) for sign in bao.signs} == {ROLE}, "every sign by the sign login (O1)"
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
    assert outcome["outcome"] == "accepted", ("a `request` fault is skipped and the pass goes on (#1363 N1)", outcome)
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


# --- #1363: pre-flight signs as a run does, and stops on our own failures ---------------------------


def _side_lookups(*qs: str) -> S.ScriptedModel:
    """An oracle whose first requests (any world's) each look idp up through the door, then submit."""
    return S.oracle(*[S.run_query("idp", "query", S.query_params(q)) for q in qs],
                    then=S.submit(S.default_calls()[0].payload, S.EMPTY_CLAIM))


def _sign_requests(bao: A.OpenBaoStandIn) -> int:
    return sum(1 for path in bao.requests if "/sign/" in path)


def test_p1c_a_pass_longer_than_a_token_s_life_signs_again_on_demand_and_reuses_otherwise(
        tmp_path, monkeypatch, data_root):
    """The live read signs at T; the holder clock then moves to T+541 (59 s left, under the 60 s
    margin), so the next proxied read signs a fresh 600 s token, which the read after it reuses.
    #1363 O1."""
    clock = Clock()
    start = clock.now

    def first_read_takes_541_s(_r: Rig) -> None:
        if clock.now == start:
            clock.now = start + TOKEN_SEC - REUSE_MARGIN_SEC + 1

    run, outcome, bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, oracle=_side_lookups("user:bob", "user:carol"),
        on_read=first_read_takes_541_s, clock=clock)
    assert run.rc == 0, run.message
    assert outcome["outcome"] == "accepted", outcome
    assert len(merged.seen) == 3, "positive control: the live read and both lookups reached the system"
    exps = [A.claims_of_payload(sign.payload)["exp"] for sign in bao.signs]
    assert len(exps) == 2, ("one sign at first need, one when too little life was left", exps)
    assert abs(exps[0] - (start + TOKEN_SEC)) <= 1, exps[0] - start
    assert abs(exps[1] - (start + TOKEN_SEC - REUSE_MARGIN_SEC + 1 + TOKEN_SEC)) <= 1, exps[1] - start
    first, second = tap.tokens[0], tap.tokens[1]
    assert first != second
    assert tap.tokens == [first, second, second], "a token with more than 60 s left is reused"


def test_p4_a_re_sign_that_fails_mid_calibration_refuses_the_pass_as_the_environments(
        tmp_path, monkeypatch, data_root):
    """OpenBao fails the re-sign a lookup needs: access is lost, the pass is `refused` naming the
    credential proxy, lists no unservable world, and nothing is signed or sent after it. #1363 O5, O6."""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    clock = Clock()
    start = clock.now

    def openbao_down_after_the_first_read(r: Rig) -> None:
        if clock.now == start:
            clock.now = start + TOKEN_SEC  # the held token has no life left
            r.bao.sign_status = 503

    run, outcome, bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, oracle=_side_lookups("user:bob", "user:carol"),
        on_read=openbao_down_after_the_first_read, clock=clock)
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", outcome
    assert "credential proxy" in outcome["reason"], outcome["reason"]
    assert outcome["unservable_worlds"] == [], "our own failure made a world unservable"
    assert len(bao.signs) == 1, "positive control: the first token was signed"
    assert _sign_requests(bao) == 2, "the failed re-sign was retried, or a later request signed again"
    assert len(tap.tokens) == 1, "a call reached the proxy after access was lost"
    assert len(merged.seen) == 1


def test_p5_a_proxy_unreachable_during_the_live_reads_refuses_the_pass_before_calibration(
        tmp_path, monkeypatch, data_root):
    """No proxy at the handed address: the live read is an `access` fault, so the pass is `refused`
    naming the credential proxy, no unservable world, and calibration never starts (the oracle is
    never asked). Today it reads `accepted` (G25). #1363 O6, D2."""
    oracle = S.oracle(then=S.submit(S.default_calls()[0].payload, S.EMPTY_CLAIM))
    run, outcome, bao, _tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, oracle=oracle, unreachable_proxy=True)
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", ("our failure is never evidence (G25)", outcome)
    assert "credential proxy" in outcome["reason"], outcome["reason"]
    assert outcome["unservable_worlds"] == []
    assert oracle.answered == 0, "calibration started after access was lost in the live-read loop"
    assert bao.signs, "positive control: the token was signed, the proxy was what failed"
    assert merged.seen == []


def test_p6_no_credential_set_for_the_read_system_refuses_the_pass_naming_it(
        tmp_path, monkeypatch, data_root):
    """No credential set stored for idp: the live read is a `setup` fault, so the pass is `refused`
    naming our setup for idp, with no unservable world and nothing sent. #1363 O4, O6."""
    run, outcome, _bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, credential_set=False)
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", outcome
    assert "idp" in outcome["reason"] and "setup" in outcome["reason"].lower(), outcome["reason"]
    assert outcome["unservable_worlds"] == []
    assert tap.tokens, "positive control: the proxy was asked"
    assert merged.seen == []
