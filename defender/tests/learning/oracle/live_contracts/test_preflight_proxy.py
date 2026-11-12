"""#1163 learning preflight reaches an `http-proxy` system through the proxy with the run's read grant
(#1363 O2, D5: every granted, declared system not judged down), signing as a run does (#1363 O1), and a working-tree base that differs from `current`
is refused by the proxy with nothing sent outside the merged declaration (A3). Pre-flight reads
live only a call the source run's capture holds no answer for (#1385 H6), so the idp call here is a
captured failure."""
from __future__ import annotations

import contextlib
import json
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
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


#: `IDP_ADAPTER` whose lookup of `user:bob` (the oracle's side query) outlives the oracle's turn deadline: it waits
#: for the pass's outcome file (the glob in `LATE_OUTCOME`), then asks once more (`q=late`) and writes how that ended
#: to the file `LATE_RESULT` names: `waited-out` when the outcome never appeared, else `sent` or `raised:<class>`.
LATE_IDP_ADAPTER = IDP_ADAPTER.replace(
    '''    return transport.request(ctx, "idp", "GET", "/events", query={"q": q},
                             timeout_sec=transport.timeout_of(config))
''',
    '''    answer = transport.request(ctx, "idp", "GET", "/events", query={"q": q},
                               timeout_sec=transport.timeout_of(config))
    if q == "user:bob":
        import glob
        import os
        import pathlib
        import time

        give_up = time.monotonic() + 40
        while not glob.glob(os.environ["LATE_OUTCOME"]) and time.monotonic() < give_up:
            time.sleep(0.05)
        if not glob.glob(os.environ["LATE_OUTCOME"]):
            seen = "waited-out"
        else:
            try:
                transport.request(ctx, "idp", "GET", "/events", query={"q": "late"},
                                  timeout_sec=transport.timeout_of(config))
                seen = "sent"
            except BaseException as raised:
                seen = "raised:" + type(raised).__name__
        pathlib.Path(os.environ["LATE_RESULT"]).write_text(seen, encoding="utf-8")
    return answer
''')
assert LATE_IDP_ADAPTER != IDP_ADAPTER, "the late adapter must differ"


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


class ScriptedBao(A.OpenBaoStandIn):
    """The OpenBao stand-in whose sign requests follow `sign_script` in order, each `(delay_sec, status)`: it
    waits `delay_sec`, then answers `status` (an error) or, for `None`, as the stand-in does. Once the
    script is spent every sign answers normally. Every request path is recorded, as the stand-in's are."""

    def __init__(self, *args: Any, **kw: Any) -> None:
        super().__init__(*args, **kw)
        self.sign_script: list[tuple[float, int | None]] = []
        self._scripting = threading.Lock()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if "/sign/" in request.url.path:
            with self._scripting:
                step = self.sign_script.pop(0) if self.sign_script else None
            if step is not None:
                delay, status = step
                time.sleep(delay)
                if status is not None:
                    self.requests.append(request.url.path)
                    return httpx.Response(status, json={"errors": ["sign failed"]})
                return super().handle_request(request)
        return super().handle_request(request)


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
        env_url: str | None = None, credential_set: bool = True, source: str = "idp",
        sign_login: bool = True, bao_type: type = A.OpenBaoStandIn, idp_adapter: str = IDP_ADAPTER) -> Iterator[Rig]:
    """The fixture tenant with `idp` and `crm` (granted, declared, never called by the source run)
    on the credential proxy, `hr` granted and declared but judged down, and the OpenBao stand-in
    that signs with the live generation's sign login. Yields before any launch. `source` is what the
    source run called through the proxy: `idp` (a captured failure, read live), `idp2` (two such
    failures), or `unproxied` (nothing proxied: only the other systems)."""
    S.T.isolate_learning_state(tmp_path, monkeypatch)
    if env_url is not None:  # operator OpenBao/Vault login material in the launcher's environment
        for name, value in (("VAULT_ADDR", env_url), ("BAO_ADDR", env_url),
                            ("VAULT_TOKEN", "env-token-1163"), ("BAO_TOKEN", "env-token-1163")):
            monkeypatch.setenv(name, value)
    # A root of its own per rig: the process caches an adapter module by its resolved path
    # (`systems.verbs._MODULES`), and pytest reuses a finished test's `tmp_path` name, so an earlier row's
    # stub `idp` adapter at the same path would answer in place of the proxy-using one written here.
    est = S.estate(tmp_path / uuid.uuid4().hex, systems=(*S.SYSTEMS, "crm", "hr"))
    (est.adapters / "idp_adapter.py").write_text(idp_adapter, encoding="utf-8")
    (est.adapters / "hr_adapter.py").write_text(HR_DOWN_ADAPTER, encoding="utf-8")
    idp = [c for c in S.default_calls() if c.system == "idp"][0]
    # Every call answers with the idp rows, so the one scripted submission is true of all three
    # (calibrating edr or siem-x against another system's rows would fail the family). The idp
    # call is a captured failure, so it has no recording and pre-flight reads it live (H6).
    calls = [S.Call(c.system, c.verb, c.params, idp.payload) for c in S.default_calls()
             if c.system != "idp"]

    def capture_idp_failure(src) -> None:
        failed = {"idp": [idp.params], "idp2": [idp.params, S.query_params("user:zed")]}.get(source, [])
        for seq, params in enumerate(failed, start=60):
            _capture_row(src, system="idp", verb=idp.verb, params=params, seq=seq, exit_code=1,
                         payload={"error": "upstream said no"})

    with H.upstream() as merged, H.upstream() as wt:
        merged.replies[f"{API}/events"] = (200, {"Content-Type": "application/json"},
                                           json.dumps(idp.payload).encode())
        files = {"settings/verb-grants.yaml": est.table(),
                 # #1366 O9: the fixture ships no `settings/systems/` (its folders are retired), so there is none to remove;
                 # the tenant's records are idp and crm alone, derived from the files planted below (crm is in the roster
                 # above and in no grant).
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
            if not sign_login:  # a live generation that records no sign login (A24')
                fields["sign_role_id"] = None
            # The tenant's records: the estate's stub systems (their calls replay), with idp, crm and hr as the files
            # planted above stand for them (each with its access declaration, so on the proxy).
            from defender.tests.support.tenancy import _systems1366 as R

            planted = R.resolve(R.DERIVED, data_root, S.FIXTURE_TENANT)
            records = t.directory_with(generations=[fields], records=R.RecordsSpec(
                {**est.records().systems, **planted.systems}, planted.case))
            bao = bao_type({ROLE: SECRET, DELIVERY_ROLE: DELIVERY_SECRET})
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
               on_read: Any = None, source: str = "idp", sign_login: bool = True,
               bao_type: type = A.OpenBaoStandIn, sign_script: Any = (), idp_adapter: str = IDP_ADAPTER,
               settle: Any = None, **seams: Any):
    """One launch through pre-flight over `rig`. `on_read(rig)` runs as the merged upstream serves
    each idp read; `unreachable_proxy` hands the launcher an address nothing listens at;
    `sign_script` (a `ScriptedBao`'s) shapes the sign requests in order; `settle(run, tap)` runs
    once the launch has returned, while the proxy is still being served."""
    with rig(tmp_path, monkeypatch, data_root, working_tree_edit=working_tree_edit, env_url=env_url,
             credential_set=credential_set, source=source, sign_login=sign_login,
             bao_type=ScriptedBao if sign_script else bao_type, idp_adapter=idp_adapter) as r:
        if sign_script:
            r.bao.sign_script = list(sign_script)
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
            if settle is not None:
                settle(run, tap)
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


def test_p2_a_working_tree_base_that_differs_from_current_is_never_read_by_preflight(
        tmp_path, monkeypatch, data_root):
    """An unmerged edit of the idp declaration in the clone's working tree reaches nothing: pre-flight reads the tenant's
    CURRENT records (H9, A5, O6: every replay uses the current records, never the working tree), so the idp call's live
    read goes to the current base through the proxy, and the working tree's upstream is never reached. A3, O2.
    (Was: the adapter's record was the working tree and the proxy refused its base. Under #1366 preflight has no working
    tree record; what stays pinned is that the edit is not obeyed.)"""
    run, outcome, bao, tap, merged, wt = _preflight(
        tmp_path, monkeypatch, data_root, working_tree_edit=True)
    assert outcome is not None, run.message  # the outcome is written before any sibling
    assert outcome["unservable_worlds"] == [], "the failed live read made a world unservable"
    assert outcome["outcome"] == "accepted", ("a `request` fault is skipped and the pass goes on (#1363 N1)", outcome)
    assert tap.tokens, "positive control: the proxy was asked"
    assert len(merged.seen) == 1, "the idp read went to the current base, once"
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


#: How long a held oracle request waits for the failing world's retry (seconds); far under the turn deadline.
HOLD_SEC = 60
CALIBRATED_WORLDS = ("b", "c")


class HeldOracle(S.ScriptedModel):
    """An oracle double that answers its first request (the scripted lookup) at once and holds every other request
    until one carrying a failed attempt's note arrives: the failing world's retry, which follows the fault and so the
    latch. No other world is then ahead of the latch, whatever the thread timing."""

    def __init__(self, *moves: S.Move, then: S.Move | None = None) -> None:
        super().__init__(*moves, then=then, name="oracle")
        self._order = threading.Lock()
        self._begun = False
        self.retried = threading.Event()

    def __call__(self, messages: list[Any], info: Any) -> Any:
        noted = "Attempt failed" in str(messages)
        with self._order:
            first, self._begun = not self._begun, True
        if noted:
            self.retried.set()
        elif not first:
            self.retried.wait(HOLD_SEC)
        return super().__call__(messages, info)


def _one_failing_lookup() -> HeldOracle:
    """Exactly one lookup, answered first; every later request submits."""
    return HeldOracle(S.run_query("idp", "query", S.query_params("user:bob")),
                      then=S.submit(S.default_calls()[0].payload, S.EMPTY_CLAIM))


def _calls_per_world(ep: Any) -> dict[str, int]:
    """The calls each calibrated world began, from its own oracle ledger's pre-flight rows."""
    return {w: sum(1 for r in S.oracle_rows(ep, w, "ledger") if r.get("actor") == "preflight")
            for w in CALIBRATED_WORLDS}


def _healthy_pass(tmp_path, monkeypatch, data_root, **kw: Any) -> tuple[int, dict[str, int]]:
    """The same pass with the same retry cap and one lookup, nothing failing: `(oracle turns, calls per world)`.
    Every world runs every call (a positive control for the bound the failing passes are held to)."""
    oracle = _side_lookups("user:bob")
    (tmp_path / "healthy").mkdir()
    run, outcome, *_rest = _preflight(tmp_path / "healthy", monkeypatch, data_root, oracle=oracle, **kw)
    assert outcome is not None, ("positive control: the healthy pass", run.message)
    assert outcome["outcome"] == "accepted", ("positive control: the healthy pass", run.message)
    calls = _calls_per_world(run.ep)
    assert len(set(calls.values())) == 1, ("positive control: every world ran every call", calls)
    assert min(calls.values()) >= 2, ("positive control: every world ran every call", calls)
    assert oracle.requests == len(calls) * min(calls.values()) + 1, "positive control: one turn per call, one more for the lookup"
    return oracle.requests, calls


def _no_world_went_on(run: Any, oracle: HeldOracle, healthy: tuple[int, dict[str, int]]) -> None:
    """After the one failed lookup (retry cap 2, so a failed world's retry would succeed and, without a stop, every
    world would run every call): no world began a second call, and the oracle took no more turns than the failing
    world's retry plus one first call for each other world. The retry itself is the design's accepted limit."""
    healthy_turns, healthy_calls = healthy
    calls = _calls_per_world(run.ep)
    assert max(calls.values()) <= 1, ("a world started another call after access was lost or setup failed (O6)",
                                       calls, healthy_calls)
    assert oracle.requests <= len(calls) + 1, ("a world went on asking the oracle after the latch (O6)",
                                               oracle.requests, healthy_turns)
    asked = oracle.requests
    time.sleep(0.5)
    assert oracle.requests == asked, "the oracle was asked again after the outcome"


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
    """A failed mid-pass re-sign loses access: `refused` naming the proxy, no unservable world, nothing signs again,
    and no world begins a second call. #1363 O5, O6, D8"""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "2")
    healthy = _healthy_pass(tmp_path, monkeypatch, data_root)
    clock = Clock()
    start = clock.now

    def first_read_leaves_no_life(_r: Rig) -> None:
        if clock.now == start:
            clock.now = start + TOKEN_SEC  # the held token has no life left

    lost = _one_failing_lookup()
    run, outcome, bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, oracle=lost,
        on_read=first_read_leaves_no_life, clock=clock, sign_script=[(0, None), (0, 503)])
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", outcome
    assert "credential proxy" in outcome["reason"], outcome["reason"]
    assert outcome["unservable_worlds"] == [], "our own failure made a world unservable"
    assert len(bao.signs) == 1, "positive control: the first token was signed; OpenBao healed and nothing signed again"
    assert _sign_requests(bao) == 2, "the failed re-sign was retried, or a later request signed again (D8)"
    assert len(tap.tokens) == 1, "a token was sent after the failed re-sign: the live read's was the only one"
    assert len(merged.seen) == 1, "the system was read after the failed re-sign: the live read was the only read"
    _no_world_went_on(run, lost, healthy)


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
    """No credential set stored for idp: the first live read is a `setup` fault, so the pass is `refused` naming
    our setup for idp, with no unservable world; the second live read is never made, nor any oracle turn.
    #1363 O4, O5, O6"""
    oracle = S.oracle(then=S.submit(S.default_calls()[0].payload, S.EMPTY_CLAIM))
    run, outcome, _bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, credential_set=False, source="idp2", oracle=oracle)
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", outcome
    assert "idp" in outcome["reason"], outcome["reason"]
    assert "setup" in outcome["reason"].lower(), outcome["reason"]
    assert outcome["unservable_worlds"] == []
    assert len(tap.tokens) == 1, "the live-read loop read again after our setup failed (one proxy request is the first read)"
    assert oracle.answered == 0, "calibration started after our setup failed"
    assert merged.seen == []


def test_p5b_a_sign_that_fails_at_the_first_read_refuses_the_pass_before_calibration(
        tmp_path, monkeypatch, data_root):
    """OpenBao refuses the first sign: access is lost at the first live read, the pass is `refused` naming the
    credential proxy, calibration never starts, and no sign is tried again. #1363 O1, O5, O6, D8"""
    oracle = S.oracle(then=S.submit(S.default_calls()[0].payload, S.EMPTY_CLAIM))
    run, outcome, bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, source="idp2", oracle=oracle, sign_script=[(0, 503)])
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", outcome
    assert "credential proxy" in outcome["reason"], outcome["reason"]
    assert outcome["unservable_worlds"] == []
    assert _sign_requests(bao) == 1, "the live-read loop or a world signed again after the failed sign (D8)"
    assert oracle.answered == 0
    assert (bao.signs, tap.tokens, merged.seen) == ([], [], [])
    assert bao.logins, "positive control: OpenBao was reached"


def test_p3b_a_pass_with_no_proxy_address_is_refused_even_when_no_replayed_call_is_proxied(
        tmp_path, monkeypatch, data_root):
    """The source run called only unproxied systems, but idp and crm are granted and declared, so an oracle
    lookup may reach them: with no proxy address the pass is `refused` naming the missing setting, before any
    OpenBao contact. Control: p1d. #1363 O3, B5"""
    from defender.kit.access import PROXY_URL_ENV
    monkeypatch.delenv(PROXY_URL_ENV, raising=False)
    run, outcome, bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, proxy_address=False, source="unproxied")
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", outcome
    assert PROXY_URL_ENV in outcome["reason"], outcome["reason"]
    assert (bao.requests, tap.tokens, merged.seen) == ([], [], [])


@pytest.mark.parametrize("sign_answer", [503, None], ids=["fails", "succeeds"])
def test_p5c_a_pass_whose_reads_need_no_live_proxied_call_still_proves_it_can_sign(
        tmp_path, monkeypatch, data_root, sign_answer):
    """The source run called only unproxied systems and the oracle looks nothing up, so no read reaches the
    proxy. Pre-flight is the gate before siblings launch, so it signs once up front all the same: a sign that
    fails refuses the pass naming the token, before any oracle turn; one that succeeds is the only sign.
    Control: the succeeding sign. Review of #1468 (finding 3)."""
    oracle = S.oracle(then=S.submit(S.default_calls()[0].payload, S.EMPTY_CLAIM))
    run, outcome, bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, source="unproxied", oracle=oracle,
        sign_script=[(0, sign_answer)])
    assert outcome is not None, run.message
    assert _sign_requests(bao) == 1, "pre-flight did not sign up front, or signed again"
    assert (tap.tokens, merged.seen) == ([], []), "nothing was to be read through the proxy"
    if sign_answer is None:
        assert outcome["outcome"] != "refused", ("positive control: a pass that can sign is not refused", outcome)
        return
    assert outcome["outcome"] == "refused", ("a pass that cannot sign its token was accepted", outcome)
    assert "cannot be signed" in outcome["reason"], outcome["reason"]
    assert outcome["unservable_worlds"] == []
    assert oracle.answered == 0, "calibration started though the token could not be signed"


def test_p3c_a_tenant_with_no_recorded_sign_login_is_refused_before_any_contact(
        tmp_path, monkeypatch, data_root):
    """The live generation records no sign login: `refused` naming the sign login, before any OpenBao
    contact or read; the up-front check is unchanged by signing on demand. Control: p1. #1363 O3"""
    run, outcome, bao, tap, merged, _wt = _preflight(tmp_path, monkeypatch, data_root, sign_login=False)
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", outcome
    assert "sign" in outcome["reason"].lower(), outcome["reason"]
    assert (bao.requests, tap.tokens, merged.seen) == ([], [], [])


def test_p1d_the_holder_serves_oracle_lookups_when_no_replayed_call_is_proxied(
        tmp_path, monkeypatch, data_root):
    """The source run called only unproxied systems; a world's oracle looks idp up: the read is signed for on
    demand under the run's read grant (idp and crm, not hr) and reaches the system. Control: p3b. #1363 B5, O2"""
    run, outcome, bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, source="unproxied", oracle=_side_lookups("user:bob"))
    assert run.rc == 0, run.message
    assert outcome["outcome"] == "accepted", outcome
    (sign,) = bao.signs
    assert A.grant_of(A.claims_of_payload(sign.payload)) == [("crm", "r"), ("idp", "r")]
    assert len(merged.seen) == 1, "positive control: the lookup reached the system"
    assert len(tap.tokens) == 1


def test_p8_a_lookup_refused_by_the_proxy_as_lost_access_refuses_the_pass_naming_the_proxy(
        tmp_path, monkeypatch, data_root):
    """A calibration lookup whose token the proxy finds expired is `access`: `refused` naming the proxy, no unservable
    world, and no world begins a second call. #1363 O5, O6, O8, B1"""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "2")
    healthy = _healthy_pass(tmp_path, monkeypatch, data_root, source="unproxied")
    clock = Clock()
    clock.now -= 2 * 3600
    oracle = _one_failing_lookup()
    run, outcome, bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, source="unproxied", oracle=oracle, clock=clock)
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", ("the proxy's refusal of our token was shown to the model as evidence", outcome)
    assert "credential proxy" in outcome["reason"], outcome["reason"]
    assert outcome["unservable_worlds"] == []
    assert len(bao.signs) == 1, "positive control: a token was signed and the proxy refused it"
    assert len(tap.tokens) == 1, "positive control: a token was signed and the proxy refused it"
    assert merged.seen == [], "the system was reached with a refused token"
    _no_world_went_on(run, oracle, healthy)


def test_p8b_a_lookup_met_by_a_setup_refusal_refuses_the_pass_naming_our_setup_for_the_system(
        tmp_path, monkeypatch, data_root):
    """A calibration lookup of idp with no credential set stored is `setup`: `refused` naming our setup for idp, no
    unservable world, and no world begins a second call. #1363 O5, O6, O8, B1"""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "2")
    healthy = _healthy_pass(tmp_path, monkeypatch, data_root, source="unproxied")
    oracle = _one_failing_lookup()
    run, outcome, _bao, tap, merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, source="unproxied", oracle=oracle, credential_set=False)
    assert outcome is not None, run.message
    assert outcome["outcome"] == "refused", ("our setup failure was shown to the model as evidence", outcome)
    assert "idp" in outcome["reason"], outcome["reason"]
    assert "setup" in outcome["reason"].lower(), outcome["reason"]
    assert outcome["unservable_worlds"] == []
    assert len(tap.tokens) >= 1, "positive control: the lookup reached the proxy"
    assert merged.seen == []
    _no_world_went_on(run, oracle, healthy)


# --- #1363: a token request in flight on a thread the oracle abandoned (O6, O1, D8) -------------------------

#: The oracle's turn deadline (seconds), set through the environment: shorter than the slow sign below.
KNOB_TURN_DEADLINE = "ORACLE_TURN_DEADLINE"


@pytest.mark.parametrize("sign_answer", [503, None], ids=["fails", "succeeds"])
def test_p7_a_slow_sign_in_flight_when_the_outcome_is_decided_is_counted_and_nothing_signs_after(
        tmp_path, monkeypatch, data_root, sign_answer):
    """A lookup's re-sign outlives the oracle's turn deadline, so its world gives up while the sign runs on an
    abandoned thread. The outcome waits for it: failed, access was lost and the pass is `refused`; succeeded,
    the pass records its own result (`accepted`, the one world listed unservable). Either way exactly the
    two signs were asked, even after the outcome. #1363 O6, O1, D8"""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    monkeypatch.setenv(KNOB_TURN_DEADLINE, "0.3")
    clock = Clock()
    start = clock.now

    def first_read_leaves_no_life(_r: Rig) -> None:
        if clock.now == start:
            clock.now = start + TOKEN_SEC

    run, outcome, bao, _tap, _merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, oracle=_side_lookups("user:bob"),
        on_read=first_read_leaves_no_life, clock=clock, sign_script=[(0, None), (1.0, sign_answer)])
    assert outcome is not None, run.message
    if sign_answer is None:
        assert outcome["outcome"] == "accepted", outcome
        assert len(outcome["unservable_worlds"]) == 1, ("positive control: the abandoned lookup's world gave up", outcome)
    else:
        assert outcome["outcome"] == "refused", ("the sign in flight was not counted", outcome)
        assert "credential proxy" in outcome["reason"], outcome["reason"]
        assert outcome["unservable_worlds"] == []
    time.sleep(0.5)
    assert _sign_requests(bao) == 2, "something signed after the outcome was decided"


def test_p7_an_adapter_that_asks_again_after_the_outcome_exists_is_refused_and_the_proxy_sees_no_further_token(
        tmp_path, monkeypatch, data_root):
    """A lookup that outlives the oracle's turn deadline waits, on its abandoned thread, until the pass's outcome
    file exists and then makes a second request: it raises, and the proxy is sent nothing for it (the pass shut
    its access holder when it decided). #1363 O6, N1."""
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    monkeypatch.setenv(KNOB_TURN_DEADLINE, "0.3")
    result = tmp_path / "late-result.txt"
    monkeypatch.setenv("LATE_OUTCOME", str(data_root / "*" / "episodes" / "*" / S.OUTCOME_NAME))
    monkeypatch.setenv("LATE_RESULT", str(result))
    waited: list[str] = []

    def until_the_late_request_ended(_run, _tap) -> None:
        limit = time.monotonic() + 45
        while not result.exists() and time.monotonic() < limit:
            time.sleep(0.05)
        waited.append(result.read_text(encoding="utf-8") if result.exists() else "never")

    run, outcome, _bao, tap, _merged, _wt = _preflight(
        tmp_path, monkeypatch, data_root, oracle=_side_lookups("user:bob"), idp_adapter=LATE_IDP_ADAPTER,
        settle=until_the_late_request_ended)

    assert outcome is not None, run.message
    assert outcome["outcome"] == "accepted", ("positive control: the pass recorded its own result", outcome)
    assert len(outcome["unservable_worlds"]) == 1, \
        ("positive control: the lookup outlived the turn deadline and its world gave up", outcome)
    assert any(b"user%3Abob" in b or b"user:bob" in b for b in tap.bodies), "positive control: the lookup reached the proxy"
    assert waited, "the late request never ended"
    assert waited[0].startswith("raised:"), f"the request made after the outcome was not refused: {waited}"
    assert not any(b"late" in body for body in tap.bodies), "the proxy was sent a request made after the pass decided"
