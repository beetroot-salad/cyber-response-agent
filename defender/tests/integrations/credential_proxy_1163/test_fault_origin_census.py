"""#1363 O4, B3, B4 on the proxy side: every refusal carries the origin of its cause, every raise
site of the proxy is labelled where it is raised, and a fault the proxy did not label reads access."""
from __future__ import annotations

import contextlib
import json
from pathlib import Path

import pytest

from defender.kit.faults import AdapterFault
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _origin1363 as O
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import proxy

BASE = T.BASE_PATH


def _observe_all(rig, rows):
    seen, found = [], []
    for row in rows:
        try:
            got = O.observe(rig, row)
        except Exception as e:  # noqa: BLE001 — a row that cannot run is reported with the rest
            found.append(f"{row.id}: could not run: {type(e).__name__}: {e}")
            continue
        seen.append(got)
        found += O.problems(row, got)
    return seen, found


@contextlib.contextmanager
def _oauth(tmp_path, data_root, token_url):
    with T.rig(tmp_path / "forge", data_root,
               lambda u: H.declaration(u + BASE, scheme=H.oauth_scheme(token_url)), creds=T.oauth_set()) as r:
        yield r


def _all_groups(tmp_path, data_root):
    """Every row run on its rig: (observations, problems)."""
    seen, found = [], []

    def take(rig, rows):
        got, bad = _observe_all(rig, rows)
        seen.extend(got)
        found.extend(bad)

    with T.rig(tmp_path / "bearer", data_root, lambda u: H.declaration(u + BASE, writes=(("POST", "/tickets"),)),
               ghosts={O.GHOST: Path()}) as r:
        r.t.merge({f"settings/systems/{O.BASIC_SYSTEM}/access.yaml": H.declaration(r.up.url + BASE, scheme=H.basic_scheme()),
                   f"settings/systems/{O.BROKEN_SYSTEM}/access.yaml": "{ not a declaration"}, "more systems")
        r.t.publish()
        take(r, O.bearer_rows())
    with H.upstream() as aux, _oauth(tmp_path / "oauth", data_root, aux.url + "/token") as r:
        take(r, O.oauth_rows(aux))
        try:
            got = O.gate_wait(r, aux)
            seen.append(got)
            found += O.problems(O.GATE_ROW, got)
        except Exception as e:  # noqa: BLE001
            found.append(f"gate wait: could not run: {type(e).__name__}: {e}")
    with _oauth(tmp_path / "dead", data_root, f"http://127.0.0.1:{H.free_port()}/token") as r:
        take(r, O.dead_endpoint_rows())
    with O.trickling(json.dumps({"access_token": "AT", "expires_in": 3600}).encode()) as slow, \
            _oauth(tmp_path / "slowx", data_root, slow + "/token") as r:
        take(r, O.slow_exchange_rows())
    with O.trickling() as slow, T.rig(tmp_path / "slows", data_root, lambda _u: H.declaration(slow + BASE)) as r:
        take(r, O.slow_system_rows(slow))
    dead = f"http://127.0.0.1:{H.free_port()}"
    with T.rig(tmp_path / "deads", data_root, lambda _u: H.declaration(dead + BASE)) as r:
        take(r, O.dead_system_rows(dead))
    return seen, found


def test_1363_o4_b3_every_cause_reads_its_origin_and_every_raise_site_is_labelled_and_driven(tmp_path, data_root):
    """Each row's refusal carries its cause's label, set where it was raised; every fault-raising site
    under `credential_proxy/` that a request can reach is tied to a row that drove it. #1363 O4, B3, B4."""
    seen, found = _all_groups(tmp_path, data_root)
    sites = O.proxy_sites()

    assert found == []
    assert O.untied(sites, seen) == []
    labels = {s.row: T.label_of(s.final) for s in seen}
    assert set(labels.values()) == {None, "request", "setup", "access"}, "positive control: every label is exercised"


def test_1363_b3_the_scan_finds_an_unlabelled_site_it_is_given_and_leaves_the_excluded_ones():
    """A planted module with a fault raised in a request-path function and one in an excluded
    function: the first is listed as untied, the second is not. #1363 B3 (control)."""
    source = ("def request_path(x):\n    raise ConfigFault(f'planted cause {x}')\n"
              "def operator_config():\n    raise ConfigFault('start-up only')\n")
    sites = O.sites_in(source, "__main__.py")
    assert [s.qualname for s in sites] == ["request_path", "operator_config"]
    assert O.untied(sites, []) == ["__main__.py request_path:2: no row's detail matches 'planted cause {}'"]
    observed = O.Observed("r", None, [], ["planted cause 3"])
    assert O.untied(sites, [observed]) == []


def test_1363_b3_the_scan_reads_every_module_of_the_proxy():
    """The sites come from every module under `credential_proxy/`, so a module added later is read. #1363 B3."""
    files = {s.file for s in O.proxy_sites()}
    assert {"_app.py", "_scope.py", "_credentials.py", "_deadline.py", "_openbao.py", "_tokens.py"} <= files
    assert files == {p.name for p in Path(proxy().__file__).parent.glob("*.py") if O.sites_in(p.read_text(encoding="utf-8"), p.name)}


def _no_origin(fault: BaseException) -> bool:
    return isinstance(fault, AdapterFault) and getattr(fault, "origin", None) is None


def test_1363_b3_helpers_the_launcher_and_the_secret_writer_share_carry_no_label():
    """`openbao_fault`, the API's secret writer, minting and `read_export_access` raise unlabelled: the
    proxy labels them at its call sites, off the proxy path they stay without an origin. #1363 B3."""
    import anyio

    from defender.credential_proxy import OpenBaoSecrets
    from defender.credential_proxy._openbao import openbao_fault

    assert [_no_origin(openbao_fault(s, "d")) for s in (503, 403)] == [True, True]

    async def writer_faults():
        out = []
        for transport, writes in ((O.answering(503), True), (O.answering(403), True), (O.openbao(unreachable=True), True),
                                  (O.answering(200, {"data": None}), False)):
            secrets = OpenBaoSecrets(addr="http://openbao.invalid", token="t", mount="secret", transport=transport)
            if writes:
                with pytest.raises(AdapterFault) as put:
                    await secrets.put_credentials(T.RUN_ID, "identity", "static", {"api_key": "k"}, generation=1)
                out.append(put.value)
            with pytest.raises(AdapterFault) as has:
                await secrets.has_credentials(T.RUN_ID, "identity", generation=1)
            out.append(has.value)
        return out

    faults = anyio.run(writer_faults)
    assert len(faults) == 7
    assert all(_no_origin(f) for f in faults), [type(f).__name__ for f in faults if not _no_origin(f)]

    with pytest.raises(AdapterFault) as minted:
        proxy().mint_request_token(H.FakeSigner(), tenant_id=T.RUN_ID, investigation="i", grant=[], expires_at=None)
    assert _no_origin(minted.value)


def test_1363_b3_read_export_access_raises_unlabelled_off_the_proxy_path(tmp_path):
    """A system with no declaration in an export folder is refused without a label by the shared
    reader; the proxy's label for it is set at its call site (the census row). #1363 B3."""
    from defender import tenancy

    with pytest.raises(AdapterFault) as refused:
        tenancy.read_export_access(tmp_path, "cmdb")
    assert _no_origin(refused.value)


@pytest.mark.parametrize(("transport", "label"), [
    pytest.param(O.openbao(unreachable=True), "access", id="unreachable"),
    pytest.param(O.answering(503), "access", id="failing"),
    pytest.param(O.answering(403), "access", id="refuses-the-proxy"),
    pytest.param(O.answering(200, {"data": None}), "setup", id="no-data-object"),
    pytest.param(O.stored({"kind": "static"}), "setup", id="not-in-the-stores-shape"),
])
def test_1363_b3_the_store_splits_its_two_causes_where_it_raises(transport, label):
    """`OpenBaoStore.read` raises `access` when OpenBao cannot be used and `setup` when the set is
    unusable, with no deadline or request around it. #1363 B3."""
    with pytest.raises(AdapterFault) as raised:
        O.openbao_store(transport).read(T.RUN_ID, "identity", 1)
    assert getattr(raised.value, "origin", None) == label, raised.value


def test_1363_b3_the_same_helper_reads_access_at_verify_and_setup_at_the_store():
    """OpenBao's answer without a data object is `access` read by the verifier and `setup` read by
    the store: one helper, two call sites, two labels. #1363 B3."""
    transport = O.answering(200, {"data": None})
    with pytest.raises(AdapterFault) as at_store:
        O.openbao_store(transport).read(T.RUN_ID, "identity", 1)
    with pytest.raises(AdapterFault) as at_verify:
        O.openbao_verifier(transport).verify(b"p", "s", tenant_id=T.RUN_ID)
    assert (at_store.value.origin, at_verify.value.origin) == ("setup", "access")
