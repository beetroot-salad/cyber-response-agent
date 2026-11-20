"""#1163 the run record carries each system's access method and its parsed declaration or its
ConfigFault, and the #1256 run-start check marks a bad http-proxy system down without stopping
the run (A5)."""
from __future__ import annotations

import pytest

from defender._paths import adapters_under
from defender.systems import system_status
from defender.systems.verbs import read_roster
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.support.tenancy import _systems1366 as R1366
from defender.tests.systems import _reads1504 as X
from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER, published_tenant

BASE = "http://identity.invalid/api"
BAD = {
    "good": (A.env_text("identity"), H.declaration(BASE)),
    "url-base": (A.env_text("identity", extra='IDENTITY_URL_BASE="http://identity.invalid"\n'),
                 H.declaration(BASE)),
    "bastion": (A.env_text("identity", extra='IDENTITY_BASTION_HOST="web-1"\n'),
                H.declaration(BASE)),
    "malformed": (A.env_text("identity"), "access: [http-proxy\nbase: {\n"),
    "duplicate-key": (A.env_text("identity"), A.duplicate_key_declaration(BASE)),
    "no-declaration": (A.env_text("identity"), None),
}


#: What each defect's reason must name, so a system down for being unimplemented does not pass.
#: A record's fault is located "system <s> settings" / "system <s> access", never by a file (#1366 DC6).
WORDS = {"url-base": ("system identity settings", "URL_BASE"), "bastion": ("system identity settings", "BASTION_HOST"),
         "malformed": ("system identity access",), "duplicate-key": ("system identity access", "duplicate"),
         "no-declaration": ("system identity access",)}


def _down(tmp_path, data_root, env, decl):
    # #1366 O9: the retired fixture folders (`R1366.import_files`) stand for the tenant's records, so "the rest are up" is not
    # vacuous; the row plants identity's record over them (no declaration = an empty access text).
    overrides = {"settings/systems/identity/config.env": env}
    if decl is not None:
        overrides.update(H.access_files("identity", decl))
    else:
        overrides["settings/systems/identity/access.yaml"] = None
    files = R1366.import_files(**overrides)
    with published_tenant(tmp_path / "forge", root=data_root, files=files) as t:
        record = T.run_record(t)  # resolving the record never raises on a bad declaration
        roster = read_roster(adapters_under(DEFENDER))
        return system_status.judge_run(roster, record, defender_dir=DEFENDER).down


@pytest.mark.parametrize("name", [n for n in BAD if n != "good"])
def test_a5_a_bad_http_proxy_system_is_down_at_run_start_and_the_rest_are_up(
        tmp_path, data_root, name):
    """URL_BASE or BASTION_HOST (keys identity does not read), a malformed, duplicate-key or missing
    declaration: that system is down with a ConfigFault's reason, others stay up. A5, #1256."""
    down = _down(tmp_path, data_root, *BAD[name])
    assert "identity" in down, f"{name}: identity was judged usable"
    assert type(down["identity"]).__name__ == "NotConfigured"
    reason = down["identity"].reason
    for word in WORDS[name]:
        assert word in reason, f"{name}: the reason does not name {word!r}: {reason}"
    assert "cmdb" not in down
    assert "elastic" not in down


def test_a5_a_well_formed_http_proxy_system_is_up(tmp_path, data_root):
    """Positive control for the rows above: the same tenant with a good declaration. A5."""
    assert "identity" not in _down(tmp_path, data_root, *BAD["good"])


def test_a5_run_main_continues_with_the_bad_system_down(tmp_path, data_root):
    """Through `run.main`: a malformed declaration marks identity down at start and the run
    goes on with cmdb. A5, #1256."""
    from defender.tests.integrations.credential_proxy_1163 import test_run_start_tokens as R
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

    S.plant(data_root, table=R.TABLE)  # every system declared; identity's is then broken
    folder = data_root / S.PLAYGROUND_ID / "knowledge"
    (folder / "settings/systems/identity/access.yaml").write_text("access: [bad\n", encoding="utf-8")
    rec = S.RunRecorder(tmp_path / "run")
    rc, refused = S.drive_run(S.run_argv(S.plant_alert(tmp_path / "in"), data_root), rec,
                              signer=A.MarkedSigner(), proxy_url="http://proxy.invalid")
    assert refused is None, (rc, refused)
    assert rc == 0, (rc, refused)
    (life,) = rec.lifecycle_calls
    assert set(life["systems"].down) == {"identity"}
    assert "system identity access" in life["systems"].down["identity"].reason  # #1366 DC6


# --- #1504 O3: a record whose non-GET reads differ from its adapter's is down at run start ------------------------------

ELASTIC_BASE = "https://elasticsearch.example:9200"
SEARCH, QUERY = ("POST", "/*/_search"), ("POST", "/_query")


def _judged(tmp_path, data_root, system: str, access: str):
    """`system`'s record planted with `access` over the fixture's records, and the run's judgement and tenant record."""
    files = R1366.import_files(**H.access_files(system, access))
    with published_tenant(tmp_path / "forge", root=data_root, files=files) as t:
        record = T.run_record(t)
        roster = read_roster(adapters_under(DEFENDER))
        return system_status.judge_run(roster, record, defender_dir=DEFENDER), record


@pytest.mark.parametrize(("system", "reads", "named", "route"), [
    pytest.param("elastic", (SEARCH,), "missing", QUERY, id="elastic-missing-the-query-route"),
    pytest.param("elastic", (SEARCH, QUERY, ("DELETE", "/*")), "extra", ("DELETE", "/*"), id="elastic-an-extra-route"),
    pytest.param("identity", (("POST", "/identity/_find"),), "extra", ("POST", "/identity/_find"),
                 id="a-get-only-adapter-with-a-post-read"),
])
def test_1504_o3_a_system_whose_non_get_reads_differ_from_its_adapters_is_down_at_run_start_and_in_no_read_pass(
        tmp_path, data_root, system, reads, named, route):
    """Run start's judgement: the system is down with the reason (access part, the word, the route); read_grant leaves it
    out while the other granted systems stay up and in the grant. (O3)"""
    access = R1366.declaration(ELASTIC_BASE, scheme="basic", reads=reads) if system == "elastic" else H.declaration(
        BASE, reads=reads)
    judged, record = _judged(tmp_path, data_root, system, access)
    assert set(judged.down) == {system}, judged.down
    reason = judged.down[system].reason
    for needle in (f"system {system} access", named, f"{route[0]} {route[1]}"):
        assert needle in reason, reason
    granted = system_status.read_grant(record, judged.down)
    assert system not in granted
    assert "cmdb" in granted, f"positive control: the other granted systems stay in the grant: {granted}"


def test_1504_o3_the_same_systems_with_exactly_their_adapters_reads_are_up_and_in_the_read_grant(tmp_path, data_root):
    """Control: Elastic with both searches, plus a GET and a HEAD read listed beside them, is up and granted. (O3)"""
    access = R1366.declaration(ELASTIC_BASE, scheme="basic", reads=(SEARCH, QUERY, ("GET", "/_cluster/health"),
                                                                    ("HEAD", "/logs-*")))
    judged, record = _judged(tmp_path, data_root, "elastic", access)
    assert judged.down == {}, judged.down
    assert {"elastic", "cmdb"} <= set(system_status.read_grant(record, judged.down))


@pytest.mark.parametrize(("reads", "refused"), [pytest.param((), False, id="exact"),
                                                 pytest.param((("POST", "/search"),), True, id="a-non-get-read")])
def test_1504_o3_a_case_only_system_with_a_non_get_read_has_no_case_verdict_target_naming_its_access(
        tmp_path, data_root, reads, refused):
    """The case verdict (run start's and the record step's): the ticket system listing a non-GET read is a
    `CaseSettingsFault` at its access part naming the route; with none the verdict is its target. (O3)"""
    from defender.systems.case_system import CaseSettingsFault, CaseTarget, case_verdict

    access = R1366.declaration("http://soc-playground:8004", reads=reads, writes=(("POST", "/tickets/*/comments"),))
    with published_tenant(tmp_path / "forge", root=data_root, files=R1366.import_files(
            **H.access_files("ticket", access))) as t:
        verdict = case_verdict(T.run_record(t), defender_dir=DEFENDER, roster=read_roster(adapters_under(DEFENDER)))
    if not refused:
        assert isinstance(verdict, CaseTarget), verdict
    else:
        assert isinstance(verdict, CaseSettingsFault), verdict
        for needle in ("system ticket access", "POST /search", X.EXTRA_WORD):
            assert needle in str(verdict), str(verdict)
        assert "cannot take the comment" not in str(verdict), str(verdict)  # the read check's sentence, not the cover's


@pytest.mark.parametrize(("reads", "down"), [pytest.param((), set(), id="exact"),
                                             pytest.param((("POST", "/identity/_find"),), {"identity"}, id="extra-read")])
def test_1504_o3_run_main_holds_a_system_with_a_non_get_read_its_adapter_does_not_declare_down_and_goes_on(
        tmp_path, data_root, reads, down):
    """Through `run.main`: identity listing a non-GET read its adapter lacks is down at start with the access reason and the
    run goes on with cmdb; with no such read nothing is down. (O3)"""
    from defender.tests.integrations.credential_proxy_1163 import test_run_start_tokens as RT
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

    S.plant(data_root, table=RT.TABLE)
    folder = data_root / S.PLAYGROUND_ID / "knowledge"
    (folder / "settings/systems/identity/access.yaml").write_text(H.declaration(BASE, reads=reads), encoding="utf-8")
    rec = S.RunRecorder(tmp_path / "run")
    rc, refused = S.drive_run(S.run_argv(S.plant_alert(tmp_path / "in"), data_root), rec,
                              signer=A.MarkedSigner(), proxy_url="http://proxy.invalid")
    assert (rc, refused) == (0, None)
    (life,) = rec.lifecycle_calls
    assert set(life["systems"].down) == down
    if down:
        for needle in ("system identity access", "POST /identity/_find", X.EXTRA_WORD):
            assert needle in life["systems"].down["identity"].reason
