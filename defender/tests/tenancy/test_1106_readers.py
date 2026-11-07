"""Every host-side settings reader reads the injected tenant's folder, never the checkout's."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from pathlib import Path

import pytest

from defender.tests.support.runtime.engine._spec767 import write_report
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

MARK = "injected"
#: The injected tenant's comment template; the checkout's fixture carries a different one.
INJECTED_BODY = "injected-tenant-body {disposition}"


@pytest.fixture
def injected(tmp_path) -> Path:
    """The injected tenant's settings folder: `<tmp root>/<T>/knowledge/settings`, every value
    carrying `MARK`, its case-record body distinct from the checkout's."""
    root = tmp_path / "injected-root"
    S.plant(
        root, T.PLAYGROUND_ID, table=T.TABLE_B, marker=MARK,
        lead_zero=T.lead_zero_text("elastic.injected-tenant-template"),
        case_body=INJECTED_BODY,
    )
    td = T.accept(root, T.PLAYGROUND_ID)
    assert not td.settings.is_relative_to(T.REPO_ROOT), "the fixture root must be outside"
    return td.settings


def _record(settings: Path):
    """The run record of the accepted tenant whose `settings/` is `settings`
    (`<root>/<id>/knowledge/settings`), through the real `accept_tenant`."""
    knowledge = settings.parent
    return T.run_tenant(T.accept(knowledge.parent.parent, knowledge.parent.name))


def _ctx(settings: Path, run_dir: Path, env: dict | None = None):
    return T.verb_context(T.DEFENDER, run_dir, env if env is not None else {},
                          settings_dir=settings)


# ---- the adapters' config.env ---------------------------------------------------------------------

def test_the_stub_transport_loads_the_injected_tenants_config(injected, tmp_path):
    transport = T.mod("integrations._stub_transport")
    cfg = transport.load_config(_ctx(injected, tmp_path), "cmdb", "CMDB")
    assert cfg["URL_BASE"] == f"http://cmdb-{MARK}:8080"  # the injected tenant's declaration
    checkout = transport.load_config(_ctx(T.FIXTURE_SETTINGS, tmp_path), "cmdb", "CMDB")
    assert checkout["URL_BASE"] != cfg["URL_BASE"], "the fixture no longer discriminates"


def test_a_system_with_no_config_in_the_injected_tenant_is_a_config_fault_naming_it(tmp_path):
    faults = T.mod("kit.faults")
    transport = T.mod("integrations._stub_transport")
    root = tmp_path / "injected-root"
    T.place_tenant(root, T.PLAYGROUND_ID, configs={})
    settings = T.accept(root, T.PLAYGROUND_ID).settings
    with pytest.raises(faults.ConfigFault) as caught:
        transport.load_config(_ctx(settings, tmp_path), "cmdb", "CMDB")
    assert "the tenant's settings/systems/cmdb/config.env" in str(caught.value)
    assert str(settings) not in str(caught.value)
    # Control: the checkout's fixture does carry a cmdb config, so the refusal above is
    # the absence of a fallback, not the absence of a file anywhere.
    assert (T.FIXTURE_SETTINGS / "systems" / "cmdb" / "config.env").is_file()


# ---- the case-record settings ----------------------------------------------------------------


def test_the_record_leg_comments_to_the_injected_tenants_store_with_its_case_record(
        injected, tmp_path):
    """The `--update-ticket` lane: the real record leg, handed the run's record, addresses the
    injected tenant's case store (`ticket/config.env`) and renders the injected tenant's
    `case-record.yaml` body, not the checkout's. Replaces the retired `case-history` mapping
    reader tests (#1359 O2: the open leg and `load_case_mapping` are gone)."""
    from defender.tests.tenancy.case_comment_1359 import _spec1359 as C

    run_dir = tmp_path / fixture_uuid("run-1106")
    run_dir.mkdir()
    C.plant_record(run_dir)
    write_report(run_dir)  # a readable report: the injected body renders over it
    proxy = S.ProxyStandIn(tmp_path / "proxy", S.store_answers_ok())
    S.record_step(run_dir, _record(injected), env={}, proxy_url=proxy.url,
                  request_token="write-token-1106")

    posts = [r for r in proxy.requests() if r["method"] == "POST"]
    assert len(posts) == 1, proxy.requests()
    (post,) = posts
    assert post["url"] == f"http://ticket-{MARK}:8080/tickets/{C.TICKET_KEY}/comments", post
    assert "injected-tenant-body" in post["body"]["body"], "the injected case-record body was not sent"
    checkout_text = (T.FIXTURE_SETTINGS / "case-record.yaml").read_text(encoding="utf-8")
    assert "injected-tenant-body" not in checkout_text, "the fixture no longer discriminates"


# ---- lead-zero ---------------------------------------------------------------------------------

def test_the_lead_zero_config_is_read_from_the_injected_tenant(injected):
    lz = T.mod("systems.lead_zero_config")
    assert lz.load_correlation_template(lz.lead_zero_config_path(injected)) == \
        "elastic.injected-tenant-template"
    assert lz.load_correlation_template(lz.lead_zero_config_path(T.FIXTURE_SETTINGS)) != \
        "elastic.injected-tenant-template"
