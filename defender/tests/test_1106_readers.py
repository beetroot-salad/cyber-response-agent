"""#1106 — every host-side settings reader reads the INJECTED tenant, never the checkout (O2, O6).

The four settings kinds had eight-odd readers, and each found its file for itself: from
`ctx.defender_dir`, from `PATHS.defender_dir`, from `$DEFENDER_DIR`, from `__file__`. After
#1106 none of them finds anything. The run's tenant settings folder is resolved once at the
process entry point (`accept_tenant(data_root, run.tenant_id).settings`) and HANDED to every
reader — on the verb context (`VerbContext.tenant`, a required field, whose `settings` is that
folder) or as an argument.

HOW EACH TEST DISCRIMINATES. The fixture tenant lives under a data root in `tmp_path` —
OUTSIDE the checkout — and carries the SAME id the committed fixture is set up under
(`playground`), with DIFFERENT values in every kind. A reader that ignored the handed folder and
went looking — the checkout's `knowledge/tenant-fixture`, `PATHS`, the old
`defender/knowledge/environment` — returns the checkout's value, and the assertion is on the
VALUE that flows out, so it catches that. Each test also reads the checkout's own value and
asserts it differs, so a later edit to the committed fixture cannot make the test vacuous.

The verb context's `defender_dir` is the REAL checkout's in every test: the tree the code runs
from is not where its settings are, which is the whole of D2.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests import _tenants1106 as T
from defender.tests.tenant_1107_settings import _spec1107 as S

MARK = "injected"


@pytest.fixture
def injected(tmp_path) -> Path:
    """The injected tenant's settings folder: `<tmp root>/playground/knowledge/settings`, every value
    carrying `MARK`, the mapping's reporter distinct from the checkout's."""
    root = tmp_path / "injected-root"
    S.plant(
        root, T.PLAYGROUND_ID, table=T.TABLE_B, marker=MARK,
        lead_zero=T.lead_zero_text("elastic.injected-tenant-template"),
        reporter="injected-reporter",
    )
    td = T.accept(root, T.PLAYGROUND_ID)
    assert not td.settings.is_relative_to(T.REPO_ROOT), "the fixture root must be outside"
    return td.settings


def _record(settings: Path):
    """The run record of the accepted tenant whose `settings/` is `settings`
    (`<root>/<id>/knowledge/settings`, #1107/#1120), through the real `accept_tenant`."""
    knowledge = settings.parent
    return T.run_tenant(T.accept(knowledge.parent.parent, knowledge.parent.name))


def _ctx(settings: Path, run_dir: Path, env: dict | None = None):
    return T.verb_context(T.DEFENDER, run_dir, env if env is not None else {},
                          settings_dir=settings)


# ---- the adapters' config.env ---------------------------------------------------------------------

def test_the_stub_transport_loads_the_injected_tenants_config(injected, tmp_path):
    transport = T.mod("scripts.adapters._stub_transport")
    cfg = transport.load_config(_ctx(injected, tmp_path), "cmdb", "CMDB")
    assert cfg["URL_BASE"] == f"http://cmdb-{MARK}:8080"
    assert cfg["BASTION_HOST"] == f"bastion-{MARK}"
    checkout = transport.load_config(_ctx(T.FIXTURE_SETTINGS, tmp_path), "cmdb", "CMDB")
    assert checkout["URL_BASE"] != cfg["URL_BASE"], "the fixture no longer discriminates"


def test_the_ticket_adapters_key_pattern_comes_from_the_injected_tenant(injected, tmp_path):
    transport = T.mod("scripts.adapters._stub_transport")
    ticket = T.mod("scripts.adapters.ticket_adapter")
    cfg = transport.load_config(
        _ctx(injected, tmp_path), ticket.SYSTEM, ticket.PREFIX, ticket.REQUIRED_CONFIG_KEYS)
    assert cfg["KEY_PATTERN"] == f"{MARK.upper()}-[0-9]+"
    assert cfg["URL_BASE"] == f"http://ticket-{MARK}:8080"


def test_the_elastic_adapter_loads_the_injected_tenants_config(injected, tmp_path):
    elastic = T.mod("scripts.adapters.elastic_adapter")
    cfg = elastic.load_config(_ctx(injected, tmp_path))
    assert cfg["ELASTICSEARCH_URL"] == f"https://es-{MARK}:9200"
    assert cfg["ELASTIC_EVENTS_INDEX"] == f"{MARK}-events-*"
    checkout = elastic.load_config(_ctx(T.FIXTURE_SETTINGS, tmp_path))
    assert checkout["ELASTICSEARCH_URL"] != cfg["ELASTICSEARCH_URL"]


def test_a_system_with_no_config_in_the_injected_tenant_is_a_config_fault_naming_it(tmp_path):
    """Absent stays the loud per-call `ConfigFault` (D3), naming the file by the settings
    pointer — never a host path (#1156's review) — while the checkout's copy it could have
    fallen back to does hold one: the fault itself is the proof there was no fallback."""
    faults = T.mod("scripts.adapters.faults")
    transport = T.mod("scripts.adapters._stub_transport")
    root = tmp_path / "injected-root"
    T.place_tenant(root, T.PLAYGROUND_ID, configs={})
    settings = T.accept(root, T.PLAYGROUND_ID).settings
    with pytest.raises(faults.ConfigFault) as caught:
        transport.load_config(_ctx(settings, tmp_path), "cmdb", "CMDB")
    assert "the tenant's settings/systems/cmdb/config.env" in str(caught.value)
    assert str(settings) not in str(caught.value)
    # Control: the checkout's playground does carry a cmdb config, so the refusal above is
    # the absence of a fallback, not the absence of a file anywhere.
    assert (T.FIXTURE_SETTINGS / "systems" / "cmdb" / "config.env").is_file()


# ---- the case-history mapping --------------------------------------------------------------

def test_the_open_payload_renders_the_injected_tenants_mapping(injected):
    case_ticket = T.mod("runtime.case_ticket")
    alert = {"rule": {"id": "r-1", "description": "d"}, "timestamp": "2026-09-26T00:00:00Z"}
    payload = case_ticket.alert_to_open_payload(
        alert, "case-1", mapping=_record(injected).ticket_mapping)
    assert payload["reporter"] == "injected-reporter"
    checkout = case_ticket.alert_to_open_payload(
        alert, "case-1", mapping=T.fixture_run_tenant().ticket_mapping)
    assert checkout["reporter"] != payload["reporter"]


def test_a_missing_mapping_is_a_refusal_naming_the_injected_path(tmp_path):
    """No `$DEFENDER_DIR`, no `__file__` fallback: the mapping the folder does not hold is a
    `CaseTicketError` naming it by the settings pointer — while the checkout's copy sits right
    there."""
    case_ticket = T.mod("runtime.case_ticket")
    settings = tmp_path / "bare" / "settings"
    settings.mkdir(parents=True)
    with pytest.raises(case_ticket.CaseTicketError) as caught:
        case_ticket.load_case_mapping(settings)
    assert "the tenant's settings/systems/case-history/mapping.yaml" in str(caught.value)
    assert str(settings) not in str(caught.value)
    assert (T.FIXTURE_SETTINGS / "systems" / "case-history" / "mapping.yaml").is_file()


def test_the_ticket_writer_posts_to_the_injected_tenants_store_with_its_mapping(
        injected, tmp_path):
    """The `--update-ticket` lane (O2 names the ticket writer): the REAL writer, over a
    recording request seam, is handed the run's record — and both the store it
    addresses (`case-history/config.env`) and the payload it renders (`mapping.yaml`) are the
    injected tenant's."""
    writer = T.mod("scripts.case_history.ticket_writer")
    run_dir = tmp_path / "run-1106"
    run_dir.mkdir()
    (run_dir / "alert.json").write_text(json.dumps(
        {"rule": {"id": "r-1", "description": "d"}, "timestamp": "2026-09-26T00:00:00Z"}),
        encoding="utf-8")
    sent: list[tuple] = []

    def request(config, method, path, body=None, *, ctx):
        sent.append((dict(config), method, path, body, ctx))
        return "201", "{}"

    writer.open_case_ticket(
        run_dir, deps=writer.TicketWriterDeps(request=request), tenant=_record(injected),
        defender_dir=T.DEFENDER, env={})
    assert len(sent) == 1, sent
    config, method, path, body, ctx = sent[0]
    assert (method, path) == ("POST", "/tickets")
    # The transport's verb context carries the SAME tenant record the config came from,
    # handed to the request as an argument rather than carried inside the config dict.
    assert ctx.tenant.settings == injected
    assert config["URL_BASE"] == f"http://case-history-{MARK}:8080"
    assert body["reporter"] == "injected-reporter"


# ---- lead-zero ---------------------------------------------------------------------------------

def test_the_lead_zero_config_is_read_from_the_injected_tenant(injected):
    lz = T.mod("runtime.lead_zero_config")
    assert lz.load_correlation_template(lz.lead_zero_config_path(injected)) == \
        "elastic.injected-tenant-template"
    assert lz.load_correlation_template(lz.lead_zero_config_path(T.FIXTURE_SETTINGS)) != \
        "elastic.injected-tenant-template"


def test_the_table_is_read_from_the_injected_tenant(injected):
    grants = T.run_grants(injected)
    assert {(s, v) for s, v, _ in grants.gather.entries} == set(T.GATHER_PAIRS_B)
    assert {(s, v) for s, v, _ in T.fixture_grants().gather.entries} != set(T.GATHER_PAIRS_B)
