"""#1106 — every host-side settings reader reads the INJECTED tenant, never the checkout (O2, O6).

The four settings kinds had eight-odd readers, and each found its file for itself: from
`ctx.defender_dir`, from `PATHS.defender_dir`, from `$DEFENDER_DIR`, from `__file__`. After
#1106 none of them finds anything. The run's tenant settings folder is resolved once at the
process entry point (`tenant_dir(tenants_root, run.tenant_id).settings`) and HANDED to every
reader — on the verb context (`VerbContext.settings_dir`, a required field) or as an argument.

HOW EACH TEST DISCRIMINATES. The fixture tenant lives under a tenants root in `tmp_path` —
OUTSIDE the checkout — and carries the SAME id as the checkout's committed tenant
(`playground`), with DIFFERENT values in every kind. A reader that ignored the handed folder and
went looking — the checkout's `knowledge/tenants/playground`, `PATHS`, the old
`defender/knowledge/environment` — returns the checkout's value, and the assertion is on the
VALUE that flows out, so it catches that. Each test also reads the checkout's own value and
asserts it differs, so a later edit to the committed playground cannot make the test vacuous.

The verb context's `defender_dir` is the REAL checkout's in every test: the tree the code runs
from is not where its settings are, which is the whole of D2.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests import _tenants1106 as T

MARK = "injected"


@pytest.fixture
def injected(tmp_path) -> Path:
    """The injected tenant's settings folder: `<tmp root>/playground/settings`, every value
    carrying `MARK`, the mapping's released status and reporter distinct from the checkout's."""
    root = tmp_path / "injected-root"
    T.plant_tenant(
        root, T.PLAYGROUND_ID, table=T.TABLE_B, marker=MARK,
        lead_zero=T.lead_zero_text("elastic.injected-tenant-template"),
        released_status="resolved-by-a-person", reporter="injected-reporter",
    )
    td = T.tenants().tenant_dir(root, T.PLAYGROUND_ID)
    assert not td.settings.is_relative_to(T.REPO_ROOT), "the fixture root must be outside"
    return td.settings


def _ctx(settings: Path, run_dir: Path, env: dict | None = None):
    return T.verb_context(T.DEFENDER, run_dir, env if env is not None else {},
                          settings_dir=settings)


# ---- the adapters' config.env ---------------------------------------------------------------------

def test_the_stub_transport_loads_the_injected_tenants_config(injected, tmp_path):
    transport = T.mod("scripts.adapters._stub_transport")
    cfg = transport.load_config(_ctx(injected, tmp_path), "cmdb", "CMDB")
    assert cfg["URL_BASE"] == f"http://cmdb-{MARK}:8080"
    assert cfg["BASTION_HOST"] == f"bastion-{MARK}"
    checkout = transport.load_config(_ctx(T.PLAYGROUND_SETTINGS, tmp_path), "cmdb", "CMDB")
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
    checkout = elastic.load_config(_ctx(T.PLAYGROUND_SETTINGS, tmp_path))
    assert checkout["ELASTICSEARCH_URL"] != cfg["ELASTICSEARCH_URL"]


def test_a_system_with_no_config_in_the_injected_tenant_is_a_config_fault_naming_it(tmp_path):
    """Absent stays the loud per-call `ConfigFault` (D3) — and it names the INJECTED tenant's
    path, not the checkout's copy it could have fallen back to (which does hold one)."""
    faults = T.mod("scripts.adapters.faults")
    transport = T.mod("scripts.adapters._stub_transport")
    root = tmp_path / "injected-root"
    T.plant_tenant(root, T.PLAYGROUND_ID, configs={})
    settings = T.tenants().tenant_dir(root, T.PLAYGROUND_ID).settings
    with pytest.raises(faults.ConfigFault) as caught:
        transport.load_config(_ctx(settings, tmp_path), "cmdb", "CMDB")
    assert str(settings / "systems" / "cmdb" / "config.env") in str(caught.value)
    # Control: the checkout's playground does carry a cmdb config, so the refusal above is
    # the absence of a fallback, not the absence of a file anywhere.
    assert (T.PLAYGROUND_SETTINGS / "systems" / "cmdb" / "config.env").is_file()


# ---- the case-history mapping --------------------------------------------------------------

def test_the_release_predicate_reads_the_injected_tenants_mapping(injected):
    case_ticket = T.mod("scripts.case_history.case_ticket")
    predicate = case_ticket.release_predicate(injected)
    assert predicate.released_status == "resolved-by-a-person"
    assert predicate.is_released({"status": "resolved-by-a-person"}) is True
    assert predicate.is_released({"status": "closed"}) is False
    assert case_ticket.release_predicate(T.PLAYGROUND_SETTINGS).released_status != \
        predicate.released_status


def test_the_open_payload_renders_the_injected_tenants_mapping(injected):
    case_ticket = T.mod("scripts.case_history.case_ticket")
    alert = {"rule": {"id": "r-1", "description": "d"}, "timestamp": "2026-09-26T00:00:00Z"}
    payload = case_ticket.alert_to_open_payload(alert, "case-1", settings_dir=injected)
    assert payload["reporter"] == "injected-reporter"
    checkout = case_ticket.alert_to_open_payload(
        alert, "case-1", settings_dir=T.PLAYGROUND_SETTINGS)
    assert checkout["reporter"] != payload["reporter"]


def test_a_missing_mapping_is_a_refusal_naming_the_injected_path(tmp_path):
    """No `$DEFENDER_DIR`, no `__file__` fallback: the mapping the folder does not hold is a
    `CaseTicketError` naming the injected path — while the checkout's copy sits right there."""
    case_ticket = T.mod("scripts.case_history.case_ticket")
    settings = tmp_path / "bare" / "settings"
    settings.mkdir(parents=True)
    with pytest.raises(case_ticket.CaseTicketError) as caught:
        case_ticket.release_predicate(settings)
    assert str(settings / "systems" / "case-history" / "mapping.yaml") in str(caught.value)
    assert (T.PLAYGROUND_SETTINGS / "systems" / "case-history" / "mapping.yaml").is_file()


def test_the_ticket_writer_posts_to_the_injected_tenants_store_with_its_mapping(
        injected, tmp_path):
    """The `--update-ticket` lane (O2 names the ticket writer): the REAL writer, over a
    recording request seam, is handed the run's settings folder — and both the store it
    addresses (`case-history/config.env`) and the payload it renders (`mapping.yaml`) are the
    injected tenant's."""
    writer = T.mod("scripts.case_history.ticket_writer")
    run_dir = tmp_path / "run-1106"
    run_dir.mkdir()
    (run_dir / "alert.json").write_text(json.dumps(
        {"rule": {"id": "r-1", "description": "d"}, "timestamp": "2026-09-26T00:00:00Z"}),
        encoding="utf-8")
    sent: list[tuple] = []

    def request(config, method, path, body=None):
        sent.append((dict(config), method, path, body))
        return "201", "{}"

    writer.open_case_ticket(
        run_dir, deps=writer.TicketWriterDeps(request=request), settings_dir=injected)
    assert len(sent) == 1, sent
    config, method, path, body = sent[0]
    assert (method, path) == ("POST", "/tickets")
    assert config["URL_BASE"] == f"http://case-history-{MARK}:8080"
    assert body["reporter"] == "injected-reporter"


# ---- lead-zero ---------------------------------------------------------------------------------

def test_the_lead_zero_config_is_read_from_the_injected_tenant(injected):
    lz = T.mod("runtime.lead_zero_config")
    assert lz.load_correlation_template(lz.lead_zero_config_path(injected)) == \
        "elastic.injected-tenant-template"
    assert lz.load_correlation_template(lz.lead_zero_config_path(T.PLAYGROUND_SETTINGS)) != \
        "elastic.injected-tenant-template"


def test_the_table_is_read_from_the_injected_tenant(injected):
    grants = T.run_grants(injected)
    assert {(s, v) for s, v, _ in grants.gather.entries} == set(T.GATHER_PAIRS_B)
    assert {(s, v) for s, v, _ in T.playground_grants().gather.entries} != set(T.GATHER_PAIRS_B)


# ---- branching: the stager's patterns and the write door ----------------------------------------------

def test_the_configured_patterns_are_the_injected_tenants(injected):
    stager = T.mod("learning.branch.estate.stagers.elastic")
    patterns = stager.configured_patterns(injected)
    assert tuple(patterns) == (f"{MARK}-events-*", f"{MARK}-alerts-*")
    assert tuple(stager.configured_patterns(T.PLAYGROUND_SETTINGS)) != tuple(patterns)


def test_the_staging_write_door_addresses_the_injected_tenants_cluster(injected, tmp_path):
    """The door is driven for real over a recording transport; the URL the transport is HANDED
    is the injected tenant's `ELASTICSEARCH_URL`, and TLS verification follows its
    `ELASTIC_SSL_VERIFY` (true here, false in the checkout's playground)."""
    staging = T.mod("learning.branch.staging")
    calls: list[dict] = []

    def transport(ctx, container, url, **kw):
        calls.append({"url": url, **kw})
        return 0, '{"count": 3}\n200', ""

    door = staging.write_door_from_env(_ctx(injected, tmp_path), transport=transport)
    assert door.count("logs-x") == 3
    assert calls and calls[0]["url"].startswith(f"https://es-{MARK}:9200/"), calls
    assert calls[0]["insecure"] is False, calls
