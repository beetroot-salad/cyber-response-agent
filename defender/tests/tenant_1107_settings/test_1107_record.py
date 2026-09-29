"""#1107 — the record: `RunTenant` grown by `systems`, `elastic`, `ticket_mapping` and `secrets`,
built once at resolve, never raising for a system's config (D-data-model, O2, O5, D2, §7 F0).

Every tenant here is PLANTED under a tmp root through `_spec1107.plant` (every value carries a
marker, so a reader returning another tenant's, the checkout's or the environment's value is
caught by the value alone) and resolved through the REAL acceptance frame,
`run_tenant.resolve_tenant` — the one every entry point uses (C1). The one exception is
`d2_shipped_tenants_complete`, which reads the COMMITTED playground and template.

Faults are real inputs through the real primitive, written in the test itself: a deleted
`config.env`, `0xff 0xfe` bytes (RG4n, executed: non-UTF-8 raises an uncaught UnicodeDecodeError
out of every reader today), a directory in a file's place, a symlink (CX6, executed: the link walk
refuses it), a stray / case-variant / dot folder under `systems/`. The one faked dependency is the
docker CLI, as `_spec1107.DockerShim` on the PATH of the env a transport forks with (CX8,
executed: a shim there receives the argv and the child's whole environment).
"""
from __future__ import annotations

import contextlib
import dataclasses
import inspect
import json
import logging
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from defender.runtime import run_tenant
from defender.scripts.adapters import _stub_transport as transport
from defender.tests import _tenants1106 as T1106
from defender.tests._by_path import load_module
from defender.tests._data_root_1078 import ensure_d9_tenant
from defender.tests.tenant_1107_settings import _spec1107 as S

TID = S.PLAYGROUND_ID
FOUR_TYPES = ("SystemConfig", "ElasticSettings", "CaseMapping", "SecretLookup")


def _resolve(root: Path, tenant_id: str = TID) -> object:
    """The REAL acceptance frame over a planted root (C1: the one frame every entry uses)."""
    return run_tenant.resolve_tenant(
        Path(root), tenant_id, defender_dir=S.DEFENDER, dispatches_lead_zero=False)


def _ctx(record: object, tmp_path: Path, env: Mapping[str, str] | None = None) -> object:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return S.verb_context(record, run_dir, dict(env or {}))


def _fault_text(fn, *args, **kw) -> str:
    """Call `fn` and return the text of the `ConfigFault` it raises ('' if it raised nothing)."""
    try:
        fn(*args, **kw)
    except S.config_fault() as fault:
        return str(fault)
    return ""


# ---------------------------------------------------------------------------------------------
# Demand #0 — the return contract (§7 F0, human: the provisional reading accepted as written).
# ---------------------------------------------------------------------------------------------

def test_d0_return_contract(tmp_path):  # noqa: PLR0915 — one contract, every field of it, read top to bottom
    """RESOLVED at §7 (F0, human, round 1: the provisional reading accepted as written). resolve_tenant
    and resolve_run_tenant return the existing frozen RunTenant, grown by four fields built in
    resolve_run_tenant (which resolve_tenant delegates to): systems, a read-only Mapping from each
    folder name under settings/systems/ to a SystemConfig or a ConfigFault, where a SystemConfig is
    a read-only Mapping[str, str] of the file's keys exactly as written; elastic, an ElasticSettings
    or a ConfigFault or None, whose ElasticSettings exposes events_index, alerts_index, url,
    ssl_verify (the raw string), es_container, kibana_container and docker_context; ticket_mapping,
    a CaseMapping or a CaseTicketError; and secrets, a SecretLookup whose get(name) returns the
    value as a str or raises ConfigFault, name being what a *_SECRET_REF key holds. Neither resolver
    raises for a system fault: TenantRefused (defender._tenant) keeps only its current
    tenant-acceptance reasons. VerbContext and AgentDeps carry the record in a field named tenant in
    place of settings_dir. An adapter's load_config keeps its return, a dict of prefix-stripped
    keys, or raises ConfigFault. A transport is asked for a secret by its declared name and sets the
    value into that one child's environment under a variable it picks. record_case_ticket and
    open_case_ticket return None and never raise; ticket_write.json is {key, status, url, ok,
    reason}, a failure receipt carrying status 'error', ok false, url null when there is no usable
    config, and a non-empty reason, a success receipt carrying reason null. The branch launcher
    refuses with its existing LauncherRefused (a SystemExit). lint_tenant_env_reads exposes
    main(argv) -> int like every other custom lint, 0 when clean and non-zero with path:line
    findings. validate_scaffold.check_config keeps its signature and reports through Report's
    FAIL/PASS entries."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="d0", secrets={"X_TOKEN": "d0-planted-secret"})
    S.set_key(folder, "cmdb", "X_TOKEN_SECRET_REF", "X_TOKEN")

    rec = _resolve(root)
    rec_direct = run_tenant.resolve_run_tenant(
        S.tenant_folder_of(root), defender_dir=S.DEFENDER, dispatches_lead_zero=False)

    # The existing frozen RunTenant, grown — from both resolvers.
    assert type(rec) is run_tenant.RunTenant, type(rec)
    assert type(rec_direct) is run_tenant.RunTenant, type(rec_direct)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.systems = {}  # type: ignore[misc]

    # systems: a read-only Mapping, folder name -> SystemConfig (a read-only Mapping[str, str]).
    SystemConfig = S.record_type("SystemConfig")
    assert isinstance(rec.systems, Mapping), type(rec.systems)
    assert set(rec.systems) == set(S.PREFIX), sorted(rec.systems)
    with pytest.raises(TypeError):
        rec.systems["cmdb"] = rec.systems["identity"]  # type: ignore[index]
    cmdb = rec.systems["cmdb"]
    assert isinstance(cmdb, SystemConfig), type(cmdb)
    assert isinstance(cmdb, Mapping), type(cmdb)
    assert cmdb["CMDB_URL_BASE"] == "http://cmdb-d0:8080", dict(cmdb)
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in cmdb.items()), dict(cmdb)
    with pytest.raises(TypeError):
        cmdb["CMDB_URL_BASE"] = "http://elsewhere:1"  # type: ignore[index]
    assert set(dict(rec_direct.systems)) == set(dict(rec.systems)), sorted(rec_direct.systems)

    # elastic: an ElasticSettings exposing the seven named attributes, ssl_verify the raw string.
    ElasticSettings = S.record_type("ElasticSettings")
    assert isinstance(rec.elastic, ElasticSettings), type(rec.elastic)
    assert rec.elastic.events_index == "d0-events-*"
    assert rec.elastic.alerts_index == "d0-alerts-*"
    assert rec.elastic.url == "https://es-d0:9200"
    assert rec.elastic.ssl_verify == "true"
    assert rec.elastic.es_container == S.es_container("d0")
    assert rec.elastic.kibana_container == S.kibana_container("d0")
    assert rec.elastic.docker_context == S.context_name("d0", "elastic")

    # ticket_mapping: a CaseMapping; secrets: a SecretLookup whose get(name) -> str | ConfigFault.
    assert isinstance(rec.ticket_mapping, S.record_type("CaseMapping")), type(rec.ticket_mapping)
    assert isinstance(rec.secrets, S.record_type("SecretLookup")), type(rec.secrets)
    value = rec.secrets.get("X_TOKEN")
    assert isinstance(value, str), value
    assert value == "d0-planted-secret", value
    with pytest.raises(S.config_fault()):
        rec.secrets.get("NOT_DECLARED_ANYWHERE")

    # Neither resolver raises for a system fault: kept as the entry, not TenantRefused.
    S.config_path(folder, "cmdb").unlink()
    faulted = _resolve(root)
    assert isinstance(faulted.systems["cmdb"], S.config_fault()), faulted.systems["cmdb"]
    assert issubclass(S.tenant_refused(), Exception)

    # VerbContext and AgentDeps: the record in a field named `tenant`, no `settings_dir`.
    VerbContext = S.mod("runtime.verbs").VerbContext
    ctx_fields = {f.name for f in dataclasses.fields(VerbContext)}
    assert S.RECORD_FIELD in ctx_fields, sorted(ctx_fields)
    assert "settings_dir" not in ctx_fields, sorted(ctx_fields)
    AgentDeps = S.mod("runtime.tools._deps").AgentDeps
    deps_fields = {f.name for f in dataclasses.fields(AgentDeps)}
    assert S.RECORD_FIELD in deps_fields, sorted(deps_fields)
    assert "settings_dir" not in deps_fields, sorted(deps_fields)
    ctx = _ctx(rec, tmp_path)
    assert S.record_on(ctx) is rec

    # load_config keeps its return: a dict of prefix-stripped keys.
    cfg = transport.load_config(ctx, "cmdb", "CMDB")
    assert isinstance(cfg, dict), type(cfg)
    assert cfg == {"URL_BASE": "http://cmdb-d0:8080", "BASTION_HOST": "bastion-d0",
                   "TIMEOUT_SEC": "10"}, cfg

    # A transport is asked for a secret by its declared name; the value reaches that one child.
    shim = S.DockerShim(tmp_path / "shim", [S.answer("{}", "200")])
    sctx = _ctx(rec, tmp_path, shim.env({"PATH": os.environ.get("PATH", "")}))
    transport.docker_exec_curl(sctx, "bastion-d0", "http://cmdb-d0:8080/health",
                               **{S.SECRETS_KW: ("X_TOKEN",)})
    calls = shim.calls()
    assert len(calls) == 1, calls
    assert "d0-planted-secret" in calls[0]["env"].values(), "the secret did not reach the child"
    assert not any("d0-planted-secret" in a for a in calls[0]["argv"]), calls[0]["argv"]

    # record_case_ticket / open_case_ticket return None and never raise; the receipt shape.
    unconfigured = tmp_path / "unconfigured"
    bare = S.plant(unconfigured, marker="d0u")
    S.config_path(bare, "case-history").unlink()
    run_dir = tmp_path / "runs" / "r-d0"
    run_dir.mkdir(parents=True)
    env = shim.env({"PATH": os.environ.get("PATH", "")})
    assert S.open_step(run_dir, _resolve(unconfigured), env=env) is None
    assert S.record_step(run_dir, _resolve(unconfigured), env=env) is None
    failure = S.receipt(run_dir)
    assert failure is not None, "no receipt for a failed record step"
    assert set(failure) == {"key", "status", "url", "ok", "reason"}, failure
    assert failure["status"] == "error", failure
    assert failure["ok"] is False, failure
    assert failure["url"] is None, failure
    assert isinstance(failure["reason"], str), failure
    assert failure["reason"].strip(), failure

    ok_dir = tmp_path / "runs" / "r-d0ok"
    ok_dir.mkdir(parents=True)
    shim.respond(*S.store_answers_ok(ok_dir.name))
    # `aborted`: the escalation note, the one arm that posts without a report in the run dir.
    assert S.record_step(ok_dir, rec, env=env, truncated_by="aborted") is None
    success = S.receipt(ok_dir)
    assert success is not None, "no receipt for a successful record step"
    assert set(success) == {"key", "status", "url", "ok", "reason"}, success
    assert success["ok"] is True, success
    assert success["reason"] is None, success
    assert success["status"] != "error", success

    # The branch launcher refuses with its existing LauncherRefused, a SystemExit.
    assert issubclass(S.mod("learning.branch.cli").LauncherRefused, SystemExit)

    # lint_tenant_env_reads.main(argv) -> int: 0 clean, non-zero with path:line findings.
    clean = tmp_path / "lint-clean"
    S.plant_module(clean, "defender/scripts/adapters/quiet.py", "X = 1\n")
    rc, out = S.run_env_lint(clean)
    assert isinstance(rc, int), (rc, out)
    assert rc == 0, (rc, out)
    dirty = tmp_path / "lint-dirty"
    S.plant_module(dirty, "defender/scripts/adapters/loud.py",
                   "import os\n\n\ndef url():\n    return os.environ['CMDB_URL_BASE']\n")
    rc, out = S.run_env_lint(dirty)
    assert isinstance(rc, int), (rc, out)
    assert rc != 0, (rc, out)
    assert "loud.py:5" in out, out

    # validate_scaffold.check_config keeps its signature and reports through Report's rows.
    vs = load_module(S.DEFENDER / "skills" / "connect" / "validate_scaffold.py",
                     name="vscaffold1107")
    assert list(inspect.signature(vs.check_config).parameters) == [
        "report", "settings_dir", "system"]
    report = vs.Report()
    vs.check_config(report, S.settings_of(folder), "identity")
    assert report.rows, report.rows
    assert (all(status in (vs.PASS, vs.WARN, vs.FAIL)
                               for status, _msg in report.rows)), report.rows


def test_d_record_fields_from_resolver():
    """resolve_tenant over a tenant folder returns the same RunTenant type, now carrying systems (one
    entry per folder under settings/systems/), elastic, ticket_mapping and secrets, all built by
    resolve_run_tenant. For the committed playground tenant every systems entry is a SystemConfig,
    elastic is an ElasticSettings, ticket_mapping is a CaseMapping and secrets is a SecretLookup."""
    tenants_root = S.REPO_ROOT / "knowledge" / "tenants"
    rec = _resolve(tenants_root, S.PLAYGROUND_ID)
    built = run_tenant.resolve_run_tenant(
        S.tenant_folder_of(tenants_root, S.PLAYGROUND_ID), defender_dir=S.DEFENDER,
        dispatches_lead_zero=False)

    assert type(rec) is run_tenant.RunTenant
    folders = {p.name for p in (S.PLAYGROUND / "settings" / "systems").iterdir()
               if p.is_dir() and not p.name.startswith(".")}
    assert set(rec.systems) == folders, (sorted(rec.systems), sorted(folders))
    SystemConfig = S.record_type("SystemConfig")
    for name, entry in rec.systems.items():
        assert isinstance(entry, SystemConfig), (name, entry)
    assert isinstance(rec.elastic, S.record_type("ElasticSettings")), rec.elastic
    assert isinstance(rec.ticket_mapping, S.record_type("CaseMapping")), rec.ticket_mapping
    assert isinstance(rec.secrets, S.record_type("SecretLookup")), rec.secrets
    # Built by resolve_run_tenant: the frame resolve_tenant delegates to gives the same fields.
    assert set(built.systems) == set(rec.systems)
    for name in rec.systems:
        assert dict(built.systems[name]) == dict(rec.systems[name]), name
    attrs = ("events_index", "alerts_index", "url", "ssl_verify", "es_container",
             "kibana_container", "docker_context")
    assert [getattr(built.elastic, a) for a in attrs] == [getattr(rec.elastic, a) for a in attrs]


def test_d_systems_verbatim(tmp_path):
    """A SystemConfig holds its config.env's keys exactly as written, prefix included (CMDB_URL_BASE,
    not URL_BASE), each mapped to its string value. systems has exactly one entry per folder under
    settings/systems/, and the entry is keyed by the folder name."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="vb")
    S.write_config(folder, "extra-sys", 'EXTRA_SYS_URL_BASE="http://extra-vb:1"\n')

    rec = _resolve(root)

    assert set(rec.systems) == {*S.PREFIX, "extra-sys"}, sorted(rec.systems)
    assert dict(rec.systems["cmdb"]) == {
        "CMDB_URL_BASE": "http://cmdb-vb:8080",
        "CMDB_BASTION_HOST": "bastion-vb",
        "CMDB_TIMEOUT_SEC": "10",
        "CMDB_TRANSPORT": S.DOCKER_EXEC,
        "CMDB_DOCKER_CONTEXT": S.context_name("vb", "cmdb"),
    }, dict(rec.systems["cmdb"])
    assert "URL_BASE" not in rec.systems["cmdb"], "the prefix was stripped at resolve"
    assert dict(rec.systems["extra-sys"]) == {"EXTRA_SYS_URL_BASE": "http://extra-vb:1"}
    elastic = dict(rec.systems["elastic"])
    assert elastic["ELASTIC_EVENTS_INDEX"] == "vb-events-*", elastic
    assert elastic["KIBANA_URL"] == "http://kibana-vb:5601", elastic


def test_d_systems_fault_kept(tmp_path):
    """A system folder whose config.env is missing, or whose config.env is not UTF-8 text, is kept in
    systems as a ConfigFault, and resolve_tenant returns normally. Asking that system for a value
    through load_config raises that ConfigFault."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="fk")
    S.config_path(folder, "cmdb").unlink()
    # RG4n (executed): these bytes raise an uncaught UnicodeDecodeError out of every reader today.
    S.write_config(folder, "identity", S.config_texts("fk")["identity"].encode("utf-8").replace(
        b"identity-fk", b"identity-\xff\xfe"))

    rec = _resolve(root)  # returns normally

    ConfigFault = S.config_fault()
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    assert isinstance(rec.systems["identity"], ConfigFault), rec.systems["identity"]
    assert isinstance(rec.systems["ticket"], S.record_type("SystemConfig")), rec.systems["ticket"]
    ctx = _ctx(rec, tmp_path)
    for system, prefix in (("cmdb", "CMDB"), ("identity", "IDENTITY")):
        with pytest.raises(ConfigFault) as raised:
            transport.load_config(ctx, system, prefix)
        # the contract is the outcome (s008), so the SAME fault's text, not its identity
        assert str(raised.value) == str(rec.systems[system]), (system, str(raised.value))


def test_d_no_folder_fault_text(tmp_path):
    """Asking for a system with no folder under settings/systems/ raises ConfigFault whose text says
    "this tenant's settings do not configure this system", the same fault load_config raises at base
    (CX5)."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="nf")
    rec = _resolve(root)
    ctx = _ctx(rec, tmp_path)

    assert "nosuch" not in rec.systems, sorted(rec.systems)
    with pytest.raises(S.config_fault()) as raised:
        transport.load_config(ctx, "nosuch", "NOSUCH")
    assert S.NOT_CONFIGURED in str(raised.value), str(raised.value)
    assert raised.value.exit_code == 2

    # The folder set is the record's: a folder planted after resolve is still not configured.
    S.write_config(folder, "late", 'LATE_URL_BASE="http://late:1"\nLATE_BASTION_HOST="b"\n'
                   'LATE_TIMEOUT_SEC="10"\n')
    with pytest.raises(S.config_fault()) as late:
        transport.load_config(ctx, "late", "LATE")
    assert S.NOT_CONFIGURED in str(late.value), str(late.value)


def test_d_elastic_view(tmp_path):
    """record.elastic is None when the tenant has no systems/elastic/ folder. It is a ConfigFault when
    that folder's config.env is missing, or when it lacks any of ELASTIC_EVENTS_INDEX,
    ELASTIC_ALERTS_INDEX, ELASTICSEARCH_URL, ELASTIC_SSL_VERIFY, ELASTIC_ES_CONTAINER,
    ELASTIC_KIBANA_CONTAINER or ELASTIC_DOCKER_CONTEXT, when any of them is present but blank
    (F3/NF-18: presence and non-blank only; values such as CHANGE-ME are carried), or when
    ELASTIC_TRANSPORT is absent or other than docker-exec (MF-7 a, human). Otherwise it is an
    ElasticSettings that carries those values from the file. resolve_tenant raises in none of these
    cases. The part is all-or-nothing over that key set (MF-7 b, human): a missing Kibana container
    makes it a ConfigFault even for a tenant that uses only Elasticsearch."""
    ConfigFault = S.config_fault()
    ElasticSettings = S.record_type("ElasticSettings")
    root = tmp_path / "tenants"

    def elastic_of(tenant_id: str, *, text: str | None, folder_too: bool = True) -> object:
        configs = S.config_texts(tenant_id)
        configs.pop("elastic")
        folder = S.plant(root, tenant_id, marker=tenant_id, configs=configs)
        if folder_too:
            (S.settings_of(folder) / "systems" / "elastic").mkdir(parents=True, exist_ok=True)
        if text is not None:
            S.write_config(folder, "elastic", text)
        return _resolve(root, tenant_id).elastic  # never raises

    full = S.config_texts("ev")["elastic"]

    def without(key: str) -> str:
        return "".join(ln + "\n" for ln in full.splitlines() if not ln.startswith(f"{key}="))

    def with_value(key: str, value: str) -> str:
        return without(key) + f'{key}="{value}"\n'

    assert elastic_of("no-folder", text=None, folder_too=False) is None
    assert isinstance(elastic_of("no-file", text=None), ConfigFault)

    good = elastic_of("good", text=full)
    assert isinstance(good, ElasticSettings), good
    assert (good.events_index, good.alerts_index, good.url, good.ssl_verify) == (
        "ev-events-*", "ev-alerts-*", "https://es-ev:9200", "true")
    assert (good.es_container, good.kibana_container, good.docker_context) == (
        S.es_container("ev"), S.kibana_container("ev"), S.context_name("ev", "elastic"))

    for i, key in enumerate(S.ELASTIC_VIEW_KEYS):
        missing = elastic_of(f"miss-{i}", text=without(key))
        assert isinstance(missing, ConfigFault), (key, missing)
        blank = elastic_of(f"blank-{i}", text=with_value(key, ""))
        assert isinstance(blank, ConfigFault), (key, blank)
    # MF-7 a (human): ELASTIC_TRANSPORT = docker-exec is part of the view.
    assert isinstance(elastic_of("no-transport", text=without("ELASTIC_TRANSPORT")), ConfigFault)
    assert isinstance(elastic_of("http-transport",
                                 text=with_value("ELASTIC_TRANSPORT", "http")), ConfigFault)
    # MF-7 b (human): all-or-nothing — a tenant using only Elasticsearch still needs Kibana's.
    assert isinstance(elastic_of("no-kibana", text=without("ELASTIC_KIBANA_CONTAINER")),
                      ConfigFault)
    # F3/NF-18: presence and non-blank only — placeholders are carried, not validated.
    carried = elastic_of("carried", text=with_value(
        "ELASTICSEARCH_URL", "CHANGE-ME").replace('ELASTIC_SSL_VERIFY="true"',
                                                  'ELASTIC_SSL_VERIFY="maybe"'))
    assert isinstance(carried, ElasticSettings), carried
    assert carried.url == "CHANGE-ME", carried
    assert carried.ssl_verify == "maybe", carried


def test_d_ticket_mapping_kept(tmp_path):
    """resolve_tenant loads systems/case-history/mapping.yaml once into ticket_mapping. A valid file
    becomes a CaseMapping. A file that is not YAML, not a mapping, or fails the lifecycle check is
    kept as its CaseTicketError and is never raised at resolve."""
    root = tmp_path / "tenants"
    CaseTicketError = S.case_ticket_error()
    cases = {
        "valid": T1106.mapping_text(),
        "not-yaml": "open: [unclosed\n  status: : :\n",
        "not-a-mapping": "- open\n- released\n",
        "lifecycle": T1106.mapping_text(released_status="open"),  # open == released
    }
    got = {}
    for tenant_id, text in cases.items():
        folder = S.plant(root, tenant_id, marker=tenant_id)
        S.mapping_path(folder).write_text(text, encoding="utf-8")
        got[tenant_id] = _resolve(root, tenant_id).ticket_mapping  # never raised

    assert isinstance(got["valid"], S.record_type("CaseMapping")), got["valid"]
    for bad in ("not-yaml", "not-a-mapping", "lifecycle"):
        assert isinstance(got[bad], CaseTicketError), (bad, got[bad])


def test_o5_resolve_keeps_system_faults(tmp_path):
    """resolve_tenant never raises because of a system's config. A missing or undecodable config.env, a
    missing or bad elastic part, and a bad mapping are each returned as the record's fault entry.
    TenantRefused (defender._tenant) keeps only its current tenant-acceptance reasons."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="o5")
    S.config_path(folder, "cmdb").unlink()
    S.write_config(folder, "identity", b"IDENTITY_URL_BASE=\xff\n")
    S.drop_key(folder, "elastic", "ELASTIC_ES_CONTAINER")
    S.mapping_path(folder).write_text("- not\n- a mapping\n", encoding="utf-8")
    rec = _resolve(root)  # never raises because of a system's config
    ConfigFault = S.config_fault()
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    assert isinstance(rec.systems["identity"], ConfigFault), rec.systems["identity"]
    assert isinstance(rec.elastic, ConfigFault), rec.elastic
    assert isinstance(rec.ticket_mapping, S.case_ticket_error()), rec.ticket_mapping

    configs = S.config_texts("o5b")
    configs.pop("elastic")
    S.plant(root, "no-elastic", marker="o5b", configs=configs)
    assert _resolve(root, "no-elastic").elastic is None

    # TenantRefused keeps its tenant-acceptance reasons, each still refusing.
    TenantRefused = S.tenant_refused()
    missing_mapping = S.plant(root, "no-mapping", marker="o5c")
    S.mapping_path(missing_mapping).unlink()  # REQUIRED_SETTINGS (MF-10 A, human)
    with pytest.raises(TenantRefused) as refused:
        _resolve(root, "no-mapping")
    assert "mapping.yaml" in str(refused.value), str(refused.value)
    linked = S.plant(root, "linked", marker="o5d")
    outside = tmp_path / "outside.env"
    outside.write_text('CMDB_URL_BASE="http://outside:1"\n', encoding="utf-8")
    S.config_path(linked, "cmdb").unlink()
    S.config_path(linked, "cmdb").symlink_to(outside)
    with pytest.raises(TenantRefused):
        _resolve(root, "linked")
    with pytest.raises(TenantRefused):
        _resolve(root, "absent")


def test_s7_nf22_systems_keyed_by_exact_directory_name(tmp_path):
    """systems has one entry per non-hidden directory under settings/systems/, keyed by its name
    exactly as listed; plain files and dot-directories are skipped. A case variant (CMDB/, Elastic/)
    is not the system: systems["cmdb"] gives "this tenant's settings do not configure this system"
    and elastic is None. A stray directory such as cmdb.orig/ is an entry, and its *_SECRET_REF
    declarations count (MF-1: tenant-wide)."""
    configs = S.config_texts("nf22")
    configs["CMDB"] = configs.pop("cmdb")
    configs["Elastic"] = configs.pop("elastic")
    configs["cmdb.orig"] = 'ORIG_TOKEN_SECRET_REF="ORIG_TOKEN"\n'
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="nf22", configs=configs, secrets={"ORIG_TOKEN": "orig-secret"})
    systems_dir = S.settings_of(folder) / "systems"
    (systems_dir / "README.txt").write_text("not a system\n", encoding="utf-8")
    (systems_dir / ".hidden").mkdir()
    (systems_dir / ".hidden" / "config.env").write_text(
        'HIDDEN_URL_BASE="http://hidden-nf22:1"\n', encoding="utf-8")

    rec = _resolve(root)

    expected = {name for name in configs}
    assert set(rec.systems) == expected, (sorted(rec.systems), sorted(expected))
    assert "cmdb" not in rec.systems
    assert "elastic" not in rec.systems
    assert rec.elastic is None, rec.elastic
    with pytest.raises(S.config_fault()) as raised:
        transport.load_config(_ctx(rec, tmp_path), "cmdb", "CMDB")
    assert S.NOT_CONFIGURED in str(raised.value), str(raised.value)
    # MF-1 (human): tenant-wide — the stray folder's declaration counts.
    assert rec.secrets.get("ORIG_TOKEN") == "orig-secret"


def test_s7_nf16_unreadable_config_env_kept_as_fault(tmp_path):
    """Any OSError reading one system's config.env (a directory in its place, EACCES, EIO) is kept as
    that system's ConfigFault in systems and never raised out of resolve; files in REQUIRED_SETTINGS
    keep #1106's TenantRefused."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="nf16")
    cmdb_env = S.config_path(folder, "cmdb")
    cmdb_env.unlink()
    cmdb_env.mkdir()  # a directory in the file's place: reading it raises IsADirectoryError
    unreadable = S.config_path(folder, "identity")
    root_user = os.geteuid() == 0
    if not root_user:
        unreadable.chmod(0)  # EACCES; as root the mode does not deny a read, so this arm is skipped

    try:
        rec = _resolve(root)
    finally:
        unreadable.chmod(0o644)

    ConfigFault = S.config_fault()
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    if not root_user:
        assert isinstance(rec.systems["identity"], ConfigFault), rec.systems["identity"]
    assert isinstance(rec.systems["ticket"], S.record_type("SystemConfig"))

    # REQUIRED_SETTINGS keep #1106's TenantRefused (the control that refusal still bites).
    required = S.plant(root, "required-dir", marker="nf16b")
    grants = S.settings_of(required) / "verb-grants.yaml"
    grants.unlink()
    grants.mkdir()
    with pytest.raises(S.tenant_refused()):
        _resolve(root, "required-dir")


def test_s7_rg4_non_utf8_is_config_fault(tmp_path):
    """Non-UTF-8 bytes are that system down, never an uncaught UnicodeDecodeError. A non-UTF-8
    config.env leaves its system a ConfigFault in systems (and elastic's makes record.elastic a
    ConfigFault) while resolve_tenant returns normally; a non-UTF-8 secrets.env makes the lookup of
    a declared name raise ConfigFault naming the reference. Today all three readers raise
    UnicodeDecodeError (RG4)."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="rg4")
    # RG4n (executed): 0xff raises UnicodeDecodeError out of every reader today.
    texts = S.config_texts("rg4")
    S.write_config(folder, "cmdb", texts["cmdb"].encode("utf-8").replace(
        b"cmdb-rg4", b"cmdb-\xff"))
    # every elastic key present and non-blank: only the bytes make the part a fault
    S.write_config(folder, "elastic", texts["elastic"].encode("utf-8").replace(
        b"es-rg4:9200", b"es-\xff:9200"))
    S.set_key(folder, "identity", "X_TOKEN_SECRET_REF", "X_TOKEN")
    S.write_secrets(folder, b'X_TOKEN="val-\xff\xfe"\n')

    rec = _resolve(root)  # returns normally

    ConfigFault = S.config_fault()
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    assert isinstance(rec.elastic, ConfigFault), rec.elastic
    with pytest.raises(ConfigFault) as raised:
        rec.secrets.get("X_TOKEN")
    assert "X_TOKEN_SECRET_REF" in str(raised.value), str(raised.value)


def test_s7_nf4_every_resolve_reads_the_folder_fresh(tmp_path, monkeypatch):
    """Every resolve builds its record from the tenant folder as of that call: a second run.main in one
    process, and each replay drive, reflects an edit made between them; nothing memoizes a record, a
    parsed config or a mapping across calls or across tenants."""
    # No arm here forks a transport; the shim first on PATH makes sure a stray one cannot
    # reach the real docker (CX8).
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "shim").path_value())
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="nf4")
    S.plant(root, "other", marker="nf4o")

    # resolve_tenant / resolve_run_tenant, twice around an edit (RG5, refuted: no cache).
    first = _resolve(root)
    S.set_key(folder, "cmdb", "CMDB_URL_BASE", "http://cmdb-edited:1")
    S.mapping_path(folder).write_text(T1106.mapping_text(released_status="done"),
                                      encoding="utf-8")
    second = _resolve(root)
    direct = run_tenant.resolve_run_tenant(
        S.tenant_folder_of(root), defender_dir=S.DEFENDER, dispatches_lead_zero=False)
    assert first.systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-nf4:8080"
    assert second.systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-edited:1"
    assert direct.systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-edited:1"
    case_ticket = S.mod("scripts.case_history.case_ticket")
    assert case_ticket.release_predicate(second.ticket_mapping).is_released({"status": "done"})
    assert not case_ticket.release_predicate(first.ticket_mapping).is_released(
        {"status": "done"})
    # ...and across tenants: resolving another tenant in between memoizes nothing.
    assert _resolve(root, "other").systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-nf4o:8080"
    assert _resolve(root).systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-edited:1"

    # A second run.main in one process reflects an edit made between the two. (run.main takes
    # its runs base from the data root, whose `playground` tenant is created on request.)
    ensure_d9_tenant()
    alert = S.plant_alert(tmp_path / "alert")
    seen: list[str] = []
    for run_id, url in (("r-nf4-a", "http://cmdb-run-a:1"), ("r-nf4-b", "http://cmdb-run-b:1")):
        S.set_key(folder, "cmdb", "CMDB_URL_BASE", url)
        rec_ = S.RunRecorder(tmp_path / "runs" / run_id)
        rc, refused = S.drive_run(S.run_argv(alert, root, run_id=run_id), rec_,
                                  visualize=rec_.visualize)
        assert refused is None, (rc, refused)
        assert rc == 0, (rc, refused)
        seen.append(rec_.lifecycle_calls[0]["tenant"].systems["cmdb"]["CMDB_URL_BASE"])
    assert seen == ["http://cmdb-run-a:1", "http://cmdb-run-b:1"], seen

    # Each replay drive reflects an edit made between them.
    from defender.tests.e2e import _replay_harness as RH

    urls: list[str] = []

    def get_host(ctx, *, host: str = "web-1") -> dict:
        urls.append(S.record_on(ctx).systems["cmdb"]["CMDB_URL_BASE"])
        return {"host": host}

    for n, url in enumerate(("http://cmdb-drive-a:1", "http://cmdb-drive-b:1")):
        S.set_key(folder, "cmdb", "CMDB_URL_BASE", url)
        run_dir = RH.materialize(tmp_path / f"drive-{n}", RH.GOLDEN_AB3)
        RH.drive(
            run_dir, run_id=f"nf4-drive-{n}",
            main=RH.ReplayFn([
                RH.Turn(tool_calls=[("gather", {
                    "lead_id": "l-001", "system": "cmdb", "goal": "measure cmdb",
                    "what_to_summarize": ["what the system says"]})]),
                RH.Turn(text="Investigation complete."),
            ]),
            gather=RH.ReplayFn([
                RH.Turn(tool_calls=[("query", {"system": "cmdb", "verb": "get-host",
                                               "params": {"host": "web-1"}})]),
                RH.Turn(text="Summary: measured the lead."),
            ]),
            verbs=RH.FakeVerbs({"cmdb": {"get-host": get_host}}),
            tenant=S.tenant_folder_of(root))
    assert urls == ["http://cmdb-drive-a:1", "http://cmdb-drive-b:1"], urls


def _closure(module: str) -> tuple[int, str, set[str]]:
    """`(exit, stderr, sys.modules)` of a FRESH interpreter after importing `module`."""
    proc = subprocess.run(  # noqa: S603 — this interpreter, a fixed program
        [sys.executable, "-c",
         f"import json, sys, {module}; print(json.dumps(sorted(sys.modules)))"],
        capture_output=True, text=True, encoding="utf-8", timeout=120, check=False,
        env={**os.environ, "PYTHONPATH": str(S.REPO_ROOT)})
    lines = proc.stdout.strip().splitlines()
    return proc.returncode, proc.stderr, set(json.loads(lines[-1])) if lines else set()


def test_d1096_record_types_outside_closure():
    """Importing defender.runtime.bash_exec in a fresh interpreter, and separately
    defender.runtime.box_codec, loads no module that defines SystemConfig, ElasticSettings,
    CaseMapping or SecretLookup."""
    closures = {}
    for module in ("defender.runtime.bash_exec", "defender.runtime.box_codec"):
        rc, err, loaded = _closure(module)
        # the probe is live: the import succeeded and the closure holds the imported module
        assert rc == 0, (module, rc, err)
        assert module in loaded, (module, rc, err)
        closures[module] = loaded

    defining = {name: S.record_type(name).__module__ for name in FOUR_TYPES}
    for module, loaded in closures.items():
        leaked = {name: where for name, where in defining.items() if where in loaded}
        assert not leaked, f"importing {module} loads {leaked}"


def test_d1096_record_types_importable():
    """Importing the record's module (runtime.run_tenant) makes SystemConfig, ElasticSettings,
    CaseMapping and SecretLookup available."""
    import importlib

    record_module = importlib.import_module("defender.runtime.run_tenant")
    for name in FOUR_TYPES:
        assert isinstance(getattr(record_module, name, None), type), (
            f"runtime.run_tenant does not make {name} available")


def test_s3_link_check_covers_secrets(tmp_path):
    """resolve_tenant refuses with TenantRefused a tenant whose settings/secrets.env is a link to a
    file outside the folder, and accepts the same tenant with a plain secrets.env (CX6)."""
    # CX6 (executed, unrefuted): the link walk already covers settings/secrets.env — a
    # survival pin, green at base by design.
    root = tmp_path / "tenants"
    S.plant(root, "plain", marker="s3p", secrets={"X_TOKEN": "plain-value"})
    linked = S.plant(root, "linked", marker="s3l")
    outside = tmp_path / "outside.env"
    outside.write_text('X_TOKEN="outside-value"\n', encoding="utf-8")
    S.secrets_path(linked).symlink_to(outside)

    accepted = _resolve(root, "plain")
    assert accepted.tenant_id == "plain"
    with pytest.raises(S.tenant_refused()) as refused:
        _resolve(root, "linked")
    assert S.SECRETS_ENV in str(refused.value), str(refused.value)


def test_o1_resolver_ignores_env(tmp_path, monkeypatch):
    """With those variables exported, resolve_tenant's systems and elastic carry the tenant file's
    values."""
    exported = {
        "CMDB_URL_BASE": "http://from-env:1",
        "TICKET_KEY_PATTERN": "ENV-[0-9]+",
        "ELASTIC_EVENTS_INDEX": "env-events-*",
        "ELASTIC_ALERTS_INDEX": "env-alerts-*",
        "ELASTICSEARCH_URL": "https://from-env:9200",
        "ELASTIC_SSL_VERIFY": "false",
        "SOC_PLAYGROUND_DOCKER_CONTEXT": "env-context",
        "SOC_PLAYGROUND_ES_CONTAINER": "env-es",
        "CMDB_DOCKER_CONTEXT": "env-cmdb-context",
        "ELASTIC_ES_CONTAINER": "env-es-container",
        "ELASTIC_DOCKER_CONTEXT": "env-elastic-context",
    }
    for key, value in exported.items():
        monkeypatch.setenv(key, value)
    root = tmp_path / "tenants"
    S.plant(root, marker="o1r")

    rec = _resolve(root)

    cmdb = rec.systems["cmdb"]
    assert cmdb["CMDB_URL_BASE"] == "http://cmdb-o1r:8080", dict(cmdb)
    assert cmdb["CMDB_DOCKER_CONTEXT"] == S.context_name("o1r", "cmdb"), dict(cmdb)
    assert rec.systems["ticket"]["TICKET_KEY_PATTERN"] == "O1R-[0-9]+"
    assert rec.elastic.events_index == "o1r-events-*"
    assert rec.elastic.alerts_index == "o1r-alerts-*"
    assert rec.elastic.url == "https://es-o1r:9200"
    assert rec.elastic.ssl_verify == "true"
    assert rec.elastic.es_container == S.es_container("o1r")
    assert rec.elastic.docker_context == S.context_name("o1r", "elastic")


def test_s7_mf8_resolve_warns_missing_access_method(tmp_path, caplog):
    """Resolving a tenant folder that predates D2 (config.env files without <PREFIX>_TRANSPORT or
    <PREFIX>_DOCKER_CONTEXT) logs one warning at resolve listing the systems whose config lacks an
    access-method key. Resolve does not refuse, and each such system faults on its first call with
    text naming the missing key (for example "CMDB_TRANSPORT is not set")."""
    def without(text: str, key: str) -> str:
        return "".join(ln + "\n" for ln in text.splitlines() if not ln.startswith(f"{key}="))

    configs = S.config_texts("mf8")
    # A folder that predates D2: cmdb's config is #1106's (neither access-method key); ticket
    # lacks only its TRANSPORT, identity only its DOCKER_CONTEXT; the rest are complete.
    configs["cmdb"] = T1106.config_texts("mf8")["cmdb"]
    configs["ticket"] = without(configs["ticket"], "TICKET_TRANSPORT")
    configs["identity"] = without(configs["identity"], "IDENTITY_DOCKER_CONTEXT")
    root = tmp_path / "tenants"
    S.plant(root, marker="mf8", configs=configs)

    with caplog.at_level(logging.WARNING):
        rec = _resolve(root)  # does not refuse

    lacking = ("cmdb", "ticket", "identity")
    warned = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
              and any(name in r.getMessage() for name in lacking)]
    assert len(warned) == 1, [r.getMessage() for r in caplog.records]
    assert all(name in warned[0] for name in lacking), warned[0]
    assert "change-mgmt" not in warned[0], warned[0]  # complete: not listed

    shim = S.DockerShim(tmp_path / "shim", [S.answer('{"host": "web-1"}', "200")])
    ctx = _ctx(rec, tmp_path, shim.env({"PATH": os.environ.get("PATH", "")}))
    cmdb_fault = _fault_text(S.mod("scripts.adapters.cmdb_adapter").get_host, ctx, host="web-1")
    ticket_fault = _fault_text(S.mod("scripts.adapters.ticket_adapter").health_check, ctx)
    identity_fault = _fault_text(S.mod("scripts.adapters.identity_adapter").health_check, ctx)
    assert "CMDB_TRANSPORT" in cmdb_fault or "CMDB_DOCKER_CONTEXT" in cmdb_fault, cmdb_fault
    assert "TICKET_TRANSPORT" in ticket_fault, ticket_fault
    assert "IDENTITY_DOCKER_CONTEXT" in identity_fault, identity_fault
    assert shim.calls() == [], "a system down for its access method still spawned docker"


def _config_keys(path: Path) -> set[str]:
    """The key names a committed `config.env` spells (`KEY=` lines; comments skipped)."""
    keys = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            keys.add(line.split("=", 1)[0].strip())
    return keys


def test_d2_shipped_tenants_complete():
    """The committed playground tenant and knowledge/tenant-template/ carry every new line. Each system
    folder, host-state's new one included, has <PREFIX>_TRANSPORT and <PREFIX>_DOCKER_CONTEXT, and
    elastic's also has ELASTIC_ES_CONTAINER and ELASTIC_KIBANA_CONTAINER. Resolving the playground
    tenant leaves no ConfigFault in systems or elastic."""
    for tenant_settings in (S.PLAYGROUND / "settings", S.TEMPLATE_DIR / "settings"):
        systems = tenant_settings / "systems"
        folders = sorted(p.name for p in systems.iterdir() if p.is_dir())
        assert "host-state" in folders, (tenant_settings, folders)
        for name in folders:
            assert name in S.PREFIX, f"{tenant_settings}: no known prefix for system {name!r}"
            prefix = S.PREFIX[name]
            config_env = systems / name / "config.env"
            assert config_env.is_file(), config_env
            keys = _config_keys(config_env)
            needed = {f"{prefix}_TRANSPORT", f"{prefix}_DOCKER_CONTEXT"}
            if name == "elastic":
                needed |= {"ELASTIC_ES_CONTAINER", "ELASTIC_KIBANA_CONTAINER"}
            assert needed <= keys, (tenant_settings, name, sorted(needed - keys))

    rec = _resolve(S.REPO_ROOT / "knowledge" / "tenants", S.PLAYGROUND_ID)
    ConfigFault = S.config_fault()
    faulted = {name: str(entry) for name, entry in rec.systems.items()
               if isinstance(entry, ConfigFault)}
    assert not faulted, faulted
    assert isinstance(rec.elastic, S.record_type("ElasticSettings")), rec.elastic


def test_defender_policy_over_a_tenant_whose_systems_are_broken(tmp_path, capsys):
    """defender-policy (policy_cli, which resolves through resolve_tenant) over a tenant whose system
    configs are broken resolves without raising: the broken systems' entries in systems are
    ConfigFault, and the grants answer for the working systems is unchanged."""
    policy_cli = S.mod("scripts.policy_cli")
    root = tmp_path / "tenants"
    S.plant(root, "healthy", marker="pol")
    broken = S.plant(root, "broken", marker="pol")
    S.config_path(broken, "cmdb").unlink()
    S.write_config(broken, "identity", b"IDENTITY_URL_BASE=\xff\n")
    S.drop_key(broken, "elastic", "ELASTICSEARCH_URL")
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    base = ["show", "gather", "--run-dir", str(run_dir), "--tenants-root", str(root)]

    assert policy_cli.main([*base, "--tenant", "healthy"]) == 0
    healthy_out = capsys.readouterr().out
    assert policy_cli.main([*base, "--tenant", "broken"]) == 0  # resolves without raising
    broken_out = capsys.readouterr().out
    assert "agent: gather" in broken_out, broken_out
    assert broken_out == healthy_out, "the grants answer moved with a system's config"

    rec = _resolve(root, "broken")  # the frame policy_cli resolves through
    ConfigFault = S.config_fault()
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    assert isinstance(rec.systems["identity"], ConfigFault), rec.systems["identity"]
    assert isinstance(rec.elastic, ConfigFault), rec.elastic
    assert rec.grants.gather == _resolve(root, "healthy").grants.gather


def test_s60_config_env_fs_confinement(tmp_path):
    """config.env is read only from the tenant's own settings/systems/<system>/ folder
    (tenant-folder-only), the link walk happens once at resolve (link-walk-once-at-resolve), and the
    file is parsed once, not on every adapter call (parsed-once-at-resolve). A break-attempt: a
    config.env reached through a symlink outside the tenant folder, or edited after resolve, does
    not change what the run addresses."""
    root = tmp_path / "tenants"
    outside = tmp_path / "outside.env"
    outside.write_text('CMDB_URL_BASE="http://outside:1"\nCMDB_BASTION_HOST="b"\n'
                       'CMDB_TIMEOUT_SEC="10"\n', encoding="utf-8")
    # A config.env reached through a symlink outside the folder: the link walk refuses it (CX6).
    linked = S.plant(root, "linked", marker="s60l")
    S.config_path(linked, "cmdb").unlink()
    S.config_path(linked, "cmdb").symlink_to(outside)
    with pytest.raises(S.tenant_refused()):
        _resolve(root, "linked")

    folder = S.plant(root, marker="s60")
    rec = _resolve(root)
    ctx = _ctx(rec, tmp_path)
    assert transport.load_config(ctx, "cmdb", "CMDB")["URL_BASE"] == "http://cmdb-s60:8080"

    # Edited after resolve: the run still addresses the value as parsed at resolve.
    S.set_key(folder, "cmdb", "CMDB_URL_BASE", "http://edited:1")
    assert transport.load_config(ctx, "cmdb", "CMDB")["URL_BASE"] == "http://cmdb-s60:8080"
    # Swapped for a link after resolve: the walk ran once, at resolve; nothing reads through it.
    S.config_path(folder, "cmdb").unlink()
    S.config_path(folder, "cmdb").symlink_to(outside)
    assert transport.load_config(ctx, "cmdb", "CMDB")["URL_BASE"] == "http://cmdb-s60:8080"
    assert rec.systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-s60:8080"


def test_a_config_fault_observed_at_resolve_fixed_on_disk_mid_run(tmp_path):
    """A config fault fixed on disk mid-run does not change what the already-resolved run addresses:
    that system stays down (its entry stays the ConfigFault) for the run's whole life; only a fresh
    resolve sees the fix."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="s063")
    fixed = S.config_path(folder, "cmdb").read_text(encoding="utf-8")
    S.config_path(folder, "cmdb").unlink()

    rec = _resolve(root)
    ConfigFault = S.config_fault()
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    ctx = _ctx(rec, tmp_path)
    with pytest.raises(ConfigFault):
        transport.load_config(ctx, "cmdb", "CMDB")

    S.write_config(folder, "cmdb", fixed)  # fixed on disk, mid-run
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    with pytest.raises(ConfigFault):
        transport.load_config(ctx, "cmdb", "CMDB")

    fresh = _resolve(root)  # only a fresh resolve sees the fix
    assert isinstance(fresh.systems["cmdb"], S.record_type("SystemConfig"))
    assert transport.load_config(_ctx(fresh, tmp_path / "fresh"), "cmdb", "CMDB")[
        "URL_BASE"] == "http://cmdb-s063:8080"


def test_s7_mf11_record_parts_read_only(tmp_path):
    """The record's ticket_mapping and each SystemConfig are read-only snapshots: an in-place edit by
    one consumer (the query tool's screen, the estate applier or the record step) raises or lands on
    that consumer's own copy, and the next consumer, including one reached through a VerbContext
    copy (_carrying), sees the resolve-time content."""
    root = tmp_path / "tenants"
    S.plant(root, marker="mf11")
    rec = _resolve(root)
    case_ticket = S.mod("scripts.case_history.case_ticket")
    registry = S.mod("learning.branch.estate.registry")
    ctx = _ctx(rec, tmp_path)
    carried = registry._carrying(ctx, world_id="w-mf11")  # the estate applier's VerbContext copy
    assert carried is not ctx
    assert carried.world_id == "w-mf11"

    # One consumer edits each part in place; the edit raises or lands on its own copy.
    for attempt in (
        lambda: rec.systems["cmdb"].__setitem__("CMDB_URL_BASE", "http://hijacked:1"),
        lambda: rec.systems.__setitem__("cmdb", {"CMDB_URL_BASE": "http://hijacked:1"}),
        lambda: rec.ticket_mapping["released"].__setitem__("status", "hijacked"),
        lambda: rec.ticket_mapping.__setitem__("released", {"status": "hijacked"}),
        lambda: setattr(rec.ticket_mapping, "released", {"status": "hijacked"}),
    ):
        # raising is one of the two outcomes the demand allows
        with contextlib.suppress(Exception):
            attempt()

    for reader in (rec, S.record_on(carried)):
        assert reader.systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-mf11:8080", dict(
            reader.systems["cmdb"])
        predicate = case_ticket.release_predicate(reader.ticket_mapping)
        assert predicate.is_released({"status": "closed"}), "resolve-time released status lost"
        assert not predicate.is_released({"status": "hijacked"}), "an in-place edit leaked"
