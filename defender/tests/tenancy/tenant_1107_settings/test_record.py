"""resolve_tenant / resolve_run_tenant: systems, case-record file never refusing, faults kept per system, fresh read per resolve, read-only parts."""
from __future__ import annotations

from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv
from defender.tests.support.shared._locations_1210 import fixture_data_root

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import contextlib
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from defender.kit import transport
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, ensure_d9_tenant
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

TID = S.PLAYGROUND_ID
RECORD_TYPES = ("SystemConfig",)  # CaseMapping retired with the mapping file (#1359)


def _resolve(root: Path, tenant_id: str = TID, **kw: object) -> object:
    """The real acceptance frame over a planted root (the one frame every entry uses); `records=` as `R.resolve_tenant`."""
    from defender.tests.support.tenancy import _systems1366 as R

    return R.resolve_tenant(
        fixture_data_root(Path(root)), tenant_id, defender_dir=S.DEFENDER, dispatches_lead_zero=False, **kw)


def _unusable(rec: object, system: str, key: str):
    """The settings judgement of `system`'s adapter over the run's record: it raises the `ConfigFault` that names `key`
    and locates the record ("system <s> settings", DC6, never a file). A system record is always its settings
    (#1366 O6: `SystemConfig`); "unusable" is what the adapter's `check_settings` says of them, down at start."""
    adapter = S.mod(f"integrations.{system.replace('-', '_')}_adapter")
    with pytest.raises(S.config_fault(), match=key) as raised:
        adapter.check_settings(rec)
    assert f"system {system} settings" in str(raised.value), str(raised.value)
    return raised.value


def _ctx(record: object, tmp_path: Path, env: Mapping[str, str] | None = None) -> object:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return S.verb_context(record, run_dir, dict(env or {}))


def _settings_empty(rec: object, system: str) -> None:
    """`system`'s record holds NO settings: a `SystemConfig` with no key (what an upgrade-invalidated or unwritten record
    is; the judgement, not a stored fault, says it is unusable, O6)."""
    entry = rec.systems[system]
    assert isinstance(entry, S.record_type("SystemConfig")), entry
    assert len(entry) == 0, dict(entry)


def test_d_systems_verbatim(tmp_path):
    root = tmp_path / "tenants"
    S.plant(root, marker="vb")

    rec = _resolve(root)

    # (the `extra-sys` arm is retired: a system no catalog adapter backs cannot be a record, O4/P2, so it is not one.)
    assert set(rec.systems) == set(S.PREFIX), sorted(rec.systems)
    assert dict(rec.systems["ticket"]) == {
        "TICKET_TIMEOUT_SEC": "10",
        "TICKET_KEY_PATTERN": "VB-[0-9]+",
    }, dict(rec.systems["ticket"])
    assert "KEY_PATTERN" not in rec.systems["ticket"], "the prefix was stripped at resolve"
    elastic = dict(rec.systems["elastic"])
    assert elastic == {"ELASTIC_EVENTS_INDEX": "vb-events-*",
                       "ELASTIC_ALERTS_INDEX": "vb-alerts-*"}, elastic


def _identity_placeholder(folder: Path) -> None:
    """identity's record carries the template's placeholder where its timeout belongs. The store refuses `CHANGE-ME` at write
    (O4), so this is a stand-in for any value the judgement fails: the shape a record an upgrade invalidated has (R12
    'settings an upgrade invalidated'; a rule added later fails a value stored earlier). A record, not a bad file."""
    S.set_key(folder, "identity", "IDENTITY_TIMEOUT_SEC", "CHANGE-ME")


def test_d_systems_fault_kept(tmp_path):
    """A system whose record is unusable (no settings; a placeholder an upgrade invalidated) is that system down only:
    resolve returns, the others keep their config. A system record is always its settings (`SystemConfig`, O6); that they
    are unusable is the adapter's `check_settings` judgement, located at the record ("system <s> settings", DC6), naming
    the key (R12 'record whose settings an upgrade invalidated', P2/O9: a settings FILE that is not UTF-8 can no longer
    reach a run, so that arm is retired; it is seeded as a record that fails the judgement)."""
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="fk")
    S.config_path(folder, "cmdb").unlink()  # the record's settings are empty
    _identity_placeholder(folder)

    rec = _resolve(root)  # returns normally

    SystemConfig = S.record_type("SystemConfig")
    ConfigFault = S.config_fault()
    _settings_empty(rec, "cmdb")
    assert isinstance(rec.systems["ticket"], SystemConfig), rec.systems["ticket"]
    judged = _unusable(rec, "cmdb", "CMDB_TIMEOUT_SEC")
    with pytest.raises(ConfigFault) as raised:
        transport.load_config(_ctx(rec, tmp_path), "cmdb", "CMDB")
    # the contract is the outcome: the verbs raise the judgement's own fault text
    assert str(raised.value) == str(judged), str(raised.value)
    _unusable(rec, "identity", "IDENTITY_TIMEOUT_SEC")
    assert S.mod("integrations.ticket_adapter").check_settings(rec) is None


def test_d_a_case_record_never_refuses_the_tenant(tmp_path):
    """Acceptance never refuses a tenant over its case record, whatever it names, whether it covers the comment route, or
    whether there is one; only a required settings file does (D-12, r4 Data). The record leg judges it (C5). The
    retired arms (a case-record FILE that is not YAML, not a mapping) cannot reach a run any more (P2, O9): the stored
    shapes that can are the arms here."""
    root = tmp_path / "tenants"
    cases = {
        "valid": T1106.case_record_text(),
        "names-an-unknown-system": T1106.case_record_text("no-such-system"),
        "empty": "",
    }
    for label, text in cases.items():
        tenant_id = fixture_uuid(f"tenant:{label}")
        folder = S.plant(root, tenant_id, marker=label)
        S.case_record_path(folder).write_text(text, encoding="utf-8")
        _resolve(root, tenant_id)  # never raises

    uncovered = fixture_uuid("tenant:not-covering")
    folder = S.plant(root, uncovered, marker="nc")
    access = S.settings_of(folder) / "systems" / "ticket" / "access.yaml"
    doc = json.loads(access.read_text(encoding="utf-8"))
    doc["writes"] = []  # an upgrade moved the comment route: the stored declaration no longer covers it
    access.write_text(json.dumps(doc), encoding="utf-8")
    _resolve(root, uncovered)  # never raises

    none = fixture_uuid("tenant:no-case-file")
    S.plant(root, none, marker="none", case_system=None)
    _resolve(root, none)  # a tenant with no case system is accepted

    # Control: a required settings file is still a refusal, so the arms above are not vacuous.
    broken = S.plant(root, fixture_uuid("tenant:no-grants"), marker="grants")
    (S.settings_of(broken) / "verb-grants.yaml").unlink()
    with pytest.raises(S.tenant_refused()):
        _resolve(root, fixture_uuid("tenant:no-grants"))


def test_o5_resolve_keeps_system_faults(tmp_path):
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="o5")
    S.config_path(folder, "cmdb").unlink()
    _identity_placeholder(folder)
    rec = _resolve(root)  # never raises because of a system's settings
    _settings_empty(rec, "cmdb")
    _unusable(rec, "cmdb", "CMDB_TIMEOUT_SEC")
    _unusable(rec, "identity", "IDENTITY_TIMEOUT_SEC")

    # TenantRefused keeps its tenant-acceptance reasons, each still refusing.
    TenantRefused = S.tenant_refused()
    missing_grants = S.plant(root, fixture_uuid("tenant:no-grants"), marker="o5c")
    (S.settings_of(missing_grants) / "verb-grants.yaml").unlink()  # a REQUIRED_SETTINGS file
    with pytest.raises(TenantRefused) as refused:
        _resolve(root, fixture_uuid("tenant:no-grants"))
    assert "verb-grants.yaml" in str(refused.value), str(refused.value)
    # A linked config.env refuses too: test_s60_config_env_fs_confinement.
    with pytest.raises(TenantRefused):
        _resolve(root, fixture_uuid("tenant:absent"))


# test_s7_nf22_systems_keyed_by_exact_directory_name is retired (repair round 7, design DC7/R10): the run's systems are the
# tenant's records, keyed by the record's `system_id`, not a census of `settings/systems/` directory names (dot-folders,
# stray files, `CMDB` beside `cmdb`). A record the store cannot hold (an id that is not its catalog adapter's) is
# refused at write (O4, `test_system_records_1366.py`); how the import treats a stray name in a folder is not decided.


def test_s7_nf16_required_settings_keep_the_refusal(tmp_path):
    """A required settings file that is not a file (REQUIRED_SETTINGS, #1106) still refuses the tenant: the control that
    acceptance's refusal bites. (Repair round 7, DC7: a `config.env` that is a directory or unreadable no longer reaches
    a run, the run reads records; that arm moved to the operator's `set-system`, which reads the one folder reader left:
    `tenant_1108_p4/test_folder_reader_w_1366.py`.)"""
    root = tmp_path / "tenants"
    S.plant(root, marker="nf16")
    required = S.plant(root, fixture_uuid("tenant:required-dir"), marker="nf16b")
    grants = S.settings_of(required) / "verb-grants.yaml"
    grants.unlink()
    grants.mkdir()
    with pytest.raises(S.tenant_refused()):
        _resolve(root, fixture_uuid("tenant:required-dir"))
    assert _resolve(root).systems["ticket"]  # control: the sibling tenant, untouched, resolves


def _with_pattern(spec, pattern: str, version: int):
    """`spec` with the ticket record's TICKET_KEY_PATTERN written as `pattern`: the operator's next version of it."""
    from defender.tests.support.tenancy import _systems1366 as R

    ticket = spec.systems["ticket"]
    return R.edited(spec, "ticket", version=version, settings={**ticket.settings, "TICKET_KEY_PATTERN": pattern})


def test_s7_nf4_every_resolve_reads_the_current_records(tmp_path, monkeypatch):
    """A records write between two resolves is seen by the second (H9/O6: every run reads the tenant's CURRENT records;
    nothing is cached across resolves or tenants). Restated from 'every resolve reads the folder fresh' (design R10/DC7:
    the run reads records, not the folder; the folder-fresh arm is retired)."""
    from defender.tests.support.tenancy import _systems1366 as R

    # Under this test's data root, the one `run.main` below reads its tenants from.
    root = current_data_root()
    folder = S.plant(root, marker="nf4")
    S.plant(root, fixture_uuid("tenant:other"), marker="nf4o")
    v1 = R.derive(S.settings_of(folder))
    v2 = _with_pattern(v1, "EDITED-[0-9]+", 2)

    # Resolved twice around a records write: nothing is cached.
    first = _resolve(root, records=v1)
    second = _resolve(root, records=v2)
    direct = R.run_tenant_for(S.tenant_folder_of(root), dispatches_lead_zero=False, records=v2)
    assert first.systems["ticket"]["TICKET_KEY_PATTERN"] == "NF4-[0-9]+"
    assert second.systems["ticket"]["TICKET_KEY_PATTERN"] == "EDITED-[0-9]+"
    assert direct.systems["ticket"]["TICKET_KEY_PATTERN"] == "EDITED-[0-9]+"
    # ...and across tenants: resolving another tenant in between memoizes nothing.
    assert _resolve(root, fixture_uuid("tenant:other")).systems["ticket"]["TICKET_KEY_PATTERN"] == "NF4O-[0-9]+"
    assert _resolve(root, records=v2).systems["ticket"]["TICKET_KEY_PATTERN"] == "EDITED-[0-9]+"

    # A second run.main in one process reflects a records write made between the two. (run.main takes
    # its runs base from the data root, whose `playground` tenant is created on request.)
    ensure_d9_tenant()
    alert = S.plant_alert(tmp_path / "alert")
    seen: list[str] = []
    for n, (run_id, pattern) in enumerate((("r-nf4-a", "RUN-A-[0-9]+"), ("r-nf4-b", "RUN-B-[0-9]+")), start=2):
        argv = S.run_argv(alert, root)
        rec_ = S.RunRecorder(tmp_path / "runs" / run_id)
        rc, refused = S.drive_run(argv, rec_, visualize=rec_.visualize,
                                  directory=directory_for_argv(argv, records=_with_pattern(v1, pattern, n)))
        assert refused is None, (rc, refused)
        assert rc == 0, (rc, refused)
        seen.append(rec_.lifecycle_calls[0]["tenant"].systems["ticket"]["TICKET_KEY_PATTERN"])
    assert seen == ["RUN-A-[0-9]+", "RUN-B-[0-9]+"], seen

    # Each replay drive reflects an edit made between them.
    from defender.tests.e2e import _replay_harness as RH

    patterns: list[str] = []

    def get_host(ctx, *, host: str = "web-1") -> dict:
        patterns.append(S.record_on(ctx).systems["ticket"]["TICKET_KEY_PATTERN"])
        return {"host": host}

    for n, pattern in enumerate(("DRIVE-A-[0-9]+", "DRIVE-B-[0-9]+")):
        S.set_key(folder, "ticket", "TICKET_KEY_PATTERN", pattern)
        run_dir = RH.materialize(tmp_path / f"drive-{n}", RH.GOLDEN_AB3, run_id=f"nf4-drive-{n}")
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
    assert patterns == ["DRIVE-A-[0-9]+", "DRIVE-B-[0-9]+"], patterns


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
    closures = {}
    for module in ("defender.execution.bash_exec", "defender.execution.box_codec"):
        rc, err, loaded = _closure(module)
        # the probe is live: the import succeeded and the closure holds the imported module
        assert rc == 0, (module, rc, err)
        assert module in loaded, (module, rc, err)
        closures[module] = loaded

    defining = {name: S.record_type(name).__module__ for name in RECORD_TYPES}
    for module, loaded in closures.items():
        leaked = {name: where for name, where in defining.items() if where in loaded}
        assert not leaked, f"importing {module} loads {leaked}"


def test_o1_resolver_ignores_env(tmp_path, monkeypatch):
    """With the same keys exported, resolve_tenant's systems carry the tenant file's values."""
    exported = {
        "TICKET_KEY_PATTERN": "ENV-[0-9]+",
        "ELASTIC_EVENTS_INDEX": "env-events-*",
        "ELASTIC_ALERTS_INDEX": "env-alerts-*",
        "ELASTIC_TRANSPORT": "docker-exec",
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
    assert "CMDB_DOCKER_CONTEXT" not in cmdb, dict(cmdb)
    assert rec.systems["ticket"]["TICKET_KEY_PATTERN"] == "O1R-[0-9]+"
    elastic = rec.systems["elastic"]
    assert elastic["ELASTIC_EVENTS_INDEX"] == "o1r-events-*"
    assert "ELASTIC_TRANSPORT" not in elastic, dict(elastic)
    assert "ELASTIC_DOCKER_CONTEXT" not in elastic, dict(elastic)


def test_defender_policy_over_a_tenant_whose_systems_are_broken(tmp_path, capsys):
    policy_cli = S.mod("cli.policy_cli")
    # policy_cli reads its tenants from `DEFENDER_DATA_ROOT` alone.
    root = current_data_root()
    S.plant(root, fixture_uuid("tenant:healthy"), marker="pol")
    broken = S.plant(root, fixture_uuid("tenant:broken"), marker="pol")
    S.config_path(broken, "cmdb").unlink()
    _identity_placeholder(broken)
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    base = ["show", "gather", "--run-dir", str(run_dir)]

    healthy = [*base, "--tenant", fixture_uuid("tenant:healthy")]
    assert policy_cli.main(healthy, directory=directory_for_argv(healthy)) == 0
    healthy_out = capsys.readouterr().out
    broken_argv = [*base, "--tenant", fixture_uuid("tenant:broken")]
    assert policy_cli.main(broken_argv, directory=directory_for_argv(broken_argv)) == 0  # resolves without raising
    broken_out = capsys.readouterr().out
    assert "agent: gather" in broken_out, broken_out
    assert broken_out == healthy_out, "the grants answer moved with a system's config"

    rec = _resolve(root, fixture_uuid("tenant:broken"))  # the frame policy_cli resolves through
    _unusable(rec, "cmdb", "CMDB_TIMEOUT_SEC")
    _unusable(rec, "identity", "IDENTITY_TIMEOUT_SEC")
    assert rec.grants.gather == _resolve(root, fixture_uuid("tenant:healthy")).grants.gather


#: The keys the ticket adapter reads (`ticket_adapter.REQUIRED_CONFIG_KEYS`).
_TICKET_KEYS = ("TIMEOUT_SEC", "KEY_PATTERN")


def test_s60_config_env_fs_confinement(tmp_path):
    root = tmp_path / "tenants"
    outside = tmp_path / "outside.env"
    outside.write_text('TICKET_TIMEOUT_SEC="10"\nTICKET_KEY_PATTERN="OUTSIDE-[0-9]+"\n',
                       encoding="utf-8")
    # A config.env reached through a symlink outside the folder: the link walk refuses it.
    linked = S.plant(root, fixture_uuid("tenant:linked"), marker="s60l")
    S.config_path(linked, "ticket").unlink()
    S.config_path(linked, "ticket").symlink_to(outside)
    with pytest.raises(S.tenant_refused()):
        _resolve(root, fixture_uuid("tenant:linked"))

    folder = S.plant(root, marker="s60")
    rec = _resolve(root)
    ctx = _ctx(rec, tmp_path)
    assert transport.load_config(ctx, "ticket", "TICKET", _TICKET_KEYS)["KEY_PATTERN"] == "S60-[0-9]+"

    # Edited after resolve: the run still addresses the value as parsed at resolve.
    S.set_key(folder, "ticket", "TICKET_KEY_PATTERN", "EDITED-[0-9]+")
    assert transport.load_config(ctx, "ticket", "TICKET", _TICKET_KEYS)["KEY_PATTERN"] == "S60-[0-9]+"
    # Swapped for a link after resolve: the walk ran once, at resolve; nothing reads through it.
    S.config_path(folder, "ticket").unlink()
    S.config_path(folder, "ticket").symlink_to(outside)
    assert transport.load_config(ctx, "ticket", "TICKET", _TICKET_KEYS)["KEY_PATTERN"] == "S60-[0-9]+"
    assert rec.systems["ticket"]["TICKET_KEY_PATTERN"] == "S60-[0-9]+"


def test_a_config_fault_observed_at_resolve_fixed_by_a_records_write_mid_run(tmp_path):
    """A run whose record holds unusable settings keeps them: an operator's fix (a new version) mid-run does not reach
    the run; only a fresh resolve reads it (O6: settings are frozen at start; H9: the next run reads the current record).
    (Was 'fixed on disk': the run reads records, not the folder, DC7.)"""
    from defender.tests.support.tenancy import _systems1366 as R

    root = tmp_path / "tenants"
    folder = S.plant(root, marker="s063")
    fixed = R.derive(S.settings_of(folder))
    broken = R.edited(fixed, "cmdb", settings={})

    rec = _resolve(root, records=broken)
    SystemConfig = S.record_type("SystemConfig")
    ConfigFault = S.config_fault()
    _settings_empty(rec, "cmdb")
    ctx = _ctx(rec, tmp_path)
    with pytest.raises(ConfigFault, match="CMDB_TIMEOUT_SEC"):
        transport.load_config(ctx, "cmdb", "CMDB")

    # the operator writes the fix (version 2) mid-run: the run's record is what it was resolved with
    _settings_empty(rec, "cmdb")
    with pytest.raises(ConfigFault, match="CMDB_TIMEOUT_SEC"):
        transport.load_config(ctx, "cmdb", "CMDB")

    fresh = _resolve(root, records=R.edited(fixed, "cmdb", version=2))  # only a fresh resolve sees the fix
    assert isinstance(fresh.systems["cmdb"], SystemConfig), fresh.systems["cmdb"]
    assert len(fresh.systems["cmdb"]) > 0
    assert transport.load_config(_ctx(fresh, tmp_path / "fresh"), "cmdb", "CMDB") == {
        "TIMEOUT_SEC": "10"}


def test_o2_each_call_uses_the_record_it_was_resolved_with(tmp_path):
    """A verb's call takes its system's base and timeout from the run's record, never from disk:
    two records resolved around an edit each keep their own values, called in turn, with the
    folder gone from disk."""
    cmdb_adapter = S.mod("integrations.cmdb_adapter")
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="ocs")
    access = S.settings_of(folder) / "systems" / "cmdb" / "access.yaml"
    S.set_key(folder, "cmdb", "CMDB_TIMEOUT_SEC", "7")
    first = _resolve(root)
    S.set_key(folder, "cmdb", "CMDB_TIMEOUT_SEC", "3")
    access.write_text(T1106.access_text("ocs", "cmdb", base="http://edited-cmdb:9"), encoding="utf-8")
    second = _resolve(root)
    S.config_path(folder, "cmdb").unlink()
    access.unlink()

    stand_in = S.ProxyStandIn(tmp_path / "proxy", [S.answer('{"host": "web-1"}')])
    seen = []
    for n, record in enumerate((first, second, first)):
        run_dir = tmp_path / f"call-{n}"
        run_dir.mkdir()
        ctx = S.verb_context(record, run_dir, {}, proxy_url=stand_in.url, request_token="token-o2")
        cmdb_adapter.get_host(ctx, host="web-1")
        [request] = stand_in.requests()[n:]
        seen.append((request["url"], request["timeout_sec"]))
    old_base = T1106.default_base("ocs", "cmdb")
    assert seen == [(f"{old_base}/hosts/web-1", 7), ("http://edited-cmdb:9/hosts/web-1", 3),
                    (f"{old_base}/hosts/web-1", 7)], seen


def _called(record, tmp_path, name, fn, **kw):
    """`fn(ctx, **kw)` against a proxy stand-in answering `{}`: (the fault or None, requests)."""
    stand_in = S.ProxyStandIn(tmp_path / f"proxy-{name}", [S.answer("{}")])
    run_dir = tmp_path / f"run-{name}"
    run_dir.mkdir()
    ctx = S.verb_context(record, run_dir, {}, proxy_url=stand_in.url, request_token=f"token-{name}")
    try:
        fn(ctx, **kw)
    except Exception as fault:  # noqa: BLE001 — the fault is the observation
        return fault, stand_in.requests()
    return None, stand_in.requests()


@pytest.mark.parametrize(("key", "value", "named"), [
    ("ELASTIC_EVENTS_INDEX", "CHANGE-ME", "CHANGE-ME"),        # S2: the template's placeholder
    ("ELASTIC_EVENTS_INDEX", "logs-CHANGE-ME-*", "CHANGE-ME"),  # S2: inside a value
    ("ELASTIC_ALERTS_INDEX", "alerts/x", "`/`"),               # T4: a settings path value
    ("ELASTIC_EVENTS_INDEX", "logs;x", "`;`"),                 # T4
])
def test_r5_a_config_env_value_the_system_cannot_use_leaves_it_not_configured(
        tmp_path, key, value, named):
    """With its access declaration filled in, a `config.env` value still carrying the template's
    `CHANGE-ME`, or a path value that is not one segment, is a `ConfigFault` naming the key at
    the settings check, and no verb call reaches the proxy (#1391 r5 S2, T4)."""
    elastic = S.mod("integrations.elastic_adapter")
    ConfigFault = S.config_fault()
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="r5c")
    S.set_key(folder, "elastic", key, value)
    record = _resolve(root)
    with pytest.raises(ConfigFault) as raised:
        elastic.check_settings(record)
    assert key in str(raised.value), str(raised.value)
    assert named in str(raised.value), str(raised.value)
    fault, sent = _called(record, tmp_path, "q", elastic.query, native_query="*")
    assert isinstance(fault, ConfigFault), fault
    assert sent == [], sent


def test_r5_a_config_env_is_optional_only_for_an_adapter_that_reads_no_key(tmp_path):
    """host-state reads no settings key: with only its access declaration it is usable and its
    verbs are sent. cmdb reads a key: with empty settings it is still not configured, located
    `system cmdb settings` (#1391 r5 O-S1; #1366 DC6: the record, not the file)."""
    host_state = S.mod("integrations.host_state_adapter")
    cmdb = S.mod("integrations.cmdb_adapter")
    ConfigFault = S.config_fault()
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="r5o")
    S.config_path(folder, "host-state").unlink(missing_ok=True)
    S.config_path(folder, "cmdb").unlink()
    record = _resolve(root)
    assert host_state.check_settings(record) is None
    fault, sent = _called(record, tmp_path, "hs", host_state.passwd, host="web-1")
    assert [r["url"] for r in sent] == [f"{T1106.default_base('r5o', 'host-state')}/hosts/web-1/accounts"], (fault, sent)
    with pytest.raises(ConfigFault, match="system cmdb settings"):
        cmdb.check_settings(record)


@pytest.mark.parametrize("config", ["absent", "undeclared-key", "placeholder"])
def test_r5_a_folder_without_its_access_declaration_is_judged_by_that_first(tmp_path, config):
    """The access declaration is judged before the settings: a system with none is named for
    the missing declaration (`system cmdb access`, #1366 DC6), whatever its settings lack (#1391 r5 S1 step 1)."""
    cmdb = S.mod("integrations.cmdb_adapter")
    ConfigFault = S.config_fault()
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="r5a")
    S.drop_access(folder, "cmdb")
    env = S.config_path(folder, "cmdb")
    if config == "absent":
        env.unlink()
    elif config == "undeclared-key":
        env.write_text(env.read_text() + "CMDB_URL_BASE=http://cmdb:8080\n")
    else:
        env.write_text("CMDB_TIMEOUT_SEC=CHANGE-ME\n")
    with pytest.raises(ConfigFault, match=r"system cmdb access") as raised:
        cmdb.check_settings(_resolve(root))
    assert "system cmdb settings" not in str(raised.value), str(raised.value)


@pytest.mark.parametrize("required", [("URL_BASE", "TIMEOUT_SEC"), ("TIMEOUT_SEC", "HOST")])
def test_r5_an_adapter_reading_a_base_or_host_key_is_broken_not_configured(tmp_path, required):
    """The base is the access declaration's and a host is a verb parameter, never a key: an adapter
    that lists either among the keys it reads is itself wrong (a `ValueError`, which the settings
    check reports as the adapter broken), so a tenant never sets a key that is silently ignored
    (#1391 r5 O-T3)."""
    root = tmp_path / "tenants"
    S.plant(root, marker="r5b")
    with pytest.raises(ValueError, match="URL_BASE|HOST"):
        transport.record_config(_resolve(root), "cmdb", "CMDB", required)


@pytest.mark.parametrize("host", ["", ".", "..", "web-1/../admin", "web-1%2Fx", "web 1", "a?b",
                                  "a#b", "a;b", "a\\b", "a\nb"])
def test_r5_an_agent_path_value_that_is_not_one_segment_is_refused_before_sending(tmp_path, host):
    """A value the agent chose that is not exactly one path segment is a `ConfinementFault`
    naming the parameter, and nothing reaches the proxy (#1391 r5 T2, O-T2)."""
    cmdb = S.mod("integrations.cmdb_adapter")
    root = tmp_path / "tenants"
    S.plant(root, marker="r5s")
    fault, sent = _called(_resolve(root), tmp_path, "g", cmdb.get_host, host=host)
    assert type(fault).__name__ == "ConfinementFault", repr(fault)
    assert fault.exit_code == 1, repr(fault)
    assert "`host`" in str(fault), str(fault)
    assert sent == [], sent


def test_r5_a_one_segment_value_is_sent_escaped_and_a_query_value_may_hold_a_separator(tmp_path):
    """A one-segment value is percent-encoded into its segment; a value in the query keeps its
    `/` (#1391 r5 T2, T3)."""
    cmdb = S.mod("integrations.cmdb_adapter")
    host_state = S.mod("integrations.host_state_adapter")
    root = tmp_path / "tenants"
    S.plant(root, marker="r5e")
    record = _resolve(root)
    _, sent = _called(record, tmp_path, "c", cmdb.get_host, host="web:1@x")
    assert [r["url"] for r in sent] == [f"{T1106.default_base('r5e', 'cmdb')}/hosts/web%3A1%40x"], sent
    _, sent = _called(record, tmp_path, "f", host_state.fim_checksum, host="web-1", path="/etc/hosts")
    assert [r["url"] for r in sent] == [
        f"{T1106.default_base('r5e', 'host-state')}/hosts/web-1/files/sha256?path=%2Fetc%2Fhosts"], sent


@pytest.mark.parametrize("answer", ["[]", '"text"'])
def test_r5_an_answer_that_is_not_the_object_a_verb_needs_is_the_system_breaking_its_contract(
        tmp_path, answer):
    """An object endpoint answering anything else is a `TransportFault`, for every adapter
    (#1391 r5 O-T4)."""
    cmdb = S.mod("integrations.cmdb_adapter")
    root = tmp_path / "tenants"
    S.plant(root, marker="r5a")
    stand_in = S.ProxyStandIn(tmp_path / "proxy", [S.answer(answer)])
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ctx = S.verb_context(_resolve(root), run_dir, {}, proxy_url=stand_in.url, request_token="t")
    with pytest.raises(S.mod("kit.faults").TransportFault):
        cmdb.get_host(ctx, host="web-1")
    assert len(stand_in.requests()) == 1, "the answer came from the system"


@pytest.mark.parametrize("value", ["http://static-cdn-sync.example/api/v2/telemetry",
                                   "10.0.0.0/8", "203.0.113.7"])
def test_r5_a_threat_intel_lookup_sends_its_value_in_the_body(tmp_path, value):
    """An indicator may hold a `/` (a URL, a CIDR range), so `lookup` sends it in the body of
    `POST /lookup` and answers the one result (#1391 r5 T3, O-T2b)."""
    import json as _json

    threat_intel = S.mod("integrations.threat_intel_adapter")
    root = tmp_path / "tenants"
    S.plant(root, marker="r5t")
    found = {"value": value, "verdict": "malicious"}
    stand_in = S.ProxyStandIn(tmp_path / "proxy", [S.answer(_json.dumps({"results": [found]}))])
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ctx = S.verb_context(_resolve(root), run_dir, {}, proxy_url=stand_in.url, request_token="t")
    assert threat_intel.lookup(ctx, value=value) == found
    [request] = stand_in.requests()
    assert (request["method"], request["url"], request["body"]) == (
        "POST", f"{T1106.default_base('r5t', 'threat-intel')}/lookup", {"values": [value]}), request


def test_s7_mf11_record_parts_read_only(tmp_path):
    root = tmp_path / "tenants"
    S.plant(root, marker="mf11")
    rec = _resolve(root)
    # The world registry no longer copies the context to carry a branch point (#1385 O1): the
    # adapter is handed the investigator's own.
    carried = _ctx(rec, tmp_path)

    # One consumer edits each part in place; the edit raises or lands on its own copy.
    for attempt in (
        lambda: rec.systems["ticket"].__setitem__("TICKET_KEY_PATTERN", "HIJACKED-[0-9]+"),
        lambda: rec.systems.__setitem__("ticket", {"TICKET_KEY_PATTERN": "HIJACKED-[0-9]+"}),
    ):
        # raising is one of the two allowed outcomes
        with contextlib.suppress(Exception):
            attempt()

    for reader in (rec, S.record_on(carried)):
        assert reader.systems["ticket"]["TICKET_KEY_PATTERN"] == "MF11-[0-9]+", dict(
            reader.systems["ticket"])

