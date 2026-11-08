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

from defender.systems import run_tenant
from defender.kit import transport
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, ensure_d9_tenant
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

TID = S.PLAYGROUND_ID
RECORD_TYPES = ("SystemConfig",)  # CaseMapping retired with the mapping file (#1359)


def _resolve(root: Path, tenant_id: str = TID) -> object:
    """The real acceptance frame over a planted root (the one frame every entry uses)."""
    return run_tenant.resolve_tenant(
        fixture_data_root(Path(root)), tenant_id, defender_dir=S.DEFENDER, dispatches_lead_zero=False)


def _ctx(record: object, tmp_path: Path, env: Mapping[str, str] | None = None) -> object:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return S.verb_context(record, run_dir, dict(env or {}))


def test_d_systems_verbatim(tmp_path):
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="vb")
    S.write_config(folder, "extra-sys", 'EXTRA_SYS_URL_BASE="http://extra-vb:1"\n')

    rec = _resolve(root)

    assert set(rec.systems) == {*S.PREFIX, "extra-sys"}, sorted(rec.systems)
    assert dict(rec.systems["ticket"]) == {
        "TICKET_TIMEOUT_SEC": "10",
        "TICKET_KEY_PATTERN": "VB-[0-9]+",
    }, dict(rec.systems["ticket"])
    assert "KEY_PATTERN" not in rec.systems["ticket"], "the prefix was stripped at resolve"
    assert dict(rec.systems["extra-sys"]) == {"EXTRA_SYS_URL_BASE": "http://extra-vb:1"}
    elastic = dict(rec.systems["elastic"])
    assert elastic == {"ELASTIC_EVENTS_INDEX": "vb-events-*",
                       "ELASTIC_ALERTS_INDEX": "vb-alerts-*"}, elastic


def test_d_systems_fault_kept(tmp_path):
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="fk")
    S.config_path(folder, "cmdb").unlink()
    # Invalid UTF-8: it must become this system's fault, never an escaping UnicodeDecodeError.
    S.write_config(folder, "identity", b'IDENTITY_TIMEOUT_SEC="\xff\xfe"\n')

    rec = _resolve(root)  # returns normally

    ConfigFault = S.config_fault()
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    assert isinstance(rec.systems["identity"], ConfigFault), rec.systems["identity"]
    assert isinstance(rec.systems["ticket"], S.record_type("SystemConfig")), rec.systems["ticket"]
    ctx = _ctx(rec, tmp_path)
    for system, prefix in (("cmdb", "CMDB"), ("identity", "IDENTITY")):
        with pytest.raises(ConfigFault) as raised:
            transport.load_config(ctx, system, prefix)
        # the contract is the outcome: the same fault's text, not its identity
        assert str(raised.value) == str(rec.systems[system]), (system, str(raised.value))


def test_d_a_case_record_file_never_refuses_the_tenant(tmp_path):
    """Acceptance never refuses a tenant over its case-record file, whatever it holds or whether it
    exists; only a required settings file does (D-12, r4 Data). The record leg judges the file."""
    root = tmp_path / "tenants"
    cases = {
        "valid": T1106.case_record_text(),
        "names-an-unknown-system": T1106.case_record_text("no-such-system"),
        "not-yaml": "system: [unclosed\n  comment: : :\n",
        "not-a-mapping": "- system\n- ticket\n",
        "empty": "",
    }
    for label, text in cases.items():
        tenant_id = fixture_uuid(f"tenant:{label}")
        folder = S.plant(root, tenant_id, marker=label)
        S.case_record_path(folder).write_text(text, encoding="utf-8")
        _resolve(root, tenant_id)  # never raises

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
    S.write_config(folder, "identity", b"IDENTITY_URL_BASE=\xff\n")
    S.case_record_path(folder).write_text("- not\n- a mapping\n", encoding="utf-8")
    rec = _resolve(root)  # never raises because of a system's config or the case-record file
    ConfigFault = S.config_fault()
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    assert isinstance(rec.systems["identity"], ConfigFault), rec.systems["identity"]

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


def test_s7_nf22_systems_keyed_by_exact_directory_name(tmp_path):
    configs = S.config_texts("nf22")
    configs["CMDB"] = configs.pop("cmdb")
    configs["Elastic"] = configs.pop("elastic")
    configs["cmdb.orig"] = 'ORIG_URL_BASE="http://orig-nf22:1"\n'
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="nf22", configs=configs)
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
    with pytest.raises(S.config_fault()) as raised:
        transport.load_config(_ctx(rec, tmp_path), "cmdb", "CMDB")
    assert S.NOT_CONFIGURED in str(raised.value), str(raised.value)
    assert rec.systems["cmdb.orig"]["ORIG_URL_BASE"] == "http://orig-nf22:1"


def test_s7_nf16_unreadable_config_env_kept_as_fault(tmp_path):
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
    required = S.plant(root, fixture_uuid("tenant:required-dir"), marker="nf16b")
    grants = S.settings_of(required) / "verb-grants.yaml"
    grants.unlink()
    grants.mkdir()
    with pytest.raises(S.tenant_refused()):
        _resolve(root, fixture_uuid("tenant:required-dir"))


def test_s7_nf4_every_resolve_reads_the_folder_fresh(tmp_path, monkeypatch):
    # Under this test's data root, the one `run.main` below reads its tenants from.
    root = current_data_root()
    folder = S.plant(root, marker="nf4")
    S.plant(root, fixture_uuid("tenant:other"), marker="nf4o")

    # Resolved twice around an edit: nothing is cached.
    first = _resolve(root)
    S.set_key(folder, "ticket", "TICKET_KEY_PATTERN", "EDITED-[0-9]+")
    second = _resolve(root)
    direct = run_tenant.run_tenant_for(
        S.tenant_folder_of(root), defender_dir=S.DEFENDER, dispatches_lead_zero=False)
    assert first.systems["ticket"]["TICKET_KEY_PATTERN"] == "NF4-[0-9]+"
    assert second.systems["ticket"]["TICKET_KEY_PATTERN"] == "EDITED-[0-9]+"
    assert direct.systems["ticket"]["TICKET_KEY_PATTERN"] == "EDITED-[0-9]+"
    # ...and across tenants: resolving another tenant in between memoizes nothing.
    assert _resolve(root, fixture_uuid("tenant:other")).systems["ticket"]["TICKET_KEY_PATTERN"] == "NF4O-[0-9]+"
    assert _resolve(root).systems["ticket"]["TICKET_KEY_PATTERN"] == "EDITED-[0-9]+"

    # A second run.main in one process reflects an edit made between the two. (run.main takes
    # its runs base from the data root, whose `playground` tenant is created on request.)
    ensure_d9_tenant()
    alert = S.plant_alert(tmp_path / "alert")
    seen: list[str] = []
    for run_id, pattern in (("r-nf4-a", "RUN-A-[0-9]+"), ("r-nf4-b", "RUN-B-[0-9]+")):
        S.set_key(folder, "ticket", "TICKET_KEY_PATTERN", pattern)
        rec_ = S.RunRecorder(tmp_path / "runs" / run_id)
        rc, refused = S.drive_run(S.run_argv(alert, root), rec_,
                                  visualize=rec_.visualize)
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


def _config_keys(path: Path) -> set[str]:
    """The key names a committed `config.env` spells (`KEY=` lines; comments skipped)."""
    keys = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            keys.add(line.split("=", 1)[0].strip())
    return keys


#: The keys a shipped system's config.env holds when it is not just `<PREFIX>_TIMEOUT_SEC`.
SHIPPED_KEYS = {
    "elastic": {"ELASTIC_EVENTS_INDEX", "ELASTIC_ALERTS_INDEX"},
    "ticket": {"TICKET_TIMEOUT_SEC", "TICKET_KEY_PATTERN"},
    "host-state": set(),
}


def test_d2_shipped_tenants_complete():
    for tenant_settings in (S.FIXTURE / "settings", S.TEMPLATE_DIR / "settings"):
        systems = tenant_settings / "systems"
        folders = sorted(p.name for p in systems.iterdir() if p.is_dir())
        assert "host-state" in folders, (tenant_settings, folders)
        for name in folders:
            assert name in S.PREFIX, f"{tenant_settings}: no known prefix for system {name!r}"
            prefix = S.PREFIX[name]
            config_env = systems / name / "config.env"
            assert config_env.is_file(), config_env
            keys = _config_keys(config_env)
            # #1391 O1/O2/Q4: every system is declared, and its config.env holds exactly the keys
            # its adapter reads (no Docker, transport or base key).
            assert (systems / name / "access.yaml").is_file(), (tenant_settings, name, "no declaration")
            expected = SHIPPED_KEYS.get(name, {f"{prefix}_TIMEOUT_SEC"})
            assert keys == expected, (tenant_settings, name, sorted(keys ^ expected))

    # The committed fixture, set up under this test's data root as `playground`.
    T1106.fixture_tenant(S.PLAYGROUND_ID)
    rec = _resolve(current_data_root(), S.PLAYGROUND_ID)
    ConfigFault = S.config_fault()
    faulted = {name: str(entry) for name, entry in rec.systems.items()
               if isinstance(entry, ConfigFault)}
    assert not faulted, faulted


def test_defender_policy_over_a_tenant_whose_systems_are_broken(tmp_path, capsys):
    policy_cli = S.mod("cli.policy_cli")
    # policy_cli reads its tenants from `DEFENDER_DATA_ROOT` alone.
    root = current_data_root()
    S.plant(root, fixture_uuid("tenant:healthy"), marker="pol")
    broken = S.plant(root, fixture_uuid("tenant:broken"), marker="pol")
    S.config_path(broken, "cmdb").unlink()
    S.write_config(broken, "identity", b"IDENTITY_URL_BASE=\xff\n")
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
    ConfigFault = S.config_fault()
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    assert isinstance(rec.systems["identity"], ConfigFault), rec.systems["identity"]
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


def test_a_config_fault_observed_at_resolve_fixed_on_disk_mid_run(tmp_path):
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


def test_a_tenant_copied_from_the_template_has_every_system_down_until_its_placeholders_go(tmp_path):
    """Every system of a tenant copied from the template is down for its settings — a
    `ConfigFault` naming the CHANGE-ME left in it — and no call reaches the proxy, whether the
    placeholder sits in its `config.env` or only in its access declaration's base (host-state
    reads no keys; elastic's indexes are not checked)."""
    import json
    import shutil

    ConfigFault = S.config_fault()
    root = tmp_path / "tenants"
    folder = root / S.PLAYGROUND_ID / "knowledge"
    shutil.copytree(S.TEMPLATE_DIR, folder)
    (folder / "agent" / ".tenant-id").write_text(f"{S.PLAYGROUND_ID}\n", encoding="utf-8")
    (root / S.PLAYGROUND_ID / "tenant.json").write_text(json.dumps(
        {"tenant_id": S.PLAYGROUND_ID, "created_at": "2026-09-28T00:00:00+00:00"}) + "\n",
        encoding="utf-8")
    # The template grants nothing (the run would be refused for that, not for its placeholders).
    (S.settings_of(folder) / "verb-grants.yaml").write_text(T1106.TABLE_A, encoding="utf-8")
    declared = sorted(p.parent.name for p in (S.settings_of(folder) / "systems").glob("*/access.yaml"))
    assert declared == sorted(S.PREFIX), f"precondition: the template declares every system: {declared}"

    record = _resolve(root)
    stand_in = S.ProxyStandIn(tmp_path / "proxy", [S.answer('{"hosts": []}')])
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ctx = S.verb_context(record, run_dir, {}, proxy_url=stand_in.url, request_token="token-tpl")
    adapter = {system: S.mod(f"integrations.{system.replace('-', '_')}_adapter") for system in S.PREFIX}
    calls = [(system, adapter[system].health_check, {}) for system in sorted(S.PREFIX)] + [
        ("host-state", adapter["host-state"].proc_tree, {"host": "web-1"}),
        ("elastic", adapter["elastic"].query, {"native_query": "*"}),
    ]
    for system, fn, kw in calls:
        with pytest.raises(ConfigFault) as raised:
            fn(ctx, **kw)
        assert raised.value.exit_code == 2, f"{system}.{fn.__name__}: {raised.value!r}"
        assert "CHANGE-ME" in str(raised.value), \
            f"{system}.{fn.__name__}: the fault must name the placeholder left in: {raised.value}"
    assert stand_in.requests() == [], f"a placeholder system reached the proxy: {stand_in.requests()}"


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
    """host-state reads no `config.env` key: with only its `access.yaml` it is usable and its
    verbs are sent. cmdb reads a key: without its `config.env` it is still "config file not
    found" (#1391 r5 O-S1)."""
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
    with pytest.raises(ConfigFault, match="config file not found"):
        cmdb.check_settings(record)


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

