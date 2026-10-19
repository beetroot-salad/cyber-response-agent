"""resolve_tenant / resolve_run_tenant: systems, ticket mapping, faults kept per system, fresh read per resolve, read-only parts."""
from __future__ import annotations

import contextlib
from datetime import UTC, datetime
import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from defender.runtime import run_tenant
from defender.scripts.adapters import _stub_transport as transport
from defender.tests import _tenants1106 as T1106
from defender.tests._data_root_1078 import current_data_root, ensure_d9_tenant
from defender.tests.tenant_1107_settings import _spec1107 as S

TID = S.PLAYGROUND_ID
RECORD_TYPES = ("SystemConfig", "CaseMapping")


def _resolve(root: Path, tenant_id: str = TID) -> object:
    """The REAL acceptance frame over a planted root (C1: the one frame every entry uses)."""
    return run_tenant.resolve_tenant(
        Path(root), tenant_id, defender_dir=S.DEFENDER, dispatches_lead_zero=False)


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


def test_d_ticket_mapping_kept(tmp_path):
    root = tmp_path / "tenants"
    CaseTicketError = S.case_ticket_error()
    cases = {
        "valid": T1106.mapping_text(),
        "open-is-released": T1106.mapping_text(open_status="closed"),  # == the legacy released
        "lifecycle": T1106.mapping_text(open_status="{summary}"),  # a templated open.status
    }
    got = {}
    for tenant_id, text in cases.items():
        folder = S.plant(root, tenant_id, marker=tenant_id)
        S.mapping_path(folder).write_text(text, encoding="utf-8")
        got[tenant_id] = _resolve(root, tenant_id).ticket_mapping  # never raised

    for good in ("valid", "open-is-released"):
        assert isinstance(got[good], S.record_type("CaseMapping")), (good, got[good])
    assert isinstance(got["lifecycle"], CaseTicketError), got["lifecycle"]

    TenantRefused = S.tenant_refused()
    for tenant_id, text in {"not-yaml": "open: [unclosed\n  status: : :\n",
                            "not-a-mapping": "- open\n- released\n"}.items():
        folder = S.plant(root, tenant_id, marker=tenant_id)
        S.mapping_path(folder).write_text(text, encoding="utf-8")
        with pytest.raises(TenantRefused):
            _resolve(root, tenant_id)


def test_o5_resolve_keeps_system_faults(tmp_path):
    root = tmp_path / "tenants"
    folder = S.plant(root, marker="o5")
    S.config_path(folder, "cmdb").unlink()
    S.write_config(folder, "identity", b"IDENTITY_URL_BASE=\xff\n")
    S.mapping_path(folder).write_text(
        T1106.mapping_text(open_status="{summary}"), encoding="utf-8")
    rec = _resolve(root)  # never raises because of a system's config
    ConfigFault = S.config_fault()
    assert isinstance(rec.systems["cmdb"], ConfigFault), rec.systems["cmdb"]
    assert isinstance(rec.systems["identity"], ConfigFault), rec.systems["identity"]
    assert isinstance(rec.ticket_mapping, S.case_ticket_error()), rec.ticket_mapping

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
    required = S.plant(root, "required-dir", marker="nf16b")
    grants = S.settings_of(required) / "verb-grants.yaml"
    grants.unlink()
    grants.mkdir()
    with pytest.raises(S.tenant_refused()):
        _resolve(root, "required-dir")


def test_s7_nf4_every_resolve_reads_the_folder_fresh(tmp_path, monkeypatch):
    # No arm here forks a transport; the shim first on PATH makes sure a stray one cannot
    # reach the real docker (CX8).
    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "shim").path_value())
    # #1120: under this test's data root, the one `run.main` below reads its tenants from.
    root = current_data_root()
    folder = S.plant(root, marker="nf4")
    S.plant(root, "other", marker="nf4o")

    # resolve_tenant / resolve_run_tenant, twice around an edit (RG5, refuted: no cache).
    first = _resolve(root)
    S.set_key(folder, "cmdb", "CMDB_URL_BASE", "http://cmdb-edited:1")
    S.mapping_path(folder).write_text(T1106.mapping_text(reporter="done"),
                                      encoding="utf-8")
    second = _resolve(root)
    direct = run_tenant.run_tenant_for(
        S.tenant_folder_of(root), defender_dir=S.DEFENDER, dispatches_lead_zero=False)
    assert first.systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-nf4:8080"
    assert second.systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-edited:1"
    assert direct.systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-edited:1"
    assert S.open_reporter(second.ticket_mapping) == "done"
    assert S.open_reporter(first.ticket_mapping) == "defender"
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
    closures = {}
    for module in ("defender.runtime.bash_exec", "defender.runtime.box_codec"):
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
    """With those variables exported, resolve_tenant's systems carry the tenant file's
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
    elastic = rec.systems["elastic"]
    assert elastic["ELASTIC_EVENTS_INDEX"] == "o1r-events-*"
    assert elastic["ELASTICSEARCH_URL"] == "https://es-o1r:9200"
    assert elastic["ELASTIC_DOCKER_CONTEXT"] == S.context_name("o1r", "elastic")


def _config_keys(path: Path) -> set[str]:
    """The key names a committed `config.env` spells (`KEY=` lines; comments skipped)."""
    keys = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            keys.add(line.split("=", 1)[0].strip())
    return keys


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
            needed = {f"{prefix}_TRANSPORT", f"{prefix}_DOCKER_CONTEXT"}
            if name == "elastic":
                needed |= {"ELASTIC_ES_CONTAINER", "ELASTIC_KIBANA_CONTAINER"}
            assert needed <= keys, (tenant_settings, name, sorted(needed - keys))

    # #1120: the committed fixture, set up under this test's data root as `playground`.
    T1106.fixture_tenant(S.PLAYGROUND_ID)
    rec = _resolve(current_data_root(), S.PLAYGROUND_ID)
    ConfigFault = S.config_fault()
    faulted = {name: str(entry) for name, entry in rec.systems.items()
               if isinstance(entry, ConfigFault)}
    assert not faulted, faulted


def test_defender_policy_over_a_tenant_whose_systems_are_broken(tmp_path, capsys):
    policy_cli = S.mod("scripts.policy_cli")
    # #1120: policy_cli reads its tenants from `DEFENDER_DATA_ROOT` alone.
    root = current_data_root()
    S.plant(root, "healthy", marker="pol")
    broken = S.plant(root, "broken", marker="pol")
    S.config_path(broken, "cmdb").unlink()
    S.write_config(broken, "identity", b"IDENTITY_URL_BASE=\xff\n")
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    base = ["show", "gather", "--run-dir", str(run_dir)]

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
    assert rec.grants.gather == _resolve(root, "healthy").grants.gather


def test_s60_config_env_fs_confinement(tmp_path):
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
    root = tmp_path / "tenants"
    S.plant(root, marker="mf11")
    rec = _resolve(root)
    registry = S.mod("learning.branch.estate.registry")
    ctx = _ctx(rec, tmp_path)
    moment = datetime(2026, 7, 28, 16, 18, 45, tzinfo=UTC)
    carried = registry._carrying(ctx, as_of=moment)  # the world registry's VerbContext copy
    assert carried is not ctx
    assert carried.as_of == moment

    # One consumer edits each part in place; the edit raises or lands on its own copy.
    for attempt in (
        lambda: rec.systems["cmdb"].__setitem__("CMDB_URL_BASE", "http://hijacked:1"),
        lambda: rec.systems.__setitem__("cmdb", {"CMDB_URL_BASE": "http://hijacked:1"}),
        lambda: rec.ticket_mapping["open"].__setitem__("reporter", "hijacked"),
        lambda: rec.ticket_mapping.__setitem__("open", {"reporter": "hijacked"}),
        lambda: setattr(rec.ticket_mapping, "open", {"reporter": "hijacked"}),
    ):
        # raising is one of the two outcomes the demand allows
        with contextlib.suppress(Exception):
            attempt()

    for reader in (rec, S.record_on(carried)):
        assert reader.systems["cmdb"]["CMDB_URL_BASE"] == "http://cmdb-mf11:8080", dict(
            reader.systems["cmdb"])
        assert S.open_reporter(reader.ticket_mapping) == "defender", (
            "an in-place edit leaked, or the resolve-time reporter was lost")
