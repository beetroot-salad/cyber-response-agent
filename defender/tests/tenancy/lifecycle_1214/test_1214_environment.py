"""#1214 O12: the database address reaches host processes only, never a box's or the bash executor's environment."""
from __future__ import annotations

from defender.tests.tenancy.tenant_1108_p4.test_publish_child import _RecordingSpawn

DSN_ENV = "DEFENDER_DATABASE_DSN"
DSN = "postgresql://defender:o12-planted@db.test:5432/defender"


def test_the_publish_child_keeps_the_database_address(monkeypatch, tmp_path):
    """The launch-time publish child is a host process and is handed the address (O12 positive)."""
    from defender.investigation import publish_launch

    monkeypatch.setenv(DSN_ENV, DSN)
    spawn = _RecordingSpawn()
    publish_launch.launch_publish("some-tenant", data_root=tmp_path, budget=5.0, spawn=spawn)
    (_argv, env), = spawn.calls
    assert env.get(DSN_ENV) == DSN


def test_a_run_lane_environment_has_no_database_address(monkeypatch, tmp_path):
    """`run_env` (what the run's lanes start from) drops the address; the base keeps it (O12)."""
    from defender import box as box_mod

    monkeypatch.setenv(DSN_ENV, DSN)
    assert box_mod.provider_scrubbed_environ().get(DSN_ENV) == DSN  # control: host base keeps it
    run_dir = tmp_path / "runs" / "o12"
    run_dir.mkdir(parents=True)
    env = box_mod.run_env(tmp_path / "defender", run_dir)
    assert DSN_ENV not in env
    assert not [k for k, v in env.items() if "o12-planted" in v]


def test_the_bash_executor_host_fallback_has_no_database_address(monkeypatch, tmp_path):
    """The unsandboxed bash lane starts from the host environment and must still drop the address (O12)."""
    from defender import box as box_mod
    from defender.box._lifecycle import _host_fallback_env

    monkeypatch.setenv(DSN_ENV, DSN)
    monkeypatch.setenv("O12_ORDINARY", "ordinary")
    code = tmp_path / "defender"
    code.mkdir()
    env = _host_fallback_env(box_mod.BoxRequest(name="o12", workdir=tmp_path, defender_dir=code, env={}))
    assert env.get("O12_ORDINARY") == "ordinary"  # control: the host environment is read
    assert DSN_ENV not in env
    assert not [k for k, v in env.items() if "o12-planted" in v]
