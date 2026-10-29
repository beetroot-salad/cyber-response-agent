"""#1214 O12 (DC-9): the database address is removed by name in the ONE base scrub, so no host child and no
box or bash-executor environment carries it; only the publish child is handed it back."""
from __future__ import annotations

from defender.tests.tenancy.tenant_1108_p4.test_publish_child import _RecordingSpawn

DSN_ENV = "DEFENDER_DATABASE_DSN"
DSN = "postgresql://defender:o12-planted@db.test:5432/defender"
#: An issuer-named variable (the scrub's existing arm): proves the publish child is built from the SCRUBBED base.
ISSUER_ENV = "O12_ISSUER_URL"


def _carries(env: dict[str, str]) -> list[str]:
    return [k for k, v in env.items() if "o12-planted" in v]


def test_the_one_base_scrub_drops_the_database_address_by_name(monkeypatch):
    """`provider_scrubbed_environ` removes the address, and still keeps ordinary variables (O12, DC-9)."""
    from defender import box as box_mod

    monkeypatch.setenv(DSN_ENV, DSN)
    monkeypatch.setenv("O12_ORDINARY", "ordinary")
    env = box_mod.provider_scrubbed_environ()
    assert env.get("O12_ORDINARY") == "ordinary"  # control: the process environment is read
    assert DSN_ENV not in env
    assert _carries(env) == []


def test_a_run_lane_environment_has_no_database_address(monkeypatch, tmp_path):
    """`run_env` (what every run lane starts from) has no address; a run variable still lands on top (O12)."""
    from defender import box as box_mod

    monkeypatch.setenv(DSN_ENV, DSN)
    run_dir = tmp_path / "runs" / "o12"
    run_dir.mkdir(parents=True)
    env = box_mod.run_env(tmp_path / "defender", run_dir)
    assert env["DEFENDER_RUN_DIR"] == str(run_dir)  # control: this is the run's environment
    assert DSN_ENV not in env
    assert _carries(env) == []


def test_the_bash_executor_host_fallback_has_no_database_address(monkeypatch, tmp_path):
    """The unsandboxed bash lane starts from the host environment and still drops the address (O12)."""
    from defender import box as box_mod
    from defender.box._lifecycle import _host_fallback_env

    monkeypatch.setenv(DSN_ENV, DSN)
    monkeypatch.setenv("O12_ORDINARY", "ordinary")
    code = tmp_path / "defender"
    code.mkdir()
    env = _host_fallback_env(box_mod.BoxRequest(name="o12", workdir=tmp_path, defender_dir=code, env={}))
    assert env.get("O12_ORDINARY") == "ordinary"  # control: the host environment is read
    assert DSN_ENV not in env
    assert _carries(env) == []


def test_a_box_launched_from_the_run_environment_never_carries_the_address(monkeypatch, tmp_path):
    """The container argv rendered for a request built from `run_env` carries no `--env` with the address (O12)."""
    from defender import box as box_mod
    from defender.box._lifecycle import _render_argv
    from defender.box._spec import BoxSpec

    monkeypatch.setenv(DSN_ENV, DSN)
    run_dir = tmp_path / "runs" / "o12-box"
    run_dir.mkdir(parents=True)
    request = box_mod.BoxRequest(name="o12-box", workdir=tmp_path, defender_dir=tmp_path, spec=BoxSpec(rootfs="defender-box:o12"),
                                 env=box_mod.run_env(tmp_path / "defender", run_dir))
    argv = _render_argv(request).argv
    assert "--env" in argv, "control: the launch renders environment variables"
    assert not [a for a in argv if "o12-planted" in a or DSN_ENV in a]


def test_the_publish_child_is_handed_the_address_the_base_lacks(monkeypatch, tmp_path):
    """The launch-time publish child gets the address back, yet only the address: an issuer-named variable stays out (O12)."""
    from defender.investigation import publish_launch

    monkeypatch.setenv(DSN_ENV, DSN)
    monkeypatch.setenv(ISSUER_ENV, "https://issuer.o12-planted.test")
    spawn = _RecordingSpawn()
    publish_launch.launch_publish("some-tenant", data_root=tmp_path, budget=5.0, spawn=spawn)
    (_argv, env), = spawn.calls
    assert env.get(DSN_ENV) == DSN
    assert ISSUER_ENV not in env  # the child is built from the scrubbed base plus the address, not from os.environ


def test_the_publish_child_is_not_handed_an_address_the_launcher_does_not_have(monkeypatch, tmp_path):
    """No address in the launcher's environment, none in the child's: nothing is invented (O12)."""
    from defender.investigation import publish_launch

    monkeypatch.delenv(DSN_ENV, raising=False)
    spawn = _RecordingSpawn()
    publish_launch.launch_publish("some-tenant", data_root=tmp_path, budget=5.0, spawn=spawn)
    (_argv, env), = spawn.calls
    assert DSN_ENV not in env
