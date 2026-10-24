"""#1108 P4 round 6 — the environment scrub, over EVERY issuer-named variable the design lists
(each narrowing of the scrub was a wrong-but-green production variant), for the publish child and
for every other host child (`provider_scrubbed_environ`, `run_env`), plus the publish child's
lack of model-provider keys."""
from __future__ import annotations

import pytest

from defender.tests.tenancy.tenant_1108_p4.test_publish_child import _RecordingSpawn

#: Names that could carry issuer or forge login material (the design's list: BAO/Vault/OpenBao,
#: ISSUER, AppRole, role_id, secret_id, a forge token), as bare names and embedded in others.
PLANTED = (
    "ROLE_ID", "SECRET_ID", "APPROLE_ROLE", "APPROLE_SECRET", "FORGEJO_TOKEN", "OPENBAO_TOKEN",
    "OPENBAO_ADDR", "ISSUER_TOKEN", "ISSUER_URL", "BAO_TOKEN", "VAULT_TOKEN", "VAULT_ADDR",
    "MY_TENANT_ROLE_ID", "PUBLISH_SECRET_ID", "TENANT_FORGEJO_TOKEN", "x_secret_id",
)
VALUE = "r6-planted-login-material-3c5d"


@pytest.fixture
def planted(monkeypatch):
    for name in PLANTED:
        monkeypatch.setenv(name, f"{VALUE}-{name}")
    monkeypatch.setenv("R6_ORDINARY", "ordinary")
    return PLANTED


def test_r6_the_publish_child_gets_none_of_the_issuer_named_variables(planted, tmp_path):
    from defender.runtime import publish_launch

    spawn = _RecordingSpawn()
    publish_launch.launch_publish("some-tenant", data_root=tmp_path, budget=5.0, spawn=spawn)
    (_argv, env), = spawn.calls
    assert env.get("R6_ORDINARY") == "ordinary", "control: the env channel is read"
    leaked = sorted(name for name in planted if name in env)
    assert leaked == [], f"the publish child was handed {leaked}"
    assert not [v for v in env.values() if VALUE in v]


def test_r6_every_other_host_child_gets_none_of_the_issuer_named_variables(planted, tmp_path):
    from defender import run_common

    scrubbed = run_common.provider_scrubbed_environ()
    assert scrubbed.get("R6_ORDINARY") == "ordinary", "control: the env channel is read"
    assert sorted(n for n in planted if n in scrubbed) == []
    run_dir = tmp_path / "runs" / "r6"
    run_dir.mkdir(parents=True)
    env = run_common.run_env(tmp_path / "defender", run_dir)
    assert sorted(n for n in planted if n in env) == []
    assert not [v for v in env.values() if VALUE in v]


@pytest.mark.parametrize("name", ["ANTHROPIC_API_KEY", "FIREWORKS_API_KEY"])
def test_r6_the_publish_child_gets_no_model_provider_key(monkeypatch, tmp_path, name):
    """EXPECTED RED until production drops model-provider keys from the publish child's
    environment (`publish_launch.child_environment` passes them today)."""
    from defender.runtime import publish_launch

    monkeypatch.setenv(name, "r6-model-provider-key")
    spawn = _RecordingSpawn()
    publish_launch.launch_publish("some-tenant", data_root=tmp_path, budget=5.0, spawn=spawn)
    (_argv, env), = spawn.calls
    assert name not in env, f"the publish child was handed {name}"
