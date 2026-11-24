"""#1592: `.devcontainer/dev-app.sh` starts the lifecycle with every setting its config requires, and refuses a start
without the request worker's two (the Keycloak login source's id, the sessions database's DSN), as
`test_dev_app_settings.py` holds the script to the API's settings. Its `start_lifecycle` runs with the background
launch replaced by a report of the `DEFENDER_*` names it was given."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from defender._git import REPO_ROOT

SCRIPT = REPO_ROOT / ".devcontainer" / "dev-app.sh"

_LIFECYCLE = r"""
source "$1"
STATE="$2"; ISSUER="$3"
pgrep() { return 1; }
pid_alive() { return 1; }
launch() { echo "launched $1"; env | sed -n 's/^\(DEFENDER_[A-Z_]*\)=\(.*\)$/\1 \2/p'; }
start_lifecycle
"""


def lifecycle_required(monkeypatch: pytest.MonkeyPatch) -> set[str]:
    """The names `LifecycleConfig.from_env` refuses to start without, as the program itself names them."""
    from defender.lifecycle import ConfigRefused, LifecycleConfig
    from defender.lifecycle import config as settings

    names = {v for k, v in vars(settings).items() if k.endswith("_ENV") and isinstance(v, str)}
    for name in names:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ConfigRefused) as refused:
        LifecycleConfig.from_env(template_dir=REPO_ROOT)
    return {n for n in names if n in str(refused.value)}


def _lifecycle(script: Path, state: Path, given: dict[str, str]) -> subprocess.CompletedProcess[str]:
    issuer = state / "issuer"
    issuer.mkdir(parents=True, exist_ok=True)
    (issuer / "lifecycle.env").write_text("".join(f"export {n}={v}\n" for n, v in given.items()), encoding="utf-8")
    return subprocess.run(["bash", "-c", _LIFECYCLE, "report", str(script), str(state), str(issuer)],
                          capture_output=True, text=True, env={"PATH": os.environ["PATH"], "HOME": str(state)},
                          check=False, timeout=30)


def test_the_launcher_starts_the_lifecycle_with_every_setting_its_config_requires(tmp_path: Path, monkeypatch) -> None:
    """#1592 Settings: with `lifecycle.env` holding each name `from_env` requires (the request worker's source id and
    sessions DSN among them), `start_lifecycle` launches the lifecycle with each of them as given."""
    from defender.lifecycle import config as settings

    required = lifecycle_required(monkeypatch)
    assert {settings.KEYCLOAK_SOURCE_ID_ENV, settings.FORGE_SESSIONS_DSN_ENV} <= required, required
    given = {name: f"value-of-{name.lower()}" for name in sorted(required)}
    done = _lifecycle(SCRIPT, tmp_path, given)
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert done.stdout.startswith("launched lifecycle"), (done.stdout, done.stderr)
    passed = dict(line.split(" ", 1) for line in done.stdout.splitlines()[1:])
    assert {name: passed.get(name) for name in required} == given


def test_the_launcher_refuses_a_lifecycle_start_without_a_request_worker_setting(tmp_path: Path, monkeypatch) -> None:
    """#1592: a `lifecycle.env` without the Keycloak source id or the sessions DSN is refused naming it, and the
    lifecycle is not launched (it would exit 2 in the background)."""
    from defender.lifecycle import config as settings

    given = {name: f"value-of-{name.lower()}" for name in sorted(lifecycle_required(monkeypatch))}
    for name in (settings.KEYCLOAK_SOURCE_ID_ENV, settings.FORGE_SESSIONS_DSN_ENV, settings.FORGE_PUBLIC_URL_ENV):
        done = _lifecycle(SCRIPT, tmp_path / name, {k: v for k, v in given.items() if k != name})
        assert done.returncode != 0, (name, done.stdout, done.stderr)
        assert "launched" not in done.stdout, (name, done.stdout)
        assert name in done.stderr, (name, done.stderr)
