"""`.devcontainer/dev-app.sh` passes the API exactly the settings the real server program reads.

The script writes the dev stack's settings in bash; nothing else runs it. A setting added to or renamed in the program
would break it only when someone next starts the app. So this runs the script's own `start_api` (the script, sourced,
only defines its functions), with the background launch replaced by a report of the `DEFENDER_*` names it was given,
and compares them with `SETTING_NAMES`, the set the program's own tests hold it to. Each secret file it names exists.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from defender._git import REPO_ROOT
from defender.tests.support.api._server1083 import SETTING_NAMES

SCRIPT = REPO_ROOT / ".devcontainer" / "dev-app.sh"

_REPORT = r"""
source "$1"
STATE="$2"; DSN=postgresql://dev/db; CERTS=/certs; BAO=https://openbao:8200; ISSUER=/issuer
mkdir -p "$STATE/secrets"; for name in signin signin-admin programs-admin; do : >"$STATE/secrets/$name"; done
port_open() { return 1; }
pid_alive() { return 1; }
launch() { env | sed -n 's/^\(DEFENDER_[A-Z_]*\)=\(.*\)$/\1 \2/p'; }
start_api 2>/dev/null
"""


def _passed(script: Path, state: Path) -> dict[str, str]:
    done = subprocess.run(["bash", "-c", _REPORT, "report", str(script), str(state)], capture_output=True, text=True,
                          env={"PATH": os.environ["PATH"], "HOME": str(state)}, check=True, timeout=30)
    return dict(line.split(" ", 1) for line in done.stdout.splitlines())


def test_the_launcher_passes_the_api_exactly_its_settings(tmp_path: Path) -> None:
    passed = _passed(SCRIPT, tmp_path)
    assert sorted(passed) == sorted(SETTING_NAMES)
    files = [value for name, value in passed.items() if name.endswith("_SECRET_FILE")]
    assert len(files) == 3
    assert all(Path(value).is_file() for value in files), files


def test_a_dropped_or_misnamed_setting_is_seen(tmp_path: Path) -> None:
    """The check can fail: the script with one export dropped, or one renamed, does not pass."""
    text = SCRIPT.read_text(encoding="utf-8")
    for old, new in (("    export DEFENDER_KEYCLOAK_CLIENT_ID=defender-api\n", ""),
                     ("DEFENDER_KEYCLOAK_PROGRAMS_AUDIENCE=", "DEFENDER_KEYCLOAK_PROGRAM_AUDIENCE=")):
        assert text.count(old) == 1, old
        mutant = tmp_path / "mutant.sh"
        mutant.write_text(text.replace(old, new), encoding="utf-8")
        assert sorted(_passed(mutant, tmp_path / "state")) != sorted(SETTING_NAMES), old


# --- #1592: the lifecycle's required settings ----------------------------------------------------------------------

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
    for name in (settings.KEYCLOAK_SOURCE_ID_ENV, settings.FORGE_SESSIONS_DSN_ENV):
        done = _lifecycle(SCRIPT, tmp_path / name, {k: v for k, v in given.items() if k != name})
        assert done.returncode != 0, (name, done.stdout, done.stderr)
        assert "launched" not in done.stdout, (name, done.stdout)
        assert name in done.stderr, (name, done.stderr)
