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
