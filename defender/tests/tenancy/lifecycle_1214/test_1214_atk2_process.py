# ruff: noqa: PT018
"""#1214 attack-2: the lifecycle process's entry (`python -m defender.lifecycle`): the version check before any other work
for `serve` and `adopt` (O11), and `serve` giving each actor the client of its own credential (DC-12, F-1)."""
from __future__ import annotations

import asyncio
import os
import signal
import sys
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.shared._postgres1339 import empty_database  # noqa: E402,F401 — fixture
from defender.tests.support.tenancy._active1214 import DSN_ENV  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import lifecycle_config  # noqa: E402

TENANT = "7f3c1a52-9d4e-4b8a-a1c6-2e5d8b9f0c13"


@pytest.mark.postgres
@pytest.mark.parametrize("command", ["serve", "adopt"])
def test_the_lifecycle_process_refuses_a_database_behind_naming_both_revisions(command, empty_database, tmp_path,  # noqa: F811
                                                                              monkeypatch, capsys):
    """`serve` and `adopt` run the light version check before reading any setting: a baseline database is refused naming its
    revision and head; the upgraded one passes that check (O11)."""
    from defender.lifecycle.__main__ import main
    from defender.migrations import RevisionMismatch, head, upgrade
    from defender.tests.migrations.test_1214_migrations import BASELINE, _upgrade_to

    argv = [command] if command == "serve" else ["adopt", TENANT, "--issuer-dir", str(tmp_path / "issuer")]
    _upgrade_to(empty_database, BASELINE)
    monkeypatch.setenv(DSN_ENV, empty_database)
    for name in [k for k in os.environ if k.startswith(("DEFENDER_", "LIFECYCLE_")) and k != DSN_ENV
                 and not k.startswith("DEFENDER_TEST_")]:
        monkeypatch.delenv(name)  # so a passed check ends at the missing settings, never serves
    with pytest.raises((SystemExit, RevisionMismatch)) as refused:
        main(argv)
    text = f"{getattr(refused.value, 'code', '')}\n{refused.value}\n{capsys.readouterr().err}"
    assert BASELINE in text and head() in text, text
    upgrade(empty_database)
    after: list[BaseException] = []
    try:
        main(argv)
    except (SystemExit, Exception) as past:  # noqa: BLE001 — past the check, whatever the unset settings say next
        after.append(past)
    assert not [e for e in after if isinstance(e, RevisionMismatch)], "control: an upgraded database is still refused"


@pytest.mark.postgres
def test_serve_gives_the_host_the_credentialless_clients_and_the_service_the_credentialed_ones(  # noqa: F811
        empty_database, tmp_path, data_root, monkeypatch):  # noqa: F811
    """`python -m defender.lifecycle serve` builds the host actor over a login client with no token and a forge client with
    no authorization, and the service over the management and admin clients (DC-12, F-1).

    The real `_serve` runs over an upgraded empty database with its settings from the environment (`from_env`). Each
    actor's constructor arguments are read as it is called (a profile hook observes, it replaces nothing); once both
    actors are built and `_serve` has installed its SIGTERM handler, the hook sends the process SIGTERM, which stops it
    (SIGINT is not used: `asyncio.run` has its own handler for it)."""
    from defender.lifecycle import HostActor, ManagementService
    from defender.lifecycle import __main__ as entry
    from defender.lifecycle import config as settings
    from defender.migrations import upgrade

    upgrade(empty_database)
    expected = lifecycle_config(tmp_path, data_root)
    for name, value in (("forge-token", expected.forge_admin_token), ("bao-login", expected.openbao_login)):
        (tmp_path / name).write_text(value + "\n", encoding="utf-8")
    for name in [k for k in os.environ if k.startswith(("DEFENDER_LIFECYCLE_", "LIFECYCLE_"))]:
        monkeypatch.delenv(name)
    for name, value in ((DSN_ENV, empty_database), (settings.FORGE_URL_ENV, expected.forge_url),
                        (settings.FORGE_TOKEN_FILE_ENV, str(tmp_path / "forge-token")),
                        (settings.OPENBAO_LOGIN_FILE_ENV, str(tmp_path / "bao-login")),
                        (settings.INTEGRATION_ENV, expected.integration_command),
                        (settings.SECRETS_DIR_ENV, str(expected.secrets_dir)), (settings.DATA_ROOT_ENV, str(data_root)),
                        (settings.POLL_ENV, "0.05")):
        monkeypatch.setenv(name, value)

    constructors = {HostActor.__init__.__code__: "host", ManagementService.__init__.__code__: "service"}
    built: dict[str, dict[str, Any]] = {}
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    before = handlers[signal.SIGTERM]
    stopped: list[bool] = []

    def watch(frame: Any, event: str, _arg: Any) -> None:
        if event != "call":
            return
        role = constructors.get(frame.f_code)
        if role is not None and role not in built:
            built[role] = dict(frame.f_locals)
        if not stopped and len(built) == 2 and signal.getsignal(signal.SIGTERM) is not before:
            stopped.append(True)
            os.kill(os.getpid(), signal.SIGTERM)  # lands on `_serve`'s own handler, installed by now

    sys.setprofile(watch)
    try:
        code = asyncio.run(asyncio.wait_for(entry._serve(), 30))
    finally:
        sys.setprofile(None)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    assert code == 0 and stopped, (code, sorted(built))
    headers = {role: {k.lower(): v for k, v in client.headers.items()}
               for role, client in (("host forge", built["host"]["forge"]), ("host bao", built["host"]["openbao_login"]),
                                    ("service forge", built["service"]["forge"]), ("service bao", built["service"]["openbao"]))}
    assert "authorization" not in headers["host forge"] and "x-vault-token" not in headers["host bao"], headers
    assert expected.forge_admin_token not in str(headers["host forge"]) and expected.openbao_login not in str(headers["host bao"])
    assert headers["service forge"]["authorization"] == f"token {expected.forge_admin_token}"
    assert headers["service bao"]["x-vault-token"] == expected.openbao_login
