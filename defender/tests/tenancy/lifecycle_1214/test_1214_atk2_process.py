# ruff: noqa: PT018
"""#1214 attack-2: the lifecycle process's entry (`python -m defender.lifecycle`): the version check before any other work
for `serve` and `adopt` (O11), and `serve` giving each actor the client of its own credential (DC-12, F-1)."""
from __future__ import annotations

import asyncio
import os
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
    no authorization, and the service over the management and admin clients (DC-12, F-1)."""
    import defender.lifecycle as lifecycle
    from defender.lifecycle import __main__ as entry
    from defender.migrations import upgrade

    upgrade(empty_database)
    monkeypatch.setenv(DSN_ENV, empty_database)
    config = lifecycle_config(tmp_path, data_root)
    monkeypatch.setattr(entry, "_lifecycle_settings", lambda: config)
    built: dict[str, dict[str, Any]] = {}

    def spy(cls: type, name: str) -> type:
        class Spy(cls):  # type: ignore[valid-type, misc]
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                built[name] = kwargs
                super().__init__(*args, **kwargs)
        return Spy

    async def no_loop(_service: Any, _host: Any, **_kw: Any) -> None:
        return None

    fakes = {"HostActor": spy(lifecycle.HostActor, "host"),
             "ManagementService": spy(lifecycle.ManagementService, "service"), "serve": no_loop}
    for name, fake in fakes.items():  # on the package and on `__main__`, however `_serve` reaches them
        monkeypatch.setattr(lifecycle, name, fake)
        monkeypatch.setattr(entry, name, fake, raising=False)
    assert asyncio.run(entry._serve()) == 0
    headers = {role: {k.lower(): v for k, v in client.headers.items()}
               for role, client in (("host forge", built["host"]["forge"]), ("host bao", built["host"]["openbao_login"]),
                                    ("service forge", built["service"]["forge"]), ("service bao", built["service"]["openbao"]))}
    assert "authorization" not in headers["host forge"] and "x-vault-token" not in headers["host bao"]
    assert config.forge_admin_token not in str(headers["host forge"]) and config.openbao_login not in str(headers["host bao"])
    assert headers["service forge"]["authorization"] == f"token {config.forge_admin_token}"
    assert headers["service bao"]["x-vault-token"] == config.openbao_login
