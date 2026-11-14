"""#1307 D7 wiring: the lifecycle's identity service holds a loud null programs port. The real API's programs wiring is
tested over the real server (`test_1083_real_server.py`, `test_1083_program.py`); the demo app that served programs over
a fake is gone (#1496).
"""
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
from defender.tests.support.tenancy._host1214 import LIFECYCLE_MARK  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import lifecycle_config  # noqa: E402



@pytest.fixture(autouse=True)
def _leave_the_lifecycle_mark_as_found(monkeypatch):
    """As `test_1214_atk2_process.py`: `_serve` marks the process; record its absence so teardown removes the mark."""
    monkeypatch.setenv(LIFECYCLE_MARK, "")
    monkeypatch.delenv(LIFECYCLE_MARK)


@pytest.mark.postgres
def test_the_lifecycle_builds_its_identity_service_with_a_programs_port_that_refuses_every_use(  # noqa: F811, C901
        empty_database, tmp_path, data_root, monkeypatch):  # noqa: F811
    """The real `_serve` gives its `IdentityService` a programs port (required, D7) whose every Keycloak operation raises
    and whose `close` is allowed; the service's other ports are untouched (D7, O6).

    As the #1214 process test: the real `_serve` runs over an upgraded empty database with settings from the environment; a
    profile hook reads the `IdentityService` constructor's arguments, and SIGTERM stops the process once the actors exist."""
    from defender.identity import IdentityService
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

    constructors = {HostActor.__init__.__code__: "host", ManagementService.__init__.__code__: "service",
                    IdentityService.__init__.__code__: "identity"}
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
        if not stopped and {"host", "service"} <= built.keys() and signal.getsignal(signal.SIGTERM) is not before:
            stopped.append(True)
            os.kill(os.getpid(), signal.SIGTERM)

    sys.setprofile(watch)
    try:
        code = asyncio.run(asyncio.wait_for(entry._serve(), 30))
    finally:
        sys.setprofile(None)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    assert code == 0, code
    assert stopped, sorted(built)
    programs = built["identity"]["programs"]
    assert programs is not None

    async def use() -> list[str]:
        refused = []
        for name, call in (("create_client", lambda: programs.create_client("c")), ("delete_client", lambda: programs.delete_client("c")),
                           ("client_ids", lambda: programs.client_ids()), ("verify_token", lambda: programs.verify_token("t"))):
            try:
                await call()
            except Exception:  # noqa: BLE001 — whatever it raises, it must not answer
                refused.append(name)
        await programs.close()  # control: closing a service closes its ports, which is allowed
        return refused

    assert asyncio.run(use()) == ["create_client", "delete_client", "client_ids", "verify_token"]
