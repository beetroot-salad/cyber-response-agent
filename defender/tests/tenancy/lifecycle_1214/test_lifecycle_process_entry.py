# ruff: noqa: PT018
"""#1214 attack-2: the lifecycle process's entry (`python -m defender.lifecycle`): the version check before any other work
for `serve` (O11), and `serve` giving each actor the client of its own credential (DC-12, F-1)."""
from __future__ import annotations

import asyncio
import dataclasses
import os
import signal
import sys
import time
from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.shared._postgres1339 import empty_database  # noqa: E402,F401 — fixture
from defender.tests.support.tenancy._active1214 import DSN_ENV  # noqa: E402
from defender.tests.support.tenancy._host1214 import LIFECYCLE_MARK  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import lifecycle_config, people_settings  # noqa: E402

TENANT = "7f3c1a52-9d4e-4b8a-a1c6-2e5d8b9f0c13"


@pytest.fixture(autouse=True)
def _leave_the_lifecycle_mark_as_found(monkeypatch):
    """These tests call the lifecycle's `main` in the pytest process, which marks the process (C6). The mark would
    outlive the test and refuse every later host acceptance in the worker, children started with a copy of the
    environment included. Recording the mark's absence now makes monkeypatch remove it at teardown (C6)."""
    monkeypatch.setenv(LIFECYCLE_MARK, "")
    monkeypatch.delenv(LIFECYCLE_MARK)


@pytest.mark.postgres
def test_the_lifecycle_process_refuses_a_database_behind_naming_both_revisions(empty_database, monkeypatch, capsys):  # noqa: F811
    """`serve` runs the light version check before reading any setting: a baseline database is refused naming its
    revision and head; the upgraded one passes that check (O11)."""
    from defender.lifecycle.__main__ import main
    from defender.migrations import RevisionMismatch, head, upgrade
    from defender.tests.migrations.test_1214_migrations import BASELINE, _upgrade_to

    argv = ["serve"]
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
        empty_database, tmp_path, data_root, monkeypatch, sessions_dsn):  # noqa: F811
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
                        (settings.POLL_ENV, "0.05"), *people_settings(settings, sessions_dsn)):
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
    # The first publish records what only its launcher sees (a child with no report) in the tenant records, as run
    # start's does, so `tenant.py check` can say why a tenant stuck at prepare never published.
    from defender.tenancy import TenantDirectory

    assert isinstance(getattr(built["host"]["publish"], "keywords", {}).get("directory"), TenantDirectory)


# --- #1592: the people worker beside the actors (S2-40) --------------------------------------------------------

@pytest.fixture
def sessions_dsn():
    from defender.tests.tenancy.people_1592._sessions1592 import shipped_sessions_database

    with shipped_sessions_database() as sessions:
        yield sessions.dsn


@pytest.mark.postgres
def test_serve_starts_the_people_worker_beside_the_actors(  # noqa: F811
        empty_database, tmp_path, data_root, monkeypatch, sessions_dsn):  # noqa: F811
    """S2-40: `_serve` builds a `PeopleWorker` over the sessions port and its own admin forge client, and its poll loop
    runs. Observed by a profile hook as the existing case does: nothing is replaced."""
    from defender.lifecycle import PeopleWorker
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
                        (settings.POLL_ENV, "0.05"), *people_settings(settings, sessions_dsn)):
        monkeypatch.setenv(name, value)

    built: dict[str, Any] = {}
    polled: list[bool] = []
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    before = handlers[signal.SIGTERM]
    stopped: list[bool] = []

    def watch(frame: Any, event: str, _arg: Any) -> None:
        if event != "call":
            return
        if frame.f_code is PeopleWorker.__init__.__code__ and "people" not in built:
            built["people"] = dict(frame.f_locals)
        if frame.f_code is PeopleWorker.poll.__code__:
            polled.append(True)
        if polled and not stopped and signal.getsignal(signal.SIGTERM) is not before:
            stopped.append(True)
            os.kill(os.getpid(), signal.SIGTERM)

    sys.setprofile(watch)
    try:
        code = asyncio.run(asyncio.wait_for(entry._serve(), 30))
    finally:
        sys.setprofile(None)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    assert code == 0 and stopped and "people" in built, (code, sorted(built))
    from defender.lifecycle import PostgresForgeSessions

    assert isinstance(built["people"]["sessions"], PostgresForgeSessions)
    forge = built["people"]["forge"]
    assert forge.headers["authorization"] == f"token {expected.forge_admin_token}"
    assert forge.timeout.read == 5.0  # `people_call_timeout`'s default


# --- #1592: every setting reaches its readers (S2-40b) --------------------------------------------------------------

#: The values `from_env` cannot give: the four durations and the concurrency are read from no variable (Settings), and
#: the older fixed names and bounds neither; the census sets them on the config `from_env` returns, as a caller that
#: constructs the config with others would. Each differs from its default and from every other value here.
INJECTED: dict[str, Any] = {
    "issuer_url": "https://issuer-census.test", "openbao_url": "https://bao-census.test:8200", "lock_keepalive": 41,
    "teardown_wait": 7.25, "oidc_key": "census-oidc-key", "token_policy": "census-token-policy",
    "sign_policy": "census-sign-policy", "people_poll": 0.3, "people_concurrency": 3, "people_call_timeout": 2.75,
    "forge_session_cap": 4321.0, "forge_cap_every": 0.7,
}
POLL_INTERVAL = 0.05  # `DEFENDER_LIFECYCLE_POLL_INTERVAL`, its default 5


def _url(client: Any) -> str:
    return str(client.base_url).rstrip("/")


def _in_config(*roles: str) -> Callable[[dict[str, Any], str, Any], list[str]]:
    """A reader that takes the field from the config it was given: each role's `config` holds the value."""
    def check(seen: dict[str, Any], name: str, value: Any) -> list[str]:
        return [f"{role}'s config has {name}={getattr(seen[role]['config'], name)!r}" for role in roles
                if getattr(seen[role]["config"], name) != value]
    return check


def _all(*checks: Callable[[dict[str, Any], str, Any], list[str]]) -> Callable[[dict[str, Any], str, Any], list[str]]:
    return lambda seen, name, value: [why for check in checks for why in check(seen, name, value)]


def _that(test: Callable[[dict[str, Any], Any], bool], what: str) -> Callable[[dict[str, Any], str, Any], list[str]]:
    return lambda seen, name, value: [] if test(seen, value) else [f"{name}={value!r}: {what}"]


def _gaps(times: list[float]) -> list[float]:
    return [b - a for a, b in zip(times, times[1:], strict=False)]


_ACTORS = _in_config("service", "host")
#: Every `LifecycleConfig` field, with what reads it in `_serve` and the people worker (a field missing here fails).
READERS: dict[str, Callable[[dict[str, Any], str, Any], list[str]]] = {
    "issuer_url": _ACTORS,
    "forge_url": _all(_ACTORS, _that(lambda s, v: {_url(s["service"]["forge"]), _url(s["host"]["forge"]),
                                                   _url(s["people"]["forge"])} == {v.rstrip("/")},
                                     "the forge clients' base URL")),
    "forge_admin_token": _that(lambda s, v: s["service"]["forge"].headers["authorization"] == f"token {v}"
                               == s["people"]["forge"].headers["authorization"], "the admin forge clients' token"),
    "openbao_url": _all(_ACTORS, _that(lambda s, v: {_url(s["service"]["openbao"]), _url(s["host"]["openbao_login"])}
                                       == {v.rstrip("/")}, "the OpenBao clients' base URL")),
    "openbao_login": _that(lambda s, v: s["service"]["openbao"].headers["x-vault-token"] == v,
                           "the management OpenBao client's token"),
    # main's public forge address: the create step records `repo_url` as `<forge_page_base>/<repo>` (test_create's
    # `test_create_records_the_repository_page_on_the_forge_address_unless_a_public_one_is_set`), a trailing slash dropped
    "forge_public_url": _all(_in_config("service"), _that(lambda s, v: s["service"]["config"].forge_page_base
                                                          == v.rstrip("/"), "the repository page's base address")),
    "integration_command": _in_config("service"),
    "template_dir": _ACTORS,
    "secrets_dir": _ACTORS,
    "data_root": _ACTORS,
    "poll_interval": _all(_ACTORS, _in_config("serve")),
    "lock_keepalive": _that(lambda s, v: s["keepalive"].get(id(s["service"]["tenants"])) == v
                            and s["people"]["tenants"] is s["service"]["tenants"], "the tenant repository's keepalive"),
    "teardown_wait": _ACTORS,
    "oidc_key": _ACTORS,
    "token_policy": _ACTORS,
    "sign_policy": _ACTORS,
    "keycloak_source_id": _in_config("people"),
    "forge_sessions_dsn": _that(lambda s, v: s["sessions"]["dsn"] == v, "the sessions port's DSN"),
    "people_poll": _that(lambda s, v: len(s["polls"]) >= 3 and all(v * 0.8 <= gap < 2.0 for gap in _gaps(s["polls"][:3])),
                         "the wait between the worker's polls"),
    "people_concurrency": _in_config("people"),
    "people_call_timeout": _that(lambda s, v: s["people"]["forge"].timeout.read == v
                                 and s["sessions"]["statement_timeout"] == v,
                                 "the worker's forge client timeout and the sessions port's statement_timeout"),
    "forge_session_cap": _that(lambda s, v: bool(s["caps"]) and all(older == v for older, _at in s["caps"]),
                               "the cap job's `older_than`"),
    "forge_cap_every": _that(lambda s, v: len(s["caps"]) >= 2 and len(s["caps"]) < len(s["polls"])
                             and all(gap >= v * 0.9 for gap in _gaps([at for _older, at in s["caps"]])),
                             "the time between cap runs"),
}


@pytest.mark.postgres
def test_every_lifecycle_setting_reaches_each_of_its_readers(  # noqa: F811, C901 — one hook watches every reader
        empty_database, tmp_path, data_root, monkeypatch, sessions_dsn):  # noqa: F811
    """S2-40b (#1592 Settings): a census over every `LifecycleConfig` field: each gets a value of its own, unlike its
    default, and `_serve`, its worker's polls and two cap runs hand each reader that value (`people_call_timeout` to the
    forge client and the sessions port's `statement_timeout`, `forge_session_cap` to `cap(older_than=)`). Observed by a
    profile hook; the only thing it sets is the config `from_env` returned, for the fields no variable gives."""
    from defender.lifecycle import (HostActor, LifecycleConfig, ManagementService, PeopleWorker, PostgresForgeSessions,
                                    serve)
    from defender.lifecycle import __main__ as entry
    from defender.lifecycle import config as settings
    from defender.migrations import upgrade
    from defender.tenancy.postgres import PostgresTenantRepository

    names = {f.name for f in dataclasses.fields(LifecycleConfig)}
    assert names == set(READERS), f"fields with no reader in the census: {sorted(names - set(READERS))}; " \
                                  f"readers of no field: {sorted(set(READERS) - names)}"
    upgrade(empty_database)
    base = lifecycle_config(tmp_path, data_root)
    expected = {f.name: getattr(base, f.name) for f in dataclasses.fields(LifecycleConfig)}
    expected |= {**INJECTED, "poll_interval": POLL_INTERVAL, "forge_sessions_dsn": sessions_dsn, "keycloak_source_id": 59,
                 "forge_url": "http://forge-census.test:3999", "forge_public_url": "https://forge-public-census.test/",
                 "forge_admin_token": "census-forge-token",
                 "openbao_login": "census-bao-login", "integration_command": "census-integration",
                 "secrets_dir": tmp_path / "census-secrets"}
    defaults = {f.name: f.default for f in dataclasses.fields(LifecycleConfig) if f.default is not dataclasses.MISSING}
    assert not [n for n, v in defaults.items() if expected[n] == v], "control: a field kept its default"
    plain = [v for v in expected.values() if isinstance(v, (int, float, str))]
    assert len(plain) == len(set(plain)), "control: two fields share a value"
    for name, value in (("forge-token", expected["forge_admin_token"]), ("bao-login", expected["openbao_login"])):
        (tmp_path / name).write_text(value + "\n", encoding="utf-8")
    for name in [k for k in os.environ if k.startswith(("DEFENDER_LIFECYCLE_", "LIFECYCLE_"))]:
        monkeypatch.delenv(name)
    for name, value in ((DSN_ENV, empty_database), (settings.FORGE_URL_ENV, expected["forge_url"]),
                        (settings.FORGE_PUBLIC_URL_ENV, expected["forge_public_url"]),
                        (settings.FORGE_TOKEN_FILE_ENV, str(tmp_path / "forge-token")),
                        (settings.OPENBAO_LOGIN_FILE_ENV, str(tmp_path / "bao-login")),
                        (settings.INTEGRATION_ENV, expected["integration_command"]),
                        (settings.SECRETS_DIR_ENV, str(expected["secrets_dir"])), (settings.DATA_ROOT_ENV, str(data_root)),
                        (settings.POLL_ENV, str(POLL_INTERVAL)),
                        (settings.KEYCLOAK_SOURCE_ID_ENV, str(expected["keycloak_source_id"])),
                        (settings.FORGE_SESSIONS_DSN_ENV, sessions_dsn)):
        monkeypatch.setenv(name, value)

    roles = {HostActor.__init__.__code__: "host", ManagementService.__init__.__code__: "service",
             PeopleWorker.__init__.__code__: "people", PostgresForgeSessions.__init__.__code__: "sessions",
             serve.__code__: "serve"}
    seen: dict[str, Any] = {"keepalive": {}, "polls": [], "caps": []}
    frames: dict[int, Any] = {}  # each coroutine frame once (a resumed coroutine is a "call" again); kept alive
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    before = handlers[signal.SIGTERM]
    stopped: list[bool] = []
    deadline = time.monotonic() + 8  # a reader that never runs (a cap job never due again) still ends the run

    def watch(frame: Any, event: str, arg: Any) -> None:
        code = frame.f_code
        if event == "return" and code is LifecycleConfig.from_env.__func__.__code__:
            for name, value in INJECTED.items():
                object.__setattr__(arg, name, value)
        if event != "call" or id(frame) in frames:
            return
        if code in roles and roles[code] not in seen:
            frames[id(frame)] = frame
            seen[roles[code]] = dict(frame.f_locals)
        elif code is PostgresTenantRepository.__init__.__code__:
            seen["keepalive"][id(frame.f_locals["self"])] = frame.f_locals.get("lock_keepalive")
        elif code is PeopleWorker.poll.__code__:
            frames[id(frame)] = frame
            seen["polls"].append(time.monotonic())
        elif code is PostgresForgeSessions.cap.__code__:
            frames[id(frame)] = frame
            seen["caps"].append((frame.f_locals["older_than"], time.monotonic()))
        enough = (len(seen["caps"]) >= 2 and len(seen["polls"]) >= 3) or time.monotonic() > deadline
        if not stopped and enough and signal.getsignal(signal.SIGTERM) is not before:
            stopped.append(True)
            os.kill(os.getpid(), signal.SIGTERM)

    sys.setprofile(watch)
    try:
        code = asyncio.run(asyncio.wait_for(entry._serve(), 30))
    finally:
        sys.setprofile(None)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    assert code == 0 and stopped, (code, sorted(seen), len(seen["polls"]), seen["caps"])
    wrong = [why for name, check in READERS.items() for why in check(seen, name, expected[name])]
    assert wrong == [], wrong
