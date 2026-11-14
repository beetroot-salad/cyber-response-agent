"""#1083 piece 1: the server program's settings, start refusals, stop and close (`python -m defender.api_server`).

The settings and the probe are covered as classes in-process (`Settings.from_environ`, `serving`); a child process
(`Child`) is kept for one case per step kind and for the stop, where the child's own `run` reports its return."""
from __future__ import annotations

import asyncio
import socket
import time
import urllib.parse
from pathlib import Path

import httpx
import pytest

from defender.tests.support.api._server1083 import (
    ADMIN_READ,
    ANN,
    BACK,
    FAULTS,
    FRONT,
    OPS,
    ORIGIN,
    PROGRAMS_REALM,
    REALMS,
    SETTING_NAMES,
    SIGNIN_REALM,
    STEPS,
    Child,
    Fail,
    FakeKeycloak,
    closed_port,
    environment,
    free_port,
    person,
    realms_named,
    seed_identity,
)
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import execute, server_dsn

pytestmark = pytest.mark.anyio

TENANT = "0b6f1c1e-3c55-4a4e-9a51-1083000000aa"
TENANT_B = "0b6f1c1e-3c55-4a4e-9a51-1083000000bb"
UNREACHABLE_DSN = "postgresql://defender@127.0.0.1:{port}/none"


def _backends(dsn: str) -> int:
    """Server backends attached to the test's database (as `pg_stat_activity` counts them)."""
    from sqlalchemy.engine import make_url

    [(count,)] = execute(server_dsn(), "SELECT count(*) FROM pg_stat_activity WHERE datname = %s",
                         (make_url(dsn).database,))
    return int(count)


def _refused(child: Child, *, mentions: tuple[str, ...]):
    """The program ended with a refusal: exit above 0 (not a signal death), `mentions` on stderr, no traceback."""
    ended = child.ended()
    assert ended.returncode > 0, (ended.returncode, ended.stderr)
    for text in mentions:
        assert text in ended.stderr, ended.stderr
    assert "Traceback" not in ended.stderr
    return ended


# --- settings and the probe, as classes ----------------------------------------------------------------

def _shape_violations(name: str, tmp_path: Path) -> list[tuple[str, str]]:
    """Bad values of the setting's own type, with a label; each one the program must refuse (Am-7, FC-3)."""
    cases: list[tuple[str, str]] = []
    if name == "DEFENDER_API_PORT":
        cases += [("port 0", "0"), ("port 70000", "70000"), ("port negative", "-1"), ("port not an integer", "eighty")]
    if name == "DEFENDER_DATABASE_DSN":
        cases.append(("unparsable dsn", "not a dsn"))
    if name == "DEFENDER_API_FRONTEND_ORIGIN":
        cases += [("origin with a path", f"{ORIGIN}/app"), ("origin with no scheme", "localhost:8000"),
                  # Not as a browser writes `Origin`, so no request would ever match it (#1498 review).
                  ("origin with an upper-case host", ORIGIN.replace("localhost", "LocalHost")),
                  ("origin with an upper-case scheme", ORIGIN.replace("http", "HTTP", 1)),
                  ("origin with its default port", "http://localhost:80"),
                  ("origin with a non-ASCII host", "http://bücher.example:8000")]
    if name == "DEFENDER_KEYCLOAK_REDIRECT_URI":
        cases += [("redirect uri relative", "/auth/callback"), ("redirect uri not http", "ftp://localhost:8000/cb"),
                  ("redirect uri no scheme", "localhost:8000/auth/callback"),
                  # OAuth forbids a fragment; the adapter's own rule refuses it, so sign-in cannot fail on it later.
                  ("redirect uri with a fragment", "http://localhost:8000/auth/callback#x")]
    if name.endswith("_ISSUER"):
        cases += [("issuer without a realm", f"{FRONT}/elsewhere"), ("issuer with no realm name", f"{FRONT}/realms/")]
    if name == "DEFENDER_KEYCLOAK_SERVER_URL":
        cases.append(("server url with a path", f"{BACK}/realms/{SIGNIN_REALM}"))
    return cases + _file_violations(name, tmp_path)


def _file_violations(name: str, tmp_path: Path) -> list[tuple[str, str]]:
    """Bad files for the secret-file settings and the administrators file."""
    cases: list[tuple[str, str]] = []
    if name.endswith("_SECRET_FILE"):
        cases += [("secret file absent", str(tmp_path / "no-such-secret")), ("secret file a directory", str(tmp_path))]
        for label, text in (("empty", ""), ("only a newline", "\n"), ("two lines", "one\ntwo\n")):
            path = tmp_path / f"secret-{label.replace(' ', '-')}"
            path.write_text(text)
            cases.append((f"secret file {label}", str(path)))
    if name == "DEFENDER_API_ADMINISTRATORS_FILE":
        cases.append(("administrators file absent", str(tmp_path / "no-such-administrators")))
        for label, text in (("list", "- ops@platform.example\n"),
                            ("tenants-section", "tenants: {}\nadministrators: [ops@platform.example]\n"),
                            ("string", "administrators: ops@platform.example\n"),
                            ("not-an-email", "administrators: [not-an-email]\n"),
                            ("empty", "")):
            path = tmp_path / f"administrators-{label}.yaml"
            path.write_text(text)
            cases.append((f"administrators file {label}", str(path)))
    return cases


def _junk(healthy: str) -> list[tuple[str, str]]:
    """Junk derived from a setting's healthy value: edge whitespace, a line break, each non-printable, embedded."""
    mid = len(healthy) // 2
    cases = [("leading space", " " + healthy), ("leading tab", "\t" + healthy), ("leading newline", "\n" + healthy),
             ("trailing space", healthy + " "), ("trailing tab", healthy + "\t"), ("trailing newline", healthy + "\n"),
             ("embedded line break", healthy[:mid] + "\n" + healthy[mid:])]
    unprintable = [*range(0x20), 0x7F, *range(0x80, 0xA0), 0x2028, 0x2029]
    for code in unprintable:
        assert not chr(code).isprintable()
        cases.append((f"embedded U+{code:04X}", healthy[:mid] + chr(code) + healthy[mid:]))
    return cases


async def _attempt(case: str, environ: dict[str, str], dsn: str, fails: tuple[Fail, ...] = ()) -> str | None:
    """Parse and start in-process; None if it started (and stopped), else the refusal's message. Leaves no
    connection of the database behind either way; any other exception fails the case."""
    from defender.api_server import Settings, StartRefused, serving

    message = None
    try:
        async with serving(Settings.from_environ(environ), transport=FakeKeycloak(fails)):
            pass
    except StartRefused as refused:
        message = str(refused)
    except Exception as unexpected:  # noqa: BLE001 - the promise is that nothing else escapes
        pytest.fail(f"{case}: {type(unexpected).__name__}: {unexpected}")
    assert _backends(dsn) == 0, case
    return message


def test_the_probe_failure_table_covers_every_step_of_both_realms():
    """The fault table has failures for every probe step of both realms; no setting name hides in another. (O3, Am-7)"""
    assert set(FAULTS) == {(realm, step) for realm in REALMS for step in STEPS}
    assert STEPS[0] == "discovery"
    assert all(FAULTS.values())
    assert not [(a, b) for a in SETTING_NAMES for b in SETTING_NAMES if a != b and a in b]


@pytest.mark.postgres
@pytest.mark.parametrize("name", SETTING_NAMES)
async def test_a_setting_missing_empty_or_misshapen_refuses_naming_only_it(tmp_path, migrated_database, name):
    """Each setting, missing, empty or misshapen: refuses to start naming that setting alone. (O1, Am-7)"""
    healthy = environment(tmp_path, dsn=migrated_database)
    assert await _attempt("healthy", healthy, migrated_database) is None  # positive control: the unspoiled environment starts
    cases: list[tuple[str, str | None]] = [("missing", None), ("empty", "")]
    cases += _shape_violations(name, tmp_path)
    for label, value in cases:
        environ = {**healthy, "DEFENDER_API_PORT": str(free_port())}
        if value is None:
            del environ[name]
        else:
            environ[name] = value
        case = f"{name} {label}"
        message = await _attempt(case, environ, migrated_database)
        assert message is not None, f"{case} started"
        stripped = message.replace(value or "\0", "")
        assert [n for n in SETTING_NAMES if n in message] == [name], (case, message)
        if "PROGRAMS" not in name:
            assert PROGRAMS_REALM not in stripped, (case, message)


def test_printing_the_settings_shows_no_client_secret(tmp_path):
    """The parsed settings, printed or shown in a failure diff, hold no secret file's value; the adapters still get
    each one, read out by name. (#1498 review)"""
    from defender.api_server import Settings

    healthy = environment(tmp_path, dsn="postgresql://defender:pw@localhost:5432/defender")
    settings = Settings.from_environ(healthy)
    secrets = {name: Path(healthy[name]).read_text().removesuffix("\n")
               for name in SETTING_NAMES if name.endswith("_SECRET_FILE")}
    assert len(secrets) == 3  # control: the three client secrets
    shown = f"{settings!r} {settings!s}"
    assert [name for name, value in secrets.items() if value in shown] == []
    held = {settings.signin_client_secret.get_secret_value(), settings.signin_admin_client_secret.get_secret_value(),
            settings.programs_admin_client_secret.get_secret_value()}
    assert held == set(secrets.values())


def test_every_setting_with_junk_derived_from_its_healthy_value_refuses_naming_only_it(tmp_path):
    """Edge whitespace, a line break or a non-printable in any setting refuses, naming that setting. (O1, Am-7)"""
    from defender.api_server import Settings, StartRefused

    healthy = environment(tmp_path, dsn="postgresql://defender:pw@localhost:5432/defender")
    Settings.from_environ(healthy)  # positive control: the healthy environment parses
    for name in SETTING_NAMES:
        for label, value in _junk(healthy[name]):
            with pytest.raises(StartRefused) as refused:
                Settings.from_environ({**healthy, name: value})
            message = str(refused.value)
            assert [n for n in SETTING_NAMES if n in message] == [name], (name, label, message)


@pytest.mark.postgres
@pytest.mark.parametrize(("realm", "step"), list(FAULTS))
async def test_every_failure_of_a_probe_step_refuses_naming_that_realm_alone(tmp_path, migrated_database, realm, step):
    """Each failure kind at each realm's probe step refuses start naming that realm, no other, no setting. (O3, FC-6)"""
    environ = environment(tmp_path, dsn=migrated_database)
    assert await _attempt("healthy", environ, migrated_database) is None  # positive control
    for kind in FAULTS[(realm, step)]:
        case = f"{realm} {step} {kind}"
        message = await _attempt(case, {**environ, "DEFENDER_API_PORT": str(free_port())}, migrated_database,
                                 (Fail(realm, step, kind),))
        assert message is not None, f"{case} started"
        assert realms_named(message) == {realm}, (case, message)
        assert [n for n in SETTING_NAMES if n in message] == [], (case, message)
        if step == "discovery":
            assert "discovery" in message, (case, message)


def test_the_command_refuses_one_missing_setting_naming_it(tmp_path):
    """The shipped command with a setting missing: that setting alone on stderr, non-zero, no traceback. (O1, Am-3)"""
    name = "DEFENDER_KEYCLOAK_ISSUER"
    environ = environment(tmp_path, dsn=UNREACHABLE_DSN.format(port=1))
    del environ[name]
    ended = _refused(Child.real(environ), mentions=(name,))
    assert [n for n in SETTING_NAMES if n in ended.stderr] == [name]


# --- refusals at each later step --------------------------------------------------------------------

@pytest.mark.postgres
def test_an_unmigrated_database_refuses_with_the_version_checks_message(tmp_path, empty_database):
    """An unmigrated database refuses start with #1339's message naming the code's head. (O2)"""
    from defender.migrations import head

    ended = _refused(Child.real(environment(tmp_path, dsn=empty_database)), mentions=())
    assert f"the database is at no recorded revision (unmigrated), but this code expects revision {head()}" \
        in ended.stderr


@pytest.mark.postgres
def test_a_database_at_another_revision_refuses_naming_both_revisions(tmp_path, migrated_database):
    """A database recorded at another revision refuses start naming it and the code's head. (O2)"""
    from defender.migrations import head

    execute(migrated_database, "UPDATE public.alembic_version SET version_num = %s", ("0001_elsewhere",))
    ended = _refused(Child.real(environment(tmp_path, dsn=migrated_database)), mentions=("0001_elsewhere", head()))
    assert "expects revision" in ended.stderr


def test_an_unreachable_database_refuses_with_the_version_checks_message(tmp_path):
    """A database nobody answers refuses start, naming its address. (O2)"""
    port = closed_port()
    ended = _refused(Child.real(environment(tmp_path, dsn=UNREACHABLE_DSN.format(port=port))),
                     mentions=("the database could not be reached",))
    assert f"127.0.0.1:{port}" in ended.stderr or str(port) in ended.stderr


@pytest.mark.postgres
def test_an_unreachable_keycloak_refuses_start_naming_realm_step_and_address(tmp_path, migrated_database):
    """With the database at head, a Keycloak nobody answers refuses start naming realm, step and address. (O3)"""
    port = closed_port()
    ended = _refused(Child.real(environment(tmp_path, dsn=migrated_database, keycloak=f"http://127.0.0.1:{port}")),
                     mentions=("discovery", f"127.0.0.1:{port}"))
    assert SIGNIN_REALM in ended.stderr.replace(f"127.0.0.1:{port}", "")


@pytest.mark.postgres
def test_a_failing_probe_step_refuses_the_program_naming_the_realm(tmp_path, migrated_database):
    """A failing probe step ends the program, naming that realm alone; the same environment healthy serves. (O3, Am-3)"""
    environ = environment(tmp_path, dsn=migrated_database)
    healthy = Child.faked(environ)
    try:
        assert healthy.ready()  # positive control: no failure, the same environment serves
    finally:
        healthy.stop()
    fail = Fail(PROGRAMS_REALM, "keys", "empty")
    ended = _refused(Child.faked({**environ, "DEFENDER_API_PORT": str(free_port())}, [fail]), mentions=())
    assert realms_named(ended.stderr) == {PROGRAMS_REALM}, ended.stderr


@pytest.mark.postgres
def test_a_taken_port_refuses_start_and_the_bootstrap_wrote_nothing(tmp_path, migrated_database):
    """A taken port refuses before the bootstrap: no administrator row is written; free, the same start writes it. (Am-3)"""
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        port = holder.getsockname()[1]
        environ = environment(tmp_path, dsn=migrated_database, port=port)
        _refused(Child.faked(environ), mentions=(str(port),))
    rows = "SELECT count(*) FROM identity.users WHERE email = %s"
    assert execute(migrated_database, rows, (OPS,)) == [(0,)]
    started = Child.faked({**environ, "DEFENDER_API_PORT": str(free_port())})
    try:
        assert started.ready()
        assert execute(migrated_database, rows, (OPS,)) == [(1,)]  # control: the bootstrap does write it
    finally:
        started.stop()


@pytest.mark.postgres
async def test_a_bootstrap_refusal_refuses_start_with_its_message(tmp_path, migrated_database):
    """An administrators file listing someone who holds a membership refuses start, naming them. (O1, Am-3)"""
    register_tenant(migrated_database, TENANT)
    register_tenant(migrated_database, TENANT_B)
    await seed_identity(migrated_database)  # Ann holds a membership of the tenant
    environ = environment(tmp_path, dsn=migrated_database, administrators=(ANN,))
    ended = _refused(Child.faked(environ), mentions=(ANN, "membership"))
    assert ended.returncode > 0


@pytest.mark.postgres
def test_a_failure_no_step_names_itself_still_refuses_in_one_line_naming_the_step(tmp_path, migrated_database, capsys):
    """A start step failing in a way it has no refusal for (here the version table answers a query error) ends the
    program with one stderr line naming that step, exit 1, no traceback. (O1, Am-3 promise 1; #1498 review)"""
    from defender.api_server import run

    execute(migrated_database, "ALTER TABLE public.alembic_version RENAME TO alembic_version_kept")
    execute(migrated_database, "CREATE VIEW public.alembic_version AS SELECT (1 / 0)::varchar(32) AS version_num")
    assert run(environment(tmp_path, dsn=migrated_database), transport=FakeKeycloak()) == 1
    stderr = capsys.readouterr().err
    assert stderr.count("\n") == 1, stderr
    assert "the database version check failed" in stderr, stderr
    assert "Traceback" not in stderr


@pytest.mark.postgres
def test_a_stop_while_a_refusal_closes_keeps_the_refusal_and_every_close(tmp_path, migrated_database, capsys):
    """A stop signal that lands while a refused start is closing what it opened cancels nothing: the program still
    exits 1 with the refusal, and both sign-in adapters are closed. (Am-3; #1498 review)"""
    import os
    import signal as _signal

    from defender.api_server import run

    class SignalsOnClose(FakeKeycloak):
        async def aclose(self) -> None:
            if self.closes == 0:  # the first close of the refusal's unwinding
                os.kill(os.getpid(), _signal.SIGINT)
                await asyncio.sleep(0.2)  # the handler runs on the loop while this close is in flight
            await super().aclose()

    keycloak = SignalsOnClose([Fail(SIGNIN_REALM, "keys", "empty")])
    assert run(environment(tmp_path, dsn=migrated_database), transport=keycloak) == 1
    assert realms_named(capsys.readouterr().err) == {SIGNIN_REALM}
    assert keycloak.closes == 2, "one close per Keycloak adapter built"


# --- stop ---------------------------------------------------------------------------------------------

def _handled_signals() -> tuple[int, ...]:
    import uvicorn.server

    return tuple(int(s) for s in uvicorn.server.HANDLED_SIGNALS)


#: Where a signal may land: serving, a Keycloak probe stalled at discovery, the version check parked on a database
#: that accepts the connection and never answers.
_PHASES = ("ready", "during start", "during the version check")


@pytest.mark.postgres
@pytest.mark.parametrize("phase", _PHASES)
@pytest.mark.parametrize("sig", _handled_signals())
def test_each_handled_signal_unwinds_a_ready_or_starting_program_to_exit_zero_with_nothing_attached(
        tmp_path, migrated_database, sig, phase):
    """Each signal uvicorn handles, ready or at each start step, makes `run` return 0 promptly with no backend left. (Am-3)"""
    environ = environment(tmp_path, dsn=migrated_database)
    stalling = [Fail(SIGNIN_REALM, "discovery", "stall")] if phase == "during start" else []
    held: list[socket.socket] = []
    with socket.socket() as mute:  # a database that accepts and never answers
        mute.bind(("127.0.0.1", 0))
        mute.listen()
        mute.settimeout(60)
        if phase == "during the version check":
            environ["DEFENDER_DATABASE_DSN"] = UNREACHABLE_DSN.format(port=mute.getsockname()[1])
        child = Child.faked(environ, stalling)
        try:
            if phase == "ready":
                assert child.ready()
                assert _backends(migrated_database) > 0  # control: a serving program holds connections
            elif stalling:
                assert child.stalled(), "the start should be waiting on discovery"
            else:
                held.append(mute.accept()[0])  # the version check connected and waits for an answer that never comes
            signalled = time.monotonic()
            child.send_signal(sig)
            reported = child.reported()
            elapsed = time.monotonic() - signalled
            unmodelled = child.unmodelled(timeout=5)
            left = _backends(migrated_database)  # the child is held alive after reporting, so this is its own doing
            ended = child.ended()
        finally:
            child.kill()
            for conn in held:
                conn.close()
    assert reported == 0, ended.stderr
    assert elapsed < (30 if phase == "ready" else 15), elapsed
    assert left == 0
    assert unmodelled == [], unmodelled
    assert (ended.returncode, "Traceback" in ended.stderr) == (0, False), ended.stderr


# --- every exit of `serving` closes what it opened ---------------------------------------------------

#: Each way `serving` can end once its first resource (the Keycloak adapters) is open: serving, then each start step.
_EXITS = ("served", *(f"probe {realm}" for realm in REALMS), "bind", "bootstrap")


async def _one_request_per_store(app, seeded) -> None:
    """A request served by each store-backed family: the job store, the identity store, the tenant rows."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        answered = [(await client.get(f"/tenants/{TENANT}/alerts", headers=person(seeded.ann_session))).status_code,
                    (await client.get("/me", headers=person(seeded.ann_session))).status_code,
                    (await client.get(f"/admin/tenants/{TENANT}", headers=person(seeded.ops_session))).status_code]
    assert answered == [200, 200, 200]


@pytest.mark.postgres
@pytest.mark.parametrize("ending", _EXITS)
async def test_every_exit_of_serving_leaves_no_backend_socket_or_keycloak_client_open(tmp_path, migrated_database, ending):
    """Served then left, or refused at a probe, the bind or the bootstrap: nothing `serving` opened stays open. (O1, Am-3, FC-1)"""
    from defender.api_server import Settings, StartRefused, serving

    dsn = migrated_database
    register_tenant(dsn, TENANT)
    register_tenant(dsn, TENANT_B)
    seeded = await seed_identity(dsn)
    keycloak = FakeKeycloak([Fail(ending.split()[1], "keys", "empty")] if ending.startswith("probe") else [])
    with socket.socket() as holder:
        holder.bind(("127.0.0.1", 0))
        holder.listen()
        port = holder.getsockname()[1] if ending == "bind" else free_port()
        settings = Settings.from_environ(environment(
            tmp_path, dsn=dsn, port=port, administrators=(ANN,) if ending == "bootstrap" else (OPS,)))
        host = "127.0.0.1"
        if ending == "served":
            async with serving(settings, transport=keycloak) as running:
                await _one_request_per_store(running.app, seeded)
                assert _backends(dsn) > 0  # control: every store has connected
                [listening] = running.sockets
                assert listening.getsockname() == (host, port)
                listening.listen()
                socket.create_connection((host, port), timeout=5).close()  # control: the bound address answers
                with pytest.raises(ConnectionRefusedError):
                    socket.create_connection(("127.0.0.2", port), timeout=5)
            assert [s.fileno() for s in running.sockets] == [-1]
        else:
            with pytest.raises(StartRefused):
                async with serving(settings, transport=keycloak):
                    pytest.fail(f"{ending} should have refused")
    assert _backends(dsn) == 0
    assert keycloak.closes == 2, "one close per Keycloak adapter built"
    if ending == "bootstrap":  # the socket was bound before the bootstrap refused: it is free again
        with socket.socket() as again:
            again.bind((host, port))


@pytest.mark.postgres
async def test_serving_holds_the_database_while_inside_and_closes_it_on_exit(tmp_path, migrated_database):
    """Inside `serving` the program holds database connections; leaving it normally closes every one. (O1, Am-3)"""
    from defender.api_server import Settings, serving

    settings = Settings.from_environ(environment(tmp_path, dsn=migrated_database))
    assert _backends(migrated_database) == 0
    async with serving(settings, transport=FakeKeycloak()):
        assert _backends(migrated_database) > 0
    assert _backends(migrated_database) == 0


@pytest.mark.postgres
async def test_a_refusal_after_the_job_store_opened_closes_what_was_opened(tmp_path, migrated_database):
    """A bootstrap refusal raises `StartRefused` and leaves no connection of this database. (O1, Am-3)"""
    from defender.api_server import Settings, StartRefused, serving

    register_tenant(migrated_database, TENANT)
    register_tenant(migrated_database, TENANT_B)
    await seed_identity(migrated_database)
    settings = Settings.from_environ(environment(tmp_path, dsn=migrated_database, administrators=(ANN,)))
    with pytest.raises(StartRefused, match=ANN):
        async with serving(settings, transport=FakeKeycloak()):
            pytest.fail("the bootstrap should have refused")
    assert _backends(migrated_database) == 0


@pytest.mark.postgres
async def test_both_realms_are_probed_at_start(tmp_path, migrated_database):
    """Start reads each realm's discovery, keys, admin token and admin read, and nothing else. (O3)"""
    from defender.api_server import Settings, serving

    keycloak = FakeKeycloak()
    async with serving(Settings.from_environ(environment(tmp_path, dsn=migrated_database)), transport=keycloak):
        probed = list(keycloak.seen)
    for realm in REALMS:
        host = "keycloak:8080"
        assert ("GET", f"{host}/realms/{realm}/.well-known/openid-configuration") in probed
        assert ("GET", f"{host}/realms/{realm}/protocol/openid-connect/certs") in probed
        assert ("POST", f"{host}/realms/{realm}/protocol/openid-connect/token") in probed
        assert ("GET", f"{host}/admin/realms/{realm}/{ADMIN_READ[realm]}") in probed
    assert keycloak.unmodelled == []


# --- every setting over a generated space of its own type ---------------------------------------------------------

#: A URL setting's stated shape (design, clarifications): `origin` scheme, host and optional port only; `issuer`
#: `<scheme>://<host>[:port]/realms/<realm>`; `absolute` an absolute http(s) URL. The server URL's path and the DSN's
#: scheme are not stated (a pending owner decision; an observation), so the oracle accepts either answer there.
_URL_SHAPES = {"DEFENDER_API_FRONTEND_ORIGIN": "origin", "DEFENDER_KEYCLOAK_ISSUER": "issuer",
               "DEFENDER_KEYCLOAK_PROGRAMS_ISSUER": "issuer", "DEFENDER_KEYCLOAK_REDIRECT_URI": "absolute",
               "DEFENDER_KEYCLOAK_SERVER_URL": "server", "DEFENDER_DATABASE_DSN": "dsn"}
REFUSE, ACCEPT, EITHER = "refuse", "accept", "either"


def _url_variants(healthy: str, shape: str) -> list[tuple[str, str, str]]:
    """(label, value, expected): the healthy URL with one component changed in turn."""
    parts = urllib.parse.urlsplit(healthy)
    host = parts.hostname
    port = f":{parts.port}" if parts.port else ""

    def url(scheme: str = parts.scheme, userinfo: str = "", port: str = port, path: str = parts.path,
            query: str = "", fragment: str = "") -> str:
        return f"{scheme}://{userinfo}{host}{port}{path}{query}{fragment}"

    def by(origin: str, issuer: str, absolute: str, server: str = EITHER) -> str:
        return {"origin": origin, "issuer": issuer, "absolute": absolute, "server": server}.get(shape, EITHER)

    healthy_path = parts.path
    cases = [("https", url(scheme="https"), by(ACCEPT, ACCEPT, ACCEPT, ACCEPT)),
             ("ftp", url(scheme="ftp"), by(REFUSE, REFUSE, REFUSE)),
             ("no scheme", url()[len(parts.scheme) + 3:], by(REFUSE, REFUSE, REFUSE)),
             ("port 8443", url(port=":8443"), by(ACCEPT, ACCEPT, ACCEPT, ACCEPT)),
             # A port that is not a TCP port makes no URL at all, whatever the setting.
             ("port not a number", url(port=":abc"), by(REFUSE, REFUSE, REFUSE, REFUSE)),
             ("port above 65535", url(port=":65536"), by(REFUSE, REFUSE, REFUSE, REFUSE)),
             ("port far above 65535", url(port=":99999"), by(REFUSE, REFUSE, REFUSE, REFUSE)),
             ("a path", url(path=healthy_path + "/more"), by(REFUSE, REFUSE, ACCEPT)),
             ("another realm", url(path="/realms/elsewhere"), by(REFUSE, ACCEPT, ACCEPT)),
             ("a path not of a realm", url(path="/elsewhere"), by(REFUSE, REFUSE, ACCEPT)),
             ("no path", url(path=""), by(ACCEPT, REFUSE, ACCEPT)),
             ("a trailing slash", url(path=healthy_path + "/"), by(REFUSE, EITHER, ACCEPT)),  # the adapter strips an issuer's (G8: one owner)
             ("a query", url(query="?a=1"), by(REFUSE, REFUSE, ACCEPT)),
             ("a fragment", url(fragment="#f"), by(REFUSE, REFUSE, EITHER))]
    cases += [(f"userinfo {info!r}", url(userinfo=info), by(REFUSE, REFUSE, EITHER))
              for info in ("user@", "user:pw@", "@", ":@")]
    if shape == "dsn":
        return [(label, value, EITHER) for label, value, _ in cases]
    return cases


#: Every YAML node type, as it is spelled in a flow sequence or after `key:`.
_YAML_NODES = {"email": "ops@platform.example", "string": "'not an email'", "empty string": "''", "int": "7",
               "float": "1.5", "bool": "true", "null": "null", "timestamp": "2026-11-14", "binary": "!!binary aGVsbG8=",
               "mapping": "{ops@platform.example: 1}", "sequence": "[ops@platform.example]",
               "set": "!!set {ops@platform.example: null}", "omap": "!!omap [{a: 1}]", "pairs": "!!pairs [{a: 1}]"}


def _administrators_variants() -> list[tuple[str, bytes, str]]:
    """(label, file bytes, expected): each YAML node type for the list and for an element, then bytes that are not YAML."""
    cases = [(f"list is a {kind}", f"administrators: {node}\n".encode(), ACCEPT if kind == "sequence" else REFUSE)
             for kind, node in _YAML_NODES.items()]
    cases += [(f"element is a {kind}", f"administrators: [ops@platform.example, {node}]\n".encode(),
               ACCEPT if kind == "email" else REFUSE) for kind, node in _YAML_NODES.items()]
    cases += [(f"document is a {kind}", f"{node}\n".encode(), REFUSE) for kind, node in _YAML_NODES.items()]
    cases += [("another key beside", b"administrators: [ops@platform.example]\nextra: 1\n", REFUSE),
              ("empty list", b"administrators: []\n", EITHER),
              ("not UTF-8", b"administrators: [ops\xff@platform.example]\n", REFUSE),
              ("UTF-16", "administrators: [ops@platform.example]\n".encode("utf-16"), REFUSE),
              ("a NUL", b"administrators: [ops\x00@platform.example]\n", REFUSE),
              ("unclosed flow sequence", b"administrators: [ops@platform.example\n", REFUSE),
              ("unclosed quote", b"administrators: ['ops@platform.example]\n", REFUSE),
              ("bad indentation", b"administrators:\n  - a@b.example\n - c@d.example\n", REFUSE),
              ("a tab indent", b"administrators:\n\t- ops@platform.example\n", REFUSE),
              ("two documents", b"administrators: [a@b.example]\n---\nadministrators: [c@d.example]\n", REFUSE),
              ("an unknown tag", b"administrators: !!python/object:os.system [x]\n", REFUSE)]
    return cases


def _secret_variants() -> list[tuple[str, bytes, str]]:
    """(label, file bytes, expected) for a secret file: one non-empty line, one trailing newline allowed."""
    return [("one line", b"s3cret\n", ACCEPT), ("no newline", b"s3cret", ACCEPT), ("empty", b"", REFUSE),
            ("a newline", b"\n", REFUSE), ("two lines", b"one\ntwo\n", REFUSE), ("a blank second line", b"s\n\n", REFUSE),
            ("a leading blank line", b"\ns\n", REFUSE), ("not UTF-8", b"s3\xffcret\n", REFUSE),
            ("UTF-16", "s3cret\n".encode("utf-16"), EITHER), ("a NUL", b"s3\x00cret\n", EITHER),
            ("CRLF", b"s3cret\r\n", EITHER), ("all bytes", bytes(range(256)), REFUSE)]


def _generated(name: str, healthy: str, tmp_path: Path) -> list[tuple[str, str, str]]:
    """(label, environment value, expected) for one setting, from its type's generated space."""
    if name in _URL_SHAPES:
        return _url_variants(healthy, _URL_SHAPES[name])
    if name.endswith("_FILE"):
        variants = _administrators_variants() if name == "DEFENDER_API_ADMINISTRATORS_FILE" else _secret_variants()
        cases = []
        for n, (label, raw, expected) in enumerate(variants):
            path = tmp_path / f"{name.lower()}-{n}"
            path.write_bytes(raw)
            cases.append((label, str(path), expected))
        return cases
    return []


@pytest.mark.postgres
async def test_every_url_and_file_setting_takes_each_generated_value_as_its_stated_shape_says(tmp_path, migrated_database):
    """A generated value of each URL or file setting parses, or refuses naming that setting alone, as its shape says;
    nothing else escapes, at parse or, for an accepted Keycloak URL, at start. (O1, Am-7, promise (1))"""
    from defender.api_server import Settings, StartRefused

    healthy = environment(tmp_path, dsn=migrated_database)
    Settings.from_environ(healthy)  # positive control: the healthy environment parses
    covered = {name for name in SETTING_NAMES if _generated(name, healthy[name], tmp_path)}
    assert covered == set(_URL_SHAPES) | {n for n in SETTING_NAMES if n.endswith("_FILE")}, covered
    wrong, started = [], []
    for name in sorted(covered):
        for label, value, expected in _generated(name, healthy[name], tmp_path):
            case = f"{name} {label}: {value!r}"
            try:
                Settings.from_environ({**healthy, name: value})
            except StartRefused as refused:
                named = [n for n in SETTING_NAMES if n in str(refused)]
                if named != [name] or expected == ACCEPT:
                    wrong.append(f"{case} refused naming {named}: {refused}")
            except Exception as unexpected:  # noqa: BLE001 - the promise is that nothing else escapes
                wrong.append(f"{case} raised {type(unexpected).__name__}: {unexpected}")
            else:
                if expected == REFUSE:
                    wrong.append(f"{case} was accepted")
                elif name.startswith("DEFENDER_KEYCLOAK_") and name in _URL_SHAPES:
                    started.append((case, {**healthy, name: value}))
    assert wrong == [], "\n".join(wrong)
    assert started, "premise: some Keycloak URL values are accepted"
    for case, environ in started:  # the adapters take what Settings took: start serves or refuses, nothing escapes
        await _attempt(case, {**environ, "DEFENDER_API_PORT": str(free_port())}, migrated_database)
