"""#1083 piece 1: the server program's settings, start refusals, stop and close (`python -m defender.api_server`).

The settings and the probe are covered as classes in-process (`Settings.from_environ`, `serving`); a child process
(`Child`) is kept for one case per step kind and for the stop, where the child's own `run` reports its return."""
from __future__ import annotations

import socket
from pathlib import Path

import pytest

from defender.tests.support.api._server1083 import (
    ADMIN_READ,
    ANN,
    BACK,
    FAULTS,
    FRONT,
    OPS,
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

#: A bad value of the setting's own type, with a label; each is one the program must refuse (Am-7, FC-3).
def _shape_violations(name: str, tmp_path: Path) -> list[tuple[str, str]]:
    cases: list[tuple[str, str]] = []
    if name == "DEFENDER_API_PORT":
        cases += [("port 0", "0"), ("port 70000", "70000"), ("port negative", "-1"), ("port not an integer", "eighty")]
    if name == "DEFENDER_DATABASE_DSN":
        cases.append(("unparsable dsn", "not a dsn"))
    if name.endswith("_ISSUER"):
        cases += [("issuer without a realm", f"{FRONT}/elsewhere"), ("issuer with no realm name", f"{FRONT}/realms/")]
    if name == "DEFENDER_KEYCLOAK_SERVER_URL":
        cases.append(("server url with a path", f"{BACK}/realms/{SIGNIN_REALM}"))
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


#: Generated junk for any setting: either it starts or it refuses naming the setting; nothing else may happen.
JUNK = {"whitespace": " \t ", "multi-line": "a\nb\n", "junk bytes": "\x01\x7f\ufffd"}


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
async def test_a_setting_missing_empty_junk_or_misshapen_starts_or_refuses_naming_only_it(
        tmp_path, migrated_database, name):
    """Each setting, missing, empty, junk or misshapen: it starts, or refuses naming that setting alone. (O1, Am-7)"""
    healthy = environment(tmp_path, dsn=migrated_database)
    assert await _attempt("healthy", healthy, migrated_database) is None  # positive control: the unspoiled environment starts
    cases: list[tuple[str, str | None, bool]] = [("missing", None, True), ("empty", "", True)]
    cases += [(label, value, False) for label, value in JUNK.items()]
    cases += [(label, value, True) for label, value in _shape_violations(name, tmp_path)]
    refused = 0
    for label, value, must_refuse in cases:
        environ = {**healthy, "DEFENDER_API_PORT": str(free_port())}
        if value is None:
            del environ[name]
        else:
            environ[name] = value
        case = f"{name} {label}"
        message = await _attempt(case, environ, migrated_database)
        if message is None:
            assert not must_refuse, f"{case} started"
            continue
        refused += 1
        stripped = message.replace(value or "\0", "")
        assert [n for n in SETTING_NAMES if n in message] == [name], (case, message)
        if "PROGRAMS" not in name:
            assert PROGRAMS_REALM not in stripped, (case, message)
    assert refused >= 2  # the missing and the empty value, at least


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


# --- stop ---------------------------------------------------------------------------------------------

def _handled_signals() -> tuple[int, ...]:
    import uvicorn.server

    return tuple(int(s) for s in uvicorn.server.HANDLED_SIGNALS)


@pytest.mark.postgres
@pytest.mark.parametrize("phase", ["ready", "during start"])
@pytest.mark.parametrize("sig", _handled_signals())
def test_each_handled_signal_unwinds_a_ready_or_starting_program_to_exit_zero_with_nothing_attached(
        tmp_path, migrated_database, sig, phase):
    """Each signal uvicorn handles, ready or mid-start, makes `run` return 0 with no backend left. (Am-3)"""
    stalling = [Fail(SIGNIN_REALM, "discovery", "stall")] if phase == "during start" else []
    child = Child.faked(environment(tmp_path, dsn=migrated_database), stalling)
    try:
        if stalling:
            assert child.stalled(), "the start should be waiting on discovery"
        else:
            assert child.ready()
            assert _backends(migrated_database) > 0  # control: a serving program holds connections
        child.send_signal(sig)
        reported = child.reported()
        left = _backends(migrated_database)  # the child is held alive after reporting, so this is its own doing
        ended = child.ended()
    finally:
        child.kill()
    assert reported == 0, ended.stderr
    assert left == 0
    assert (ended.returncode, "Traceback" in ended.stderr) == (0, False), ended.stderr


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
