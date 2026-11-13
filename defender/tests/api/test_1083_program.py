"""#1083 piece 1: the server program's settings, start refusals, stop and close (`python -m defender.api_server`).

Refusals and stops run the program as a child (`Child`); the close promise is also observed in-process through
`defender.api_server.serving`, because a child's exit drops its connections either way."""
from __future__ import annotations

import socket
from pathlib import Path

import pytest

from defender.tests.support.api._server1083 import (
    ADMIN_READ,
    ANN,
    OPS,
    PROGRAMS_REALM,
    REALMS,
    SETTING_NAMES,
    SIGNIN_REALM,
    Child,
    FakeKeycloak,
    Faults,
    closed_port,
    environment,
    free_port,
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
    """The program ended with a refusal: non-zero, `mentions` on stderr, no traceback."""
    ended = child.ended()
    assert ended.returncode not in (0, -9999), ended.stderr
    for text in mentions:
        assert text in ended.stderr, ended.stderr
    assert "Traceback" not in ended.stderr
    return ended


def _names_realm(stderr: str, realm: str) -> bool:
    """The realm is named by its own name; `defender` is also a prefix of `defender-programs`."""
    return PROGRAMS_REALM in stderr if realm == PROGRAMS_REALM else SIGNIN_REALM in stderr.replace(PROGRAMS_REALM, "")


# --- settings --------------------------------------------------------------------------------------

def test_the_full_environment_parses_and_each_missing_setting_refuses_naming_it(tmp_path):
    """`Settings.from_environ` parses the full environment; each setting missing refuses, naming it. (O1, Am-7)"""
    from defender.api_server import Settings, StartRefused

    environ = environment(tmp_path, dsn="postgresql://defender@127.0.0.1:1/none")
    assert Settings.from_environ(environ) is not None  # positive control
    for name in SETTING_NAMES:
        without = {k: v for k, v in environ.items() if k != name}
        with pytest.raises(StartRefused, match=name):
            Settings.from_environ(without)


def _invalid_settings(tmp_path: Path) -> list[tuple[str, str, str]]:
    """`(case, setting, bad value)` for every setting where invalid is meaningful, generated from the names:
    a port that is not an integer, a secret file that cannot be read (absent; a directory), an administrators file
    that is not the FC-4 shape (absent; a list; the retired `tenants` section; a string for the list; not an
    email; empty)."""
    cases = []
    for name in SETTING_NAMES:
        if name.endswith("_SECRET_FILE"):
            cases.append(("absent", name, str(tmp_path / "no-such-secret")))
            cases.append(("directory", name, str(tmp_path)))
        if name == "DEFENDER_API_PORT":
            cases.append(("not-an-integer", name, "eighty"))
        if name == "DEFENDER_API_ADMINISTRATORS_FILE":
            cases.append(("absent", name, str(tmp_path / "no-such-administrators")))
            for label, text in (("list", "- ops@platform.example\n"),
                                ("tenants-section", "tenants: {}\nadministrators: [ops@platform.example]\n"),
                                ("string", "administrators: ops@platform.example\n"),
                                ("not-an-email", "administrators: [not-an-email]\n"),
                                ("empty", "")):
                path = tmp_path / f"administrators-{label}.yaml"
                path.write_text(text)
                cases.append((label, name, str(path)))
    return cases


def test_each_invalid_setting_refuses_naming_it(tmp_path):
    """`Settings.from_environ` refuses every invalid value, naming its setting. (O1, Am-7)"""
    from defender.api_server import Settings, StartRefused

    environ = environment(tmp_path, dsn="postgresql://defender@127.0.0.1:1/none")
    cases = _invalid_settings(tmp_path)
    assert {name for _, name, _ in cases} >= {n for n in SETTING_NAMES if n.endswith("_SECRET_FILE")}
    for _case, name, bad in cases:
        with pytest.raises(StartRefused, match=name):
            Settings.from_environ({**environ, name: bad})


@pytest.mark.parametrize("name", SETTING_NAMES)
def test_the_command_refuses_a_missing_setting_naming_it(tmp_path, name):
    """The shipped command, one setting missing: that setting on stderr, non-zero, no traceback. (O1, Am-3)"""
    environ = environment(tmp_path, dsn=UNREACHABLE_DSN.format(port=1))
    del environ[name]
    _refused(Child.real(environ), mentions=(name,))


def test_the_program_refuses_each_invalid_setting_naming_it(tmp_path):
    """Each invalid setting ends the program with that setting on stderr, non-zero, no traceback. (O1, Am-3)"""
    cases = _invalid_settings(tmp_path)
    for case, name, bad in cases:
        environ = environment(tmp_path, dsn=UNREACHABLE_DSN.format(port=1))
        environ[name] = bad
        ended = _refused(Child.faked(environ), mentions=(name,))
        assert ended.returncode > 0, case


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


def _faults(realm: str) -> dict[str, Faults]:
    """One fault per kind the fake can produce, on `realm` alone."""
    return {
        "missing realm": Faults(missing=(realm,)),
        "wrong issuer": Faults(issuer={realm: "http://elsewhere.example/realms/other"}),
        "bad secret": Faults(bad_secret=(realm,)),
        "no role": Faults(no_role=(realm,)),
    }


@pytest.mark.postgres
def test_every_realm_probe_failure_refuses_start_naming_that_realm(tmp_path, migrated_database):
    """Each fault of each realm refuses start naming that realm and no other, after a clean start works. (O3)"""
    environ = environment(tmp_path, dsn=migrated_database)
    healthy = Child.faked(environ)
    try:
        assert healthy.ready()  # positive control: no fault, the same environment serves
    finally:
        healthy.stop()
    for realm in REALMS:
        other = PROGRAMS_REALM if realm == SIGNIN_REALM else SIGNIN_REALM
        for kind, faults in _faults(realm).items():
            ended = _refused(Child.faked({**environ, "DEFENDER_API_PORT": str(free_port())}, faults), mentions=())
            assert _names_realm(ended.stderr, realm), (realm, kind, ended.stderr)
            if other == PROGRAMS_REALM:
                assert PROGRAMS_REALM not in ended.stderr, (realm, kind, ended.stderr)
            if kind in ("missing realm", "wrong issuer"):
                assert "discovery" in ended.stderr, (realm, kind, ended.stderr)


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
@pytest.mark.parametrize("sig", _handled_signals())
def test_a_ready_program_stopped_by_each_handled_signal_exits_zero_and_leaves_the_database(
        tmp_path, migrated_database, sig):
    """Each signal uvicorn handles stops a ready program with exit 0, no traceback, nothing attached. (Am-3)"""
    child = Child.faked(environment(tmp_path, dsn=migrated_database))
    try:
        assert child.ready()
        assert _backends(migrated_database) > 0  # control: a serving program holds connections
        ended = child.stop(sig)
    finally:
        child.kill()
    assert (ended.returncode, "Traceback" in ended.stderr) == (0, False), ended.stderr
    assert _backends(migrated_database) == 0


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
