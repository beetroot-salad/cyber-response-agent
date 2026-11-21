# ruff: noqa: F811
# ruff: noqa: PT018
"""#1214 attack-3 hole 7 (DC-14, deck PR #1042): the `__main__` block of `python -m defender.lifecycle` is exercised in a
real subprocess: it parses its own arguments, refuses a missing database address, and runs a subcommand, not only `--help`.
"""
from __future__ import annotations

import collections
import http.server
import os
import subprocess
import sys
import threading
from pathlib import Path

import httpx
import pytest

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._postgres1339 import empty_database, execute, migrated_database  # noqa: F401 — fixtures
from defender.tests.support.tenancy._active1214 import insert_active_tenant
from defender.tests.support.tenancy._host1214 import LIFECYCLE_MARK
from defender.tests.tenancy.lifecycle_1214._fakes import ADMIN_TOKEN
from defender.tests.tenancy.people_1592._spec1592 import KEYCLOAK_SOURCE_ID, PeopleForge, login_of, pairs, requests_sql

DEFENDER = Path(__file__).resolve().parents[3]
TENANT = "7f3c1a52-9d4e-4b8a-a1c6-2e5d8b9f0c13"
DSN_ENV = "DEFENDER_DATABASE_DSN"


def _lifecycle(*args: str, dsn: str | None = None, settings: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("DEFENDER_", "LIFECYCLE_"))}
    env["PYTHONPATH"] = str(DEFENDER.parent)
    env.update(settings or {})
    if dsn is not None:
        env[DSN_ENV] = dsn
    return subprocess.run([sys.executable, "-m", "defender.lifecycle", *args], cwd=DEFENDER.parent, env=env,  # noqa: S603
                          capture_output=True, text=True, timeout=120, check=False)


def test_the_command_with_no_subcommand_is_a_usage_error():
    """No argument: exit 2 with a usage line, not the help page and success (DC-14)."""
    done = _lifecycle()
    assert done.returncode == 2, (done.returncode, done.stdout, done.stderr)
    assert "usage" in done.stderr.lower()


@pytest.mark.parametrize("command", [["serve"], ["resync-people"]])
def test_a_subcommand_with_no_database_address_refuses_naming_it(command):
    """`serve` and `resync-people` run their work: with no `DEFENDER_DATABASE_DSN` they exit non-zero naming it (DC-14, S3-18)."""
    done = _lifecycle(*command)
    assert done.returncode != 0
    assert DSN_ENV in done.stderr, done.stderr
    assert "usage:" not in done.stdout


@pytest.mark.postgres
@pytest.mark.parametrize("command", [["serve"], ["resync-people"]])
def test_a_subcommand_with_a_database_and_no_settings_refuses_as_the_command(migrated_database, command):  # noqa: F811
    """With a database at this revision but none of the lifecycle's settings, the subcommand itself refuses: exit 2, naming it (DC-14)."""
    done = _lifecycle(*command, dsn=migrated_database)
    assert done.returncode == 2, (done.returncode, done.stdout, done.stderr)
    assert command[0] in done.stderr, done.stderr
    assert "invalid choice" not in done.stderr, "the subcommand is not known to the command"


# --- resync-people (#1592 S3-17, S3-18) -----------------------------------------------------------------------------

#: The settings names the design gives (Settings): the two new required ones follow the `DEFENDER_LIFECYCLE_*` pattern.
SOURCE_ENV = "DEFENDER_LIFECYCLE_KEYCLOAK_SOURCE_ID"
SESSIONS_ENV = "DEFENDER_LIFECYCLE_FORGE_SESSIONS_DSN"


def _settings(tmp_path: Path, forge_url: str) -> dict[str, str]:
    """Every lifecycle setting as the environment gives it, the forge at `forge_url`."""
    from defender.lifecycle import config as names

    (tmp_path / "forge-token").write_text(ADMIN_TOKEN + "\n", encoding="utf-8")
    (tmp_path / "bao-login").write_text("bao-management-token\n", encoding="utf-8")
    return {names.FORGE_URL_ENV: forge_url, names.FORGE_TOKEN_FILE_ENV: str(tmp_path / "forge-token"),
            names.OPENBAO_LOGIN_FILE_ENV: str(tmp_path / "bao-login"), names.INTEGRATION_ENV: "forgejo-test",
            names.SECRETS_DIR_ENV: str(tmp_path / "secrets"), names.DATA_ROOT_ENV: str(tmp_path / "data"),
            SOURCE_ENV: str(KEYCLOAK_SOURCE_ID), SESSIONS_ENV: "postgresql://fs_lifecycle_login@sessions.test:5432/forgejo_sessions"}


@pytest.mark.parametrize("missing", [SOURCE_ENV, SESSIONS_ENV])
@pytest.mark.parametrize("command", ["serve", "resync-people"])
@pytest.mark.postgres
def test_a_missing_required_people_setting_refuses_as_the_command_naming_it(migrated_database, tmp_path, command, missing):
    """Every setting but one of the two #1592 requires: exit 2, one line naming the command and the setting (OD-4, OD-12, S3-18)."""
    settings = {k: v for k, v in _settings(tmp_path, "http://127.0.0.1:1").items() if k != missing}
    done = _lifecycle(command, dsn=migrated_database, settings=settings)
    assert done.returncode == 2, (done.returncode, done.stdout, done.stderr)
    assert command in done.stderr and missing in done.stderr, done.stderr
    assert "Traceback" not in done.stderr


@pytest.mark.parametrize("fault", ["unreachable", "revision"])
def test_resync_people_over_a_database_it_cannot_use_exits_one_with_one_line_naming_the_command(empty_database, tmp_path, fault):  # noqa: F811
    """An unreachable database or one at another revision: exactly one stderr line naming the command, exit 1, no
    traceback (review 15 F2, S3-18)."""
    dsn = "postgresql://nobody:nothing@127.0.0.1:1/none" if fault == "unreachable" else empty_database
    done = _lifecycle("resync-people", dsn=dsn, settings=_settings(tmp_path, "http://127.0.0.1:1"))
    lines = [line for line in done.stderr.splitlines() if line.strip()]
    assert done.returncode == 1, (done.returncode, done.stdout, done.stderr)
    assert "Traceback" not in done.stderr, done.stderr
    assert len(lines) == 1 and "resync-people" in lines[0], lines


class _Bridge(http.server.BaseHTTPRequestHandler):
    """Serves `forge.handle` over a real socket, so the command's own client talks to the fake."""

    forge: PeopleForge

    def _answer(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        request = httpx.Request(self.command, f"http://forge.test{self.path}", headers=dict(self.headers),
                                content=self.rfile.read(length))
        answered = self.forge.handle(request)
        self.send_response(answered.status_code)
        for name, value in answered.headers.items():
            if name.lower() not in ("content-length", "transfer-encoding", "connection"):
                self.send_header(name, value)
        self.send_header("content-length", str(len(answered.content)))
        self.end_headers()
        self.wfile.write(answered.content)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _answer  # noqa: N815 — the server's verb hooks

    def log_message(self, *_args: object) -> None:
        return None


@pytest.fixture
def forge_url(tmp_path):
    forge = PeopleForge(tmp_path / "forge")
    handler = type("Bridge", (_Bridge,), {"forge": forge})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield forge, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def _plant_user(dsn: str, user: str, sub: str) -> None:
    execute(dsn, """INSERT INTO identity.users (id, email, display_name, status, is_platform_admin, signin_account_id,
                    set_password_requested_seq, set_password_sent_seq, set_password_attempts, created_at, updated_at,
                    activated_at) VALUES (%s, %s, '', 'active', false, %s, 0, 0, 0, now(), now(), now())""",
            (user, f"{user}@x.org", sub))


def test_resync_people_records_the_tenants_and_every_person_account_and_lists_the_oddities_without_changing_them(  # noqa: F811, PLR0914
        migrated_database, forge_url, tmp_path, monkeypatch, capsys):
    """Three wired tenants give (none, T) each, the tenant with no wiring none; the 54 `p-` accounts of the source (past
    one page, known to the product or not) give (U, none) each; a non-`p-` login, a login_name that is not its user's sub, and
    an account of another source are not recorded; the first two are listed; the forge is written to never (OD-4, S3-17)."""
    from defender.lifecycle import __main__ as entry

    forge, url = forge_url
    wired = [fixture_uuid(f"tenant:1592-resync-{n}") for n in range(3)]
    bare = fixture_uuid("tenant:1592-resync-bare")
    for tenant in wired:
        insert_active_tenant(migrated_database, tenant)
    insert_active_tenant(migrated_database, bare, wiring=False)
    known = [fixture_uuid(f"user:1592-resync-known-{n}") for n in range(3)]
    for n, user in enumerate(known):
        _plant_user(migrated_database, user, f"sub-{n}")
    odd_login = login_of(known[2])
    for n, user in enumerate(known):
        forge.add_account(login_of(user), login_name=f"sub-{n}" if n < 2 else "someone-elses-sub")
    unknown = [login_of(fixture_uuid(f"user:1592-resync-unknown-{n}")) for n in range(51)]
    for login in unknown:
        forge.add_account(login, login_name="whatever")
    forge.add_account("operator-alice", login_name="alice")
    elsewhere = login_of(fixture_uuid("user:1592-resync-elsewhere"))
    forge.add_account(elsewhere, login_name="x", source_id=KEYCLOAK_SOURCE_ID + 1)
    on_source = [login for login, a in forge.accounts.items() if a["source_id"] == KEYCLOAK_SOURCE_ID]
    assert len(on_source) == 55, "premise: the source holds more than one page of accounts"
    before = ({k: dict(v) for k, v in forge.accounts.items()}, set(forge.prohibit_login), set(forge.users))
    seen = {r.id for r in requests_sql(migrated_database)}
    forge.calls.clear()

    monkeypatch.setenv(LIFECYCLE_MARK, "")  # `main` marks the process; monkeypatch removes the mark at teardown
    monkeypatch.delenv(LIFECYCLE_MARK)
    for name in [k for k in os.environ if k.startswith(("DEFENDER_LIFECYCLE_", "LIFECYCLE_"))]:
        monkeypatch.delenv(name)
    for name, value in {**_settings(tmp_path, url), DSN_ENV: migrated_database}.items():
        monkeypatch.setenv(name, value)
    capsys.readouterr()
    assert entry.main(["resync-people"]) == 0

    new = [r for r in requests_sql(migrated_database) if r.id not in seen]
    expected = collections.Counter({(None, t): 1 for t in wired})
    expected.update({(u.removeprefix("p-"), None): 1 for u in [*(login_of(k) for k in known), *unknown]})
    assert pairs(new) == expected
    out = capsys.readouterr().out
    assert "operator-alice" in out and odd_login in out, out
    assert login_of(known[0]) not in out and elsewhere not in out, "a clean account, or one of another source, was listed"
    assert forge.writes() == [], "resync-people wrote to the forge"
    assert ({k: dict(v) for k, v in forge.accounts.items()}, set(forge.prohibit_login), set(forge.users)) == before
    reads = [c for c in forge.calls if c.method == "GET" and c.path == "/api/v1/admin/users"]
    assert len(reads) >= 2, "only the first page of the source was read"
