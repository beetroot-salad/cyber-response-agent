"""Run the tenant lifecycle (#1214 DC-14).

    python -m defender.lifecycle serve  # the management service and the host actor, one process (dev)
    python -m defender.lifecycle make-runs-folders  # one-time: `<T>/runs` for every active tenant made before #1471
    python -m defender.lifecycle resync-people  # after a restore, and at the #1592 upgrade: a request per person and tenant

It reads `DEFENDER_DATABASE_DSN` (the database at exactly this code's revision) and the lifecycle's
settings (`defender.lifecycle.config`: the files holding the forge admin token and the OpenBao
management login, the integration container, the secrets directory, `DEFENDER_DATA_ROOT`). The
issuer and OpenBao addresses are fixed service names (`defender.configuration.issuer`); the
infrastructure routes them. `resync-people` reads only `DEFENDER_DATABASE_DSN`, the forge's address, the file holding its
admin token and the sign-in provider's login source's id."""
from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import functools
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


class _NoPeople:
    """The sign-in, mail and programs ports of an identity service that only ends memberships (offboarding's
    `end_tenant`); anything else it is asked is a programming error. Offboarding revokes a program's
    credentials but never touches the programs realm: the API's reconciliation deletes the clients."""

    async def close(self) -> None:
        return None

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(f"the lifecycle's identity service has no {name}: it only ends memberships")


def _dsn() -> str:
    from defender.migrations import check_version
    from defender.tenancy import database_address_variable

    variable = database_address_variable()
    dsn = os.environ.get(variable, "")
    if not dsn:
        raise SystemExit(f"{variable} is not set: the lifecycle works the tenant records in PostgreSQL")
    check_version(dsn)
    return dsn


def _lifecycle_settings() -> Any:
    from defender._paths import PATHS
    from defender.lifecycle.config import LifecycleConfig
    from defender.tenancy import template_dir

    return LifecycleConfig.from_env(template_dir=template_dir(PATHS.repo_root))


async def _make_runs_folders() -> int:
    """The one-time upgrade step (R13-0): make each active tenant's `<T>/runs`. Any refusal, after the sweep, is one error
    naming every refused tenant and a non-zero exit."""
    from defender.lifecycle import RunsFoldersRefused, make_runs_folders
    from defender.lifecycle.config import DATA_ROOT_ENV, ConfigRefused
    from defender.tenancy.postgres import PostgresTenantRepository

    raw = os.environ.get(DATA_ROOT_ENV, "")
    if not raw or not Path(raw).is_absolute():
        raise ConfigRefused(f"set {DATA_ROOT_ENV} to the absolute data root")
    tenants = PostgresTenantRepository(_dsn())
    try:
        try:
            made = await make_runs_folders(tenants, data_root=Path(raw))
        except RunsFoldersRefused as refused:
            print(f"python -m defender.lifecycle make-runs-folders: {refused}", file=sys.stderr)
            return 1
    finally:
        await tenants.close()
    print(f"made the runs folder of {len(made)} tenant(s)" + "".join(f"\n  {t}" for t in made))
    return 0


async def _resync_people() -> int:
    """`resync-people` (#1592 F6(c)): a (none, T) request for every wired tenant and a (U, none) one for every `p-<id>`
    account on the sign-in provider's source; the accounts it cannot vouch for are listed on stdout, unchanged."""
    from defender.identity.postgres import PostgresIdentityRepository
    from defender.lifecycle._process import forge_client
    from defender.lifecycle._resync import resync_people
    from defender.lifecycle.config import (FORGE_TOKEN_FILE_ENV, FORGE_URL_ENV, KEYCLOAK_SOURCE_ID_ENV, ConfigRefused,
                                           _secret_file, source_id_from_env)
    from defender.tenancy import database_address_variable
    from defender.tenancy.postgres import PostgresTenantRepository

    missing = [n for n in (FORGE_URL_ENV, FORGE_TOKEN_FILE_ENV, KEYCLOAK_SOURCE_ID_ENV, database_address_variable())
               if not os.environ.get(n)]
    if missing:
        raise ConfigRefused(f"set {', '.join(missing)}")
    source_id = source_id_from_env()
    token = _secret_file(os.environ[FORGE_TOKEN_FILE_ENV], FORGE_TOKEN_FILE_ENV)
    dsn = _dsn()
    tenants, identity = PostgresTenantRepository(dsn), PostgresIdentityRepository(dsn)
    forge = forge_client(os.environ[FORGE_URL_ENV], token)
    try:
        await resync_people(tenants, identity, forge, source_id=source_id, say=print)
    finally:
        await forge.aclose()
        await identity.close()
        await tenants.close()
    return 0


async def _serve() -> int:
    from defender.identity import Bootstrap, IdentityService
    from defender.identity.postgres import PostgresIdentityRepository
    from defender.investigation.publish_launch import launch_publish
    from defender.lifecycle import (HostActor, ManagementService, PeopleWorker, PostgresForgeSessions, git_runner,
                                    integration_runner, serve)
    from defender.lifecycle import _process as clients
    from defender.tenancy import TenantDirectory
    from defender.tenancy.postgres import PostgresTenantRepository

    dsn, config = _dsn(), _lifecycle_settings()
    tenants = PostgresTenantRepository(dsn, lock_keepalive=config.lock_keepalive)
    people_records = PostgresIdentityRepository(dsn)
    identity = IdentityService(people_records, signin=_NoPeople(), mail=_NoPeople(),
                               programs=_NoPeople(), clock=_now, bootstrap=Bootstrap(administrators=()))
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stopping.set)
    service = ManagementService(tenants, identity=identity, forge=clients.forge_admin(config),
                                openbao=clients.openbao_management(config),
                                integration=integration_runner(config.integration_command), git=git_runner,
                                config=config, clock=_now)
    directory = TenantDirectory(lambda: PostgresTenantRepository(dsn))
    host = HostActor(tenants, forge=clients.forge_anonymous(config), openbao_login=clients.openbao_login(config),
                     git=git_runner, config=config, clock=_now,
                     # as run start's: the outcomes only the launcher sees are recorded for the readiness check
                     publish=functools.partial(launch_publish, directory=directory))
    people = PeopleWorker(tenants, identity=people_records, forge=clients.forge_people(config),
                          sessions=PostgresForgeSessions(config.forge_sessions_dsn,
                                                         statement_timeout=config.people_call_timeout),
                          config=config, clock=_now)
    _logger.info("lifecycle: serving both actors every %ss, the people worker every %ss", config.poll_interval,
                 config.people_poll)
    people_task = asyncio.ensure_future(people.start())
    try:
        await serve(service, host, config=config, stop=stopping.is_set)
    finally:
        people_task.cancel()
        await asyncio.gather(people_task, return_exceptions=True)
        await people.close()
        await identity.close()
        await tenants.close()
    return 0


def _run(command: str) -> int:
    """The command's coroutine run to its end; `resync-people` names a database or forge it cannot use in one line."""
    if command == "make-runs-folders":
        return asyncio.run(_make_runs_folders())
    if command == "serve":
        return asyncio.run(_serve())
    import httpx

    from defender.lifecycle._job import StepFailed
    from defender.migrations import DatabaseUnreachable, RevisionMismatch

    try:
        return asyncio.run(_resync_people())
    except (DatabaseUnreachable, RevisionMismatch, StepFailed, httpx.HTTPError) as failed:
        print(f"python -m defender.lifecycle {command}: {failed}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    from defender.tenancy import mark_lifecycle_process

    # r10.1 C6: first, so nothing this process runs can take a shared host hold (prepare holds the
    # lock exclusive here; the host acceptance refuses in a marked process).
    mark_lifecycle_process()
    parser = argparse.ArgumentParser(prog="python -m defender.lifecycle", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="run the management service and the host actor until stopped (dev)")
    commands.add_parser("make-runs-folders", help="one-time upgrade: make <T>/runs for every active tenant that lacks it")
    commands.add_parser("resync-people", help="after a restore: record a people request for every tenant and person account")
    args = parser.parse_args(argv)

    from defender.lifecycle import ConfigRefused

    try:
        return _run(args.command)
    except ConfigRefused as refused:
        print(f"python -m defender.lifecycle {args.command}: {refused}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    from defender._log import configure_from_env

    configure_from_env()
    sys.exit(main())
