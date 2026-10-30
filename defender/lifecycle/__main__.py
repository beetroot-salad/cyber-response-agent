"""Run the tenant lifecycle (#1214 DC-14).

    python -m defender.lifecycle serve  # the management service and the host actor, one process (dev)

It reads `DEFENDER_DATABASE_DSN` (the database at exactly this code's revision) and the lifecycle's
settings (`defender.lifecycle.config`: the files holding the forge admin token and the OpenBao
management login, the integration container, the secrets directory, `DEFENDER_DATA_ROOT`). The
issuer and OpenBao addresses are fixed service names (`defender.configuration.issuer`); the
infrastructure routes them."""
from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import functools
import logging
import os
import signal
import sys
from typing import Any

_logger = logging.getLogger(__name__)


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


class _NoPeople:
    """The sign-in and mail ports of an identity service that only ends memberships (offboarding's
    `end_tenant`); anything else it is asked is a programming error."""

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


async def _serve() -> int:
    from defender.identity import Bootstrap, IdentityService
    from defender.identity.postgres import PostgresIdentityRepository
    from defender.investigation.publish_launch import launch_publish
    from defender.lifecycle import HostActor, ManagementService, git_runner, integration_runner, serve
    from defender.lifecycle import _process as clients
    from defender.tenancy import TenantDirectory
    from defender.tenancy.postgres import PostgresTenantRepository

    dsn, config = _dsn(), _lifecycle_settings()
    tenants = PostgresTenantRepository(dsn, lock_keepalive=config.lock_keepalive)
    identity = IdentityService(PostgresIdentityRepository(dsn), signin=_NoPeople(), mail=_NoPeople(),
                               clock=_now, bootstrap=Bootstrap(administrators=()))
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stopping.set)
    service = ManagementService(tenants, identity=identity, forge=clients.forge_admin(config),
                                openbao=clients.openbao_management(config),
                                integration=integration_runner(config.integration_command), git=git_runner,
                                config=config, clock=_now)
    host = HostActor(tenants, forge=clients.forge_anonymous(config), openbao_login=clients.openbao_login(config),
                     git=git_runner, config=config, clock=_now,
                     # as run start's: the outcomes only the launcher sees are recorded for `tenant.py check`
                     publish=functools.partial(launch_publish,
                                               directory=TenantDirectory(lambda: PostgresTenantRepository(dsn))))
    _logger.info("lifecycle: serving both actors every %ss", config.poll_interval)
    try:
        await serve(service, host, config=config, stop=stopping.is_set)
    finally:
        await identity.close()
        await tenants.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m defender.lifecycle", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="run the management service and the host actor until stopped (dev)")
    args = parser.parse_args(argv)

    from defender.lifecycle import ConfigRefused

    try:
        return asyncio.run(_serve())
    except ConfigRefused as refused:
        print(f"python -m defender.lifecycle {args.command}: {refused}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    from defender._log import configure_from_env

    configure_from_env()
    sys.exit(main())
