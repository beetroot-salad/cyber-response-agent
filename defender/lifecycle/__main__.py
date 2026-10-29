"""Run the tenant lifecycle (#1214 DC-14).

    python -m defender.lifecycle serve           # the management service and the host actor, one process (dev)
    python -m defender.lifecycle adopt <tenant>  # Flow 5: adopt the pre-#1214 lab tenant (dev, O9)

Both read `DEFENDER_DATABASE_DSN` (the database at exactly this code's revision) and the lifecycle's
settings (`defender.lifecycle.config`: the files holding the forge admin token and the OpenBao
management login, the integration container, the secrets directory, `DEFENDER_DATA_ROOT`). The
issuer and OpenBao addresses are fixed service names (`defender.configuration.issuer`); the
infrastructure routes them. `adopt` also takes the old issuer directory (`--issuer-dir`)."""
from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)
_DSN_ENV = "DEFENDER_DATABASE_DSN"


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

    dsn = os.environ.get(_DSN_ENV, "")
    if not dsn:
        raise SystemExit(f"{_DSN_ENV} is not set: the lifecycle works the tenant records in PostgreSQL")
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
                     git=git_runner, publish=launch_publish, config=config, clock=_now)
    _logger.info("lifecycle: serving both actors every %ss", config.poll_interval)
    try:
        await serve(service, host, config=config, stop=stopping.is_set)
    finally:
        await identity.close()
        await tenants.close()
    return 0


async def _adopt(tenant: str, issuer_dir: Path) -> int:
    from defender.lifecycle import adopt
    from defender.lifecycle import _process as clients
    from defender.tenancy.postgres import PostgresTenantRepository

    dsn, config = _dsn(), _lifecycle_settings()
    tenants = PostgresTenantRepository(dsn, lock_keepalive=config.lock_keepalive)
    try:
        async with clients.openbao_management(config) as openbao:
            print(await adopt(tenant, tenants=tenants, openbao=openbao, config=config, clock=_now,
                              issuer_dir=issuer_dir))
    finally:
        await tenants.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m defender.lifecycle", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="run the management service and the host actor until stopped (dev)")
    adopting = commands.add_parser("adopt", help="adopt the pre-#1214 lab tenant (Flow 5); run again once active")
    adopting.add_argument("tenant", help="the lab tenant's id")
    adopting.add_argument("--issuer-dir", type=Path, required=True,
                          help="the old issuer directory whose client/<tenant>/ is retired")
    args = parser.parse_args(argv)

    from defender.lifecycle import AdoptRefused, ConfigRefused

    try:
        if args.command == "serve":
            return asyncio.run(_serve())
        return asyncio.run(_adopt(args.tenant, args.issuer_dir))
    except (ConfigRefused, AdoptRefused) as refused:
        print(f"python -m defender.lifecycle {args.command}: {refused}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    from defender._log import configure_from_env

    configure_from_env()
    sys.exit(main())
