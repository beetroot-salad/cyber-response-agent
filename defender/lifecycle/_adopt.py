"""Lab adoption (#1214 Flow 5, O9): the one tenant whose row predates #1214 becomes a tenant of the
job, and once active its pre-#1214 facts are retired.

`adopt` does what is due on each call and is idempotent. While the row is at the backfill's `adopt`
step it makes the clearing commit (failure cleared, step `names`) and leaves the job to the actors,
which keep the recorded repo and the existing clone. Once the tenant is `active` it retires the
on-disk row (`tenancy.retire_row`), the old issuer client directory `<issuer dir>/client/<T>/` and
the old unsalted OpenBao entries (`tenant-<T>` role and entity, `delivery-<T>` AppRole with its
secret ids)."""
from __future__ import annotations

import asyncio
import datetime as _dt
import logging
import shutil
from collections.abc import Callable
from pathlib import Path

import httpx

from defender.lifecycle._job import SERVICE, answered
from defender.lifecycle.config import LifecycleConfig
from defender.tenancy import ADOPT_FAILURE, TenantId, TenantRepository, retire_row

_logger = logging.getLogger(__name__)
_ADOPT_STEP = "adopt"


class AdoptRefused(Exception):
    """Adoption cannot go on now; the message says why and what to do."""


async def adopt(tenant_id: str, *, tenants: TenantRepository, openbao: httpx.AsyncClient,  # noqa: PLR0913 — the pinned call
                config: LifecycleConfig, clock: Callable[[], _dt.datetime], issuer_dir: Path) -> str:
    """Do what adoption has due for `tenant_id` (module doc); what was done, as one line."""
    del clock  # the clearing commit stamps nothing; kept for the pinned call
    tenant = str(TenantId(tenant_id))
    record = await tenants.tenant(tenant)
    if record is None:
        raise AdoptRefused(f"there is no tenant {tenant}; the #1214 revision registers the lab's row")
    if record.step == _ADOPT_STEP:
        if record.failure != ADOPT_FAILURE:
            raise AdoptRefused(f"tenant {tenant} is at `adopt` without the backfill's failure; it is not the lab's row")
        async with tenants.lock(tenant) as held:
            if held is None:
                raise AdoptRefused(f"tenant {tenant} is held by a worker; run adoption again")
            await held.commit(step="names", actor=SERVICE, expect_failure=ADOPT_FAILURE)
        return f"tenant {tenant}: adopted; the lifecycle actors now run its job"
    if record.state != "active":
        return f"tenant {tenant} is {record.state} at step {record.step}; adopt again once it is active"
    await _retire(tenant, openbao=openbao, config=config, issuer_dir=issuer_dir)
    return f"tenant {tenant}: active; its pre-#1214 row, issuer client directory and OpenBao entries are retired"


async def _retire(tenant: str, *, openbao: httpx.AsyncClient, config: LifecycleConfig, issuer_dir: Path) -> None:
    if await asyncio.to_thread(retire_row, config.data_root, tenant):
        _logger.info("tenant %s: removed the pre-#1214 on-disk tenant row", tenant)
    client = Path(issuer_dir) / "client" / tenant
    if client.is_symlink():
        raise AdoptRefused(f"{client} is a link; remove it by hand")
    if client.is_dir():
        await asyncio.to_thread(shutil.rmtree, client)
    for path in (f"identity/oidc/role/tenant-{tenant}", f"auth/approle/role/delivery-{tenant}",
                 f"identity/entity/name/tenant-{tenant}"):
        answered(await openbao.delete(f"/v1/{path}"), 404)
