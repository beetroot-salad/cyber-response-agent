"""The lifecycle's side of the evidence store (#1546 A-O5, A-O7): what ends a tenant's evidence, over the jobs rows and the
store's objects.

- `purge_tenant`: the offboarding pass (a host step between `teardown` and `finish`, repeated each host pass for an
  offboarded tenant). Everything under `t/<T>/` in the store goes, then the tenant's staged facts and upload rows; its
  claims stay with their launch facts nulled.
- `sweep_evidence`: one pass of the retention sweep (the management service's): objects past their tenant's value expire
  (age from acceptance), unpromoted uploads of claims no longer live go after an hour's grace, store objects no upload row
  names go, and claims of long-ended references go with their facts.

The rows are the jobs database's own (`jobs.claims`, `jobs.uploads`, `jobs.staged_facts` and the owners' `evidence_state`),
read and written here by SQL on the clock of the database. A store failure after a row change leaves objects no row names,
which the same sweep removes later; a row change is never made for an object the store still holds the only record of."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from defender.evidence import BlobStore, BlobStoreError
from defender.lifecycle._job import StepFailed

_logger = logging.getLogger(__name__)

#: An unpromoted upload's grace, by the database's clock (PR7): within it the claim's helper may still be finishing.
GRACE = "1 hour"
#: The store prefix of a tenant (`t/<tenant>/<owner kind>/<owner id>/<claim token>/<object>`).
_TENANT_PREFIX = "t/{tenant}/"
#: The two kinds of owner, each with its table, the claim column naming it, its live stages and its retention column.
_OWNERS = {
    "investigation": ("jobs.investigations", "investigation_id", "stage IN ('queued', 'running')", "investigation_days"),
    "learning": ("jobs.learning_jobs", "learning_job_id", "status IN ('queued', 'running')", "learning_days"),
}
#: The states that had accepted objects and so read `expired` once the sweep removes them.
_HELD = "('complete', 'partial', 'lost')"
#: Whether a claim's reference is still live: no write to it may be pending, whatever its age.
_CLAIM_LIVE = """(
    EXISTS (SELECT 1 FROM jobs.investigations i WHERE i.id = c.investigation_id AND i.stage IN ('queued', 'running'))
 OR EXISTS (SELECT 1 FROM jobs.learning_jobs l WHERE l.id = c.learning_job_id AND l.status IN ('queued', 'running'))
 OR EXISTS (SELECT 1 FROM jobs.host_requests h WHERE h.id = c.host_request_id AND h.stage IN ('queued', 'running'))
 OR EXISTS (SELECT 1 FROM jobs.learning_checks k WHERE k.tenant_id = c.hold_tenant_id AND k.holder = c.token))"""

Sessions = async_sessionmaker[AsyncSession]


def object_key(tenant: str, kind: str, owner: str, token: str, name: str) -> str:
    return f"t/{tenant}/{kind}/{owner}/{token}/{name}"


async def _delete_objects(blob: BlobStore, keys: Sequence[str]) -> None:
    """Each key removed from the store (one already gone is done). A failure is raised: the caller decides whether the
    step fails or the sweep tries again next pass."""
    for key in keys:
        await asyncio.to_thread(blob.delete, key)


# --- offboarding ------------------------------------------------------------------------------------------------------

async def purge_tenant(sessions: Sessions, blob: BlobStore, tenant: str) -> None:
    """The tenant's evidence gone: its objects, then its staged facts and upload rows, and the launch facts of its claims
    nulled (the claims themselves stay: an owner's reference to the work is its own record). Idempotent: run again it
    removes what arrived since. A store that cannot be reached fails it with the store's words and deletes no row."""
    try:
        await asyncio.to_thread(blob.delete_prefix, _TENANT_PREFIX.format(tenant=tenant))
    except BlobStoreError as failed:
        raise StepFailed(f"the evidence store could not be emptied: {failed}") from failed
    async with sessions() as session, session.begin():
        mine = "SELECT token FROM jobs.claims WHERE tenant_id = CAST(:tenant AS uuid)"
        for table in ("jobs.staged_facts", "jobs.uploads"):
            await session.execute(text(f"DELETE FROM {table} WHERE token IN ({mine})"), {"tenant": tenant})  # noqa: S608
        await session.execute(text("UPDATE jobs.claims SET launch = NULL WHERE tenant_id = CAST(:tenant AS uuid) "
                                   "AND launch IS NOT NULL"), {"tenant": tenant})


# --- the retention sweep ----------------------------------------------------------------------------------------------

async def sweep(sessions: Sessions, blob: BlobStore) -> None:
    """One pass: expiry, the unpromoted uploads' grace, orphan objects, long-ended claims. Each part is independent: one
    that fails is logged and the others still run, and the next pass runs it again."""
    for part in (_expire, _drop_unpromoted, _drop_orphans, _drop_old_claims):
        try:
            await part(sessions, blob)
        except Exception:  # noqa: BLE001 — a failed part never stops the others, nor the service's own passes
            _logger.exception("evidence sweep: %s failed; the next pass runs it again", part.__name__.strip("_"))


async def _expire(sessions: Sessions, blob: BlobStore) -> None:
    for kind in _OWNERS:
        for owner in await _expired_candidates(sessions, kind):
            keys = await _expire_owner(sessions, kind, owner)
            await _delete_objects(blob, keys)


async def _expired_candidates(sessions: Sessions, kind: str) -> list[str]:
    """The owners of `kind` with an object accepted longer ago than their tenant's value for the kind. A tenant with no
    retention row expires nothing (an offboarded tenant from before the setting, D16)."""
    table, column, _live, days = _OWNERS[kind]
    async with sessions() as session:
        found = await session.execute(text(
            f"SELECT o.id FROM {table} o JOIN tenancy.evidence_retention r ON r.tenant_id = o.tenant_id "  # noqa: S608
            f"WHERE o.evidence_state IN {_HELD} AND (SELECT min(u.accepted_at) FROM jobs.claims c "
            f"JOIN jobs.uploads u ON u.token = c.token WHERE c.{column} = o.id AND u.accepted_at IS NOT NULL) "
            f"< now() - make_interval(days => r.{days}) ORDER BY o.id"))
        return [str(row[0]) for row in found]


async def _expire_owner(sessions: Sessions, kind: str, owner: str) -> list[str]:
    """One owner expired, its object rows gone, in one transaction under `FOR UPDATE` on the owner: a learning job's insert
    holds `FOR SHARE` on its source, so the pass either waits for it and sees its job, or the insert waits for this and is
    refused once the source reads `expired` (A-O7). The keys of the removed objects, for the store."""
    table, column, _live, _days = _OWNERS[kind]
    async with sessions() as session, session.begin():
        row = (await session.execute(text(f"SELECT tenant_id, evidence_state FROM {table} WHERE id = CAST(:id AS uuid) "  # noqa: S608
                                          "FOR UPDATE"), {"id": owner})).first()
        if row is None or row.evidence_state not in ("complete", "partial", "lost"):
            return []
        if kind == "investigation" and (await session.execute(text(
                "SELECT 1 FROM jobs.learning_jobs WHERE investigation_id = CAST(:id AS uuid) "
                "AND status IN ('queued', 'running') LIMIT 1"), {"id": owner})).first():
            return []  # a learning job still reads it as its source
        held = (await session.execute(text(
            f"SELECT c.token, u.object FROM jobs.uploads u JOIN jobs.claims c ON c.token = u.token "  # noqa: S608
            f"WHERE c.{column} = CAST(:id AS uuid)"), {"id": owner})).all()
        await session.execute(text(f"UPDATE {table} SET evidence_state = 'expired' WHERE id = CAST(:id AS uuid)"),  # noqa: S608
                              {"id": owner})
        await session.execute(text(f"DELETE FROM jobs.uploads WHERE token IN (SELECT token FROM jobs.claims "  # noqa: S608
                                   f"WHERE {column} = CAST(:id AS uuid))"), {"id": owner})
        return [object_key(str(row.tenant_id), kind, owner, str(token), str(name)) for token, name in held]


async def _drop_unpromoted(sessions: Sessions, blob: BlobStore) -> None:
    """Upload rows never promoted (`pending`, `uploaded`, `refused`) of a claim no longer live, older than the grace by the
    database's clock, with their objects: an ended claim writes no more (PR7), so what is left is not coming."""
    async with sessions() as session, session.begin():
        found = (await session.execute(text(
            "DELETE FROM jobs.uploads u USING jobs.claims c WHERE c.token = u.token AND u.accepted_at IS NULL "
            f"AND u.created_at < now() - interval '{GRACE}' AND NOT {_CLAIM_LIVE} "
            "RETURNING c.tenant_id, c.kind, c.investigation_id, c.learning_job_id, u.token, u.object"))).all()
    keys = []
    for tenant, kind, investigation, learning, token, name in found:
        owner = investigation if kind == "investigation" else learning
        if owner is not None and kind in _OWNERS:
            keys.append(object_key(str(tenant), kind, str(owner), str(token), str(name)))
    await _delete_objects(blob, keys)


async def _drop_orphans(sessions: Sessions, blob: BlobStore) -> None:
    """Objects under a tenant's prefix that no upload row names (an investigation delete removes its rows in its own
    transaction, never the store's objects). Only tenants the database holds, and not an offboarded one (its own pass owns
    that prefix): never a listing of `t/` itself, which is every tenant's, other deployments' tests' included. The listing
    comes before the rows are read: an upload's row is committed before its PUT, so a listed object has its row."""
    async with sessions() as session:
        tenants = [str(row[0]) for row in await session.execute(text(
            "SELECT id FROM tenancy.tenants WHERE state <> 'offboarded' ORDER BY id"))]
    for tenant in tenants:
        prefix = _TENANT_PREFIX.format(tenant=tenant)
        listed = await asyncio.to_thread(blob.keys, prefix)
        if not listed:
            continue
        async with sessions() as session:
            named = {f"{token}/{name}" for token, name in await session.execute(text(
                "SELECT c.token, u.object FROM jobs.uploads u JOIN jobs.claims c ON c.token = u.token "
                "WHERE c.tenant_id = CAST(:tenant AS uuid)"), {"tenant": tenant})}
        await _delete_objects(blob, [key for key in listed if _orphan(key, prefix, named)])


def _orphan(key: str, prefix: str, named: set[str]) -> bool:
    """Whether `key` is shaped as an evidence object (`<kind>/<owner>/<claim token>/<object>` below the prefix) and no row
    names it. Anything else under the prefix is not this sweep's to judge."""
    parts = key[len(prefix):].split("/", 3)
    return len(parts) == 4 and parts[0] in _OWNERS and f"{parts[2]}/{parts[3]}" not in named


async def _drop_old_claims(sessions: Sessions, _blob: BlobStore) -> None:
    """Claims of references that ended longer ago than their tenant's longest retention, with their staged facts. A claim
    that still has an upload row stays (an object a learning source keeps), as does any claim of a tenant with no
    retention row (the offboarding pass alone governs it). A post-step's claim has no end of its own: its creation."""
    async with sessions() as session, session.begin():
        await session.execute(text("""
            WITH due AS (
              SELECT c.token FROM jobs.claims c
              JOIN tenancy.evidence_retention r ON r.tenant_id = c.tenant_id
              LEFT JOIN jobs.investigations i ON i.id = c.investigation_id AND i.stage NOT IN ('queued', 'running')
              LEFT JOIN jobs.learning_jobs l ON l.id = c.learning_job_id AND l.status NOT IN ('queued', 'running')
              LEFT JOIN jobs.host_requests h ON h.id = c.host_request_id AND h.stage NOT IN ('queued', 'running')
              LEFT JOIN jobs.learning_checks k ON k.tenant_id = c.hold_tenant_id
              WHERE NOT EXISTS (SELECT 1 FROM jobs.uploads u WHERE u.token = c.token)
                AND coalesce(i.finished_at, l.finished_at, h.finished_at,
                             CASE WHEN c.hold_tenant_id IS NOT NULL AND k.holder IS DISTINCT FROM c.token
                                  THEN c.created_at END)
                    < now() - make_interval(days => greatest(r.investigation_days, r.learning_days))),
            facts AS (DELETE FROM jobs.staged_facts WHERE token IN (SELECT token FROM due))
            DELETE FROM jobs.claims WHERE token IN (SELECT token FROM due)"""))


async def sweep_evidence(*, jobs: Any, blob: BlobStore) -> None:
    """One pass of the retention sweep over the job store `jobs` and the evidence store `blob` (see the module's words).
    The sweep uses the job store's own connection pool (`JobStore._sessions`: the store has no public way to its pool), so
    it never opens a second database."""
    await sweep(jobs._sessions, blob)
