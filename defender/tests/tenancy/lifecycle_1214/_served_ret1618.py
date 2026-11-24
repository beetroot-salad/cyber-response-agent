"""#1618 (flow 4, K8): the host entry points that read knowledge read a copy the fetch child made from Forgejo, not the
tenant's folder. This rig serves one tenant's knowledge over a real git listener so an admitted entry's fetch seam
(`K.Fetch`, the REAL fetch child) answers `ok <commit>`: the boundary cases then judge the entry's refusals and holds,
not a fetch that could not reach any forge.

The knowledge is `place_tenant`'s set-up folder, planted in a scratch root OUTSIDE the data root (the tenant's own folder
holds no knowledge under r5) and pushed to a bare remote that `GitHTTP` serves with the issuer fake's token.
"""
from __future__ import annotations

import contextlib
from collections.abc import Iterator
from pathlib import Path

from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_delivery._identity import token as issuer_token
from defender.tests.tenancy.tenant_1108_delivery._support import BARE_NO_UPKEEP, GitHTTP, git


@contextlib.contextmanager
def served_fetch(scratch: Path, tenant: str) -> Iterator[K.Fetch]:
    """A fetch seam (`fetch(tenant_id, dest, *, data_root, commit=None) -> line`) over the real fetch child, for `tenant`
    whose `main` holds `place_tenant`'s knowledge on a served remote."""
    from defender.tests.support.tenancy._tenants1106 import place_tenant

    scratch = Path(scratch)
    clone = Path(place_tenant(scratch / "seed-root", tenant))
    git(clone, "init", "-b", "main")
    git(clone, "config", "user.name", "served knowledge")
    git(clone, "config", "user.email", "served@test.invalid")
    git(clone, "add", "-A")
    git(clone, "commit", "-m", "tenant content")
    forge = scratch / "forge"
    remote = forge / "tenants" / f"{tenant}.git"
    remote.parent.mkdir(parents=True)
    git(forge, "clone", "--bare", *BARE_NO_UPKEEP, clone, remote)
    server = GitHTTP(forge, token=issuer_token(tenant))
    try:
        origin = f"{server.url}/tenants/{tenant}.git"
        yield K.fetch_seam(None, scratch / "fetch-work", origin_of=lambda _t: origin)
    finally:
        server.close()
