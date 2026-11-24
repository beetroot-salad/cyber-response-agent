"""#1618 (flow 5, D9, D10): the readiness helper reads the tenant's knowledge through the fetch child, not the launch-time publish.

FORCED: the seam `job_host.main(..., fetch=)` replaces `publish=`; its one shape and the whole seam list are in
`knowledge_1618._support` (`fetch(tenant_id, dest, *, data_root, commit=None) -> report line`, the real child by default). The FORCED
`client=` seam (the forge client the drain's delivery uses, `job_host.main(client=)`) carries the branch-protection check (D9).
`readiness_fetching` is `_readiness1471.readiness` with that seam in place of `publish` (which `drive_helper` always adds)."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from defender.tests.support.jobs._job_helper import HelperScene
from defender.tests.support.jobs._readiness1471 import Readied


def fetching(scene: HelperScene) -> Any:
    """The one fetch seam over the scene's tenant: the real child against the scene's bare remote (`K.fetch_seam`)."""
    from defender.tests.tenancy.knowledge_1618 import _support as K

    return K.fetch_seam(scene.t)


def readiness_fetching(scene: HelperScene, *, fetch: Callable[..., str], client: Any = None, signer: Any = None,
                       rid: str | None = None, container: Callable[[Any], int] | None = None) -> Readied:
    """The helper for a readiness check of the scene's tenant with `fetch` (and `client`, when given) as its seams; like
    `_readiness1471.readiness` it never raises for the subject's absence. #1546: it is that driver (the request row and its
    claim planted first, the real evidence store configured; the records are staged facts, `Readied.record`/`.knowledge`)."""
    from defender.tests.support.jobs._readiness1471 import readiness

    return readiness(scene, fetch=fetch, client=client, signer=signer, rid=rid, container=container)
