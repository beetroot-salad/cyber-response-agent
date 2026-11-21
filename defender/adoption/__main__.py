"""The adoption job's container entry (#1471 A3, R13-1.3/.4): `python -m defender.adoption --job <id> --tenant <T>`.

Inside the job container it takes no host lock, runs no admission and opens no database: the per-job host helper did, and answers
`launch` and `forge.token` over the job socket. The entry asks `launch`, checks the facts are this request's (kind, tenant, job,
a rendering, a digest and the forge origin the helper read), accepts the tenant's folder by the folder rules alone, opens the
tenant's repository against the recorded forge origin with the socket's credential, runs `adopt()` (which fetches, decides and
delivers, `learning.author.version_control.adoption`) and writes the one create-only record `<runs>/<job>.adoption.json`:

- `{outcome, pr_number}` from `adopt()`;
- `{failed, handover}`: the launch is unanswered or refused, or its facts are not this request's (R13-1.3, .4);
- `{failed, tenant_not_active}`: the facts say the tenant is not `active`;
- `{failed, delivery_failed}`: the tenant's folder or repository cannot be opened (an unprotected `main` among them), or
  `adopt()`'s own anything-else.

With no job socket in the environment (a host shell) it does nothing and exits non-zero. `client` is the forge API's `httpx`
client (a new one by default), the seam `opened_delivery(client=)` has."""
from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import logging
import re
import signal
import sys
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender import job_socket, tenancy
from defender._paths import process_defender_dir
from defender.learning.author.version_control import DeliveryRefused, ForgejoAuthError
from defender.learning.author.version_control.adoption import DELIVERY_FAILED, adopt
from defender.learning.author.version_control.forgejo import ForgeError
from defender.learning.author.version_control.repository import GitRepository
from defender.learning.branch.container import JobContainer, NotInContainer
from defender.records import job_lane
from defender.records.formats import TenantRefused

if TYPE_CHECKING:
    import httpx

_logger = logging.getLogger(__name__)

HANDOVER = "handover"
TENANT_NOT_ACTIVE = "tenant_not_active"
_DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
_DIGEST = re.compile(r"[0-9a-f]{64}")
#: What opening the repository or the folder may refuse with: each is the adoption's `delivery_failed`.
_OPEN_FAULTS = (TenantRefused, DeliveryRefused, ForgejoAuthError, ForgeError, OSError, ValueError)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m defender.adoption", description="One adoption, run in its job container.")
    p.add_argument("--job", required=True, help="the adoption request's id")
    p.add_argument("--tenant", required=True, help="the request's tenant")
    return p.parse_args(argv)


def _data_root(environ: Mapping[str, str]) -> Any:
    """The data root `environ` names, as `tenancy.resolve_data_root` reads this process's: set, absolute, resolved."""
    raw = environ.get(_DATA_ROOT_ENV, "")
    if not raw or not Path(raw).is_absolute():
        raise TenantRefused(f"{_DATA_ROOT_ENV} must be an absolute path")
    return tenancy.data_root_from_path(Path(raw).resolve())


def _decoded_rendering(facts: Mapping[str, Any]) -> dict[str, bytes] | None:
    """The rendering the facts carry (`{path: base64 bytes}`), or None when they carry none that decodes."""
    raw = facts.get("rendering")
    if not isinstance(raw, dict) or not raw or not all(isinstance(p, str) and isinstance(d, str) for p, d in raw.items()):
        return None
    try:
        return {path: base64.b64decode(data, validate=True) for path, data in raw.items()}
    except (binascii.Error, ValueError):
        return None


def _is_this_requests(facts: Mapping[str, Any], ns: argparse.Namespace) -> bool:
    return (facts.get("kind") == "adoption" and str(facts.get("tenant")) == ns.tenant and str(facts.get("job")) == ns.job
            and isinstance(facts.get("system"), str) and bool(facts["system"])
            and isinstance(facts.get("digest"), str) and _DIGEST.fullmatch(facts["digest"]) is not None
            and isinstance(facts.get("forge_origin"), str) and bool(facts["forge_origin"])
            and _decoded_rendering(facts) is not None)


def _deliver(container: JobContainer, ns: argparse.Namespace, root: Any, client: httpx.Client | None) -> job_lane.AdoptionRecord:
    """The tenant's repository opened and `adopt()` run over it; a refusal to open is `delivery_failed`."""
    facts = container.launch
    rendering = _decoded_rendering(facts)
    assert rendering is not None  # `_is_this_requests` held
    with contextlib.ExitStack() as owned:
        try:
            tenant = tenancy.accept_tenant(root, ns.tenant, defender_dir=process_defender_dir())
            if client is None:
                import httpx

                client = owned.enter_context(httpx.Client())
            repository = GitRepository.open(tenant.knowledge, tenant_id=str(tenant.id), origin=str(facts["forge_origin"]),
                                            identity=container.forge_credential(), client=client)
        except _OPEN_FAULTS as refused:
            _logger.error("adoption %s: the tenant's repository cannot be opened: %s", ns.job, refused)
            return job_lane.AdoptionRecord.failed(DELIVERY_FAILED)
        return adopt(repository, system=str(facts["system"]), rendering=rendering, digest=str(facts["digest"]))


def _outcome(ns: argparse.Namespace, environ: Mapping[str, str], root: Any, client: httpx.Client | None) -> job_lane.AdoptionRecord:
    try:
        container = JobContainer.of(environ, tenant=ns.tenant)
    except (OSError, ValueError, job_socket.Refused) as unanswered:
        _logger.error("adoption %s: the helper's launch facts cannot be had: %s", ns.job, unanswered)
        return job_lane.AdoptionRecord.failed(HANDOVER)
    if not _is_this_requests(container.launch, ns):
        _logger.error("adoption %s: the launch facts are not this request's", ns.job)
        return job_lane.AdoptionRecord.failed(HANDOVER)
    if container.launch.get("tenant_state") != "active":
        return job_lane.AdoptionRecord.failed(TENANT_NOT_ACTIVE)
    return _deliver(container, ns, root, client)


def main(argv: list[str], *, environ: Mapping[str, str] | None = None, client: httpx.Client | None = None) -> int:
    """Run one adoption and write its record (module doc); 0 once a record is written. A host shell (no job socket) does
    nothing and returns non-zero; a record that cannot be written raises, so the process ends non-zero and the worker reads
    no record."""
    import os

    ns = _parse_args(argv)
    environ = os.environ if environ is None else environ
    try:
        JobContainer.client(environ)
    except NotInContainer as outside:
        sys.stderr.write(f"[adoption] job {ns.job}: {outside}; nothing was done\n")
        return 2
    try:
        root = _data_root(environ)
    except TenantRefused as refused:
        sys.stderr.write(f"[adoption] job {ns.job}: {refused}\n")
        return 2
    record = _outcome(ns, environ, root, client)
    try:
        with job_lane.JobLane.open(root, ns.tenant) as lane:
            lane.write_adoption(ns.job, record)
    except FileExistsError:
        _logger.error("adoption %s: a record is already there; it is kept", ns.job)
    return 0


if __name__ == "__main__":
    from defender import _log

    _log.configure_from_env()
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, signal.default_int_handler)  # the first SIGTERM unwinds the entry as a KeyboardInterrupt
    job_socket.sigterm_on_stdin_eof()
    sys.exit(main(sys.argv[1:]))
