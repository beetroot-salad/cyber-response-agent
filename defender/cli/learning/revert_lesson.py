#!/usr/bin/env python3
"""Revert a lesson the commit-maker wrote, on the tenant's own repository (#1108 P4 flow 5).

`--tenant T <lesson>`: the tenant's forge binding and issuer client config, the AppRole login
(A-ID), `TenantDelivery.open`, then `TenantDelivery.revert` (D-peel) as a PR on the tenant
forge. The author drain's lock stays the revert's mutual exclusion with the drain (exit 3)."""
from __future__ import annotations

import logging
import sys

from pathlib import Path
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.knowledge._knowledge import AGENT_REL, LESSONS
from defender.learning.core.cli import command_line_paths
from defender.learning.core.state import AUTHOR_DRAIN_LOCK, TRY_ONCE, LearningState

_logger = logging.getLogger(__name__)

_DEFENDER_DIR = Path(__file__).resolve().parents[2]


def lesson_path(lesson_name: str) -> str:
    """The lesson's repo-relative spelling in the tenant repo (`agent/lessons/<name>.md`)."""
    return f"{AGENT_REL}/{LESSONS}/{lesson_name}.md"


def revert(
    lesson_name: str, *, state: LearningState | None, tenant, client=None, identity=None,
    issuer_config: Path | None = None, issuer_transport=None,
) -> int:
    """Under the author drain's lock (`state`'s; `None` when the tenant has no learning state
    root yet, so no drain can hold it): log in (unless `identity` is given), open the tenant's
    delivery and revert. A refusal is logged `critical` naming why, exit 2."""
    if state is None:
        return _revert_unlocked(lesson_name, tenant=tenant, client=client, identity=identity,
                                issuer_config=issuer_config, issuer_transport=issuer_transport)
    with state.lock(AUTHOR_DRAIN_LOCK, wait=TRY_ONCE) as locked:
        if not locked:
            _logger.warning("an author drain is in progress — retry shortly")
            return 3
        return _revert_unlocked(lesson_name, tenant=tenant, client=client, identity=identity,
                                issuer_config=issuer_config, issuer_transport=issuer_transport)


def _revert_unlocked(
    lesson_name: str, *, tenant, client, identity, issuer_config: Path | None, issuer_transport,
) -> int:
    from defender.learning.author import version_control as vc
    from defender.tenancy import _tenant

    try:
        binding = _tenant.read_forge_binding(tenant)
        if identity is None:
            identity = vc.issuer_login(
                tenant, issuer_config=issuer_config or vc.DEV_ISSUER_CONFIG,
                transport=issuer_transport)
        if client is None:
            import httpx

            client = httpx.Client()
        delivery = vc.TenantDelivery.open(
            tenant, defender_dir=_DEFENDER_DIR, client=client, identity=identity,
            origin=binding.origin)
        delivered = delivery.revert(lesson_path(lesson_name), lesson_name)
    except (vc.DeliveryRefused, vc.ForgejoAuthError, _tenant.TenantRefused) as refused:
        _logger.critical(f"revert of {lesson_name} refused: {refused}")
        return 2
    if delivered.status in (vc.DeliveryStatus.OPENED, vc.DeliveryStatus.OPEN):
        print(f"revert PR: {delivered.url}")
    else:
        print(f"revert: {delivered.status}" + (f" {delivered.url}" if delivered.url else ""))
    return 0


def _has_state_root(paths) -> bool:
    """Whether the tenant's learning state root exists: without one no drain has run or can
    run (nothing but `tenant.py setup` creates it), so there is no lock to wait out."""
    return paths.tenant.learning_state_exists()


def main(
    argv: list[str], *, client=None, identity=None, issuer_config: Path | None = None,
    issuer_transport=None,
) -> int:
    """The CLI. The keywords are in-process stand-ins for the forge client and the issuer
    login (`identity` given: no login)."""
    import argparse

    parser = argparse.ArgumentParser(description="Revert a lesson under its tenant's drain lock")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--issuer-config", type=Path, default=None)
    parser.add_argument("lesson_name")
    args = parser.parse_args(argv)
    paths = command_line_paths(parser, args.tenant)
    if not _has_state_root(paths):
        return revert(args.lesson_name, state=None, tenant=paths.tenant, client=client,
                      identity=identity, issuer_config=issuer_config or args.issuer_config,
                      issuer_transport=issuer_transport)
    with LearningState.open(paths) as state:
        return revert(args.lesson_name, state=state, tenant=paths.tenant, client=client,
                      identity=identity, issuer_config=issuer_config or args.issuer_config,
                      issuer_transport=issuer_transport)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
