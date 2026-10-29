#!/usr/bin/env python3
"""Revert a lesson the commit-maker wrote, on the tenant's own repository (#1108 P4 flow 5).

`--tenant T <lesson>`: under the tenant's host lock (shared, #1214 P3), the tenant admitted from
the tenant records (`active`, its forge wiring, #1214 Flow 4), its forge credential minted through
its live generation, `TenantDelivery.open`, then `TenantDelivery.revert` (D-peel) as a PR on the
tenant forge. The author drain's lock stays the revert's mutual exclusion with the drain (exit 3)."""
from __future__ import annotations

import logging
import sys

from pathlib import Path
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import tenancy
from defender.knowledge import AGENT_REL, LESSONS
from defender.learning.core.cli import admitted_directory, command_line_paths
from defender.learning.core.state import AUTHOR_DRAIN_LOCK, TRY_ONCE, LearningState
from defender.records.formats import TenantRefused

_logger = logging.getLogger(__name__)


class _Refusing:
    """Stands in for the argument parser in the shared admission: its usage error becomes the refusal the revert reports."""

    def error(self, message: str):
        raise TenantRefused(message)

_DEFENDER_DIR = Path(__file__).resolve().parents[2]


def lesson_path(lesson_name: str) -> str:
    """The lesson's repo-relative spelling in the tenant repo (`agent/lessons/<name>.md`)."""
    return f"{AGENT_REL}/{LESSONS}/{lesson_name}.md"


def revert(
    lesson_name: str, *, state: LearningState | None, tenant, client=None, identity=None,
    directory=None, credential_config=None, issuer_transport=None,
) -> int:
    """Under the author drain's lock (`state`'s; `None` when the tenant has no learning state
    root yet, so no drain can hold it): log in (unless `identity` is given), open the tenant's
    delivery and revert. A refusal is logged `critical` naming why, exit 2."""
    if state is None:
        return _revert_unlocked(lesson_name, tenant=tenant, client=client, identity=identity,
                                directory=directory, credential_config=credential_config,
                                issuer_transport=issuer_transport)
    with state.lock(AUTHOR_DRAIN_LOCK, wait=TRY_ONCE) as locked:
        if not locked:
            _logger.warning("an author drain is in progress — retry shortly")
            return 3
        return _revert_unlocked(lesson_name, tenant=tenant, client=client, identity=identity,
                                directory=directory, credential_config=credential_config,
                                issuer_transport=issuer_transport)


def _revert_unlocked(
    lesson_name: str, *, tenant, client, identity, directory, credential_config, issuer_transport,
) -> int:
    from defender.learning.author import version_control as vc
    from defender.learning.core.drains import revert_delivery

    try:
        with revert_delivery(tenant, directory=directory, client=client, identity=identity,
                             credential_config=credential_config,
                             issuer_transport=issuer_transport) as delivery:
            delivered = delivery.revert(lesson_path(lesson_name), lesson_name)
    except (vc.DeliveryRefused, vc.ForgejoAuthError, TenantRefused) as refused:
        _logger.critical(f"revert of {lesson_name} refused: {refused}")
        return 2
    if delivered.status in (vc.DeliveryStatus.OPENED, vc.DeliveryStatus.OPEN):
        print(f"revert PR: {delivered.url}")
    else:
        print(f"revert: {delivered.status}" + (f" {delivered.url}" if delivered.url else ""))
    return 0


def _has_state_root(paths) -> bool:
    """Whether the tenant's learning state root exists: without one no drain has run or can
    run (the host's prepare step creates it, #1214), so there is no lock to wait out."""
    return paths.tenant.learning_state_exists()


def main(
    argv: list[str], *, client=None, identity=None, directory=None, credential_config=None,
    issuer_transport=None,
) -> int:
    """The CLI. The keywords are in-process stand-ins for the forge client, the tenant's
    credential (`identity` given: none is minted), the tenant records (else
    `DEFENDER_DATABASE_DSN`'s) and the host's issuer configuration."""
    import argparse

    parser = argparse.ArgumentParser(description="Revert a lesson under its tenant's drain lock")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("lesson_name")
    args = parser.parse_args(argv)
    # The tenant's host lock, shared for the whole revert (it mints the tenant's credential and opens a
    # PR), this process recorded under it first, as every entry point does (#1214 P3, Flow 4: id, data
    # root, lock, then state): prepare and teardown wait for it, and a teardown finds it to stop it.
    try:
        tenancy.requested_tenant_id(args.tenant)
        held = tenancy.hold_tenant(tenancy.resolve_data_root(), args.tenant)
    except TenantRefused as refused:
        parser.error(str(refused))
    with held:
        try:
            records = admitted_directory(_Refusing(), args.tenant, directory)
        except TenantRefused as refused:
            # A revert reports a refusal as its other refusals: critical log, exit 2, nothing minted or opened.
            _logger.critical(f"revert of {args.lesson_name} refused: {refused}")
            return 2
        paths = command_line_paths(parser, args.tenant)
        if not _has_state_root(paths):
            return revert(args.lesson_name, state=None, tenant=paths.tenant, client=client,
                          identity=identity, directory=records, credential_config=credential_config,
                          issuer_transport=issuer_transport)
        with LearningState.open(paths) as state:
            return revert(args.lesson_name, state=state, tenant=paths.tenant, client=client,
                          identity=identity, directory=records, credential_config=credential_config,
                          issuer_transport=issuer_transport)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
