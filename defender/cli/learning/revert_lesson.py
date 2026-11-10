#!/usr/bin/env python3
"""Revert a lesson the commit-maker wrote, on the tenant's own repository (#1108 P4 flow 5, #1278 Reverts).

`--tenant T <lesson>`: under the tenant's host lock (shared, #1214 P3), the tenant admitted from
the tenant records (`active`, its forge wiring, #1214 Flow 4), its forge credential minted through
its live generation, `TenantDelivery.open`, then the D-peel revert over the learning store
(`store_delivery.revert_lesson`): a batch of kind revert, its one commit recorded in the store, its
branch pushed and its PR opened. A working batch of the author lane (a running tick, another
revert) is the revert's mutual exclusion with the drain: exit 3, before any forge request."""
from __future__ import annotations

import argparse
import logging
import sys

from pathlib import Path
from typing import TYPE_CHECKING, Any
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender import tenancy
from defender.knowledge import AGENT_REL, LESSONS
from defender.learning.core.config import AUTHOR_DRAIN_LABEL, FatalConfigError
from defender.records.formats import TenantRefused

if TYPE_CHECKING:
    from defender.systems.run_tenant import Admitted

_logger = logging.getLogger(__name__)

_DEFENDER_DIR = Path(__file__).resolve().parents[2]

#: The exit of a revert held off by a working batch of the author lane (retry shortly).
BUSY_RC = 3


def lesson_path(lesson_name: str) -> str:
    """The lesson's repo-relative spelling in the tenant repo (`agent/lessons/<name>.md`)."""
    return f"{AGENT_REL}/{LESSONS}/{lesson_name}.md"


def revert(  # noqa: PLR0913 — the lesson, its store and admission, and the delivery's stand-ins
    lesson_name: str, *, store: Any, admitted: Admitted, client=None, identity=None,
    credential_config=None, issuer_transport=None,
) -> int:
    """With the author lane free in `store` (a working batch of it: exit 3, nothing asked of the forge or
    the origin): log in (unless `identity` is given), open the admitted tenant's delivery and revert
    through a revert batch. A refusal is logged `critical` naming why, exit 2; a refusal after the
    commit (its push, its PR) leaves the batch working, for the next tick to take over."""
    from defender.learning.author import version_control as vc
    from defender.learning.author.version_control.forgejo import ForgeError
    from defender.learning.author.version_control.store_delivery import revert_lesson
    from defender.learning.core.drains import revert_delivery
    from defender.learning.core.store_tick import AUTHOR_LANE, owner_name
    from defender.learning.store import LaneBusy

    tenant_id = str(admitted.tenant.id)
    if any(b.lane == AUTHOR_LANE and b.phase == "working" for b in store.batches(tenant_id)):
        _logger.warning("an author drain is in progress — retry shortly")
        return BUSY_RC
    try:
        with revert_delivery(admitted, client=client, identity=identity,
                             credential_config=credential_config,
                             issuer_transport=issuer_transport) as delivery:
            delivered = revert_lesson(delivery, store, lesson_path=lesson_path(lesson_name), lesson_name=lesson_name,
                                      owner=owner_name("revert"), lanes=AUTHOR_DRAIN_LABEL.lanes)
    except LaneBusy:
        _logger.warning("an author drain is in progress — retry shortly")
        return BUSY_RC
    except (vc.DeliveryRefused, vc.ForgejoAuthError, TenantRefused, ForgeError) as refused:
        _logger.critical(f"revert of {lesson_name} refused: {refused}")
        return 2
    if delivered.status in (vc.DeliveryStatus.OPENED, vc.DeliveryStatus.OPEN):
        print(f"revert PR: {delivered.url}")
    else:
        print(f"revert: {delivered.status}" + (f" {delivered.url}" if delivered.url else ""))
    return 0


def main(
    argv: list[str], *, client=None, identity=None, directory=None, credential_config=None,
    issuer_transport=None,
) -> int:
    """The CLI. The keywords are in-process stand-ins for the forge client, the tenant's
    credential (`identity` given: none is minted), the tenant records (else
    `DEFENDER_DATABASE_DSN`'s) and the host's issuer configuration. The learning store is the one
    `DEFENDER_DATABASE_DSN` names."""
    parser = argparse.ArgumentParser(description="Revert a lesson through a revert batch of its tenant's learning store")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("lesson_name")
    args = parser.parse_args(argv)
    # The one host acceptance (r10 A1) for the whole revert, which mints the tenant's credential
    # and opens a PR: recorded under the tenant's host lock, `active` with its forge wiring.
    from defender.learning.core.store_tick import opened_store
    from defender.systems.run_tenant import host_tenant

    try:
        admitted = host_tenant(tenancy.resolve_data_root(), args.tenant, directory=directory)
    except TenantRefused as refused:
        # A revert reports a refusal as its other refusals: critical log, exit 2, nothing minted or opened.
        _logger.critical(f"revert of {args.lesson_name} refused: {refused}")
        return 2
    with admitted:
        try:
            with opened_store() as store:
                return revert(args.lesson_name, store=store, admitted=admitted, client=client, identity=identity,
                              credential_config=credential_config, issuer_transport=issuer_transport)
        except FatalConfigError as unset:
            _logger.critical(f"revert of {args.lesson_name} refused: {unset}")
            return 2


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
