#!/usr/bin/env python3
"""Build and publish this tenant's learning pages (`lessons.html`, `queues.html` and their
contracts) into its learning area. Run by path; the views come from learning's serializers and
the HTML from `presentation/lessons_page.py`."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[3]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender.execution._venv import reexec_into_venv  # noqa: E402

if __name__ == "__main__":
    reexec_into_venv(__file__)

from defender.learning.core.config import LoopPaths  # noqa: E402
from defender.learning.frontend import serialize, serialize_queues  # noqa: E402
from defender.presentation.lessons_page import render, render_queues  # noqa: E402
from defender.presentation.publisher import NoPublishRoot, Publisher  # noqa: E402

if TYPE_CHECKING:
    from defender.tenancy._tenant import Tenant


def main(tenant: Tenant) -> int:
    """Both pages and their contracts, published into the accepted tenant's learning area (#1279
    O1). Refuses before building when there is nowhere to publish: outside `dev` (O4), or a
    `dev` deployment with no publish folder set (A11). The lessons page shows the tenant's
    published knowledge; with nothing published it shows no lesson (and says why), and the queue
    page is built all the same."""
    from defender.tenancy._exports import DeliveryRefused

    publisher = Publisher.for_tenant(tenant)
    agent_root = None
    try:
        agent_root = serialize.published_agent_root(tenant)
    except DeliveryRefused as refused:
        print(f"note: no published knowledge to show lessons from: {refused}", file=sys.stderr)
    queues = serialize_queues.stamped_view(LoopPaths.for_tenant(tenant))
    view = serialize.stamped_view(agent_root)

    pages = {
        "lessons.json": serialize.dump_contract(view),
        "lessons.html": render(view),
        "queues.json": serialize_queues.dump_contract(queues),
        "queues.html": render_queues(queues),
    }
    for name, text in pages.items():
        publisher.learning_page(name).write(text)

    counts = {k: len(v["lessons"]) for k, v in view["groups"].items()}
    dead = {ch["name"]: len(ch["deadletter"]) for ch in queues["channels"]}
    print(f"published {publisher.learning_page('lessons.html').path.parent} — {counts}, dead letters {dead}")
    return 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    import argparse
    from defender.learning.core.cli import command_line_tenant

    parser = argparse.ArgumentParser(description="Build this tenant's learning queue pages")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    try:
        sys.exit(main(command_line_tenant(parser, args.tenant)))
    except NoPublishRoot as refused:
        parser.exit(2, f"{parser.prog}: {refused}\n")
