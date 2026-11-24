#!/usr/bin/env python3
"""Build and publish this tenant's learning pages (`lessons.html`, `queues.html` and their
contracts) into its learning area. Run by path; the views come from learning's serializers and
the HTML from `presentation/lessons_page.py`."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[3]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender.execution.venv_guard import reexec_into_venv  # noqa: E402

if __name__ == "__main__":
    reexec_into_venv(__file__)

from defender.learning.core.config import LoopPaths  # noqa: E402
from defender.learning.frontend import serialize, serialize_queues  # noqa: E402
from defender.presentation.lessons_page import render, render_queues  # noqa: E402
from defender.presentation.publisher import NoPublishRoot, Publisher  # noqa: E402

if TYPE_CHECKING:
    from defender.tenancy import Tenant, TenantDirectory


def build(tenant: Tenant, agent_root: Path) -> int:
    """Both pages and their contracts, published into the accepted tenant's learning area (#1279
    O1). Refuses before building when there is nowhere to publish: outside `dev` (O4), or a
    `dev` deployment with no publish folder set (A11). The lessons page shows the tenant's
    knowledge at `agent_root` (a copy of its `main`, #1618 F4)."""
    publisher = Publisher.for_tenant(tenant)
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


def main(argv: list[str], *, directory: TenantDirectory | None = None, fetch: Any = None) -> int:
    """`lessons_page.py --tenant T`: the tenant through the one host acceptance (r10 A1), held
    while both pages are built and published (`build`) over a copy of its `main` (made by the
    fetch child, `fetch` when a test hands one in, removed after). `directory` is the tenant records
    a test hands in; a production process passes none and reads them from `DEFENDER_DATABASE_DSN`. A
    refusal, a knowledge fetch's too, is one stderr line and exit 2, before anything is built."""
    import argparse

    from defender import run_common, tenancy
    from defender.records.formats import TenantRefused
    from defender.systems.run_tenant import host_tenant
    from defender.tenancy import run_knowledge

    parser = argparse.ArgumentParser(description="Build this tenant's learning queue pages")
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args(argv)
    try:
        admitted = host_tenant(tenancy.resolve_data_root(), args.tenant, directory=directory)
    except TenantRefused as refused:
        print(f"{parser.prog}: {refused}", file=sys.stderr)
        return 2
    with admitted:
        try:
            with run_common.temporary_copy(admitted.tenant.id, data_root=tenancy.resolve_data_root(), fetch=fetch) as copy:
                return build(admitted.tenant, copy / "agent")
        except (NoPublishRoot, run_knowledge.KnowledgeRefused) as refused:
            print(f"{parser.prog}: {refused}", file=sys.stderr)
            return 2


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
