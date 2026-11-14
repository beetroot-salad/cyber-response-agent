"""#1503 e2e: the step-zero correlation lead runs from its grant alone. A tenant whose catalog
holds no saved query still dispatches it, and the lead's goal names no query to bind: the lead
writes its own (#1003's `lead-zero.yaml` binding is retired)."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    L3,
    answer_hits,
    hit,
    run,
)
from defender.tests.e2e._replay_harness import DEFENDER  # noqa: E402

pytestmark = pytest.mark.e2e

#: A run reads its TENANT's catalog (`agent/skills/gather/queries/` in its export), never the
#: checkout's, so an editable catalog is a copy of the fixture tenant's `agent/`.
FIXTURE_AGENT = DEFENDER / "tests" / "fixtures" / "tenant-fixture" / "agent"
CATALOG_REL = Path("skills") / "gather" / "queries"

ANCESTORS = [
    hit(ts="2026-05-25T15:26:10.000Z", user="dev.dana", ip="172.18.0.15", host="office-ws-1"),
]


def test_a_tenant_with_no_saved_query_still_dispatches_the_lead(tmp_path):
    tree = tmp_path / "t" / "agent"
    tree.parent.mkdir(parents=True)
    shutil.copytree(FIXTURE_AGENT, tree, symlinks=True)
    shutil.rmtree(tree / CATALOG_REL, ignore_errors=True)

    res = run(tmp_path / "t", run_id="lz1503-nocache", answer=answer_hits(ANCESTORS), agent=tree)

    assert res.has_sidecar(L3), f"l-00c was not dispatched ({res.gather_raw_names()})"
    assert res.gather is not None
    [prompt] = res.gather.seen
    assert "Write the query yourself" in prompt
    assert "Bind `" not in prompt
