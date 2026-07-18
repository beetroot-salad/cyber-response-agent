"""E2E script for #585 — the template index reaches the gather subagent for real.

The unit spec (`tests/test_gather_template_discovery.py`) pins the index against
`_gather_prompt` directly. This drives the WHOLE seam: `driver.run_investigation` → the main
loop's `gather` tool → `_run_gather` → `bind(GATHER_DEF, …)` → `_gather_prompt` → the nested
gather agent's first request. `ReplayFn.seen` captures that agent's flattened message history,
so the dispatch prompt the model actually received is observable.

This is the SURVIVAL demand (d17): the workflow that depended on the removed `ls`/`grep`
discovery route — gather binding a template for its lead — must still complete via its
substitute. It is the one assertion that survives a refactor of every internal seam.

Replay machinery lives in `_replay_harness.py`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.e2e._replay_harness import (
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

_DEFENDER = Path(__file__).resolve().parents[2]
_CATALOG = _DEFENDER / "skills" / "gather" / "queries"


def _established_ids() -> set[str]:
    from defender._corpus import iter_query_templates

    return {r.id for r in iter_query_templates(_CATALOG) if r.status == "established"}


def _draft_ids() -> set[str]:
    from defender._corpus import iter_query_templates

    return {r.id for r in iter_query_templates(_CATALOG) if r.status == "draft"}


def test_d17_gather_dispatch_carries_the_template_index_end_to_end(tmp_path):
    """d3 + d4 + d17, through the real driver against the REAL repo corpus.

    The dispatch prompt the gather subagent receives must carry every ESTABLISHED template id
    (all systems — not just the dispatched `elastic`) and NO draft id. Gather then binds one of
    them: it tags `--query-id` with a template id it found in the index, and the queries table
    records that binding — which is the whole point of the change (a bound id is a catalog reuse;
    a coined id is a miss).
    """
    from defender.tests.e2e._replay_harness import FakeVerbs

    run_id, salt = "tmpl-index", "1122334455667788"
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    report_md = ("---\ncase_id: tmpl-index\ndisposition: benign\n"
                 "confidence: low\n---\nSynthetic template-index test.\n")

    main_replay = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic",
            "goal": "check sshd auth history", "what_to_summarize": ["auth events"]})]),
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "report.md"), "content": report_md})]),
        Turn(text="Investigation complete."),
    ])
    # Gather binds a template it could only have learned from the index, and tags its id via the
    # `query` tool's `query_id` param (#611 — no more `--query-id` pseudo-flag on a bash adapter).
    def esql(ctx, *, query: str) -> list[dict]:
        return [{"@timestamp": "2026-01-01T00:00:00Z", "event.action": "sshd-auth"}]

    gather_replay = ReplayFn([
        Turn(tool_calls=[("query", {
            "system": "elastic", "verb": "esql",
            "params": {"query": "FROM logs-system.auth-* | LIMIT 1"},
            "query_id": "elastic.sshd-auth-history"})]),
        Turn(text="Summary: 1 sshd auth event."),
    ])

    drive(run_dir, run_id=run_id, salt=salt, main=main_replay, gather=gather_replay,
          verbs=FakeVerbs({"elastic": {"esql": esql}}))

    dispatch = gather_replay.seen[0]

    established, drafts = _established_ids(), _draft_ids()
    assert established, "the corpus has established templates to index"
    missing = sorted(i for i in established if i not in dispatch)
    assert not missing, f"established template ids absent from the dispatch prompt: {missing[:5]}"

    leaked = sorted(i for i in drafts if i in dispatch)
    assert not leaked, f"draft ids leaked into the dispatch prompt: {leaked[:5]}"

    # all systems, not just the dispatched one (d3)
    assert "cmdb." in dispatch
    assert "host-state." in dispatch

    # the index gives gather the PATH, so it can read the body before it binds the id (d16)
    assert "skills/gather/queries/elastic/sshd-auth-history.md" in dispatch

    # ...and the tool it uses when the index is too coarse (d19's fallback surface)
    assert "template_search" in dispatch

    # SURVIVAL: the lead completed and the bound template id landed in the queries table.
    rows = (run_dir / "executed_queries.jsonl").read_text().strip().splitlines()
    assert rows, "gather executed no query"
    import json

    assert any(json.loads(r).get("query_id") == "elastic.sshd-auth-history" for r in rows), \
        "gather did not bind the template it found in the index"
