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


class _KeyRecordingReplay(ReplayFn):
    """A `ReplayFn` that also records the `model_settings` each request was issued under.

    `AgentInfo` — the second argument every `FunctionModel` callable receives — carries the
    settings the Agent was BUILT with, which is where `build_agent_core` puts the prompt-cache
    affinity key. That makes the composition root's own choice observable from inside a driven
    run, through the seam the harness already injects, with no `monkeypatch.setattr` on the
    closure (`driver._build_gather`) that makes it."""

    __name__ = "KeyRecordingReplay"

    def __init__(self, turns):
        super().__init__(turns)
        self.keys: list[str | None] = []

    def __call__(self, messages, info):
        settings = info.model_settings or {}
        self.keys.append(settings.get("openai_prompt_cache_key"))
        return super().__call__(messages, info)

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

    The dispatch prompt the gather subagent receives must carry every ESTABLISHED template ID
    (all systems — not just the dispatched `elastic`) and NO draft id. Gather then binds one of
    them: it passes a template id it found in the index as `query_id`, and the queries table
    records that binding — which is the whole point of the change (a bound id is a catalog reuse;
    a coined id is a miss).

    #835 narrows what "carry" means, and the last block pins the narrowing on the wire rather
    than only at `_gather_prompt`: every id still arrives, but an off-target system's `## Goal`
    prose does not.
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

    assert "cmdb." in dispatch
    assert "host-state." in dispatch

    assert "skills/gather/queries/elastic/sshd-auth-history.md" in dispatch

    assert "template_search" in dispatch

    # #835, on the wire: an off-target system reaches the model as id + path, without its Goal.
    from defender._corpus import iter_query_templates

    off = next(t for t in iter_query_templates(_CATALOG)
               if t.status == "established" and t.system == "cmdb")
    assert off.id in dispatch, "an off-target id was filtered out rather than shortened"
    assert " ".join(off.goal.split()) not in dispatch, "an off-target Goal reached the wire"
    on = next(t for t in iter_query_templates(_CATALOG)
              if t.status == "established" and t.system == "elastic")
    assert " ".join(on.goal.split()) in dispatch, "the dispatched system lost its Goal prose"

    rows = (run_dir / "executed_queries.jsonl").read_text().strip().splitlines()
    assert rows, "gather executed no query"
    import json

    assert any(json.loads(r).get("query_id") == "elastic.sshd-auth-history" for r in rows), \
        "gather did not bind the template it found in the index"


def test_835_the_composition_root_keys_each_gather_lane_on_its_dispatched_system(tmp_path):
    """The other half of #835, at the seam that actually decides it: `driver._build_gather`'s
    `cache_key=f"gather:{system}"`.

    The unit tests around it pin the CONTRACT (`gather_factory(agent_id, system)`) and the
    PASSTHROUGH (`build_gather_agent(cache_key=…)` reaches `model_settings`) — but neither
    reaches the closure that supplies the key, so reverting that one line to `agent_id` left the
    whole suite green and silently restored a per-lead cache lane. `AgentInfo.model_settings`
    closes it: the settings the gather Agent was built with are visible from inside a driven run,
    through the `make_model` seam the harness already injects.

    THREE leads, TWO systems, one run: the two elastic leads must land on ONE lane, and the cmdb
    lead on a different one. The negative half is what makes it a test of the key rather than of
    any constant — a `cache_key` that stopped varying with the system would pass the first
    assertion and fail the second; one that kept varying with the LEAD fails the first."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    report_md = ("---\ncase_id: cache-lane\ndisposition: benign\n"
                 "confidence: low\n---\nSynthetic cache-lane test.\n")

    def _dispatch(lead: str, system: str):
        return ("gather", {"lead_id": lead, "system": system,
                           "goal": "measure this lead", "what_to_summarize": ["events"]})

    main_replay = ReplayFn([
        Turn(tool_calls=[_dispatch("l-001", "elastic"), _dispatch("l-002", "cmdb")]),
        Turn(tool_calls=[_dispatch("l-003", "elastic")]),
        Turn(tool_calls=[("write_file", {"path": str(run_dir / "report.md"),
                                         "content": report_md})]),
        Turn(text="Investigation complete."),
    ])
    gather_replay = _KeyRecordingReplay([Turn(text="Summary: nothing to report.")] * 3)

    drive(run_dir, run_id="cache-lane", salt="1122334455667788",
          main=main_replay, gather=gather_replay)

    keys = gather_replay.keys
    assert len(keys) == 3, f"expected one request per lead, saw {len(keys)}"
    assert keys.count("gather:elastic") == 2, (
        f"the two elastic leads did not share one cache lane: {keys}"
    )
    assert "gather:cmdb" in keys, f"the cmdb lead was not keyed on its own system: {keys}"
    assert not any(k is not None and "l-00" in k for k in keys), (
        f"a lead id is still in the cache key — the per-lead lane is back: {keys}"
    )
