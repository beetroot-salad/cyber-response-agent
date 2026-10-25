"""E2E script for #585 — the template index reaches the gather subagent for real."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

from defender.tests.e2e._replay_harness import (
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e


class _KeyRecordingReplay(ReplayFn):
    """A `ReplayFn` that also records the `model_settings` each request was issued under."""

    __name__ = "KeyRecordingReplay"

    def __init__(self, turns):
        super().__init__(turns)
        self.keys: list[str | None] = []

    def __call__(self, messages, info):
        settings = info.model_settings or {}
        self.keys.append(settings.get("openai_prompt_cache_key"))
        return super().__call__(messages, info)

#: #1108 P4 (O1, O2): the gather index lists the RUN's tenant catalog (its run copy's
#: `agent/skills/gather/queries/`), never the checkout's — the product tree holds no catalog.
#: The tenant here is the committed fixture set up under the test's data root, plus the
#: made-up templates below, written into that tenant's own `agent/` (decision 4: no lab content).
_CATALOG_REL = Path("skills") / "gather" / "queries"

#: The template the scripted gather binds, an off-target sibling comes from the fixture
#: (`cmdb.host-owner`), a draft that must never be indexed, and the lead-zero template the
#: fixture's `lead-zero.yaml` names (so the correlation lead the harness dispatches resolves
#: against the tenant's catalog, as run start resolves it).
_TEMPLATES = {
    "elastic/sshd-auth-history.md": (
        "---\nid: elastic.sshd-auth-history\nstatus: established\nverb: esql\n---\n\n"
        "## Goal\n\nFixture template (#1108 P4): sshd authentication history for one user "
        "over a window (sshd, auth, history).\n\n## Query\n\n```esql\nFROM logs | LIMIT 1\n```\n"),
    "elastic/_draft/fixture-draft-probe.md": (
        "---\nid: elastic.fixture-draft-probe\nstatus: draft\nverb: esql\n---\n\n"
        "## Goal\n\nFixture draft (#1108 P4) that must never reach the index.\n\n"
        "## Query\n\n```esql\nFROM logs | LIMIT 1\n```\n"),
    "elastic/correlate-alerts-by-entity.md": (
        "---\nid: elastic.correlate-alerts-by-entity\nstatus: established\nverb: alerts\n"
        "params: [end, start]\nbody_substitutions: [entity_filter]\n---\n\n"
        "## Goal\n\nFixture lead-zero template (#1108 P4): alerts naming one entity.\n\n"
        "## Query\n\n```\n${entity_filter}\n```\n"),
}


def _tenant_catalog() -> tuple[object, Path]:
    """The fixture tenant (accepted under this test's data root) with `_TEMPLATES` added to its
    own `agent/` catalog; returns the tenant and that catalog directory."""
    from defender.tests.support.tenancy import _tenants1106

    tenant = _tenants1106.fixture_tenant()
    catalog = Path(tenant.agent) / _CATALOG_REL
    for rel, text in _TEMPLATES.items():
        (catalog / rel).parent.mkdir(parents=True, exist_ok=True)
        (catalog / rel).write_text(text, encoding="utf-8")
    return tenant, catalog


def _ids(catalog: Path, status: str) -> set[str]:
    from defender.knowledge._corpus import iter_query_templates

    return {r.id for r in iter_query_templates(catalog) if r.status == status}


def test_d17_gather_dispatch_carries_the_template_index_end_to_end(tmp_path):
    """d3 + d4 + d17, through the real driver against the run's TENANT catalog (#1108 P4 O2:
    the gather prompt's index is the tenant's, shown at its `/agent/...` model path; O1: no
    template of the checkout's is indexed or spelled)."""
    from defender.tests.e2e._replay_harness import FakeVerbs

    tenant, catalog = _tenant_catalog()
    run_id = "tmpl-index"
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)
    report_md = ("---\ncase_id: tmpl-index\ndisposition: benign\n"
                 "confidence: low\n---\nSynthetic template-index test.\n")

    main_replay = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": "l-001", "system": "elastic",
            "goal": "check sshd auth history", "what_to_summarize": ["auth events"]})]),
        Turn(tool_calls=[("write_file", {"path": model_path(run_dir / "report.md", run_dir=run_dir), "content": report_md})]),
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

    drive(run_dir, run_id=run_id, main=main_replay, gather=gather_replay,
          verbs=FakeVerbs({"elastic": {"esql": esql}}), tenant=tenant)

    dispatch = gather_replay.seen[0]

    established, drafts = _ids(catalog, "established"), _ids(catalog, "draft")
    assert {"cmdb.host-owner", "elastic.sshd-auth-history"} <= established, established
    assert drafts == {"elastic.fixture-draft-probe"}, drafts
    missing = sorted(i for i in established if i not in dispatch)
    assert not missing, f"established template ids absent from the dispatch prompt: {missing[:5]}"

    leaked = sorted(i for i in drafts if i in dispatch)
    assert not leaked, f"draft ids leaked into the dispatch prompt: {leaked[:5]}"

    assert "cmdb." in dispatch

    # O2/O-TEXT: the locator the model is shown is the tenant catalog's path in the model view
    # (`/agent` is the run copy's `agent/`), and no checkout catalog spelling reaches the wire.
    assert "/agent/skills/gather/queries/elastic/sshd-auth-history.md" in dispatch, (
        "the bound template is not shown at the tenant catalog's model path")
    assert "/defender/skills/gather/queries/" not in dispatch, (
        "the gather index still names the product tree's catalog")

    assert "template_search" in dispatch

    # #835, on the wire: an off-target system reaches the model as id + path, without its Goal.
    from defender.knowledge._corpus import iter_query_templates

    off = next(t for t in iter_query_templates(catalog)
               if t.status == "established" and t.system == "cmdb")
    assert off.id in dispatch, "an off-target id was filtered out rather than shortened"
    assert " ".join(off.goal.split()) not in dispatch, "an off-target Goal reached the wire"
    on = next(t for t in iter_query_templates(catalog)
              if t.status == "established" and t.system == "elastic")
    assert " ".join(on.goal.split()) in dispatch, "the dispatched system lost its Goal prose"

    rows = (run_dir / "executed_queries.jsonl").read_text().strip().splitlines()
    assert rows, "gather executed no query"
    import json

    assert any(json.loads(r).get("query_id") == "elastic.sshd-auth-history" for r in rows), \
        "gather did not bind the template it found in the index"


def test_835_the_composition_root_keys_each_gather_lane_on_its_dispatched_system(tmp_path):
    """The other half of #835, at the seam that actually decides it: `driver._build_gather`'s
    `cache_key=f"gather:{system}"`."""
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='cache-lane')
    report_md = ("---\ncase_id: cache-lane\ndisposition: benign\n"
                 "confidence: low\n---\nSynthetic cache-lane test.\n")

    def _dispatch(lead: str, system: str):
        return ("gather", {"lead_id": lead, "system": system,
                           "goal": "measure this lead", "what_to_summarize": ["events"]})

    main_replay = ReplayFn([
        Turn(tool_calls=[_dispatch("l-001", "elastic"), _dispatch("l-002", "cmdb")]),
        Turn(tool_calls=[_dispatch("l-003", "elastic")]),
        Turn(tool_calls=[("write_file", {"path": model_path(run_dir / "report.md", run_dir=run_dir),
                                         "content": report_md})]),
        Turn(text="Investigation complete."),
    ])
    gather_replay = _KeyRecordingReplay([Turn(text="Summary: nothing to report.")] * 3)

    drive(run_dir, run_id="cache-lane",
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
