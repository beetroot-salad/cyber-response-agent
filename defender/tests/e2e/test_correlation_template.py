"""#1003 e2e: a correlation template whose verb disagrees with the table's grant refuses the run at start, before anything is spent; runs that never dispatch the lead are not refused."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import re
from defender.tests.support.runtime.state._1255_view import MODEL_DEFENDER, model_path

import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    CORRELATION_SUMMARY,
    L3,
    alert_doc,
    answer_hits,
    elastic_backend,
    hit,
    materialize_alert,
    run,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
)
from defender.tests.support.storage._store_owner import reread

pytestmark = pytest.mark.e2e

TEMPLATE_REL = Path("skills") / "gather" / "queries" / "elastic" / "correlate-alerts-by-entity.md"
#: The fixture tenant's correlation id, transcribed (the unit module holds the same literal).
SHIPPED_TEMPLATE_ID = "elastic.correlate-alerts-by-entity"
RULE_ID = "v2-sshd-success-after-failures"

#: A run reads its TENANT's catalog (`agent/skills/gather/queries/` in its export), never the
#: checkout's, so an editable catalog is a copy of the fixture tenant's `agent/` driven through
#: `drive(agent=...)`.
FIXTURE_AGENT = DEFENDER.parent / "knowledge" / "tenant-fixture" / "agent"

ANCESTORS = [
    hit(ts="2026-05-25T15:26:10.000Z", user="dev.dana", ip="172.18.0.15", host="office-ws-1"),
    hit(ts="2026-05-25T15:26:50.000Z", user="svc.config-mgmt", ip="172.18.0.4", host="db-1"),
]


def planted_agent(root: Path) -> Path:
    """A tenant agent half the run can be pointed at whose CATALOG is editable: a copy of the
    fixture tenant's `agent/` at `root/agent` (each `root` names its own tenant)."""
    tree = root / "agent"
    tree.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(FIXTURE_AGENT, tree, symlinks=True)
    return tree


def _mismatched(root: Path) -> Path:
    """The reproduced silent burn as a tenant catalog: the template's verb rebound."""
    tree = planted_agent(root)
    _rebind_verb(tree, "query")
    return tree


def _rebind_verb(tree: Path, verb: str) -> None:
    """Rewrite the planted template's one `verb: alerts` line to `verb` (a same-vendor mismatch)."""
    path = tree / TEMPLATE_REL
    text = path.read_text(encoding="utf-8")
    assert text.count("\nverb: alerts\n") == 1, "the fixture template's front matter moved"
    path.write_text(text.replace("\nverb: alerts\n", f"\nverb: {verb}\n"), encoding="utf-8")


def test_a_catalog_whose_template_disagrees_with_the_table_refuses_the_run_before_anything_is_spent(tmp_path):
    """The reproduced silent burn, closed where the design puts the check."""
    tree = planted_agent(tmp_path / "ok")
    res = run(tmp_path / "ok", run_id="lz1003-ok", answer=answer_hits(ANCESTORS), agent=tree)
    assert res.has_sidecar(L3), f"positive control: the planted catalog did not dispatch l-00c ({res.gather_raw_names()})"
    assert res.gather is not None
    assert len(res.gather.seen) == 1, "positive control: item 3 was not dispatched"
    assert re.search(rf"^defender_dir: {re.escape(MODEL_DEFENDER)}$", res.gather.seen[0],
                     re.MULTILINE), "positive control: the lead was not dispatched with its checkout"
    assert res.budget, "positive control: the budget did not open"

    tree = _mismatched(tmp_path / "bad")
    run_dir = materialize_alert(tmp_path / "bad", alert_doc())
    rec = VerbRecorder()
    main = ReplayFn([Turn(tool_calls=[("read_file", {
                         "path": model_path(run_dir / "alert.json", run_dir=run_dir)})]),
                     Turn(text="Investigation complete.")])
    gather = ReplayFn([Turn(text=CORRELATION_SUMMARY)])

    from defender.investigation.lead_zero import CorrelationDispatchError

    with pytest.raises(CorrelationDispatchError) as caught:
        drive(run_dir, run_id="lz1003-bad", main=main, gather=gather,
              verbs=elastic_backend(rec, answer_hits(ANCESTORS)), agent=tree)
    message = str(caught.value)
    assert SHIPPED_TEMPLATE_ID in message, message
    assert "elastic.query" in message, f"the template's pair is not named:\n{message}"
    assert "elastic.alerts" in message, f"the table's pair is not named:\n{message}"

    assert not (run_dir / "wire_logs").exists(), "the wire log opened before the check"
    assert not (run_dir / "gather_raw" / f"{L3}.lead.json").exists(), "l-00c was claimed before the check"
    assert rec.calls == [], f"a backend call was issued before the check: {rec.verbs}"
    assert main.seen == [], "MAIN was asked for a turn before the check"
    assert gather.seen == [], "the gather model was asked for a turn before the check"


def test_a_run_that_will_not_dispatch_the_lead_is_not_refused_for_its_template(tmp_path):
    """The check is gated on the SAME predicate as the dispatch."""
    from defender.tests.support.learning.branch._branch_947 import spec_at
    from defender.tests.support.storage._session_store_705 import store_factory
    from defender.tests.e2e._replay_harness import GOLDEN, _split_at_fences

    # (a) No registry injected.
    tree = _mismatched(tmp_path / "noreg")
    res = run(tmp_path / "noreg", run_id="lz1003-noreg", verbs=None, agent=tree)
    assert not res.has_sidecar(L3), "a run with no registry claimed l-00c"
    assert res.summary_dict.get("truncated_by") is None, res.summary_dict

    # (b) A resume: a source run on an agreeing planted catalog (the data root already holds
    # (a)'s tenant; the fixture tenant is set up only into a fresh one), then a sibling over the
    # mismatched catalog whose recorder catches every call lead-0 would make.
    sink: list = []
    source = run(
        tmp_path / "source", run_id="lz1003-source", answer=answer_hits(ANCESTORS),
        agent=planted_agent(tmp_path / "source"),
        stores=sink, store_factory=store_factory(tmp_path, sink=sink),
        # one real call by `l-00c`: a branch needs a query that reached a system (#1222)
        gather_turns=[
            Turn(tool_calls=[("query", {"system": "elastic", "verb": "alerts",
                                        "params": {"native_query": "user.name:dev.dana"}})]),
            Turn(text=CORRELATION_SUMMARY),
        ],
        main_turns=[
            *[Turn(tool_calls=[("append_block", {"text": chunk})])
              for chunk in _split_at_fences(
                  (GOLDEN / "investigation.md").read_text(encoding="utf-8"), 7)],
            Turn(text="Holding here; the evidence is in hand and nothing is settled."),
        ],
    )
    assert source.summary_dict.get("truncated_by") is None, source.summary_dict
    store = reread(sink[0])
    from defender.tests.support.runtime.state._1255_snapshot import tool_calling_responses

    spec = spec_at(store, source.run_dir, tool_calling_responses(store)[-1])

    tree = _mismatched(tmp_path / "resumed")
    sibling_dir = materialize_alert(tmp_path / "resumed", alert_doc())
    rec = VerbRecorder()
    sibling = ReplayFn([Turn(text="Resumed and stopping.")])
    summary = drive(sibling_dir, run_id="lz1003-sibling", main=sibling, resume=spec,
                    verbs=elastic_backend(rec, answer_hits(ANCESTORS)), agent=tree)
    assert summary.get("truncated_by") is None, summary
    assert sibling.seen, "the resumed run never reached its model"
    assert rec.calls == [], f"a resumed run issued a backend call: {rec.verbs}"
    sidecar = sibling_dir / "gather_raw" / f"{L3}.lead.json"
    assert sidecar.read_bytes() == (source.run_dir / "gather_raw" / f"{L3}.lead.json").read_bytes()


def test_the_config_is_read_from_the_tree_the_run_reads(tmp_path):
    """The correlation id comes from the run's tenant's `lead-zero.yaml`, not a process-cached read;
    with that config removed, the run refuses naming its path before opening its logger."""
    from defender.systems.lead_zero_config import LeadZeroConfigError, lead_zero_config_path
    from defender.tests.support.tenancy import _tenants1106 as T1106
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107

    planted_id = "elastic.correlate-alerts-by-entity-second"
    # A planted tenant whose table grants the lead `elastic.alerts` and whose config names the
    # planted id; its agent half holds the fixture template plus a copy under the planted id.
    knowledge = T1106.place_tenant(tmp_path / "tenants", fixture_uuid("tenant:acme"),
                                   configs=S1107.config_texts("acme"),
                                   lead_zero=f"correlation_template: {planted_id}\n")
    shipped = knowledge / "agent" / TEMPLATE_REL
    second = shipped.with_name("correlate-alerts-by-entity-second.md")
    second.write_text(
        shipped.read_text(encoding="utf-8").replace(f"id: {SHIPPED_TEMPLATE_ID}\n", f"id: {planted_id}\n", 1),
        encoding="utf-8",
    )
    assert second.read_text(encoding="utf-8") != shipped.read_text(encoding="utf-8")
    tenant = T1106.accept(tmp_path / "tenants", fixture_uuid("tenant:acme"))
    config = lead_zero_config_path(tenant.settings)
    assert config.is_file(), "the planted tenant carries no config"
    assert not config.is_symlink(), "the config must be the tenant's own copy"

    res = run(tmp_path / "second", run_id="lz1003-second", answer=answer_hits(ANCESTORS),
              tenant=tenant)
    assert res.has_sidecar(L3), f"the planted tenant did not dispatch l-00c ({res.gather_raw_names()})"
    goal = res.sidecar(L3)["goal"]
    assert f"`{planted_id}`" in goal, goal
    assert f"`{SHIPPED_TEMPLATE_ID}`" not in goal, (
        f"the lead was told to bind the CHECKOUT's configured id, not the run tree's:\n{goal}"
    )
    assert (res.run_dir / "wire_logs").is_dir(), \
        "positive control: a run that read its config never opened its wire log"

    config.unlink()
    run_dir = materialize_alert(tmp_path / "noconfig", alert_doc())
    with pytest.raises(LeadZeroConfigError) as caught:
        drive(run_dir, run_id="lz1003-noconfig", main=ReplayFn([Turn(text="never")]),
              gather=ReplayFn([Turn(text=CORRELATION_SUMMARY)]),
              verbs=elastic_backend(VerbRecorder(), answer_hits(ANCESTORS)), tenant=tenant)
    assert str(config) in str(caught.value), str(caught.value)
    # A raising run hands its `RunState` back to no one, so "nothing spent" is read off the run dir.
    assert not (run_dir / "wire_logs").exists(), "the run opened its logger before the config was read"
