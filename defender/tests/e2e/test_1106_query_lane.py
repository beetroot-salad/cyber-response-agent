"""#1106 — inside a run, gather works on the RUN's tenant: its verbs are handed the run's settings
folder, and what it is told it may reach is its tenant's grant (O2 gather's `query`, O3).

Driven end to end through the REAL `driver.run_investigation` on the replay harness, with the
run's `TenantDir` and `RunGrants` handed in as the driver's two new inputs (#1106 M4: nothing
reads a table at import, so the run carries them). Two lanes are observed on what the fakes
RECEIVED:

  * the `query` lane — the verb context the query tool builds for a model-dispatched call
    carries the run's tenant `settings_dir` (M3), so an adapter's `load_config` reads THAT
    tenant's `config.env`; never the checkout's committed copy;
  * the dispatch prompt — gather's descriptor index ("Systems of record") and its template
    index are narrowed to the run's gather grant, which is a consumer of the process-level
    grant before #1106 (`driver._dispatch_catalogs` read `GATHER_DEF.verb_grant`). Tenant A
    reaches cmdb and elastic, tenant B identity and threat-intel; each prompt must name its
    own tenant's systems and not the other's.

Every fixture tenant carries the COMMITTED tenant's id (`playground`) under a tmp root, so a
lane that resolved the checkout's folder by id would be caught by value.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests import _tenants1106 as T  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

LEAD = "l-001"
DONE = Turn(text="Summary: measured the lead.")


def _tenant(tmp_path: Path, table: str, marker: str):
    root = tmp_path / f"root-{marker}"
    T.plant_tenant(root, T.PLAYGROUND_ID, table=table, marker=marker)
    tenant = T.tenants().tenant_dir(root, T.PLAYGROUND_ID)
    return tenant, T.run_grants(tenant.settings)


def _run(tmp_path: Path, *, tenant, grants, verbs, system: str, gather_turns: list[Turn],
         run_id: str) -> tuple[Path, ReplayFn]:
    run_dir = materialize(tmp_path / run_id, GOLDEN_AB3)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": system, "goal": f"measure the {system} lead",
            "what_to_summarize": ["what the system says"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(gather_turns)
    drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs,
          tenant=tenant, grants=grants)
    return run_dir, gather


def _lead_prompt(gather: ReplayFn) -> str:
    """The first gather prompt that dispatched THIS test's lead (not a harness lead-0)."""
    for seen in gather.seen:
        if f"lead_id: {LEAD}" in seen or f"lead_id: '{LEAD}'" in seen:
            return seen
    raise AssertionError(f"no gather prompt for {LEAD}: {[s[:200] for s in gather.seen]}")


def _systems_of_record(prompt: str) -> str:
    start = prompt.index("## Systems of record")
    rest = prompt[start + len("## Systems of record"):]
    ends = [i for i in (rest.find("\n## "), rest.find("\n### ")) if i >= 0]
    return rest[: min(ends)] if ends else rest


def test_a_query_verb_is_handed_the_runs_tenant_settings_folder(tmp_path):
    tenant, grants = _tenant(tmp_path, T.TABLE_A, "lane")
    rec = VerbRecorder()

    def get_host(ctx, *, host: str = "web-1") -> dict:
        rec.record("get-host", ctx, {"host": host})
        return {"host": host}

    _run(tmp_path, tenant=tenant, grants=grants, system="cmdb",
         verbs=FakeVerbs({"cmdb": {"get-host": get_host}}), run_id="q1106-lane",
         gather_turns=[
             Turn(tool_calls=[("query", {"system": "cmdb", "verb": "get-host",
                                         "params": {"host": "web-1"}})]),
             DONE,
         ])
    call = rec.only()
    assert Path(call.ctx.settings_dir).resolve() == tenant.settings
    assert Path(call.ctx.settings_dir).resolve() != T.PLAYGROUND_SETTINGS.resolve()
    # Read THROUGH what the verb was handed: the adapter's config is the run tenant's.
    transport = T.mod("scripts.adapters._stub_transport")
    assert transport.load_config(call.ctx, "cmdb", "CMDB")["URL_BASE"] == "http://cmdb-lane:8080"


@pytest.mark.parametrize(("own", "system", "reached", "withheld"), [
    ("A", "cmdb", ("cmdb", "elastic"), ("identity", "threat-intel")),
    ("B", "identity", ("identity", "threat-intel"), ("cmdb", "elastic")),
])
def test_the_gather_dispatch_advertises_exactly_the_runs_tenants_systems(
        tmp_path, own, system, reached, withheld):
    table = {"A": T.TABLE_A, "B": T.TABLE_B}[own]
    tenant, grants = _tenant(tmp_path, table, f"idx{own.lower()}")
    verbs = FakeVerbs({system: {"health-check": lambda ctx: {"ok": True}}})
    _run_dir, gather = _run(tmp_path, tenant=tenant, grants=grants, verbs=verbs, system=system,
                            gather_turns=[DONE], run_id=f"q1106-idx{own.lower()}")
    prompt = _lead_prompt(gather)
    catalog = _systems_of_record(prompt)
    for s in reached:
        assert f"- `{s}`:" in catalog, f"tenant {own}'s grant reaches {s}:\n{catalog}"
    for s in withheld:
        assert f"- `{s}`:" not in catalog, f"tenant {own}'s grant does not reach {s}:\n{catalog}"
    # The template index filters on the same grant: the shipped elastic correlation template
    # binds elastic.alerts, which A grants gather and B does not.
    listed = T.SHIPPED_CORRELATION_TEMPLATE in prompt
    assert listed is ("elastic" in reached), (own, listed)


# ---- lead-zero item 1 reads the run's tenant, not the checkout ------------------------------------

def test_lead_zero_item1_reads_the_runs_tenant_alerts_index_and_hands_its_verbs_that_tenant(
        tmp_path):
    """Item 1 falls back to the configured `ELASTIC_ALERTS_INDEX` when the alert names no
    `signal_index` (#808 R4) — and "configured" is the RUN's tenant's `config.env` (O2), not
    the checkout's. The injected tenant carries the committed tenant's id and a distinct
    alerts index; the shell fetch's `index` (the inbound payload) must be that value, and every
    lead-0 verb call must be handed that tenant's settings folder. The control: the same
    scenario's checkout value is a different string."""
    from defender.tests.e2e import _lead_zero_808 as LZ

    root = tmp_path / "root-lz"
    T.plant_tenant(root, T.PLAYGROUND_ID, table=T.TABLE_A, configs=T.config_texts(
        "lz", events_index="lz-tenant-events-*", alerts_index="lz-tenant-alerts-*"))
    tenant = T.tenants().tenant_dir(root, T.PLAYGROUND_ID)
    grants = T.run_grants(tenant.settings)
    assert LZ.ALERTS_INDEX != "lz-tenant-alerts-*", "the fixture no longer discriminates"

    res = LZ.run(tmp_path / "run", run_id="lz1106-tenant", alert=LZ.alert_doc(signal_index=None),
                 answer=LZ.answer_hits([LZ.hit(ts="2026-05-25T15:22:00.000Z")]),
                 tenant=tenant, grants=grants)
    assert res.shell_call.params["index"] == "lz-tenant-alerts-*", res.shell_call.params
    assert res.rec.calls, "lead-0 issued no backend call"
    for call in res.rec.calls:
        assert Path(call.ctx.settings_dir).resolve() == tenant.settings, (call.verb, call.ctx)
