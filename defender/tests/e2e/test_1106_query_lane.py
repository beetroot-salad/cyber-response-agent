"""#1106 e2e through the real driver: gather's query verbs are handed the run's tenant record, config faults name the settings folder not its host path, and the dispatch advertises exactly the run tenant's granted systems."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S  # noqa: E402
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
    T.place_tenant(root, T.PLAYGROUND_ID, table=table, marker=marker,
                   configs=S.config_texts(marker))
    return T.accept(root, T.PLAYGROUND_ID)


def _run(tmp_path: Path, *, tenant, verbs, system: str, gather_turns: list[Turn],
         run_id: str) -> tuple[Path, ReplayFn, ReplayFn]:
    """(run dir, MAIN's replay, gather's replay) — each replay's `.seen` is what that model
    was shown."""
    run_dir = materialize(tmp_path / run_id, GOLDEN_AB3, run_id=run_id)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": system, "goal": f"measure the {system} lead",
            "what_to_summarize": ["what the system says"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(gather_turns)
    drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs,
          tenant=tenant)
    return run_dir, main, gather


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


def test_a_query_verb_is_handed_the_runs_tenant_record(tmp_path):
    tenant = _tenant(tmp_path, T.TABLE_A, "lane")
    rec = VerbRecorder()

    def get_host(ctx, *, host: str = "web-1") -> dict:
        rec.record("get-host", ctx, {"host": host})
        return {"host": host}

    _run(tmp_path, tenant=tenant, system="cmdb",
         verbs=FakeVerbs({"cmdb": {"get-host": get_host}}), run_id="q1106-lane",
         gather_turns=[
             Turn(tool_calls=[("query", {"system": "cmdb", "verb": "get-host",
                                         "params": {"host": "web-1"}})]),
             DONE,
         ])
    call = rec.only()
    assert Path(call.ctx.tenant.settings).resolve() == tenant.settings
    assert Path(call.ctx.tenant.settings).resolve() != T.FIXTURE_SETTINGS.resolve()
    # Read THROUGH what the verb was handed: the adapter's config is the run tenant's.
    transport = T.mod("scripts.adapters._stub_transport")
    assert transport.load_config(call.ctx, "cmdb", "CMDB")["URL_BASE"] == "http://cmdb-lane:8080"


def test_a_config_fault_reaches_the_model_naming_the_settings_folder_not_its_host_path(
        tmp_path):
    """The settings half is host-only (#1106):"""
    tenant = _tenant(tmp_path, T.TABLE_A, "fault")
    (tenant.settings / "systems" / "cmdb" / "config.env").unlink()
    transport = T.mod("scripts.adapters._stub_transport")
    rec = VerbRecorder()

    def get_host(ctx, *, host: str = "web-1") -> dict:
        rec.record("get-host", ctx, {"host": host})
        return transport.load_config(ctx, "cmdb", "CMDB")

    run_dir, main, gather = _run(
        tmp_path, tenant=tenant, system="cmdb",
        verbs=FakeVerbs({"cmdb": {"get-host": get_host}}), run_id="q1106-fault",
        gather_turns=[
            Turn(tool_calls=[("query", {"system": "cmdb", "verb": "get-host",
                                        "params": {"host": "web-1"}})]),
            DONE,
        ])
    told_main = "\n".join(main.seen)
    about_cmdb = [ln for ln in told_main.splitlines() if "cmdb" in ln][:20]
    assert "config file not found" in told_main, (
        f"MAIN was never told why cmdb is down (#1256 O-3/O-4); its cmdb lines: {about_cmdb}")
    assert "settings/systems/cmdb/config.env" in told_main, (
        f"the reason MAIN was given does not name the settings file: {about_cmdb}")
    assert rec.calls == [], f"the down system's verb ran: {rec.calls}"
    queries = run_dir / "executed_queries.jsonl"
    rows = read_jsonl_rows(queries) if queries.is_file() else []
    assert not [r for r in rows if r.get("lead_id") == LEAD], (
        f"the refused lead {LEAD} left a queries row — its call ran: {rows}")
    table = "\n".join(p.read_text(encoding="utf-8") for p in run_dir.rglob("*.jsonl"))
    data_root = str(tenant.data_root)
    shown = "\n".join([*main.seen, *gather.seen])
    reason_lines = [ln for ln in shown.splitlines()
                    if "config file not found" in ln or "systems/cmdb/config.env" in ln]
    assert reason_lines, "no model-visible line carries the reason"
    # Nothing either model was shown, nor any run-dir table, locates the tenant folder (at base
    # neither model's view held the data root at all, so the sweep is over every line).
    for label, text in (("the reason", "\n".join(reason_lines)), ("a model's view", shown),
                        ("the run-dir tables", table)):
        assert data_root not in text, (
            f"{label} holds the data root {data_root}: "
            f"{[ln for ln in text.splitlines() if data_root in ln][:5]}")


@pytest.mark.parametrize(("own", "system", "reached", "withheld"), [
    ("A", "cmdb", ("cmdb", "elastic"), ("identity", "threat-intel")),
    ("B", "identity", ("identity", "threat-intel"), ("cmdb", "elastic")),
])
def test_the_gather_dispatch_advertises_exactly_the_runs_tenants_systems(
        tmp_path, own, system, reached, withheld):
    table = {"A": T.TABLE_A, "B": T.TABLE_B}[own]
    tenant = _tenant(tmp_path, table, f"idx{own.lower()}")
    verbs = FakeVerbs({system: {"health-check": lambda ctx: {"ok": True}}})
    _run_dir, _main, gather = _run(tmp_path, tenant=tenant, verbs=verbs, system=system,
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
