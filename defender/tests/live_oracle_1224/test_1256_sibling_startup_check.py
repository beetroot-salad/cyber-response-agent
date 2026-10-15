"""#1256 O-9 — a branch sibling runs the same startup check over its OWN resolved settings.

The design (#1256 r2, decided D2): a sibling resolves its tenant at its own start and runs the
startup check there; a system its settings do not configure is down in that sibling even if the
source run's capture holds answers for it — serving captured answers for a system the tenant
cannot reach would make the world disagree with its own settings. (It arises only when settings
changed between the source run and the branch.)

THE PATH DRIVEN IS THE SIBLING'S OWN, minus the process and the box: `run._resolve_run_tenant`
resolves the tenant at the sibling's start (`dispatches_lead_zero=False`, as `run.main` does for
an `--episode` run); `run._world_seams` settles the world's oracle side; `run._drive_investigation`
builds the `WorldRegistry` over the checkout's roster with that tenant and the source run's
pre-branch keys, exactly as `run.main`'s lifecycle does, and hands it to its `investigate` seam,
which here runs the REAL driver (`_replay_harness.drive`, `resume=` the `BranchSpec` the world's
manifest names) with scripted models. The source run is `_branch_947.legal_source` — a finished
run a branch may legally be taken from — and the world is the episode's control world (no facts),
whose every call is answered from the family's base recording when the recording holds it
(`passthrough`, no oracle turn, no provider call).

THE CAPTURE holds an answer for `cmdb.get-host {host: web-1}` carrying `CAPTURE_MARK`. The control
sibling (cmdb configured) is answered from it — the mark reaches the gather agent and the world
ledger records the call — so the channel can show a served capture. The down sibling (cmdb's
`config.env` loses `CMDB_URL_BASE` after the source run, before the sibling starts) must not be:
the mark reaches no agent, the world ledger records no cmdb call, the run writes no cmdb row, the
breaker is charged nothing, and the agent is told cmdb is not configured and why (on the dispatch
refusal MAIN sees, or on the call refusal the gather agent sees — the design gates both).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.run_repository import RunPaths  # noqa: E402
from defender.run_repository import Run  # noqa: E402
from defender.tests import _tenants1106 as T6  # noqa: E402
from defender.tests._branch_947 import GOLDEN_INVESTIGATION, legal_source, spec_at  # noqa: E402
from defender.tests._data_root_1078 import current_data_root  # noqa: E402
from defender.tests.e2e import _lead_zero_808 as LZ  # noqa: E402
from defender.tests.e2e import _replay_harness as H  # noqa: E402
from defender.tests.live_oracle_1224 import _spec1224 as S  # noqa: E402
from defender.tests.tenant_1107_settings import _spec1107 as S7  # noqa: E402

pytestmark = pytest.mark.e2e

TENANT_ID = "acme-sibling"
HOST = "web-1"
LEAD = "l-001"
#: What the family's base recording answers for `cmdb.get-host {host: web-1}`.
CAPTURE_MARK = "FD1256-CAPTURED-OWNER-OF-WEB-1"
#: The key the sibling's settings lose between the source run and the branch.
DROPPED = "CMDB_URL_BASE"
CONTINUATION = "Continue the investigation from here."


def _plant_tenant() -> tuple[Path, Any]:
    """A complete tenant under this test's data root (K6: every system configured), its table
    granting gather cmdb.get-host: (knowledge folder, accepted Tenant)."""
    root = current_data_root()
    knowledge = T6.place_tenant(root, TENANT_ID, table=T6.TABLE_A)
    return knowledge, T6.accept(root, TENANT_ID)


def _episode(where: Path, spec: Any, source_dir: Path) -> Path:
    """An episode whose manifest names the source run's branch point and ONE control world, and
    whose base recording holds the source run's capture of `cmdb.get-host {host: web-1}`."""
    as_of = spec.as_of.isoformat().replace("+00:00", "Z")
    doc = S.family_v2(worlds=[S.control_world("a")], source_run_dir=str(source_dir),
                      served_systems=("cmdb", "elastic"), as_of=as_of,
                      branch_message_id=spec.branch_message_id,
                      continuation_prompt=spec.continuation_prompt)
    capture = S.captured("cmdb", "get-host", {"host": HOST},
                         {"host": HOST, "owner": CAPTURE_MARK})
    return S.episode_v2(where, doc=doc, root=where / "episodes", base_rows=[capture])


def _sibling(tmp_path: Path, label: str, *, accepted: Any, spec: Any, source_dir: Path,
             ) -> dict[str, Any]:
    """Start one sibling of world `a` at the branch point: resolve its tenant NOW (its own
    start), build its world registry as `run.main` does, and drive the real driver resumed. MAIN
    dispatches one lead on cmdb; the lead asks `cmdb.get-host {host: web-1}`, then summarises."""
    run_py = S.mod("run")
    ep = _episode(tmp_path / f"ep-{label}", spec, source_dir)
    world = S.load_world(ep, "a")
    tenant = run_py._resolve_run_tenant(accepted, defender_dir=S.DEFENDER,
                                        dispatches_lead_zero=False)
    source = Run.under(source_dir.parent, source_dir.name)
    sibling_dir = LZ.materialize_alert(tmp_path / f"sibling-{label}", LZ.alert_doc())
    main = H.ReplayFn([
        H.Turn(tool_calls=[("gather", {"lead_id": LEAD, "system": "cmdb",
                                       "goal": "who owns web-1",
                                       "what_to_summarize": ["web-1's owner"]})]),
        H.Turn(text="Resumed and stopping."),
    ])
    gather = H.ReplayFn([
        H.Turn(tool_calls=[("query", {"system": "cmdb", "verb": "get-host",
                                      "params": {"host": HOST}})]),
        H.Turn(text="Summary: asked cmdb who owns web-1."),
    ])
    state = S.run_state(sibling_dir, sibling_dir.name)
    handed: dict[str, Any] = {}

    def investigate(*, run: Any, defender_dir: Path, verbs: Any, resume: Any,
                    source_run: Any, **kw: Any) -> dict:
        handed.update(verbs=verbs, resume=resume, tenant=kw.get("tenant"))
        # The driver re-resolves the same accepted tenant from the same files (`drive` takes
        # an accepted Tenant): the values the registry was built with.
        return H.drive(Path(run.run_dir), run_id=Path(run.run_dir).name, main=main,
                       gather=gather, verbs=verbs, resume=resume, source_run=source_run,
                       defender_dir=defender_dir, tenant=accepted, run_state=state)

    with S.mod("_episode_handle").Episode.open(ep) as episode:
        summary = run_py._drive_investigation(
            alert_path=RunPaths(sibling_dir).alert,
            run=Run.under(sibling_dir.parent, sibling_dir.name),
            defender_dir=S.DEFENDER, model_name="fd1256-sibling", model_override=None,
            box=None, tenant=tenant, world=world, episode=episode, investigate=investigate,
            **run_py._world_seams(world, oracle=None, verifier=None, source=source))
    assert type(handed.get("verbs")).__name__ == "WorldRegistry", (
        f"premise: the sibling's investigation was not handed a world registry: {handed!r}")
    assert handed.get("resume") is not None, "premise: the sibling was not resumed"
    return {"ep": ep, "dir": sibling_dir, "main": main, "gather": gather, "state": state,
            "summary": summary, "tenant": tenant}


#: The world-ledger decisions that SERVE a call (an answer delivered to the investigator).
SERVED = (S.PASSTHROUGH, S.ORACLE_DECISION)


def _served_cmdb(sib: dict[str, Any]) -> list[dict]:
    """The world ledger's rows that served a cmdb call (or carry the capture's answer). A row
    recording a refusal is not pinned either way: the design is silent on the world ledger."""
    return [r for r in S.ledger_rows(sib["ep"], "a") if r.get("system") == "cmdb"
            and (r.get("source") in SERVED or CAPTURE_MARK in str(r.get("payload_text")))]


def _cmdb_query_rows(sib: dict[str, Any]) -> list[dict]:
    return [r for r in S.read_jsonl(Path(RunPaths(sib["dir"]).executed_queries))
            if r.get("system") == "cmdb"]


def test_o9_a_sibling_judges_its_own_settings_not_the_captures(tmp_path: Path) -> None:
    """A system configured when the source ran but not at the sibling's start is down in that sibling: its call is refused without being answered from the source run's capture, the agent is told 'not configured' and why, and nothing is charged. The same sibling with the system configured is answered from the capture."""
    knowledge, accepted = _plant_tenant()
    store, source_dir, _session, path_ids = legal_source(
        tmp_path / "source", investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    spec = spec_at(store, source_dir, path_ids[-1], prompt=CONTINUATION)

    # Control: settings unchanged since the source run — the capture answers the call.
    configured = _sibling(tmp_path, "configured", accepted=accepted, spec=spec,
                          source_dir=source_dir)
    gather_saw = "\n".join(configured["gather"].seen)
    assert CAPTURE_MARK in gather_saw, (
        "premise: the configured sibling's call was not answered from the source run's capture "
        f"(the gather agent saw {len(configured['gather'].seen)} requests)")
    assert _served_cmdb(configured), (
        "premise: the configured sibling's world ledger records no served cmdb call")

    # The operator edits the tenant's settings after the source run, before the branch.
    S7.drop_key(knowledge, "cmdb", DROPPED)
    down = _sibling(tmp_path, "down", accepted=accepted, spec=spec, source_dir=source_dir)
    assert DROPPED not in down["tenant"].systems.get("cmdb", {}), (
        "premise: the sibling's own start did not resolve the edited settings")

    main_saw = "\n".join(down["main"].seen)
    gather_saw = "\n".join(down["gather"].seen)
    assert CAPTURE_MARK not in main_saw + gather_saw, (
        "the sibling was answered from the source run's capture for a system its own settings "
        "do not configure (#1256 O-9: down in the sibling)")
    assert _served_cmdb(down) == [], (
        f"the sibling's world served cmdb though cmdb is down at its start: "
        f"{_served_cmdb(down)}")
    assert _cmdb_query_rows(down) == [], (
        f"a refused call to a down system wrote a queries row: {_cmdb_query_rows(down)}")
    told = [text for text in (main_saw, gather_saw)
            if "cmdb" in text and "not configured" in text.lower() and DROPPED in text]
    assert told, (
        "the sibling's agent was never told cmdb is not configured and why (neither MAIN's "
        "dispatch return nor the gather agent's call return names 'not configured' and "
        f"{DROPPED})")
    assert down["state"].breaker_failures("cmdb") == 0, (
        f"the breaker was charged for a system down at the sibling's start: "
        f"{down['state'].breaker_snapshot()!r}")
    assert down["state"].breaker_snapshot().get("total_failures", 0) == 0, (
        f"the run-wide failure count was charged: {down['state'].breaker_snapshot()!r}")
