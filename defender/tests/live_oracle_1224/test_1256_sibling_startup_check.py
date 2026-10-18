"""#1256 O-9 — a branch sibling runs the same startup check over its OWN resolved settings.

The design (#1256 r3, decided D2): a sibling resolves its tenant at its own start and runs the
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
manifest names) with scripted models. The source run is `_branch_947.planted_source` — a snapshotted fixture
run a branch may legally be taken from — and the world is the episode's control world (no facts),
whose every call is answered from the family's base recording when the recording holds it
(`passthrough`, no oracle turn, no provider call).

THE CAPTURE holds an answer for `cmdb.get-host {host: web-1}` carrying `CAPTURE_MARK`. The control
sibling (cmdb configured) is answered from it — the mark reaches the gather agent and the world
ledger records the call — so the channel can show a served capture. The down sibling (cmdb's
`config.env` loses `CMDB_URL_BASE` after the source run, before the sibling starts) must not be:
the mark reaches no agent, the world ledger records no cmdb call, the run writes no cmdb row, the
breaker is charged nothing, and the agent is told cmdb is not configured and why. The lead is
dispatched on elastic (configured in both siblings), so the gather agent runs in the down sibling
too and the resumed run's surfaces can be read: its system index and its `list_verbs(cmdb)`
answer carry cmdb's down status (the design's resume non-obligation), and its cmdb call is
refused.

O-8 x O-9 — a sibling whose EVERY granted system is down at its own start is refused at that
start like a fresh run (O-8), naming each system and its reason. That arm drives the sibling's
whole entry (`run.main --episode E --world b --tenant T`, the #1107 resume path) with recording
seams (`_spec1107.RunRecorder`): the refusal must come before the sibling's run is made and
before its lifecycle (where the world that would answer from the capture is built), and the
episode's recordings and run container are left as they were.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.run_repository import RunPaths  # noqa: E402
from defender.run_repository import Run  # noqa: E402
from defender.tests import _tenants1106 as T6  # noqa: E402
from defender.tests import _triplet_947 as T947  # noqa: E402
from defender.tests._branch_947 import (  # noqa: E402
    GOLDEN_INVESTIGATION, LEGACY_BRANCH_CALL, planted_source, spec_at,
)
from defender.tests._data_root_1078 import current_data_root  # noqa: E402
from defender.tests.e2e import _lead_zero_808 as LZ  # noqa: E402
from defender.tests.e2e import _replay_harness as H  # noqa: E402
from defender.tests.live_oracle_1224 import _spec1224 as S  # noqa: E402
from defender.tests.tenant_1078_pass_a import _spec1078 as H78  # noqa: E402
from defender.tests.tenant_1107_settings import _spec1107 as S7  # noqa: E402
from defender.tests.tenant_1107_settings.test_1107_lead_zero_replay import (  # noqa: E402
    _identity_worlds,
    _plant_at_data_root,
    _resume_argv,
    _sibling_episode,
)

pytestmark = pytest.mark.e2e

TENANT_ID = "acme-sibling"
HOST = "web-1"
LEAD = "l-001"
#: What the family's base recording answers for `cmdb.get-host {host: web-1}`.
CAPTURE_MARK = "FD1256-CAPTURED-OWNER-OF-WEB-1"
#: The key the sibling's settings lose between the source run and the branch.
DROPPED = "CMDB_URL_BASE"


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
                      branch_message_id=spec.branch_message_id)
    capture = S.captured("cmdb", "get-host", {"host": HOST},
                         {"host": HOST, "owner": CAPTURE_MARK})
    return S.episode_v2(where, doc=doc, root=where / "episodes", base_rows=[capture])


def _sibling(tmp_path: Path, label: str, *, accepted: Any, spec: Any, source_dir: Path,
             ) -> dict[str, Any]:
    """Start one sibling of world `a` at the branch point: resolve its tenant NOW (its own
    start), build its world registry as `run.main` does, and drive the real driver resumed. MAIN
    dispatches one lead on elastic (configured in both siblings, so the lead runs and its first
    prompt carries the system index the resumed run rebuilds); the lead asks `list_verbs(cmdb)`,
    then `cmdb.get-host {host: web-1}`, then summarises."""
    run_py = S.mod("run")
    ep = _episode(tmp_path / f"ep-{label}", spec, source_dir)
    world = S.load_world(ep, "a")
    tenant = run_py._resolve_run_tenant(accepted, defender_dir=S.DEFENDER,
                                        dispatches_lead_zero=False)
    source = Run.under(source_dir.parent, source_dir.name)
    sibling_dir = LZ.materialize_alert(tmp_path / f"sibling-{label}", LZ.alert_doc())
    main = H.ReplayFn([
        H.Turn(tool_calls=[("gather", {"lead_id": LEAD, "system": "elastic",
                                       "goal": "who owns web-1",
                                       "what_to_summarize": ["web-1's owner"]})]),
        H.Turn(text="Resumed and stopping."),
    ])
    gather = H.ReplayFn([
        H.Turn(tool_calls=[("list_verbs", {"system": "cmdb"})]),
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


def _answer(seen: list[str], request: int) -> str:
    """The lines the gather model's request `request` carries that its previous one did not —
    the host's answer to the previous turn's call."""
    shown = set(seen[request - 1].splitlines())
    return "\n".join(ln for ln in seen[request].splitlines() if ln not in shown)


def _down_lines(text: str) -> list[str]:
    """The lines of `text` naming cmdb (as a word) as not configured with the dropped key."""
    return [ln for ln in text.splitlines()
            if re.search(r"(?<![\w-])cmdb(?![\w-])", ln) and "not configured" in ln.lower()
            and DROPPED in ln]


def _cmdb_query_rows(sib: dict[str, Any]) -> list[dict]:
    return [r for r in S.read_jsonl(Path(RunPaths(sib["dir"]).executed_queries))
            if r.get("system") == "cmdb"]


def test_o9_a_sibling_judges_its_own_settings_not_the_captures(tmp_path: Path) -> None:
    """A system configured when the source ran but not at the sibling's start is down in that sibling: its call is refused without being answered from the source run's capture, the agent is told 'not configured' and why, and nothing is charged. The same sibling with the system configured is answered from the capture.

    The resumed sibling's surfaces carry the status (the design's resume non-obligation: "the rebuilt gather index, `list_verbs`, and dispatch refusals carry the down status"; adversary A3): the lead's first prompt — the system index the resumed run builds — and its `list_verbs(cmdb)` answer each name cmdb not configured with the dropped key. In the configured sibling neither does, and `list_verbs(cmdb)` lists cmdb's verbs."""
    knowledge, accepted = _plant_tenant()
    store, source_dir, _session, path_ids = planted_source(
        tmp_path / "source", investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    spec = spec_at(store, source_dir, path_ids[LEGACY_BRANCH_CALL])

    # Control: settings unchanged since the source run — the capture answers the call.
    configured = _sibling(tmp_path, "configured", accepted=accepted, spec=spec,
                          source_dir=source_dir)
    gather_saw = "\n".join(configured["gather"].seen)
    assert CAPTURE_MARK in gather_saw, (
        "premise: the configured sibling's call was not answered from the source run's capture "
        f"(the gather agent saw {len(configured['gather'].seen)} requests)")
    assert _served_cmdb(configured), (
        "premise: the configured sibling's world ledger records no served cmdb call")
    seen = configured["gather"].seen
    assert len(seen) >= 3, f"premise: the configured sibling's lead ran its script: {len(seen)}"
    assert _down_lines(seen[0]) == [], (
        "control: the configured sibling's system index shows cmdb as not configured")
    assert _down_lines(_answer(seen, 1)) == [], (
        "control: the configured sibling's list_verbs(cmdb) shows cmdb as not configured")
    assert "get-host" in _answer(seen, 1), (
        f"control: list_verbs(cmdb) in the configured sibling lists its verbs: "
        f"{_answer(seen, 1)!r}")

    # The operator edits the tenant's settings after the source run, before the branch.
    S7.drop_key(knowledge, "cmdb", DROPPED)
    down = _sibling(tmp_path, "down", accepted=accepted, spec=spec, source_dir=source_dir)
    assert DROPPED not in down["tenant"].systems.get("cmdb", {}), (
        "premise: the sibling's own start did not resolve the edited settings")

    seen = down["gather"].seen
    assert len(seen) >= 2, (
        f"premise: the down sibling's lead on elastic ran (its gather model was asked "
        f"{len(seen)} times)")
    assert _down_lines(seen[0]), (
        "the resumed sibling's rebuilt system index (the lead's first prompt) does not name "
        f"cmdb as not configured with {DROPPED} on any line (resume non-obligation, O-3)")
    assert _down_lines(_answer(seen, 1)), (
        f"list_verbs(cmdb) in the resumed sibling does not name cmdb not configured with "
        f"{DROPPED}: {_answer(seen, 1)!r}")

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


# --- O-8 x O-9: every granted system down at the sibling's start -----------------------------------

#: Every system the playground tenant's table (`TABLE_A`) grants gather, with a key its adapter's
#: settings check requires; dropping one makes that system not configured.
ALL_DOWN = (("cmdb", "CMDB_URL_BASE"), ("elastic", "ELASTICSEARCH_URL"))


def _episode_census(episode: Path) -> dict[str, bytes]:
    """What a sibling could leave in its episode: every recording (`*.jsonl`, the world ledgers
    and the base recording) by content, and every entry of its run container."""
    rows = {str(p.relative_to(episode)): p.read_bytes() for p in sorted(episode.rglob("*.jsonl"))}
    runs = episode / "runs"
    entries = {f"runs/{p.name}": b"" for p in sorted(runs.iterdir())} if runs.is_dir() else {}
    return {**rows, **entries}


def _resume(tmp_path: Path, label: str, source: Path, monkeypatch: Any,
            down: tuple[tuple[str, str], ...],
            ) -> tuple[Any, Any, Any, Path, dict[str, bytes]]:
    """Plant the playground tenant afresh with `down`'s keys dropped, open a family over the
    source run, and start sibling `b` through `run.main`. Returns (rc, refusal, recorder,
    episode, the episode's census before the sibling started)."""
    _root, folder, _tenant = _plant_at_data_root(f"o8o9{label}")
    for system, key in down:
        S7.drop_key(folder, system, key)
    doc = T947.family_doc(source_run_dir=str(source), worlds=_identity_worlds())
    episode = _sibling_episode(tmp_path, doc, root=tmp_path / f"episodes-{label}",
                               monkeypatch=monkeypatch)
    before = _episode_census(episode)
    rec = S7.RunRecorder(tmp_path / f"sibling-{label}")
    rc, refused = S7.drive_run(_resume_argv(episode / "family.yaml"), rec,
                               visualize=rec.visualize)
    return rc, refused, rec, episode, before


def test_o8_o9_a_sibling_with_every_granted_system_down_at_its_start_is_refused(
        tmp_path: Path, data_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A branch sibling whose own settings leave every granted system down is refused at its start, naming each system and its reason, before its run exists and before its world (which would answer from the source run's capture) is built. With one system configured the same sibling resumes."""
    _base, source = H78.tenant_source(data_root, S7.PLAYGROUND_ID)

    rc, refused, rec, _episode_dir, _before = _resume(
        tmp_path, "one-up", source, monkeypatch, down=ALL_DOWN[1:])
    assert refused is None, (
        f"control: the sibling with cmdb configured was refused: {H78.refusal_text(refused)}")
    assert "lifecycle" in rec.order, f"control: the sibling never ran (rc={rc}, {rec.order})"

    rc, refused, rec, episode, before = _resume(
        tmp_path, "all-down", source, monkeypatch, down=ALL_DOWN)
    assert refused is not None, (
        f"the sibling started though every granted system is down at its start (rc={rc}, "
        f"seams reached: {rec.order}) — #1256 O-8 holds for a sibling's own start (O-9)")
    text = H78.refusal_text(refused)
    for system, key in ALL_DOWN:
        assert re.search(rf"(?<![\w-]){system}(?![\w-])", text, re.IGNORECASE), (
            f"the sibling's refusal does not name the down system {system}: {text!r}")
        assert key in text, f"the sibling's refusal does not name {system}'s reason ({key}): {text!r}"
    assert "not configured" in text.lower(), f"the refusal does not name the cause: {text!r}"
    reached = [seam for seam in ("materialize", "lifecycle") if seam in rec.order]
    assert reached == [], f"the refused sibling reached {reached} before refusing: {rec.order}"
    assert rec.lifecycle_calls == [], "the refused sibling's world was built"
    assert _episode_census(episode) == before, (
        "the refused sibling left recordings or a run in its episode: "
        f"{sorted(set(_episode_census(episode)) ^ set(before))}")
