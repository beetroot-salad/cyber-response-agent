"""run_common.materialize_run: the runs base follows from the tenant; record mismatch, torn record, missing row and sibling-base refusals."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
import os
import sys
from pathlib import Path
from defender.run_repository import RunPaths
from typing import Any

import pytest

from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H
from defender.episodes._episode_handle import Episode  # noqa: E402

T_ID = H.VALID_ID
R1 = fixture_uuid("r1")
X = fixture_uuid("case-x")


def _materialize(alert: Path, run_id: str | None, tenant_id: str, **kw):
    """The entry's pipeline (#1120 D1): resolve the data root and accept `tenant_id` there
    (`accept_tenant` — the row check pass (A) made materialize's step 1 now runs here, at the
    entry), then `materialize_run(tenant=...)` over the accepted `Tenant`."""
    tenant = H.accept(H.resolve_data_root(), tenant_id)
    return H.run_common().materialize_run(alert, run_id, tenant=tenant, **kw).run_dir


def _refused(fn) -> str:
    """Drive `fn` and hand back its refusal's text — a `sys.exit(msg)` or the owner's
    `TenantRefused` propagating. Anything else escaping (or nothing raised) fails the test."""
    try:
        fn()
    except SystemExit as exc:
        return H.refusal_text(exc)
    except H.tenant().TenantRefused as exc:
        return str(exc)
    raise AssertionError("materialize_run was not refused")


@pytest.fixture
def tenant_root(tmp_path, monkeypatch) -> Path:
    """A data root under this test's tmp dir, holding T (created through the real owner)."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, T_ID)
    return root


def _stamp(run_dir: Path) -> dict:
    return json.loads((run_dir / "provenance.json").read_text(encoding="utf-8"))


def _closing_turns():
    from defender.tests.e2e._replay_harness import GOLDEN, Turn

    return [
        Turn(tool_calls=[("append_block", {"text": (GOLDEN / "investigation.md").read_text()})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "inconclusive"})]),
        Turn(text="Investigation complete."),
    ]


def _replay(run_dir: Path) -> None:
    """The REAL driver over `run_dir`, hermetic, through the project's replay harness."""
    pytest.importorskip("pydantic_ai")
    from defender.tests.e2e._replay_harness import ReplayFn, drive

    drive(run_dir, run_id=run_dir.name, main=ReplayFn(_closing_turns()))


def _golden_alert(tmp_path: Path) -> Path:
    from defender.tests.e2e._replay_harness import GOLDEN

    alert = tmp_path / "golden" / "alert.json"
    alert.parent.mkdir(parents=True, exist_ok=True)
    alert.write_bytes((GOLDEN / "alert.json").read_bytes())
    return alert


def _sibling_world(tmp_path: Path, root: Path, label: str = "b", **family: Any):
    """An episode at `<root>/<T>/episodes/<uuid>` (#1187 Layout A) whose manifest names a
    source at T's tenant location, and the `ResumeWorld` a sibling resolves from it. `family`
    passes through to `H.family_for` (#1187 R2: the episode as RUNS leaves it — `runs/` and the
    arm roster — unless `roster=False`). No container record (R1)."""
    del tmp_path
    _base, src = H.tenant_source(root, T_ID, row=False)
    manifest = H.family_for(src, **family)
    ep = manifest.parent
    world = H.run_py().resume_world(
        Episode.open(manifest.parent), label,
        tenant=lambda: H.T1106.run_tenant(H.accept(root, T_ID)))
    return src, ep, world


def test_o4_materialize_layout(tmp_path, tenant_root):
    import uuid

    pinned = str(uuid.uuid4())
    run_dir = _materialize(H.plant_alert(tmp_path / "in"), pinned, T_ID)
    expected = tenant_root / T_ID / "runs" / pinned
    assert Path(run_dir) == expected
    assert expected.is_dir()
    assert not (tenant_root / T_ID / "runs" / H.RECORD_NAME).exists(), (
        "run setup wrote the retired runs-base record")
    assert _stamp(expected)["tenant_id"] == T_ID


def test_o4_run_store_location(tmp_path, tenant_root):
    run_dir = Path(_materialize(_golden_alert(tmp_path), R1, T_ID))
    _replay(run_dir)
    store = H.mod("runtime.session_store").resolve_store_path(_run_handle_1165(run_dir))
    assert store.parent == tenant_root / T_ID / "sessions", f"the store is at {store}"
    assert store.suffix == ".db"
    assert store.is_file()


def test_d2_only_sessions_beside_base(tmp_path, tenant_root):
    from defender.tests.support.tenancy._launch_publish_p4 import forge_scratch
    from defender.tests.tenancy.tenant_1108_p4._support import publish_once

    row_bytes = location_path(H.row_path)(tenant_root, T_ID).read_bytes()
    # #1108 P4 (O11): a run reads a PUBLISHED export, and the replay harness publishes the
    # tenant (unchanged folder: the same commit, into the same remote) before it drives. What
    # publishing leaves in the tenant folder is the publish's (P3), not the run's: it is taken
    # here, up front, as the baseline, so the listings below still pin that materialize and
    # the driver add nothing beside `runs/` but `sessions/`.
    publish_once(forge_scratch(tenant_root), root=tenant_root, tenant_id=T_ID)
    published = set(H.entries(tenant_root / T_ID))
    assert {H.ROW_NAME, "knowledge"} <= published, published
    assert not published & {"runs", "sessions"}, published
    run_dir = Path(_materialize(_golden_alert(tmp_path), R1, T_ID))
    # `knowledge/` is the operator's (#1120 DC2: placed before setup), never materialize's.
    assert H.entries(tenant_root / T_ID) == sorted(published | {"runs"}), (
        "materialize wrote beside runs/")
    _replay(run_dir)
    assert H.entries(tenant_root / T_ID) == sorted(published | {"runs", "sessions"})
    assert H.entries(tenant_root) == [T_ID]
    assert location_path(H.row_path)(tenant_root, T_ID).read_bytes() == row_bytes, "the row was rewritten"


def test_o2_materialize_never_creates_row(tmp_path, monkeypatch):
    root = tmp_path / "data"
    root.mkdir()
    H.set_data_root(monkeypatch, root)
    alert = H.plant_alert(tmp_path / "in")
    text = _refused(lambda: _materialize(alert, R1, T_ID))
    H.assert_verbatim(text, H.owner_refusal(H.require_tenant, root, T_ID),
                      entry="materialize_run")
    assert H.entries(root) == [], "the refused materialize created something"

    H.make_tenant(root, T_ID)
    row_bytes = location_path(H.row_path)(root, T_ID).read_bytes()
    _materialize(alert, R1, T_ID)
    assert location_path(H.row_path)(root, T_ID).read_bytes() == row_bytes


def test_tenant_row_deleted_mid_materialize(tmp_path, tenant_root):
    row = location_path(H.row_path)(tenant_root, T_ID)
    fired: list[str] = []

    def hook(frame, event, _arg):
        if (event == "return" and not fired and frame.f_code.co_name == "accept_tenant"
                and frame.f_globals.get("__name__") == "defender.tenancy._tenant"):
            row.unlink()
            fired.append("row removed")

    alert = H.plant_alert(tmp_path / "in")
    previous = sys.getprofile()
    sys.setprofile(hook)
    try:
        run_dir = Path(_materialize(alert, R1, T_ID))
    finally:
        sys.setprofile(previous)
    assert fired, "the pipeline never ran defender.tenancy._tenant.accept_tenant (D2 step 1)"
    assert not row.exists()
    assert run_dir == tenant_root / T_ID / "runs" / R1
    assert run_dir.is_dir()
    assert _stamp(run_dir)["tenant_id"] == T_ID


def test_d2_sibling_runs_base(tmp_path, tenant_root):
    src, ep, world_b = _sibling_world(tmp_path, tenant_root, "b")
    world_c = H.run_py().resume_world(
        Episode.open(ep), "c", tenant=lambda: H.T1106.run_tenant(H.accept(tenant_root, T_ID)))
    arm_b, arm_c = H.T.roster_arm_id(ep, H.T.world_id(ep, "b")), H.T.roster_arm_id(ep, H.T.world_id(ep, "c"))
    alert = RunPaths(src).alert
    with Episode.open(ep) as episode:
        view = H.accept(tenant_root, T_ID).runs_repository().episode(ep.name, held=episode)
        rb = Path(_materialize(alert, arm_b, T_ID, world=world_b, episode_runs=view))
        rc = Path(_materialize(alert, arm_c, T_ID, world=world_c, episode_runs=view))
    assert rb == ep / "runs" / arm_b
    assert rc == ep / "runs" / arm_c
    assert _stamp(rb).get("world_id") is None
    assert _stamp(rc).get("world_id") is None
    assert not (ep / "runs" / H.RECORD_NAME).exists()
    assert H.entries(tenant_root / T_ID / "runs") == sorted(
        [src.name, RunPaths(src).session_pointer().name])


@pytest.mark.parametrize("state_location", ["root", "inside", "ancestor", "disjoint"])
def test_1186_sibling_ignores_legacy_state_override(
        tmp_path, monkeypatch, tenant_root, state_location):
    src, ep, world = _sibling_world(tmp_path, tenant_root, "b")
    alert = RunPaths(src).alert
    # #1187 (review-4 F42): the arm's id is the one the roster holds for its label, never the
    # world's composed `run_id` (design: `ResumeWorld.run_id` is deleted or the roster's).
    arm_id = H.T.roster_arm_id(ep, H.T.world_id(ep, "b"))
    argv = H.sibling_argv(ep / "family.yaml", "b", "--tenant", T_ID)
    with Episode.open(ep) as episode:
        # #1187 (O4b): the sibling's form requires its UUID roster (`require_roster=True`, replacing
        # PR 2's `container_required`).
        view = H.accept(tenant_root, T_ID).runs_repository().episode(
            ep.name, held=episode, require_roster=True)
        learning = {"root": tenant_root, "inside": tenant_root / T_ID / "learning",
                    "ancestor": tmp_path, "disjoint": tmp_path.parent / "elsewhere-learning"}[
                        state_location]
        monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(learning))
        assert H.resolve_data_root() == tenant_root.resolve()
        rc, refused = H.drive_main(argv, H.Recorder(tmp_path / "sib-ok"))
        assert refused is None, H.refusal_text(refused)
        assert rc == 0, rc
        assert Path(_materialize(alert, arm_id, T_ID, world=world,
                                 episode_runs=view)).is_dir()


def test_o6_old_run_id_fresh_under_tenant(tmp_path, monkeypatch, tenant_root):
    old = tmp_path / "defender-runs"
    H.plant_record(old, "default")
    (old / X).mkdir()
    (old / X / "report.md").write_text("an old-layout run\n", encoding="utf-8")
    (old / X / "alert.json").write_text('{"old": true}\n', encoding="utf-8")
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(old))
    before = H.census(old)
    run_dir = Path(_materialize(H.plant_alert(tmp_path / "in"), X, T_ID))
    assert run_dir == tenant_root / T_ID / "runs" / X
    paths = H.mod("run_repository._layout").RunPaths(run_dir)
    assert set(os.listdir(run_dir)) == {paths.alert_input_dir.name, paths.gather_raw.name,
                                        paths.provenance.name}, "not a fresh setup"
    assert H.census(old) == before, "the old run X was touched"
