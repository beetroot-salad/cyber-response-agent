"""run_common.materialize_run: the runs base follows from the tenant; record mismatch, torn record, missing row and sibling-base refusals."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
import os
import sys
from pathlib import Path
from defender.run_repository import RunPaths
from typing import Any

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H
from defender.episodes._episode_handle import Episode  # noqa: E402

T_ID = H.VALID_ID


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
    """A pass-(A) episode (under the OLD episodes base, outside the data root) whose manifest
    names a source at T's tenant location, and the `ResumeWorld` a sibling resolves from it.
    `family` passes through to `H.family_for` (#1105 PR 2: the container the launcher makes
    with T's record is planted unless `container=None`)."""
    _base, src = H.tenant_source(root, T_ID, row=False)
    ep = tmp_path / "episodes" / T.EPISODE_ID
    manifest = H.family_for(src, ep, **family)
    world = H.run_py().resume_world(
        Episode.open(manifest.parent), label,
        tenant=lambda: H.T1106.run_tenant(H.accept(root, T_ID)))
    return src, ep, world


def test_o4_materialize_layout(tmp_path, tenant_root):
    run_dir = _materialize(H.plant_alert(tmp_path / "in"), "r1", T_ID)
    expected = tenant_root / T_ID / "runs" / "r1"
    assert Path(run_dir) == expected
    assert expected.is_dir()
    record = json.loads((tenant_root / T_ID / "runs" / H.RECORD_NAME).read_text(encoding="utf-8"))
    assert record["tenant_id"] == T_ID
    assert _stamp(expected)["tenant_id"] == T_ID


def test_o4_run_store_location(tmp_path, tenant_root):
    """A fresh run under <root>/T/runs/ keeps its session store at
    <root>/T/sessions/<case>.db."""
    run_dir = Path(_materialize(_golden_alert(tmp_path), "r1", T_ID))
    _replay(run_dir)
    store = H.mod("runtime.session_store").resolve_store_path(_run_handle_1165(run_dir))
    assert store.parent == tenant_root / T_ID / "sessions", f"the store is at {store}"
    assert store.suffix == ".db"
    assert store.is_file()


def test_d2_only_sessions_beside_base(tmp_path, tenant_root):
    """A materialize writes nothing into <root>/T/ beside runs/ except sessions/, and the
    tenant.json there exists because setup wrote it."""
    row_bytes = H.row_path(tenant_root, T_ID).read_bytes()
    run_dir = Path(_materialize(_golden_alert(tmp_path), "r1", T_ID))
    # `knowledge/` is the operator's (#1120 DC2: placed before setup), never materialize's.
    assert H.entries(tenant_root / T_ID) == sorted([H.ROW_NAME, "knowledge", "runs"]), (
        "materialize wrote beside runs/")
    _replay(run_dir)
    assert H.entries(tenant_root / T_ID) == sorted([H.ROW_NAME, "knowledge", "runs",
                                                     "sessions"])
    assert H.entries(tenant_root) == [T_ID]
    assert H.row_path(tenant_root, T_ID).read_bytes() == row_bytes, "the row was rewritten"


def test_o2_materialize_never_creates_row(tmp_path, monkeypatch):
    root = tmp_path / "data"
    root.mkdir()
    H.set_data_root(monkeypatch, root)
    alert = H.plant_alert(tmp_path / "in")
    text = _refused(lambda: _materialize(alert, "r1", T_ID))
    H.assert_verbatim(text, H.owner_refusal(H.require_tenant, root, T_ID),
                      entry="materialize_run")
    assert H.entries(root) == [], "the refused materialize created something"

    H.make_tenant(root, T_ID)
    row_bytes = H.row_path(root, T_ID).read_bytes()
    _materialize(alert, "r1", T_ID)
    assert H.row_path(root, T_ID).read_bytes() == row_bytes


def test_o6_record_mismatch_refused(tmp_path, tenant_root):
    base = tenant_root / T_ID / "runs"
    record = H.plant_record(base, "someone-else")
    before = record.read_bytes()
    text = _refused(lambda: _materialize(H.plant_alert(tmp_path / "in"), "r1", T_ID))
    H.assert_verbatim(text, H.owner_refusal(H.ensure_runs_base_record, base, T_ID),
                      entry="materialize_run")
    assert record.read_bytes() == before, "the disagreeing record was relabelled"
    assert H.entries(base) == [H.RECORD_NAME], "the refused materialize created a run dir"


@pytest.mark.parametrize("body", ["", '{"tenant_id": "playgr'], ids=["empty", "truncated"])
def test_torn_runs_base_record_under_the_tenant(tmp_path, tenant_root, body):
    base = tenant_root / T_ID / "runs"
    record = H.plant_record(base, T_ID, body=body)
    alert = H.plant_alert(tmp_path / "in")
    for run_id in ("r1", "r2"):
        text = _refused(lambda rid=run_id: _materialize(alert, rid, T_ID))
        H.assert_verbatim(text, H.owner_refusal(H.ensure_runs_base_record, base, T_ID),
                          entry="materialize_run")
        assert record.read_bytes() == body.encode("utf-8"), "the torn record was re-minted"
    record.unlink()
    _materialize(alert, "r3", T_ID)
    assert json.loads(record.read_text(encoding="utf-8"))["tenant_id"] == T_ID


def test_tenant_row_deleted_mid_materialize(tmp_path, tenant_root):
    """The row is checked once, at step 1; a row removed after it does not stop the later
    steps (no re-check within the call)."""
    row = H.row_path(tenant_root, T_ID)
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
        run_dir = Path(_materialize(alert, "r1", T_ID))
    finally:
        sys.setprofile(previous)
    assert fired, "the pipeline never ran defender.tenancy._tenant.accept_tenant (D2 step 1)"
    assert not row.exists()
    assert run_dir == tenant_root / T_ID / "runs" / "r1"
    assert run_dir.is_dir()
    assert _stamp(run_dir)["tenant_id"] == T_ID


def test_d2_sibling_runs_base(tmp_path, tenant_root):
    src, ep, world_b = _sibling_world(tmp_path, tenant_root, "b", container=None)
    world_c = H.run_py().resume_world(
        Episode.open(ep), "c", tenant=lambda: H.T1106.run_tenant(H.accept(tenant_root, T_ID)))
    alert = RunPaths(src).alert
    with Episode.open(ep) as episode:
        view = H.accept(tenant_root, T_ID).runs_repository().episode(ep.name, held=episode)
        assert view.state == "absent"
        _refused(lambda: _materialize(alert, world_b.run_id, T_ID, world=world_b,
                                      episode_runs=view))
        assert not (ep / "runs").exists(), "a sibling's run setup made the episode container"
        view.create_container()
        record_path = ep / "runs" / H.RECORD_NAME
        minted = json.loads(record_path.read_text(encoding="utf-8"))
        rb = Path(_materialize(alert, world_b.run_id, T_ID, world=world_b, episode_runs=view))
        rc = Path(_materialize(alert, world_c.run_id, T_ID, world=world_c, episode_runs=view))
    assert rb == ep / "runs" / world_b.run_id
    assert rc == ep / "runs" / world_c.run_id
    assert minted["tenant_id"] == T_ID
    assert json.loads(record_path.read_text(encoding="utf-8")) == minted, "the record changed"
    assert _stamp(rb)["world_id"] in (None, H.mod("tenancy._tenant").read_tenant(src.parent).base_world_id)
    # #1235 F2: the source run's case link is a host sidecar beside its run dir.
    assert H.entries(tenant_root / T_ID / "runs") == sorted(
        [H.RECORD_NAME, src.name, RunPaths(src).session_pointer().name])


def test_s7_j24_widened_refusal_on_sibling_path(tmp_path, monkeypatch, tenant_root):
    src, ep, world = _sibling_world(tmp_path, tenant_root, "b", monkeypatch=monkeypatch)
    alert = RunPaths(src).alert
    argv = H.sibling_argv(ep / "family.yaml", "b", "--tenant", T_ID)
    with Episode.open(ep) as episode:
        view = H.accept(tenant_root, T_ID).runs_repository().episode(
            ep.name, held=episode, container_required=True)
        for n, learning in enumerate((tenant_root, tenant_root / T_ID / "learning", tmp_path)):
            monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(learning))
            widened = H.owner_refusal(H.resolve_data_root)
            _rc, refused = H.drive_main(argv, H.Recorder(tmp_path / f"sib-{n}"))
            assert refused is not None, "the sibling's entry accepted a widened learning root"
            H.assert_verbatim(H.refusal_text(refused), widened,
                              entry="the sibling's entry (run.py --episode)")
            text = _refused(lambda: _materialize(alert, world.run_id, T_ID, world=world,
                                                 episode_runs=view))
            H.assert_verbatim(text, widened, entry="the sibling's materialize_run")
            assert not (ep / "runs" / world.run_id).exists()
        monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR",
                           str(tmp_path.parent / "elsewhere-learning"))
        rc, refused = H.drive_main(argv, H.Recorder(tmp_path / "sib-ok"))
        assert refused is None, H.refusal_text(refused)
        assert rc == 0, rc
        assert Path(_materialize(alert, world.run_id, T_ID, world=world,
                                 episode_runs=view)).is_dir()


def test_o6_old_run_id_fresh_under_tenant(tmp_path, monkeypatch, tenant_root):
    """--run-id X --tenant T while an old run X sits in another base materializes a fresh
    <root>/T/runs/X and leaves the old X untouched."""
    old = tmp_path / "defender-runs"
    H.plant_record(old, "default")
    (old / "x").mkdir()
    (old / "x" / "report.md").write_text("an old-layout run\n", encoding="utf-8")
    (old / "x" / "alert.json").write_text('{"old": true}\n', encoding="utf-8")
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(old))
    before = H.census(old)
    run_dir = Path(_materialize(H.plant_alert(tmp_path / "in"), "x", T_ID))
    assert run_dir == tenant_root / T_ID / "runs" / "x"
    paths = H.mod("run_repository._layout").RunPaths(run_dir)
    assert set(os.listdir(run_dir)) == {paths.alert_input_dir.name, paths.gather_raw.name,
                                        paths.provenance.name}, "not a fresh setup"
    assert H.census(old) == before, "the old run X was touched"
