"""#1078 pass (A) — `run_common.materialize_run_dir(alert, run_id, *, tenant_id, model, world)`
(D2, O2, O4, O6): the runs base follows from the tenant.

D2's order, which every test here observes from the outside:
  1. `require_tenant` — the row exists;
  2. the runs base: `runs_base_for(T)`, or `EpisodePaths(world.episode_dir).runs` for a sibling;
  3. `guarded_mkdir`;
  4. `ensure_runs_base_record` — mint with T, or read back and refuse on disagreement (§7 J34:
     THIS is the guard that fires in the sequential case, record bytes unchanged);
  5. `Run.for_tenant` — the race backstop (pinned directly in `test_1078_records.py`).

Driven directly, with `DEFENDER_DATA_ROOT` pointed at a tmp root and the tenant made by the REAL
`create_tenant` (D10: fixtures call it against a fresh tmp root). Refusals are observed as the
owner's own refusal passed through verbatim (demand #0); every fault — the disagreeing and torn
records, the stale `DEFENDER_RUNS_BASE`, the used run id, the row removed mid-call — is a real
input on the real filesystem.

The two replay-driven tests (`o4_run_store_location`, `d2_only_sessions_beside_base`) run the
REAL driver over the materialized run dir through `tests/e2e/_replay_harness.drive` — the
project's harness — so the session store lands where the run itself opens it.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from defender.tests import _triplet_947 as T
from defender.tests.tenant_1078_pass_a import _spec1078 as H

T_ID = H.VALID_ID


def _materialize(alert: Path, run_id: str | None, tenant_id: str, **kw):
    return H.run_common().materialize_run_dir(alert, run_id, tenant_id=tenant_id, **kw)


def _refused(fn) -> str:
    """Drive `fn` and hand back its refusal's text — a `sys.exit(msg)` or the owner's
    `ValueError` propagating. Anything else escaping (or nothing raised) fails the test."""
    try:
        fn()
    except SystemExit as exc:
        return H.refusal_text(exc)
    except ValueError as exc:
        return str(exc)
    raise AssertionError("materialize_run_dir was not refused")


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


def _sibling_world(tmp_path: Path, root: Path, label: str = "b"):
    """A pass-(A) episode (under the OLD episodes base, outside the data root) whose manifest
    names a source at T's tenant location, and the `ResumeWorld` a sibling resolves from it."""
    _base, src = H.tenant_source(root, T_ID, row=False)
    ep = tmp_path / "episodes" / T.EPISODE_ID
    manifest = H.family_for(src, ep)
    world = H.run_py().resume_world(manifest, label)
    return src, ep, world


# ======================================================================================
# Layout (O4) and the stamp
# ======================================================================================

def test_o4_materialize_layout(tmp_path, tenant_root):
    """materialize_run_dir(alert, 'r1') with its tenant_id keyword set to T creates <root>/T/runs/r1/, the runs-base
    record <root>/T/runs/_tenant.json names T, and the run's provenance stamp carries
    tenant_id T."""
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
    store = H.mod("runtime.session_store").resolve_store_path(run_dir)
    assert store.parent == tenant_root / T_ID / "sessions", f"the store is at {store}"
    assert store.suffix == ".db"
    assert store.is_file()


def test_d2_only_sessions_beside_base(tmp_path, tenant_root):
    """A materialize writes nothing into <root>/T/ beside runs/ except sessions/, and the
    tenant.json there exists because setup wrote it.

    Materialize and a real replayed run over it (which opens the store): `<root>/T/` then holds
    exactly the row, `runs/` and `sessions/`, the row byte-identical to what create_tenant
    wrote, and the data root holds T alone."""
    row_bytes = H.row_path(tenant_root, T_ID).read_bytes()
    run_dir = Path(_materialize(_golden_alert(tmp_path), "r1", T_ID))
    assert H.entries(tenant_root / T_ID) == sorted([H.ROW_NAME, "runs"]), (
        "materialize wrote beside runs/")
    _replay(run_dir)
    assert H.entries(tenant_root / T_ID) == sorted([H.ROW_NAME, "runs", "sessions"])
    assert H.entries(tenant_root) == [T_ID]
    assert H.row_path(tenant_root, T_ID).read_bytes() == row_bytes, "the row was rewritten"


def test_d9_run_dir_file_set_unchanged(tmp_path, tenant_root):
    """The run-dir file-set pins pass unchanged: materialize adds no file inside the run dir.

    A fresh materialize leaves exactly what setup writes — the owner's alert, gather_raw and
    provenance names — and beside the run dir only the runs-base record."""
    run_dir = Path(_materialize(H.plant_alert(tmp_path / "in"), "r1", T_ID))
    paths = H.mod("_run_paths").RunPaths(run_dir)
    assert set(H.entries(run_dir)) == {paths.alert.name, paths.gather_raw.name,
                                       paths.provenance.name}
    assert H.entries(run_dir.parent) == sorted([H.RECORD_NAME, "r1"])


def test_g_r7_family_base_world_id_coherence(tmp_path, tenant_root):
    """The fresh-run family's base_world_id read (run_common.py:159, tenant_record.base_world_id)
    is unaffected by which tenant_id the record now carries — read off a record minted under
    pass (A)'s new derivation, base_world_id still round-trips into the stamp unchanged.

    Two fresh runs of T share the base's one base_world_id, and the launcher's own reader of
    it (`learning/branch/cli._family_base_world_id`) answers the same value."""
    alert = H.plant_alert(tmp_path / "in")
    r1 = Path(_materialize(alert, "r1", T_ID))
    r2 = Path(_materialize(alert, "r2", T_ID))
    record = json.loads((r1.parent / H.RECORD_NAME).read_text(encoding="utf-8"))
    assert record["tenant_id"] == T_ID
    assert _stamp(r1)["world_id"] == _stamp(r2)["world_id"] == record["base_world_id"]
    assert H.branch_cli()._family_base_world_id({"a": r1}) == record["base_world_id"]


# ======================================================================================
# Refusals: the row (O2), the order (D2), the record (O6)
# ======================================================================================

def test_o2_materialize_never_creates_row(tmp_path, monkeypatch):
    """materialize_run_dir with its tenant_id keyword set to T, with no row for T is refused before creating anything
    and never writes <root>/T/tenant.json; after a successful materialize for an existing T
    the row is byte-identical."""
    root = tmp_path / "data"
    root.mkdir()
    H.set_data_root(monkeypatch, root)
    alert = H.plant_alert(tmp_path / "in")
    text = _refused(lambda: _materialize(alert, "r1", T_ID))
    H.assert_verbatim(text, H.owner_refusal(H.require_tenant, root, T_ID),
                      entry="materialize_run_dir")
    assert H.entries(root) == [], "the refused materialize created something"

    H.make_tenant(root, T_ID)
    row_bytes = H.row_path(root, T_ID).read_bytes()
    _materialize(alert, "r1", T_ID)
    assert H.row_path(root, T_ID).read_bytes() == row_bytes


def test_d2_materialize_order(tmp_path, monkeypatch):
    """materialize_run_dir runs require_tenant before creating anything, then the runs base,
    guarded_mkdir, ensure_runs_base_record and Run.for_tenant in that order, so an unknown
    tenant leaves no runs base.

    Observed as which refusal wins: (1) no row — nothing is created, no runs base; (2) no row
    over a base whose record names U — require_tenant's refusal, not the record's; (3) a row,
    and a record naming U — ensure_runs_base_record's refusal (step 4), not Run.for_tenant's
    (step 5), and no run dir; (4) the ordinary case — the runs base made, the record minted."""
    alert = H.plant_alert(tmp_path / "in")
    root = tmp_path / "unknown"
    root.mkdir()
    H.set_data_root(monkeypatch, root)
    _refused(lambda: _materialize(alert, "r1", T_ID))
    assert not (root / T_ID / "runs").exists(), "an unknown tenant left a runs base"

    root = tmp_path / "rowless"
    H.set_data_root(monkeypatch, root)
    H.plant_record(root / T_ID / "runs", "someone-else")
    text = _refused(lambda: _materialize(alert, "r1", T_ID))
    H.assert_verbatim(text, H.owner_refusal(H.require_tenant, root, T_ID),
                      entry="materialize_run_dir")

    root = tmp_path / "disagreeing"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, T_ID)
    base = root / T_ID / "runs"
    H.plant_record(base, "someone-else")
    text = _refused(lambda: _materialize(alert, "r1", T_ID))
    H.assert_verbatim(text, H.owner_refusal(H.ensure_runs_base_record, base, T_ID),
                      entry="materialize_run_dir")
    assert not (base / "r1").exists(), "the run dir was made before the record check"

    root = tmp_path / "ordinary"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, T_ID)
    _materialize(alert, "r1", T_ID)
    assert (root / T_ID / "runs" / H.RECORD_NAME).is_file()


def test_o6_record_mismatch_refused(tmp_path, tenant_root):
    """materialize_run_dir with its tenant_id keyword set to T, over a runs base whose record names U is refused by
    ensure_runs_base_record's disagreement refusal at materialize step 4, and the record still
    names U, byte-for-byte unmodified."""
    base = tenant_root / T_ID / "runs"
    record = H.plant_record(base, "someone-else")
    before = record.read_bytes()
    text = _refused(lambda: _materialize(H.plant_alert(tmp_path / "in"), "r1", T_ID))
    H.assert_verbatim(text, H.owner_refusal(H.ensure_runs_base_record, base, T_ID),
                      entry="materialize_run_dir")
    assert record.read_bytes() == before, "the disagreeing record was relabelled"
    assert H.entries(base) == [H.RECORD_NAME], "the refused materialize created a run dir"


@pytest.mark.parametrize("body", ["", '{"tenant_id": "playgr'], ids=["empty", "truncated"])
def test_torn_runs_base_record_under_the_tenant(tmp_path, tenant_root, body):
    """A torn or empty <T>/runs/_tenant.json refuses every later fresh run of T at materialize
    (ensure_runs_base_record reads it as corrupt); the record is never re-minted or overwritten
    (universal 4). No repair is designed; deleting it by hand re-mints base_world_id (C10)."""
    base = tenant_root / T_ID / "runs"
    record = H.plant_record(base, T_ID, body=body)
    alert = H.plant_alert(tmp_path / "in")
    for run_id in ("r1", "r2"):
        text = _refused(lambda rid=run_id: _materialize(alert, rid, T_ID))
        H.assert_verbatim(text, H.owner_refusal(H.ensure_runs_base_record, base, T_ID),
                          entry="materialize_run_dir")
        assert record.read_bytes() == body.encode("utf-8"), "the torn record was re-minted"
    record.unlink()
    _materialize(alert, "r3", T_ID)
    assert json.loads(record.read_text(encoding="utf-8"))["tenant_id"] == T_ID


def test_pre_a_process_with_the_old_knob_pointed_into_the_tenants_runs_base(tmp_path,
                                                                             tenant_root):
    """A <T>/runs/_tenant.json naming `default` (minted by pre-A code) refuses every pass-A run
    of T at materialize, and the record is left unchanged (O6, universal 4)."""
    base = tenant_root / T_ID / "runs"
    record = H.plant_record(base, "default")
    before = record.read_bytes()
    alert = H.plant_alert(tmp_path / "in")
    for run_id in ("r1", "r2"):
        text = _refused(lambda rid=run_id: _materialize(alert, rid, T_ID))
        H.assert_verbatim(text, H.owner_refusal(H.ensure_runs_base_record, base, T_ID),
                          entry="materialize_run_dir")
    assert record.read_bytes() == before
    assert H.entries(base) == [H.RECORD_NAME]


def test_tenant_row_deleted_mid_materialize(tmp_path, tenant_root):
    """require_tenant runs once, at materialize step 1; a row removed after it does not stop
    the later steps (no re-check within the call).

    The removal is the REAL unlink of the real row, timed to the instant the owner's
    `require_tenant` first returns inside the call (a profile hook on that return — no attribute
    is patched; the design names that step). The materialize then completes: the run dir and a
    stamp naming T."""
    row = H.row_path(tenant_root, T_ID)
    fired: list[str] = []

    def hook(frame, event, _arg):
        if (event == "return" and not fired and frame.f_code.co_name == "require_tenant"
                and frame.f_globals.get("__name__") == "defender._tenant"):
            row.unlink()
            fired.append("row removed")

    alert = H.plant_alert(tmp_path / "in")
    previous = sys.getprofile()
    sys.setprofile(hook)
    try:
        run_dir = Path(_materialize(alert, "r1", T_ID))
    finally:
        sys.setprofile(previous)
    assert fired, "materialize never ran defender._tenant.require_tenant (D2 step 1)"
    assert not row.exists()
    assert run_dir == tenant_root / T_ID / "runs" / "r1"
    assert run_dir.is_dir()
    assert _stamp(run_dir)["tenant_id"] == T_ID


# ======================================================================================
# The sibling's runs base (D2 step 2) and the widened refusal on that path (§7 J24)
# ======================================================================================

def test_d2_sibling_runs_base(tmp_path, tenant_root):
    """A sibling's materialize puts its run dir under EpisodePaths(world.episode_dir).runs and
    mints or reads that base's record for T.

    Two worlds of one pass-(A) episode: the first mints `<ep>/runs/_tenant.json` naming T, the
    second reads it (one base_world_id), and neither lands under `<root>/T/runs/` (O4's gap
    until (B))."""
    src, ep, world_b = _sibling_world(tmp_path, tenant_root, "b")
    world_c = H.run_py().resume_world(ep / "family.yaml", "c")
    alert = src / "alert.json"
    rb = Path(_materialize(alert, world_b.run_id, T_ID, world=world_b))
    record_path = ep / "runs" / H.RECORD_NAME
    minted = json.loads(record_path.read_text(encoding="utf-8"))
    rc = Path(_materialize(alert, world_c.run_id, T_ID, world=world_c))
    assert rb == ep / "runs" / world_b.run_id
    assert rc == ep / "runs" / world_c.run_id
    assert minted["tenant_id"] == T_ID
    assert json.loads(record_path.read_text(encoding="utf-8")) == minted, "the record changed"
    assert H.entries(tenant_root / T_ID / "runs") == sorted([H.RECORD_NAME, src.name])


def test_s7_j24_widened_refusal_on_sibling_path(tmp_path, monkeypatch, tenant_root):
    """A sibling's materialize, whose runs base is EpisodePaths(ep).runs rather than
    runs_base_for(T), still meets the widened learning-state refusal: resolve_data_root,
    reached through tenant_of_run_dir, refuses a learning state root equal to, inside, or
    containing the data root.

    The sibling's derivation (`tenant_of_run_dir` on its source) and its materialize both
    carry the widened refusal verbatim, and no sibling run dir is made; the control is the
    same sibling with a disjoint learning root."""
    src, ep, world = _sibling_world(tmp_path, tenant_root, "b")
    alert = src / "alert.json"
    for learning in (tenant_root, tenant_root / T_ID / "learning", tmp_path):
        monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(learning))
        widened = H.owner_refusal(H.resolve_data_root)
        H.assert_verbatim(str(H.owner_refusal(H.tenant_of_run_dir, src)), widened,
                          entry="tenant_of_run_dir")
        text = _refused(lambda: _materialize(alert, world.run_id, T_ID, world=world))
        H.assert_verbatim(text, widened, entry="the sibling's materialize_run_dir")
        assert not (ep / "runs" / world.run_id).exists()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path.parent / "elsewhere-learning"))
    assert H.tenant_of_run_dir(src) == T_ID
    assert Path(_materialize(alert, world.run_id, T_ID, world=world)).is_dir()


# ======================================================================================
# Resume (O6, N4, N5)
# ======================================================================================

def test_o6_resume_tests_survive(tmp_path, tenant_root):
    """The existing --run-id resume tests pass given --tenant T: a setup-only run dir under
    <root>/T/runs/<id> is resumed and one a run has been in is refused."""
    alert = H.plant_alert(tmp_path / "in")
    first = Path(_materialize(alert, "resume-me", T_ID))
    assert first == tenant_root / T_ID / "runs" / "resume-me"
    assert Path(_materialize(alert, "resume-me", T_ID)) == first, "a setup-only dir not resumed"
    (first / "report.md").write_text("a run was here\n", encoding="utf-8")
    before = H.census(first)
    with pytest.raises(SystemExit):
        _materialize(alert, "resume-me", T_ID)
    assert H.census(first) == before, "the refused resume touched the run dir"


def test_old_style_setup_state_classification_runs_against_a_tenant_scoped_run_dir(
        tmp_path, tenant_root):
    """_setup_state's absent/setup/ran classification is unchanged (N5) and works against
    <T>/runs/<id>/: a same `--run-id --tenant` resume finds the run dir Run.for_tenant
    computes as runs_base_for(T)/<id>."""
    rc = H.run_common()
    Run = H.mod("_run_handle").Run
    base = H.runs_base_for(T_ID)
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(_materialize(alert, "x1", T_ID))
    handle = Run.for_tenant(T_ID, "x1", runs_base=base)
    assert handle.run_dir == base / "x1" == run_dir
    assert rc._setup_state(handle) == "setup"
    assert Path(_materialize(alert, "x1", T_ID)) == run_dir
    assert rc._setup_state(Run.for_tenant(T_ID, "x2", runs_base=base)) == "absent"
    (run_dir / "investigation.md").write_text("+ ran\n", encoding="utf-8")
    assert rc._setup_state(handle) == "ran"
    with pytest.raises(SystemExit):
        _materialize(alert, "x1", T_ID)


def test_existing_resume_tests_given_a_tenant_but_old_env_setup(tmp_path, monkeypatch,
                                                                 tenant_root):
    """The existing --run-id resume tests pass given --tenant T and the D9 helper's tmp root
    with T created; their stale DEFENDER_RUNS_BASE setenv has no effect.

    The stale base holds a run under the same id that a run has been in: were it still read,
    the resume would be refused as `ran`. It is neither read nor touched."""
    stale = tmp_path / "stale-runs"
    H.plant_record(stale, "default")
    (stale / "x1").mkdir()
    (stale / "x1" / "report.md").write_text("an old run\n", encoding="utf-8")
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(stale))
    before = H.census(stale)
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(_materialize(alert, "x1", T_ID))
    assert run_dir == tenant_root / T_ID / "runs" / "x1"
    assert Path(_materialize(alert, "x1", T_ID)) == run_dir, "the setup-only dir not resumed"
    assert H.census(stale) == before, "the stale DEFENDER_RUNS_BASE was touched"


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
    paths = H.mod("_run_paths").RunPaths(run_dir)
    assert set(os.listdir(run_dir)) == {paths.alert.name, paths.gather_raw.name,
                                        paths.provenance.name}, "not a fresh setup"
    assert H.census(old) == before, "the old run X was touched"
