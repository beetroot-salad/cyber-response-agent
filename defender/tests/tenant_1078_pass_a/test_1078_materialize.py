"""#1078 pass (A) — `run_common.materialize_run(alert, run_id, *, tenant_id, model, world)`
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

from defender.tests._spec1077 import fixture_run as _run_handle_1165

import json
import os
import sys
from pathlib import Path
from defender.run_repository import RunPaths
from typing import Any

import pytest

from defender.tests._fixture_uuid import fixture_uuid
from defender.tests.tenant_1078_pass_a import _spec1078 as H
from defender._episode_handle import Episode  # noqa: E402

T_ID = H.VALID_ID
#: #1187 declared change 1: a run id is a canonical lowercase uuid4 text (`--run-id` refuses an
#: old one), so each pinned id is a fixture uuid named by its old label.
R1, RESUME = fixture_uuid("1078-materialize-r1"), fixture_uuid("1078-materialize-resume-me")
X1, X2, X = (fixture_uuid("1078-materialize-x1"), fixture_uuid("1078-materialize-x2"),
             fixture_uuid("1078-materialize-x"))


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


# ======================================================================================
# Layout (O4) and the stamp
# ======================================================================================

def test_o4_materialize_layout(tmp_path, tenant_root):
    """materialize_run(alert, <id>) with its tenant_id keyword set to T creates
    <root>/T/runs/<id>/, and the run's provenance stamp carries tenant_id T.

    #1187 declared changes 6 and 1 (R1): no runs-base record is written — the run's tenant is
    where it sits (`<root>/T/runs/`), and `<root>/T/runs/_tenant.json` does not exist; the id is
    a UUID. (Name kept.)"""
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
    """A fresh run under <root>/T/runs/ keeps its session store at
    <root>/T/sessions/<case>.db."""
    run_dir = Path(_materialize(_golden_alert(tmp_path), R1, T_ID))
    _replay(run_dir)
    store = H.mod("runtime.session_store").resolve_store_path(_run_handle_1165(run_dir))
    assert store.parent == tenant_root / T_ID / "sessions", f"the store is at {store}"
    assert store.suffix == ".db"
    assert store.is_file()


def test_d2_only_sessions_beside_base(tmp_path, tenant_root):
    """A materialize writes nothing into <root>/T/ beside runs/ except sessions/, and the
    tenant.json there exists because setup wrote it.

    Materialize and a real replayed run over it (which opens the store): `<root>/T/` then holds
    exactly the row, the operator-placed `knowledge/` (#1120 DC2), `runs/` and `sessions/`, the row byte-identical to what create_tenant
    wrote, and the data root holds T alone."""
    row_bytes = H.row_path(tenant_root, T_ID).read_bytes()
    run_dir = Path(_materialize(_golden_alert(tmp_path), R1, T_ID))
    # `knowledge/` is the operator's (#1120 DC2: placed before setup), never materialize's.
    assert H.entries(tenant_root / T_ID) == sorted([H.ROW_NAME, "knowledge", "runs"]), (
        "materialize wrote beside runs/")
    _replay(run_dir)
    assert H.entries(tenant_root / T_ID) == sorted([H.ROW_NAME, "knowledge", "runs",
                                                     "sessions"])
    assert H.entries(tenant_root) == [T_ID]
    assert H.row_path(tenant_root, T_ID).read_bytes() == row_bytes, "the row was rewritten"


def test_d9_run_dir_file_set_unchanged(tmp_path, tenant_root):
    """The run-dir file-set pins pass unchanged: materialize adds no file inside the run dir.

    A fresh materialize leaves exactly what setup writes — the owner's alert, gather_raw and
    provenance names — and beside the run dir nothing at all.

    #1187 declared changes 6 and 1 (R1): the runs-base record is no longer written, so the run
    dir is the runs base's only entry; the id is a UUID. (Name kept.)"""
    import uuid

    pinned = str(uuid.uuid4())
    run_dir = Path(_materialize(H.plant_alert(tmp_path / "in"), pinned, T_ID))
    paths = H.mod("run_repository._layout").RunPaths(run_dir)
    assert set(H.entries(run_dir)) == {paths.alert_input_dir.name, paths.gather_raw.name,
                                       paths.provenance.name}
    assert H.entries(run_dir.parent) == [pinned], (
        f"beside the run dir: {H.entries(run_dir.parent)}")


# ======================================================================================
# Refusals: the row (O2) and the order (D2) (the record's (O6) retired by #1187 R1)
# ======================================================================================

def test_o2_materialize_never_creates_row(tmp_path, monkeypatch):
    """materialize_run with its tenant_id keyword set to T, with no row for T is refused before creating anything
    and never writes <root>/T/tenant.json; after a successful materialize for an existing T
    the row is byte-identical.

    #1120 D1: the row check is the entry's `accept_tenant` (materialize takes the accepted
    `Tenant`), so the refusal is observed on that accept-then-materialize pipeline."""
    root = tmp_path / "data"
    root.mkdir()
    H.set_data_root(monkeypatch, root)
    alert = H.plant_alert(tmp_path / "in")
    text = _refused(lambda: _materialize(alert, R1, T_ID))
    H.assert_verbatim(text, H.owner_refusal(H.require_tenant, root, T_ID),
                      entry="materialize_run")
    assert H.entries(root) == [], "the refused materialize created something"

    H.make_tenant(root, T_ID)
    row_bytes = H.row_path(root, T_ID).read_bytes()
    _materialize(alert, R1, T_ID)
    assert H.row_path(root, T_ID).read_bytes() == row_bytes


def test_d2_materialize_order(tmp_path, monkeypatch):
    """materialize_run runs require_tenant before creating anything, then the runs base,
    guarded_mkdir, ensure_runs_base_record and Run.for_tenant in that order, so an unknown
    tenant leaves no runs base.

    Observed as which refusal wins: (1) no row — nothing is created, no runs base; (2) no row
    over a base whose record names U — require_tenant's refusal, not the record's; (3) a row,
    and a record naming U — ensure_runs_base_record's refusal (step 4), not Run.for_tenant's
    (step 5), and no run dir; (4) the ordinary case — the runs base made, the record minted.

    #1120 D1: step 1 is now the entry's `accept_tenant` (whose row check is `require_tenant`'s,
    verbatim) ahead of `materialize_run(tenant=...)`; cells (1) and (2) observe that pipeline.

    #1187 declared change 6 (R1): `ensure_runs_base_record` and `Run.for_tenant` are retired
    with the record, so cell (3) — a record naming U refused at step 4 — is gone (a record left
    in cell (2) is a stray file, read by nothing), and cell (4) is the runs base and the run dir
    made with NO record minted. The ids are UUIDs. (Name kept.)"""
    import uuid

    pinned = str(uuid.uuid4())
    alert = H.plant_alert(tmp_path / "in")
    root = tmp_path / "unknown"
    root.mkdir()
    H.set_data_root(monkeypatch, root)
    _refused(lambda: _materialize(alert, pinned, T_ID))
    assert not (root / T_ID / "runs").exists(), "an unknown tenant left a runs base"

    root = tmp_path / "rowless"
    H.set_data_root(monkeypatch, root)
    H.plant_record(root / T_ID / "runs", "someone-else")
    text = _refused(lambda: _materialize(alert, pinned, T_ID))
    H.assert_verbatim(text, H.owner_refusal(H.require_tenant, root, T_ID),
                      entry="materialize_run")

    root = tmp_path / "ordinary"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, T_ID)
    _materialize(alert, pinned, T_ID)
    assert (root / T_ID / "runs" / pinned).is_dir(), "the ordinary run dir was not made"
    assert not (root / T_ID / "runs" / H.RECORD_NAME).exists(), (
        "run setup minted the retired runs-base record")


def test_tenant_row_deleted_mid_materialize(tmp_path, tenant_root):
    """The row is checked once, at step 1; a row removed after it does not stop the later
    steps (no re-check within the call).

    #1120 D1 moved step 1 to the entry: `accept_tenant` reads the row and hands
    `materialize_run` the accepted `Tenant`. The removal is the REAL unlink of the real row,
    timed to the instant the owner's `accept_tenant` returns inside the pipeline (a profile
    hook on that return — no attribute is patched). The materialize then completes: the run
    dir and a stamp naming T."""
    row = H.row_path(tenant_root, T_ID)
    fired: list[str] = []

    def hook(frame, event, _arg):
        if (event == "return" and not fired and frame.f_code.co_name == "accept_tenant"
                and frame.f_globals.get("__name__") == "defender._tenant"):
            row.unlink()
            fired.append("row removed")

    alert = H.plant_alert(tmp_path / "in")
    previous = sys.getprofile()
    sys.setprofile(hook)
    try:
        run_dir = Path(_materialize(alert, R1, T_ID))
    finally:
        sys.setprofile(previous)
    assert fired, "the pipeline never ran defender._tenant.accept_tenant (D2 step 1)"
    assert not row.exists()
    assert run_dir == tenant_root / T_ID / "runs" / R1
    assert run_dir.is_dir()
    assert _stamp(run_dir)["tenant_id"] == T_ID


# ======================================================================================
# The sibling's runs base (D2 step 2) and the widened refusal on that path (§7 J24)
# ======================================================================================

def test_s7_j24_widened_refusal_on_sibling_path(tmp_path, monkeypatch, tenant_root):
    """A sibling's materialize, whose runs base is EpisodePaths(ep).runs rather than
    runs_base_for(T), still meets the widened learning-state refusal: resolve_data_root,
    reached through the sibling's entry, refuses a learning state root equal to, inside, or
    containing the data root.

    The sibling's entry (#1105 PR 2: `run.py --tenant T --episode <ep>` resolves the data root
    itself; `tenant_of_run_dir` is gone, F-13) and its materialize both carry the widened
    refusal verbatim, and no sibling run dir is made; the control is the same sibling with a
    disjoint learning root."""
    src, ep, world = _sibling_world(tmp_path, tenant_root, "b")
    alert = RunPaths(src).alert
    argv = H.sibling_argv(ep / "family.yaml", "b", "--tenant", T_ID)
    with Episode.open(ep) as episode:
        # #1187 (O4b): the sibling's form names its roster label (`roster_label=`, replacing
        # PR 2's `container_required`).
        view = H.accept(tenant_root, T_ID).runs_repository().episode(
            ep.name, held=episode, roster_label="b")
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


# ======================================================================================
# Resume (O6, N4, N5)
# ======================================================================================

def test_o6_resume_tests_survive(tmp_path, tenant_root):
    """The existing --run-id resume tests pass given --tenant T: a setup-only run dir under
    <root>/T/runs/<id> is resumed and one a run has been in is refused."""
    alert = H.plant_alert(tmp_path / "in")
    first = Path(_materialize(alert, RESUME, T_ID))
    assert first == tenant_root / T_ID / "runs" / RESUME
    assert Path(_materialize(alert, RESUME, T_ID)) == first, "a setup-only dir not resumed"
    (first / "report.md").write_text("a run was here\n", encoding="utf-8")
    before = H.census(first)
    with pytest.raises(SystemExit):
        _materialize(alert, RESUME, T_ID)
    assert H.census(first) == before, "the refused resume touched the run dir"


def test_old_style_setup_state_classification_runs_against_a_tenant_scoped_run_dir(
        tmp_path, tenant_root):
    """_setup_state's absent/setup/ran classification is unchanged (N5) and works against
    <T>/runs/<id>/: a same `--run-id --tenant` resume finds the run dir Run.for_tenant
    computes as runs_base_for(T)/<id>."""
    rc = H.run_common()
    Run = H.mod("run_repository._handle").Run
    base = H.runs_base_for(T_ID)
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(_materialize(alert, X1, T_ID))
    handle = Run.under(base, X1, tenant_id=T_ID)  # #1187: `Run.for_tenant` retired (R1)
    assert handle.run_dir == base / X1 == run_dir
    assert rc._setup_state(handle) == "setup"
    assert Path(_materialize(alert, X1, T_ID)) == run_dir
    assert rc._setup_state(Run.under(base, X2, tenant_id=T_ID)) == "absent"
    (run_dir / "investigation.md").write_text("+ ran\n", encoding="utf-8")
    assert rc._setup_state(handle) == "ran"
    with pytest.raises(SystemExit):
        _materialize(alert, X1, T_ID)


def test_existing_resume_tests_given_a_tenant_but_old_env_setup(tmp_path, monkeypatch,
                                                                 tenant_root):
    """The existing --run-id resume tests pass given --tenant T and the D9 helper's tmp root
    with T created; their stale DEFENDER_RUNS_BASE setenv has no effect.

    The stale base holds a run under the same id that a run has been in: were it still read,
    the resume would be refused as `ran`. It is neither read nor touched."""
    stale = tmp_path / "stale-runs"
    H.plant_record(stale, "default")
    (stale / X1).mkdir()
    (stale / X1 / "report.md").write_text("an old run\n", encoding="utf-8")
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(stale))
    before = H.census(stale)
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(_materialize(alert, X1, T_ID))
    assert run_dir == tenant_root / T_ID / "runs" / X1
    assert Path(_materialize(alert, X1, T_ID)) == run_dir, "the setup-only dir not resumed"
    assert H.census(stale) == before, "the stale DEFENDER_RUNS_BASE was touched"


def test_o6_old_run_id_fresh_under_tenant(tmp_path, monkeypatch, tenant_root):
    """--run-id X --tenant T while an old run X sits in another base materializes a fresh
    <root>/T/runs/X and leaves the old X untouched."""
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
