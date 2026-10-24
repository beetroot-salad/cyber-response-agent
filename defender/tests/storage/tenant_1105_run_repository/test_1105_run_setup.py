"""Run setup checks: minted ids, sidecar-like alert names, linked runs folders, one-line stderr refusals."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import uuid

import pytest
from defender.tests.storage.ids_1187 import _spec1187 as S

import os
from pathlib import Path

from defender.tenancy import _tenant
from defender import run as run_py
from defender import run_common
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H


def _setup(alert: Path, t, **kw):
    """Run setup itself (the function `run.py` calls): `materialize_run`."""
    return run_common.materialize_run(alert, tenant=t, **kw)


def _via_run_py(alert: Path, t, **kw):
    """Run setup through `run.py`'s single call site, which surfaces a `TenantRefused` as
    `sys.exit("[run.py] …")`."""
    return run_py._materialize_run(alert, tenant=t, model=None, **kw)


def _one_line_exit(err: BaseException | None) -> bool:
    """A `sys.exit(str)` refusal: one stderr line, no traceback."""
    return (isinstance(err, SystemExit) and isinstance(err.code, str)
            and len(err.code.splitlines()) == 1)


def _link_runs_to(t, outside: Path) -> None:
    """`t.runs` as a link to a real folder elsewhere (another tenant's, say)."""
    outside.mkdir(parents=True, exist_ok=True)
    Path(location_path(t.runs)).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(outside, location_path(t.runs))


def test_1105_run_setup_checks_the_runs_folder_and_nothing_after_it_refuses(
        tmp_path, data_root):
    """A linked runs folder gets TenantRefused ('[run.py] ...') with nothing created through the
    link; past the folder there is no record step and no claimed-id step."""
    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    outside = tmp_path / "elsewhere"
    _link_runs_to(t, outside)
    err = H.raised(_via_run_py, alert, t)
    assert H.message(err).startswith("[run.py] "), f"a linked runs folder gave {err!r}"
    assert H.tree_state(outside) == {}, "run setup created something through a linked runs folder"
    os.unlink(location_path(t.runs))
    runs = Path(location_path(t.runs))
    H.plant_record(runs, str(uuid.uuid4()), t.id, str(uuid.uuid4()), {"a": str(uuid.uuid4())})
    assert not (runs / "_tenant.json").exists()
    run = _setup(alert, t)
    assert run.run_dir.parent == runs, f"the run was not created: {run!r}"
    assert run.run_dir.is_dir()


def test_1105_run_setup_names_a_run_by_a_bare_uuid_whatever_the_alert_label_is(
        tmp_path, data_root):
    t = H.tenant(data_root, H.T_ID)
    runs = Path(location_path(t.runs))
    for label in ("a" * 190, "ß" * 95, "ß" * 94):
        labelled = H.alert_file(tmp_path / f"in-{len(label)}-{label[0]}", f"{label}.json")
        minted = _setup(labelled, t)
        name = Path(minted.run_dir).name
        assert S.is_canonical_uuid(name), f"{len(label)} x {label[0]!r} minted {name!r}"
        assert Path(minted.run_dir).parent == runs, minted.run_dir
        assert Path(minted.run_dir).is_dir(), minted.run_dir


def test_1105_run_setup_names_a_run_by_a_bare_uuid_whatever_suffix_the_alert_carries(
        tmp_path, data_root):
    t = H.tenant(data_root, H.T_ID)
    runs = Path(location_path(t.runs))
    for minted_from in (H.alert_file(tmp_path / "in-stem", "x.run-end.json.txt"),
                        H.alert_file(tmp_path / "y.scrub-verdict.json")):
        minted = _setup(minted_from, t)
        name = Path(minted.run_dir).name
        assert S.is_canonical_uuid(name), (
            f"an alert at {minted_from.relative_to(tmp_path)} minted {name!r}, not a bare uuid")
        assert Path(minted.run_dir).is_dir(), "the minted run's folder exists"
    assert all(S.is_canonical_uuid(n) for n in os.listdir(runs)), sorted(os.listdir(runs))


def test_1105_run_setup_refuses_a_linked_runs_folder_before_creating_anything(
        tmp_path, data_root):
    """When tenant.runs is a link to an outside folder, run setup refuses before creating or
    reading anything inside it, and run.py prints the refusal as '[run.py] ...': the outside
    folder stays empty and no raw OSError escapes. Positive control: an absent tenant.runs is
    created with the run. The link is P2's one representative state of the runs folder; a
    dangling link and a non-directory there are not driven here: _io.hold(follow=False) tells
    those states apart (test_1105_hold_follow_false_refuses_a_link_root_and_tells_the_states_apart).
    The tenant.runs arm is driven through run.main itself."""
    from defender.run_repository import RunRefused

    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    outside = tmp_path / "outside"
    _link_runs_to(t, outside)
    lifecycles: list[object] = []
    err = H.raised(run_py.main, [str(alert), "--tenant", t.id, "--no-learn"],
                   preflight=lambda _model: 0,
                   lifecycle=lambda **kw: lifecycles.append(kw) or {},
                   visualize=lambda _run, **_kw: None)
    assert H.message(err).startswith("[run.py] "), (
        f"run.main over a linked tenant.runs did not exit '[run.py] …': {err!r}")
    assert not isinstance(err, OSError), f"a raw OSError escaped: {err!r}"
    assert H.tree_state(outside) == {}, "run setup wrote through the linked runs folder"
    assert lifecycles == [], "the run went on past a refused runs folder"
    err = H.raised(_setup, alert, t)
    assert isinstance(err, (_tenant.TenantRefused, RunRefused)), f"materialize_run raised {err!r}"
    assert H.tree_state(outside) == {}, "materialize_run wrote through the linked runs folder"
    os.unlink(location_path(t.runs))

    run = _setup(alert, t)
    assert run.run_dir.parent == Path(location_path(t.runs)), (
        f"an absent runs folder is created: {run!r}")
    assert Path(location_path(t.runs)).is_dir(), "the absent runs folder was created as a real directory"
    assert not (Path(location_path(t.runs)) / "_tenant.json").exists(), (
        "run setup wrote the retired tenant record")


def test_1105_run_setups_refusal_of_a_linked_runs_folder_is_one_stderr_line_naming_the_path(
        tmp_path, data_root):
    """The hold's refusal of a linked runs folder is TenantRefused shown as '[run.py] ...'
    naming the path. (The odd-occupant refusals at a run's own name moved with the pinned ids:
    see test_1187_roster_sibling's O8 cases.)"""
    from defender.run_repository import RunRefused

    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    runs = Path(location_path(t.runs))
    runs.mkdir(parents=True)
    os.rename(runs, tmp_path / "moved-runs")
    os.symlink(tmp_path / "moved-runs", runs)

    err = H.raised(_via_run_py, alert, t)
    assert H.message(err).startswith("[run.py] "), (
        f"the hold's refusal of a linked runs folder is not '[run.py] …': {err!r}")
    assert _one_line_exit(err), f"the refusal is one stderr line: {err!r}"
    assert str(runs) in H.message(err), f"the refusal names {runs}: {H.message(err)!r}"
    plain = H.raised(_setup, alert, t)
    assert isinstance(plain, (_tenant.TenantRefused, RunRefused)), (
        f"the walk's refusal type (TenantRefused or RunRefused, declared change 8): {plain!r}")


def test_1279_o8_make_run_dir_makes_the_run_dir_once_and_refuses_a_second_time(
        tmp_path, data_root):
    """O8: the run dir is made exclusively through a handle from `create()`; no second make."""
    from defender.run_repository import RunPaths

    t = H.tenant(data_root, H.T_ID)
    run = t.runs_repository().create()
    assert not os.path.lexists(run.run_dir), "create made the run folder"

    run.make_run_dir()

    assert RunPaths(run.run_dir).gather_raw.is_dir()
    (run.run_dir / "report.md").write_text("a run was here\n", encoding="utf-8")
    before = H.tree_state(run.run_dir)
    err = H.raised(run.make_run_dir)
    assert isinstance(err, FileExistsError), f"a second make gave {err!r}"
    assert H.tree_state(run.run_dir) == before, "the refused make changed the run dir"


@pytest.mark.parametrize("kind", ["empty-dir", "setup-only", "regular-file", "link-to-dir",
                                  "dangling-link"])
def test_1279_o8_make_run_dir_refuses_anything_at_the_run_dir_without_following_it(
        tmp_path, data_root, kind):
    """O8: an empty dir, a setup-only dir, a file or a link at the run id is refused as found."""
    from defender.run_repository import RunPaths

    t = H.tenant(data_root, H.T_ID)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "kept.txt").write_text("kept\n", encoding="utf-8")
    before_outside = H.tree_state(outside)
    run = t.runs_repository().create()
    at = run.run_dir
    if kind == "empty-dir":
        at.mkdir()
    elif kind == "setup-only":
        RunPaths(at).gather_raw.mkdir(parents=True)
    elif kind == "regular-file":
        at.write_text("not a dir\n", encoding="utf-8")
    elif kind == "link-to-dir":
        os.symlink(outside, at, target_is_directory=True)
    else:
        os.symlink(tmp_path / "nowhere", at)
    before = H.tree_state(at) if kind in ("empty-dir", "setup-only") else None

    err = H.raised(run.make_run_dir)

    assert isinstance(err, FileExistsError), f"{kind}: make_run_dir gave {err!r}"
    assert H.tree_state(outside) == before_outside, f"{kind}: the make reached through the link"
    assert not (tmp_path / "nowhere").exists(), f"{kind}: the make followed a dangling link"
    if before is not None:
        assert H.tree_state(at) == before, f"{kind}: the refused make changed the dir"
    assert os.path.islink(at) == (kind in ("link-to-dir", "dangling-link"))


@pytest.mark.parametrize("kind", ["directory", "dangling-link", "link-to-file"])
def test_1279_o8_make_run_dir_refuses_what_appears_between_a_check_and_the_make(
        tmp_path, data_root, kind):
    """O8: an entry planted right before the run dir's own mkdir is refused untouched (exclusive make)."""
    from defender.tests.support.storage import _setup_faults_1279 as F

    t = H.tenant(data_root, H.T_ID)
    elsewhere = tmp_path / "elsewhere"
    io = F.PlantBeforeRunDirIo(lambda at: F.plant_entry(kind, at, elsewhere))
    run = F.tenant_with_runs_io(t, io).runs_repository().create()
    clean = t.runs_repository().create()
    clean.make_run_dir()
    assert clean.run_dir.is_dir(), "positive control: with nothing planted the make succeeds"

    err = H.raised(run.make_run_dir)

    assert io.planted_in == run.run_dir, f"nothing was planted before the run dir make: {io.planted_in}"
    assert isinstance(err, FileExistsError), f"{kind}: a make over a planted entry gave {err!r}"
    assert os.path.islink(run.run_dir) == (kind != "directory"), f"{kind}: the planted entry was replaced"
    if kind == "directory":
        assert H.tree_state(run.run_dir) == {}, "the make went into the planted dir"
    assert not (elsewhere / "nowhere").exists(), f"{kind}: the make followed the planted link"


def _sidecar_suffixes() -> tuple[str, ...]:
    from defender.run_repository._layout import _SIDECAR_SUFFIXES

    return tuple(_SIDECAR_SUFFIXES)


@pytest.mark.parametrize("kind", ["regular-file", "directory", "dangling-link", "link-to-file"])
@pytest.mark.parametrize("suffix", _sidecar_suffixes())
def test_1279_o8_natural_setup_refuses_any_entry_at_its_minted_ids_sidecar_name(
        tmp_path, data_root, monkeypatch, suffix, kind):
    """O8: in the natural lane too, any entry at the minted id's sidecar name is refused, naming it."""
    from defender.run_repository import RunId
    from defender.tests.support.storage import _setup_faults_1279 as F

    t = H.tenant(data_root, H.T_ID)
    alert = H.alert_file(tmp_path / "in")
    runs = Path(location_path(t.runs))
    fixed = str(uuid.uuid4())
    # No seam fixes the id `create()` mints, and a sidecar can only be planted at a known id: the
    # one targeted patch of this test.
    monkeypatch.setattr(RunId, "mint", classmethod(lambda cls: cls.parse(fixed)))
    runs.mkdir(parents=True)
    sidecar = runs / f"{fixed}{suffix}"
    F.plant_entry(kind, sidecar, tmp_path / "elsewhere")
    before = H.tree_state(runs)

    err = H.raised(_via_run_py, alert, t)

    assert _one_line_exit(err), f"{suffix} {kind}: setup gave {err!r}"
    assert str(sidecar) in H.message(err), f"the refusal does not name the sidecar: {H.message(err)!r}"
    assert not os.path.lexists(runs / fixed), "the run dir was made past a sidecar"
    assert H.tree_state(runs) == before, "the refused setup changed the runs folder"

    os.unlink(sidecar) if kind != "directory" else sidecar.rmdir()
    run = _setup(alert, t)
    assert run.run_dir == runs / fixed, "positive control: without the entry setup goes on"
    assert run.run_dir.is_dir(), "positive control: without the entry setup goes on"
