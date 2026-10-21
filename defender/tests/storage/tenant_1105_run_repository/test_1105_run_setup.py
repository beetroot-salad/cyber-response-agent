"""Run setup checks: pinned ids claimed by records, id bounds, sidecar suffixes, linked runs folders, one-line stderr refusals."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import uuid
from defender.tests.storage.ids_1187 import _spec1187 as S

import os
from pathlib import Path

from defender.tenancy import _tenant
from defender import run as run_py
from defender import run_common
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H


def _pinned(alert: Path, run_id: str | None, t, **kw):
    """Run setup itself (the function `run.py` calls): `materialize_run`."""
    return run_common.materialize_run(alert, run_id, tenant=t, **kw)


def _via_run_py(alert: Path, run_id: str | None, t, **kw):
    """Run setup through `run.py`'s single call site, which surfaces a `TenantRefused` as
    `sys.exit("[run.py] …")`."""
    return run_py._materialize_run(alert, run_id, tenant=t, model=None, **kw)


def _one_line_exit(err: BaseException | None) -> bool:
    """A `sys.exit(str)` refusal: one stderr line, no traceback."""
    return (isinstance(err, SystemExit) and isinstance(err.code, str)
            and len(err.code.splitlines()) == 1)


def _link_runs_to(t, outside: Path) -> None:
    """`t.runs` as a link to a real folder elsewhere (another tenant's, say)."""
    outside.mkdir(parents=True, exist_ok=True)
    Path(location_path(t.runs)).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(outside, location_path(t.runs))


def test_1105_run_setup_admits_the_id_then_checks_the_folder_then_the_record_then_the_claims(
        tmp_path, data_root):
    """Run setup refuses in order: a bad id over a linked runs folder gets 'invalid run id: ...'
    and nothing is created; a linked runs folder gets TenantRefused ('[run.py] ...') with
    nothing created through the link."""
    import uuid

    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    outside = tmp_path / "elsewhere"
    _link_runs_to(t, outside)
    pinned = str(uuid.uuid4())
    # 1. id admission comes first: over a linked runs folder, the id refusals fire.
    for bad in ("_tenant.json", "Bad Name", "r1"):
        err = H.raised(_via_run_py, alert, bad, t)
        assert H.message(err).startswith("invalid run id: "), f"pinned {bad!r} gave {err!r}"
    assert H.tree_state(outside) == {}, "an id refusal created something through the link"
    # 2. the runs-folder state.
    err = H.raised(_via_run_py, alert, pinned, t)
    assert H.message(err).startswith("[run.py] "), f"a linked runs folder gave {err!r}"
    assert H.tree_state(outside) == {}, "run setup created something through a linked runs folder"
    os.unlink(location_path(t.runs))
    # 3. nothing after the folder refuses: no record step, no claimed-id step.
    runs = Path(location_path(t.runs))
    H.plant_record(runs, str(uuid.uuid4()), t.id, str(uuid.uuid4()), {"a": pinned})
    assert not (runs / "_tenant.json").exists()
    run = _pinned(alert, pinned, t)
    assert run.run_dir == runs / pinned, f"the pinned run was not created: {run!r}"
    assert (runs / pinned).is_dir()


def test_1105_run_setup_refuses_a_pinned_or_minted_id_over_206_bytes_with_the_invalid_run_id_exit(
        tmp_path, data_root):
    t = H.tenant(data_root, H.T_ID)
    runs = Path(location_path(t.runs))
    alert = H.alert_file(tmp_path / "in")
    for pinned in ["r" + "1" * (n - 1) for n in (207, 231, 256, 206)] + [S.OLD_PINNED_ID]:
        err = H.raised(_pinned, alert, pinned, t)
        assert H.message(err).startswith("invalid run id: "), (
            f"a pinned {len(pinned)}-byte id {pinned[:12]!r}… gave {err!r}, not the invalid-run-id exit")
        assert not os.path.lexists(runs), f"a refused id created {runs} before refusing"
    for label in ("a" * 190, "ß" * 95, "ß" * 94):
        labelled = H.alert_file(tmp_path / f"in-{len(label)}-{label[0]}", f"{label}.json")
        minted = _pinned(labelled, None, t)
        name = Path(minted.run_dir).name
        assert S.is_canonical_uuid(name), f"{len(label)} x {label[0]!r} minted {name!r}"
        assert Path(minted.run_dir).parent == runs, minted.run_dir
        assert Path(minted.run_dir).is_dir(), minted.run_dir
    pinned = str(uuid.uuid4())
    run = _pinned(alert, pinned, t)
    assert run.run_dir == runs / pinned, f"a pinned uuid runs: {run!r}"
    assert Path(run.run_dir).is_dir(), "the pinned uuid's run folder exists"


def test_1105_run_setup_refuses_a_sidecar_suffixed_pinned_or_minted_id(tmp_path, data_root):
    t = H.tenant(data_root, H.T_ID)
    runs = Path(location_path(t.runs))
    alert = H.alert_file(tmp_path / "in")
    run_id = str(uuid.uuid4())
    names = [f"{run_id}{s}" for s in H.SIDECAR_SUFFIXES] + [f"{run_id}.run-end.json{H.STAGED_TAIL}"]
    for name in names:
        err = H.raised(_pinned, alert, name, t)
        assert H.message(err).startswith("invalid run id: "), f"pinned {name!r} gave {err!r}"
        assert not os.path.lexists(runs / name), f"a folder named {name!r} was created"
    for minted_from in (H.alert_file(tmp_path / "in-stem", "x.run-end.json.txt"),
                        H.alert_file(tmp_path / "y.scrub-verdict.json")):
        minted = _pinned(minted_from, None, t)
        name = Path(minted.run_dir).name
        assert S.is_canonical_uuid(name), (
            f"an alert at {minted_from.relative_to(tmp_path)} minted {name!r}, not a bare uuid")
        assert Path(minted.run_dir).is_dir(), "the minted run's folder exists"
    assert all(S.is_canonical_uuid(n) for n in os.listdir(runs)), sorted(os.listdir(runs))
    assert _pinned(alert, run_id, t).run_dir == runs / run_id, "the plain uuid runs"


def test_1105_run_setup_refuses_a_linked_runs_folder_before_creating_anything(
        tmp_path, data_root):
    """When tenant.runs is a link to an outside folder, run setup refuses before creating or
    reading anything inside it, and run.py prints the refusal as '[run.py] ...': the outside
    folder stays empty and no raw OSError escapes. Positive control: an absent tenant.runs is
    created with the run. The link is P2's one representative state of the runs folder; a
    dangling link and a non-directory there are not driven here: _io.hold(follow=False) tells
    those states apart (test_1105_hold_follow_false_refuses_a_link_root_and_tells_the_states_apart).
    The tenant.runs arm is driven through run.main itself."""
    import uuid

    from defender.run_repository import RunRefused

    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    outside = tmp_path / "outside"
    _link_runs_to(t, outside)
    pinned = str(uuid.uuid4())
    lifecycles: list[object] = []
    err = H.raised(run_py.main, [str(alert), "--tenant", t.id, "--run-id", pinned, "--no-learn"],
                   preflight=lambda _model: 0,
                   lifecycle=lambda **kw: lifecycles.append(kw) or {},
                   visualize=lambda _run, **_kw: None)
    assert H.message(err).startswith("[run.py] "), (
        f"run.main over a linked tenant.runs did not exit '[run.py] …': {err!r}")
    assert not isinstance(err, OSError), f"a raw OSError escaped: {err!r}"
    assert H.tree_state(outside) == {}, "run setup wrote through the linked runs folder"
    assert lifecycles == [], "the run went on past a refused runs folder"
    err = H.raised(_pinned, alert, pinned, t)
    assert isinstance(err, (_tenant.TenantRefused, RunRefused)), f"materialize_run raised {err!r}"
    assert H.tree_state(outside) == {}, "materialize_run wrote through the linked runs folder"
    os.unlink(location_path(t.runs))

    run = _pinned(alert, pinned, t)
    assert run.run_dir == Path(location_path(t.runs)) / pinned, f"an absent runs folder is created: {run!r}"
    assert Path(location_path(t.runs)).is_dir(), "the absent runs folder was created as a real directory"
    assert not (Path(location_path(t.runs)) / "_tenant.json").exists(), (
        "run setup wrote the retired tenant record")


def test_1105_run_setups_refusals_are_one_stderr_line_naming_the_path(tmp_path, data_root):
    """Run setup's refusals are one stderr line: the hold's own refusal of a linked runs folder
    is TenantRefused shown as '[run.py] ...' naming the path; 'invalid run id: ...' carries
    RunId's repr-quoted refusal. Odd occupants at a pinned id's name keep today's outcome
    (RG-21-a): a regular file exits '<runs>/<id> is not a directory — refusing to materialise a
    run over it', an empty directory proceeds, and a directory holding investigation.md exits
    'run dir already exists and a run has been in it: ...'."""
    import uuid

    from defender.run_repository import RunId, RunRefused

    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    runs = Path(location_path(t.runs))
    runs.mkdir(parents=True)
    r1, r3, r4, r5 = (str(uuid.uuid4()) for _ in range(4))

    bad = "Bad\nName"
    refusal = H.raised(RunId.parse, bad)
    err = H.raised(_pinned, alert, bad, t)
    assert H.message(err) == f"invalid run id: {refusal}", (
        f"the invalid-run-id exit does not carry RunId's refusal {refusal!r}: {err!r}")
    assert _one_line_exit(err), f"the invalid-run-id exit is one stderr line: {err!r}"
    assert repr(bad) in H.message(err), f"the bad id is repr-quoted: {H.message(err)!r}"

    (runs / r1).write_text("not a run\n", encoding="utf-8")
    err = H.raised(_pinned, alert, r1, t)
    assert H.message(err) == (f"{runs / r1} is not a directory — refusing to materialise a "
                              "run over it"), f"a file at the run's name gave {err!r}"
    (runs / r3).mkdir()
    assert _pinned(alert, r3, t).run_dir == runs / r3, "an empty directory proceeds"
    (runs / r4).mkdir()
    (runs / r4 / "investigation.md").write_text("+ ran\n", encoding="utf-8")
    err = H.raised(_pinned, alert, r4, t)
    assert H.message(err).startswith(
        f"run dir already exists and a run has been in it: {runs / r4}"), f"got {err!r}"

    os.rename(runs, tmp_path / "moved-runs")
    os.symlink(tmp_path / "moved-runs", runs)
    err = H.raised(_via_run_py, alert, r5, t)
    assert H.message(err).startswith("[run.py] "), (
        f"the hold's refusal of a linked runs folder is not '[run.py] …': {err!r}")
    assert str(runs) in H.message(err), f"the refusal names {runs}: {H.message(err)!r}"
    plain = H.raised(_pinned, alert, r5, t)
    assert isinstance(plain, (_tenant.TenantRefused, RunRefused)), (
        f"the walk's refusal type (TenantRefused or RunRefused, declared change 8): {plain!r}")
