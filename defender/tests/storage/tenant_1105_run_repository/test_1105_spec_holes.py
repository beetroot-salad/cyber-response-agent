"""Edge cases: non-directory runs folders and episodes, sidecar names, surrogate escapes."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import os
from pathlib import Path

import pytest

from defender import run as run_py
from defender import run_common
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.records._tenant_id import TenantRefused

#: The fixture's run ids, named by their old handles.
R1, R2 = fixture_uuid("spec-holes-r1"), fixture_uuid("spec-holes-r2")


def _good(tmp_path: Path, *run_ids: str, tenant_id: str = H.T_ID):
    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, tenant_id)
    H.runs_folder(t)
    for rid in run_ids:
        H.make_run(location_path(t.runs), rid)
    return t


def _listings(t, run_id: str = R1):
    """The repository methods that judge the whole runs folder's listing."""
    return [
        ("runs.list", lambda: t.runs_repository().list()),
    ]


def _every_function(t, *, run_id: str = R1):
    """Every lookup over the natural container."""
    from defender.records import RunId

    return [*_listings(t, run_id),
            ("runs.open", lambda: t.runs_repository().open(RunId.parse(run_id)))]


# -- Run setup over a non-directory runs folder ----------------------------------------------


@pytest.mark.parametrize("kind", ["file", "fifo", "dangling-link"])
def test_1105_run_setup_refuses_a_non_directory_runs_folder_before_creating_anything(
        tmp_path, data_root, kind):
    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    runs = Path(location_path(t.runs))
    runs.parent.mkdir(parents=True, exist_ok=True)
    if kind == "file":
        runs.write_text("not a folder\n", encoding="utf-8")
    elif kind == "fifo":
        H.make_fifo(runs)
    else:
        os.symlink(tmp_path / "nowhere", runs)
    err = H.raised(run_common.materialize_run, alert, tenant=t)
    assert isinstance(err, TenantRefused), f"{kind}: materialize_run raised {err!r}"
    err = H.raised(run_py._materialize_run, alert, tenant=t, model=None)
    assert H.message(err).startswith("[run.py] "), f"{kind}: run.py gave {err!r}"
    assert not isinstance(err, OSError), f"{kind}: a raw OSError escaped: {err!r}"
    assert os.path.lexists(runs), f"{kind}: run setup removed it"
    assert not runs.is_dir(), f"{kind}: run setup replaced it with a folder"
    assert not (tmp_path / "nowhere").exists(), f"{kind}: run setup followed the link"


# -- Every function over a file or FIFO at tenant.runs -----------------------------------------


@pytest.mark.parametrize("kind", ["file", "fifo"])
def test_1105_every_function_refuses_a_non_directory_runs_folder(tmp_path, kind):
    from defender.records import RunUnreachable

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root)
    runs = Path(location_path(t.runs))
    if kind == "file":
        runs.write_text("not a folder\n", encoding="utf-8")
    else:
        H.make_fifo(runs)
    for name, call in _every_function(t):
        err = H.raised(call)
        if name == "runs.open":
            err = err.__cause__ if H.is_a(err, RunUnreachable) else None
        assert H.is_a(err, TenantRefused), (
            f"a {kind} at tenant.runs: {name} answered or raised {err!r}")


# -- runs.open over a non-directory at the run's name ------------------------------------------


@pytest.mark.parametrize("kind", ["file", "fifo"])
def test_1105_open_run_refuses_a_non_directory_at_the_runs_name(tmp_path, kind):
    from defender.records import RunId, RunRefused

    t = _good(tmp_path, R1)
    entry = Path(location_path(t.runs)) / R2
    if kind == "file":
        entry.write_text("x\n", encoding="utf-8")
    else:
        H.make_fifo(entry)
    err = H.raised(t.runs_repository().open, RunId.parse(R2))
    assert H.is_a(err, RunRefused), f"a {kind} at r2: runs.open gave {err!r}"
    assert str(entry) in H.message(err), f"the refusal does not name {entry}: {err!r}"


# -- Sidecar-shaped entries that are not known sidecars ----------------------------------------


@pytest.mark.parametrize("name", [
    "Bad Name.run-end.json",
    "UPPER.scrub-verdict.json",
    f"Bad Name.run-end.json{H.STAGED_TAIL}",
])
def test_1105_a_sidecar_file_whose_owner_is_not_a_run_id_refuses_the_listings(tmp_path, name):
    from defender.records import RunRefused

    t = _good(tmp_path, R1)
    (Path(location_path(t.runs)) / name).write_text("{}\n", encoding="utf-8")
    for fn, call in _listings(t):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{name!r}: {fn} answered or raised {err!r}"
        assert name in H.message(err), f"{fn}'s refusal does not name {name!r}: {err!r}"


@pytest.mark.parametrize("kind", ["link", "fifo"])
def test_1105_a_link_or_fifo_wearing_a_sidecar_name_refuses_the_listings(tmp_path, kind):
    """A known sidecar is a REGULAR file: a link or FIFO at `<r1>.run-end.json` refuses the
    listing, named (r1 is a UUID, so the refusal is the entry kind's, not the id rule's)."""
    from defender.records import RunRefused

    t = _good(tmp_path, R1)
    entry = Path(location_path(t.runs)) / f"{R1}.run-end.json"
    if kind == "link":
        os.symlink(Path(location_path(t.runs)) / R1 / "alert.json", entry)
    else:
        H.make_fifo(entry)
    for fn, call in _listings(t):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"a {kind} sidecar name: {fn} answered or raised {err!r}"
        assert entry.name in H.message(err), f"{fn}'s refusal does not name it: {err!r}"


# -- Lone surrogates -----------------------------------------------------------------------


def test_1105_a_surrogate_escaped_run_id_is_refused_not_a_raw_encoding_error(tmp_path,
                                                                             data_root):
    from defender.records import RunId, RunRefused

    err = H.raised(RunId.parse, "r\udcff1")
    assert H.is_a(err, RunRefused), f"RunId.parse('r\\udcff1') raised {err!r}"
