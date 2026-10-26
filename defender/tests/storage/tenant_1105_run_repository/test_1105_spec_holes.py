"""Edge cases: non-directory runs folders and episodes, sidecar names, surrogate escapes."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import os
from pathlib import Path

import pytest

from defender.tenancy import _tenant
from defender import run as run_py
from defender import run_common
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.support.shared._fixture_uuid import fixture_uuid

#: The fixture's run ids (#1187 declared change 1), named by their old handles.
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
    """The repository methods that judge the whole runs folder's listing (PR 1's `list_run_ids`;
    `bound_runs` is gone, #1105 PR 2; `run_exists` is gone, #1105 PR 2 review)."""
    return [
        ("runs.list", lambda: t.runs_repository().list()),
    ]


def _every_function(t, *, run_id: str = R1):
    """Every lookup over the natural container. #1187 (R6, D-del): `record_episode_runs`,
    `episode_runs` and `sibling_run_ids` are deleted with the `_episodes` record."""
    from defender.records import RunId

    return [*_listings(t, run_id),
            ("runs.open", lambda: t.runs_repository().open(RunId.parse(run_id)))]


# -- A: run setup over a non-directory runs folder -------------------------------------------


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
    assert isinstance(err, _tenant.TenantRefused), f"{kind}: materialize_run raised {err!r}"
    err = H.raised(run_py._materialize_run, alert, tenant=t, model=None)
    assert H.message(err).startswith("[run.py] "), f"{kind}: run.py gave {err!r}"
    assert not isinstance(err, OSError), f"{kind}: a raw OSError escaped: {err!r}"
    assert os.path.lexists(runs), f"{kind}: run setup removed it"
    assert not runs.is_dir(), f"{kind}: run setup replaced it with a folder"
    assert not (tmp_path / "nowhere").exists(), f"{kind}: run setup followed the link"


# -- B1: readers over a linked or file `_episodes` ---------------------------------------------




# -- B2: every function over a file or FIFO at tenant.runs -------------------------------------


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
        assert H.is_a(err, _tenant.TenantRefused), (
            f"a {kind} at tenant.runs: {name} answered or raised {err!r}")


# -- B3: runs.open over a non-directory at the run's name --------------------------------------


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


# -- C and S: sidecar-shaped entries that are not known sidecars -------------------------------


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
    """A link and a FIFO named `r1.run-end.json` beside run r1: runs.list raises RunRefused
    naming it. A known sidecar is a REGULAR file (rev 4.1). (#1187: r1 is a uuid, so the name
    is a real sidecar name and the refusal is the entry KIND's, not the id rule's.)"""
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


# -- D2: lone surrogates (D1 retired by #1187 R6) ------------------------------------------


def test_1105_a_surrogate_escaped_run_id_is_refused_not_a_raw_encoding_error(tmp_path,
                                                                             data_root):
    from defender.records import RunId, RunRefused

    err = H.raised(RunId.parse, "r\udcff1")
    assert H.is_a(err, RunRefused), f"RunId.parse('r\\udcff1') raised {err!r}"


# -- E: the tenant record is judged before the listing -----------------------------------------
