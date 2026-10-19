"""Edge cases: non-directory runs folders and episodes, sidecar names, surrogate escapes."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender import _io, _tenant
from defender import run as run_py
from defender import run_common
from defender.tests.tenant_1105_run_repository import _spec1105 as H


def _good(tmp_path: Path, *run_ids: str, tenant_id: str = H.T_ID):
    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, tenant_id)
    H.runs_folder(t)
    for rid in run_ids:
        H.make_run(t.runs, rid)
    return t


def _listings(t, run_id: str = "r1"):
    """The repository methods that judge the whole runs folder's listing (PR 1's `list_run_ids`;
    `bound_runs` is gone, #1105 PR 2; `run_exists` is gone, #1105 PR 2 review)."""
    return [
        ("runs.list", lambda: t.runs_repository().list()),
    ]


def _every_function(t, *, run_id: str = "r1", episode_id: str = "ep9"):
    from defender.run_repository import (
        RunId, episode_runs, record_episode_runs, sibling_run_ids,
    )

    return [*_listings(t, run_id),
            ("runs.open", lambda: t.runs_repository().open(RunId.parse(run_id))),
            ("record_episode_runs", lambda: record_episode_runs(
                t, episode_id, RunId.parse(run_id), {"a": RunId.parse(f"{episode_id}-a")})),
            ("episode_runs", lambda: episode_runs(t, "ep")),
            ("sibling_run_ids", lambda: sibling_run_ids(t))]


def _one_line_exit(err: BaseException | None) -> bool:
    return (isinstance(err, SystemExit) and isinstance(err.code, str)
            and len(err.code.splitlines()) == 1)


# -- A: run setup over a non-directory runs folder -------------------------------------------


@pytest.mark.parametrize("kind", ["file", "fifo", "dangling-link"])
def test_1105_run_setup_refuses_a_non_directory_runs_folder_before_creating_anything(
        tmp_path, data_root, kind):
    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    runs = Path(t.runs)
    runs.parent.mkdir(parents=True, exist_ok=True)
    if kind == "file":
        runs.write_text("not a folder\n", encoding="utf-8")
    elif kind == "fifo":
        H.make_fifo(runs)
    else:
        os.symlink(tmp_path / "nowhere", runs)
    err = H.raised(run_common.materialize_run, alert, "r1", tenant=t)
    assert isinstance(err, _tenant.TenantRefused), f"{kind}: materialize_run raised {err!r}"
    err = H.raised(run_py._materialize_run, alert, "r1", tenant=t, model=None)
    assert H.message(err).startswith("[run.py] "), f"{kind}: run.py gave {err!r}"
    assert not isinstance(err, OSError), f"{kind}: a raw OSError escaped: {err!r}"
    assert os.path.lexists(runs), f"{kind}: run setup removed it"
    assert not runs.is_dir(), f"{kind}: run setup replaced it with a folder"
    assert not (tmp_path / "nowhere").exists(), f"{kind}: run setup followed the link"


# -- B1: readers over a linked or file `_episodes` ---------------------------------------------


@pytest.mark.parametrize("kind", ["link", "file"])
def test_1105_every_reader_refuses_a_linked_or_file_episodes(tmp_path, data_root, kind):
    from defender.run_repository import RunRefused, episode_sibling_ids, sibling_run_ids

    t = _good(tmp_path, "r0", "ep-a")
    runs = Path(t.runs)
    if kind == "link":
        outside = tmp_path / "outside-runs"
        H.plant_record(outside, "ep", t.id, "r0", {"a": "ep-a", "b": "ep-b"})
        os.symlink(outside / "_episodes", runs / "_episodes")
    else:
        (runs / "_episodes").write_text("{}\n", encoding="utf-8")
    readers = [("runs.list", lambda: t.runs_repository().list()),
               ("sibling_run_ids", lambda: sibling_run_ids(t))]
    for name, call in readers:
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{kind} _episodes: {name} answered or raised {err!r}"
        assert "_episodes" in H.message(err), f"{name}'s refusal does not name _episodes: {err!r}"
    with _io.hold(runs, follow=False) as held:
        err = H.raised(episode_sibling_ids, held.view())
    assert H.is_a(err, RunRefused), f"{kind} _episodes: episode_sibling_ids gave {err!r}"
    assert "_episodes" in H.message(err), f"the path-only refusal does not name it: {err!r}"

    alert = H.alert_file(tmp_path / "in")
    err = H.raised(run_common.materialize_run, alert, "ep-b", tenant=t)
    assert _one_line_exit(err), f"{kind} _episodes: run setup gave {err!r}"
    assert not (runs / "ep-b").exists(), "run setup created a run the broken record folder hid"


# -- B2: every function over a file or FIFO at tenant.runs -------------------------------------


@pytest.mark.parametrize("kind", ["file", "fifo"])
def test_1105_every_function_refuses_a_non_directory_runs_folder(tmp_path, kind):
    from defender.run_repository import RunUnreachable

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root)
    runs = Path(t.runs)
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
    from defender.run_repository import RunId, RunRefused

    t = _good(tmp_path, "r1")
    entry = Path(t.runs) / "r2"
    if kind == "file":
        entry.write_text("x\n", encoding="utf-8")
    else:
        H.make_fifo(entry)
    err = H.raised(t.runs_repository().open, RunId.parse("r2"))
    assert H.is_a(err, RunRefused), f"a {kind} at r2: runs.open gave {err!r}"
    assert str(entry) in H.message(err), f"the refusal does not name {entry}: {err!r}"


# -- C and S: sidecar-shaped entries that are not known sidecars -------------------------------


@pytest.mark.parametrize("name", [
    "Bad Name.run-end.json",
    "UPPER.scrub-verdict.json",
    f"Bad Name.run-end.json{H.STAGED_TAIL}",
])
def test_1105_a_sidecar_file_whose_owner_is_not_a_run_id_refuses_the_listings(tmp_path, name):
    from defender.run_repository import RunRefused

    t = _good(tmp_path, "r1")
    (Path(t.runs) / name).write_text("{}\n", encoding="utf-8")
    for fn, call in _listings(t):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{name!r}: {fn} answered or raised {err!r}"
        assert name in H.message(err), f"{fn}'s refusal does not name {name!r}: {err!r}"


@pytest.mark.parametrize("kind", ["link", "fifo"])
def test_1105_a_link_or_fifo_wearing_a_sidecar_name_refuses_the_listings(tmp_path, kind):
    """A link and a FIFO named `r1.run-end.json` beside run r1: runs.list raises RunRefused
    naming it. A known sidecar is a REGULAR file (rev 4.1)."""
    from defender.run_repository import RunRefused

    t = _good(tmp_path, "r1")
    entry = Path(t.runs) / "r1.run-end.json"
    if kind == "link":
        os.symlink(Path(t.runs) / "r1" / "alert.json", entry)
    else:
        H.make_fifo(entry)
    for fn, call in _listings(t):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"a {kind} sidecar name: {fn} answered or raised {err!r}"
        assert entry.name in H.message(err), f"{fn}'s refusal does not name it: {err!r}"


# -- D1 and D2: lone surrogates --------------------------------------------------------------


def test_1105_a_json_escaped_lone_surrogate_makes_a_record_corrupt(tmp_path):
    from defender.run_repository import (
        RunRefused, episode_runs, episode_sibling_ids, sibling_run_ids,
    )

    t = _good(tmp_path, "r0")
    runs = Path(t.runs)
    raw_label = ('{"episode_id": "ep", "runs": {"\\ud800": "ep-a"}, "source_run_id": "r0", '
                 f'"tenant_id": "{t.id}"}}')
    H.plant_record(runs, "ep", t.id, "r0", {}, raw=raw_label)
    for name, call in [("episode_runs", lambda: episode_runs(t, "ep")),
                       ("sibling_run_ids", lambda: sibling_run_ids(t))]:
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"an escaped surrogate label: {name} gave {err!r}"
        assert "ep.json" in H.message(err), f"{name}'s refusal does not name the file: {err!r}"

    raw_tenant = ('{"episode_id": "ep", "runs": {"a": "ep-a"}, "source_run_id": "r0", '
                  '"tenant_id": "\\ud800"}')
    H.plant_record(runs, "ep", t.id, "r0", {}, raw=raw_tenant)
    with _io.hold(runs, follow=False) as held:
        err = H.raised(episode_sibling_ids, held.view())
    assert H.is_a(err, RunRefused), f"an escaped surrogate tenant_id: path-only reader {err!r}"
    assert "ep.json" in H.message(err), f"the path-only refusal does not name the file: {err!r}"


def test_1105_a_surrogate_escaped_run_id_is_refused_not_a_raw_encoding_error(tmp_path,
                                                                             data_root):
    from defender.run_repository import RunId, RunRefused

    err = H.raised(RunId.parse, "r\udcff1")
    assert H.is_a(err, RunRefused), f"RunId.parse('r\\udcff1') raised {err!r}"
    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    err = H.raised(run_common.materialize_run, alert, "r\udcff1", tenant=t)
    assert _one_line_exit(err), f"run setup over 'r\\udcff1' gave {err!r}"
    assert H.message(err).startswith("invalid run id: "), f"run setup said {err!r}"


# -- E: the tenant record is judged before the listing -----------------------------------------


def test_1105_a_foreign_record_beside_an_odd_entry_refuses_on_the_record(tmp_path):
    t = _good(tmp_path, "r1")
    runs = Path(t.runs)
    H.plant_tenant_record(runs, H.U_ID)
    odd = "Beta Legacy Case 7"
    (runs / odd).mkdir()
    for fn, call in _listings(t):
        err = H.raised(call)
        assert H.is_a(err, _tenant.TenantRefused), f"{fn} gave {err!r}"
        text = H.message(err)
        assert "_tenant.json" in text, f"{fn}'s refusal does not name the record: {err!r}"
        assert odd not in text, f"{fn}'s refusal carries the folder's entry: {err!r}"
