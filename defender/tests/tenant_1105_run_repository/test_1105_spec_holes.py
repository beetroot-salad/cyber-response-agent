"""#1105 PR 1 — the holes the spec adversary and the guard probes found, closed (owner's ruling).

Each test pins a clause the design states and the rest of this suite drove only by its first
named representative (a link), so an implementation refusing that one state and degrading on
its neighbours (a plain file, a FIFO, a badly named file) stayed green:

* A  — run setup over a non-directory runs folder (O5.4, OP-2);
* B1 — every READER over a linked or file `_episodes` (NM-04, R1, MF-17), and run setup's
       claimed-id check over it;
* B2 — every lookup and record function over a file or FIFO at `tenant.runs` (H2, P2);
* B3 — `runs.open` (PR 1's `open_run`) over a file or FIFO at the run's name (H6 step 4);
* C  — a sidecar-suffixed regular file whose owner `RunId.parse` refuses (rev 4.1, H4);
* S  — a link or FIFO wearing a sidecar's name (rev 4.1: sidecars are regular files; H4);
* D1 — a JSON-escaped lone surrogate in a record (NM-04);
* D2 — a surrogate-escaped run id at `RunId.parse` and run setup (D12.2, P2);
* E  — a foreign `_tenant.json` beside an unexpected entry (NF-8: the tenant check comes first
       and the refusal never carries the folder's entries).

Every input is real on disk. Red against the adversary's exploits (`RUNSETUP_LINK_ONLY`,
`EPISODES_NONDIR_ABSENT`, `ENOTDIR_ABSENT`, `OPENRUN_LINK_ONLY`, `SIDECAR_NO_STEM`,
`SURROGATE_BOUND_FIRST`, `ORDER_LIST_FIRST`) and the guard probe's sidecar-kind mutation.

#1187 (design rev 2) retired three of these: B1 and D1 judged the `_episodes` record and its
readers (`sibling_run_ids`, `episode_sibling_ids`, `episode_runs`), which R6 deletes (D-del);
E judged a foreign `_tenant.json`, which R1 deletes. Their tests are deleted with them; the
replacement — a `_tenant.json` or `_episodes` in `<T>/runs` is an OLD entry the listing refuses,
naming the one-time command — is pinned by
`ids_1187/test_1187_layout_isolation.py::test_the_listing_refuses_a_tenant_record_or_an_episodes_folder`
and `::test_a_pinned_id_is_not_refused_by_an_episodes_claim_and_the_listing_refuses`. B2 keeps
its guard (a file or FIFO at `<T>/runs` refuses every lookup, never an empty answer) over the
functions that remain. Every run id here is a uuid (declared change 1: `RunId` admits nothing
else, so an old-shaped id would be refused by the id rule before the guard under test).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender import _tenant
from defender import run as run_py
from defender import run_common
from defender.tests._fixture_uuid import fixture_uuid
from defender.tests.tenant_1105_run_repository import _spec1105 as H

#: The fixture's run ids (#1187 declared change 1), named by their old handles.
R1, R2 = fixture_uuid("spec-holes-r1"), fixture_uuid("spec-holes-r2")


def _good(tmp_path: Path, *run_ids: str, tenant_id: str = H.T_ID):
    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, tenant_id)
    H.runs_folder(t)
    for rid in run_ids:
        H.make_run(t.runs, rid)
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
    from defender.run_repository import RunId

    return [*_listings(t, run_id),
            ("runs.open", lambda: t.runs_repository().open(RunId.parse(run_id)))]


def _one_line_exit(err: BaseException | None) -> bool:
    return (isinstance(err, SystemExit) and isinstance(err.code, str)
            and len(err.code.splitlines()) == 1)


# -- A: run setup over a non-directory runs folder -------------------------------------------


@pytest.mark.parametrize("kind", ["file", "fifo", "dangling-link"])
def test_1105_run_setup_refuses_a_non_directory_runs_folder_before_creating_anything(
        tmp_path, data_root, kind):
    """A regular file, a FIFO and a dangling link at tenant.runs: run setup raises
    TenantRefused (run.py prints it as '[run.py] ...'), never a raw OSError, and leaves the
    entry as it found it (O5.4: today a file or dangling link raises a raw FileExistsError)."""
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
    err = H.raised(run_common.materialize_run, alert, R1, tenant=t)
    assert isinstance(err, _tenant.TenantRefused), f"{kind}: materialize_run raised {err!r}"
    err = H.raised(run_py._materialize_run, alert, R1, tenant=t, model=None)
    assert H.message(err).startswith("[run.py] "), f"{kind}: run.py gave {err!r}"
    assert not isinstance(err, OSError), f"{kind}: a raw OSError escaped: {err!r}"
    assert os.path.lexists(runs), f"{kind}: run setup removed it"
    assert not runs.is_dir(), f"{kind}: run setup replaced it with a folder"
    assert not (tmp_path / "nowhere").exists(), f"{kind}: run setup followed the link"


# -- B2: every function over a file or FIFO at tenant.runs -------------------------------------


@pytest.mark.parametrize("kind", ["file", "fifo"])
def test_1105_every_function_refuses_a_non_directory_runs_folder(tmp_path, kind):
    """A regular file and a FIFO at tenant.runs are not "absent": every lookup and record
    function raises TenantRefused (H2: every refusal of the hold other than absent) — an open,
    `RunUnreachable` raised from it (#1105 PR 2 review: one refusal family) — never an empty
    answer."""
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
    """A regular file and a FIFO named r2 in the runs folder: runs.open (PR 1's open_run) raises
    RunRefused naming the path; no Run is handed out (H6 step 4: a real directory, anything else
    refuses)."""
    from defender.run_repository import RunId, RunRefused

    t = _good(tmp_path, R1)
    entry = Path(t.runs) / R2
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
    """A regular file with a known sidecar suffix whose `<id>` RunId.parse refuses, beside a
    good run: runs.list raises RunRefused naming it (rev 4.1: known sidecar
    files are named `<id><suffix>` with `<id>` a run id; H4: any other entry refuses)."""
    from defender.run_repository import RunRefused

    t = _good(tmp_path, R1)
    (Path(t.runs) / name).write_text("{}\n", encoding="utf-8")
    for fn, call in _listings(t):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{name!r}: {fn} answered or raised {err!r}"
        assert name in H.message(err), f"{fn}'s refusal does not name {name!r}: {err!r}"


@pytest.mark.parametrize("kind", ["link", "fifo"])
def test_1105_a_link_or_fifo_wearing_a_sidecar_name_refuses_the_listings(tmp_path, kind):
    """A link and a FIFO named `r1.run-end.json` beside run r1: runs.list raises RunRefused
    naming it. A known sidecar is a REGULAR file (rev 4.1). (#1187: r1 is a uuid, so the name
    is a real sidecar name and the refusal is the entry KIND's, not the id rule's.)"""
    from defender.run_repository import RunRefused

    t = _good(tmp_path, R1)
    entry = Path(t.runs) / f"{R1}.run-end.json"
    if kind == "link":
        os.symlink(Path(t.runs) / R1 / "alert.json", entry)
    else:
        H.make_fifo(entry)
    for fn, call in _listings(t):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"a {kind} sidecar name: {fn} answered or raised {err!r}"
        assert entry.name in H.message(err), f"{fn}'s refusal does not name it: {err!r}"


# -- D2: lone surrogates (D1 retired by #1187 R6) ------------------------------------------


def test_1105_a_surrogate_escaped_run_id_is_refused_not_a_raw_encoding_error(tmp_path,
                                                                             data_root):
    """`r\\udcff1` (a surrogate-escaped name, as os.fsdecode gives an undecodable byte) is
    refused by RunId.parse with RunRefused, never a raw UnicodeEncodeError, and run setup exits
    one line `invalid run id: ...` (D12.2: every refusal is RunRefused; deck replay #677)."""
    from defender.run_repository import RunId, RunRefused

    err = H.raised(RunId.parse, "r\udcff1")
    assert H.is_a(err, RunRefused), f"RunId.parse('r\\udcff1') raised {err!r}"
    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    err = H.raised(run_common.materialize_run, alert, "r\udcff1", tenant=t)
    assert _one_line_exit(err), f"run setup over 'r\\udcff1' gave {err!r}"
    assert H.message(err).startswith("invalid run id: "), f"run setup said {err!r}"
