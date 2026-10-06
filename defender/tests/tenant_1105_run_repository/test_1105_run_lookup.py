"""#1105 PR 1 — run lookup (D2, D2.0; O1, O3, S1, S2; P1/P2 and the expected states).

`open_run(tenant, run_id)`, `list_run_ids(tenant)`, `bound_runs(tenant)` and
`run_exists(tenant, run_id)` take an accepted `Tenant` and a `RunId`; the runs folder is always
`tenant.runs`. Each call opens it ONCE with `_io.hold(tenant.runs, follow=False)` (amendment A,
DV-1) and works only relative to that handle: the tenant record is judged by `read_tenant`
served through the held view plus an exact compare (DV-3), the folder's entries are listed once
and judged from the directory entry (D2.4), and an entry is judged by `stat_entry` (D2 step 4).
P2: an unexpected state raises ONE named error — `TenantRefused` for the runs folder and its
`_tenant.json`, `RunRefused` otherwise — naming the path and the fault, never a raw `OSError`.
The expected states answer normally: an absent runs folder (empty answers), an absent
`_episodes` (no claims), and the known sidecar files beside run folders (a staged one included).
The P2 representatives here are: a link at `tenant.runs`, a `_tenant.json` naming another
tenant, and a link at a run's name.

COINED INTERFACE (the implementer matches these names, or renames them here):
* every lookup and record function takes a keyword-only `io=` seam, default the real
  `defender._io` (as `Run.for_tenant(..., io=)` does). Observed with `H.RecordingIO()`: a
  function's single no-follow open is one recorded `hold(tenant.runs, follow=False)` call, and
  the `Run` `open_run` hands out reads through the same seam (`run.facts.alert.read()` records
  `rooted_read`). The seam is never used to inject a fault (the owner's test shape).
* `bound_runs(tenant)` is a context manager: `with bound_runs(t) as runs:` gives `runs.absent`
  (a bool; there is no `reason`), and `for rid, w in runs:` yields `(RunId, w)` rows in
  `list_run_ids`' order. The row wrapper `w` serves `w.read(name)`, answering like
  `Bound.read` (a RecordRead-shaped answer with `.text` / `.absent`) but RAISING `RunRefused`
  where `Bound.read` would answer a `reason`, and after the block; `w.entries()` likewise. The
  object is single use: a second `with` on it, or iterating one never entered, raises
  `RunRefused`.
* `open_run` builds its `Run` with `Run.under(tenant.runs, str(run_id), tenant_id=tenant.id)`
  (DV-2): the tenant record is read once, through the held view, never again by path.

Every fault is a real input on the real filesystem: links (`os.symlink`), records naming another
tenant, a UTF-8 BOM, a 200,000-deep record, names carrying control characters.

Red at base 80888efb: every test imports what it drives from `defender.run_repository`, which
does not exist, so each fails at its own import (`ModuleNotFoundError`).
"""
from __future__ import annotations

import copy
import gc
import inspect
import json
import os
import pickle
import shutil
from pathlib import Path

from defender import _io
from defender import _tenant
from defender import run_common
from defender._tenant import TenantRecordMismatch, TenantRefused, read_tenant
from defender.tests.tenant_1105_run_repository import _spec1105 as H

DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"


# ==========================================================================================
# Same-file helpers: they build state and hand answers back; the tests assert.
# ==========================================================================================

def _good(tmp_path: Path, *run_ids: str, tenant_id: str = H.T_ID):
    """A data root holding `tenant_id` with a checked runs folder (its `_tenant.json` naming it)
    and a real run folder per id."""
    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, tenant_id)
    H.runs_folder(t)
    for rid in run_ids:
        H.make_run(t.runs, rid)
    return root, t


def _bound_ids(t, **kw) -> list[str]:
    """The ids `bound_runs(t)` yields, entering and leaving the block."""
    from defender.run_repository import bound_runs

    with bound_runs(t, **kw) as runs:
        return [str(rid) for rid, _w in runs]


def _ids(answer) -> list[str]:
    return [str(i) for i in answer]


def _every_function(t, *, run_id: str = "r1", episode_id: str = "ep9"):
    """`(name, thunk)` per lookup and tenant-keyed record function, each over `t`."""
    from defender.run_repository import (
        RunId, episode_runs, list_run_ids, open_run, record_episode_runs, run_exists,
        sibling_run_ids,
    )

    return [
        ("open_run", lambda: open_run(t, RunId.parse(run_id))),
        ("list_run_ids", lambda: list_run_ids(t)),
        ("bound_runs", lambda: _bound_ids(t)),
        ("run_exists", lambda: run_exists(t, RunId.parse(run_id))),
        ("record_episode_runs", lambda: record_episode_runs(
            t, episode_id, RunId.parse(run_id), {"a": RunId.parse(f"{episode_id}-a")})),
        ("episode_runs", lambda: episode_runs(t, "ep")),
        ("sibling_run_ids", lambda: sibling_run_ids(t)),
    ]


def _reader_answers(t, **kw) -> dict:
    """What every lookup and record reader answers over `t`, as plain values."""
    from defender.run_repository import (
        RunId, episode_runs, list_run_ids, open_run, run_exists, sibling_run_ids,
    )

    r1 = RunId.parse("r1")
    run = open_run(t, r1, **kw)
    return {
        "open_run": (str(run.run_dir), str(getattr(run, "tenant_id", None))),
        "list_run_ids": _ids(list_run_ids(t, **kw)),
        "bound_runs": _bound_ids(t, **kw),
        "run_exists": run_exists(t, r1, **kw) is True,
        "episode_runs": {k: str(v) for k, v in dict(episode_runs(t, "ep", **kw)).items()},
        "sibling_run_ids": sorted(str(i) for i in sibling_run_ids(t, **kw)),
    }


def _hold_calls(rec: H.RecordingIO):
    return rec.named("hold")


def _is_one_nofollow_hold_of(rec: H.RecordingIO, runs: Path) -> bool:
    holds = _hold_calls(rec)
    if len(holds) != 1 or not holds[0][0] or not isinstance(holds[0][0][0], (str, os.PathLike)):
        return False
    return Path(holds[0][0][0]) == Path(runs) and holds[0][1].get("follow") is False


#: Run names just outside the sidecar clause (MF-21 B; I061, DV-5): no sidecar suffix at the
#: end, or a staged tail that is not lowercase hex. Each is a run.
_OUTSIDE_THE_SIDECAR_CLAUSE = ("r1.run-end.json-2", "run-end.json", "r1.run-end.json.staged-g")


def _swap_record(runs: Path, tenant_id: str) -> None:
    rec = Path(runs) / "_tenant.json"
    rec.unlink()
    H.plant_tenant_record(runs, tenant_id)


def _episodes_to_link(runs: Path, scratch: Path) -> None:
    """Move `<runs>/_episodes` out of the runs folder and leave a link to it in its place."""
    real = Path(scratch) / "episodes-real"
    os.rename(Path(runs) / "_episodes", real)
    os.symlink(real, Path(runs) / "_episodes")


def _episodes_from_link(runs: Path, scratch: Path) -> None:
    """Undo `_episodes_to_link`."""
    os.unlink(Path(runs) / "_episodes")
    os.rename(Path(scratch) / "episodes-real", Path(runs) / "_episodes")


# ==========================================================================================
# open_run's return contract and its checks.
# ==========================================================================================

def test_1105_open_run_returns_the_tenants_run_under_tenant_runs(tmp_path):
    """open_run(tenant, RunId.parse(id)) over a runs folder whose _tenant.json names the tenant
    and whose entry tenant.runs/<id> is a real directory returns the Run that
    Run.under(tenant.runs, id, tenant_id=tenant.id) builds: its tenant_id is tenant.id, its
    runs_base is tenant.runs (tenant.data_root / tenant.id / 'runs'), its run_dir is
    tenant.runs / id; the tenant record is read once, through the held view, and not a second
    time by path (Run.for_tenant would re-read it, R41-18); nothing is written. Observed through
    the recording io= seam: one no-follow hold of tenant.runs and no path read of _tenant.json."""
    from defender.run_repository import Run, RunId, open_run

    root, t = _good(tmp_path, "r1")
    before = H.tree_state(root)
    rec = H.RecordingIO()
    run = open_run(t, RunId.parse("r1"), io=rec)
    assert run.run_dir == t.runs / "r1", f"open_run handed out run_dir {run.run_dir!r}"
    assert run.runs_base == t.runs == t.data_root / t.id / "runs", run.runs_base
    assert run.tenant_id == t.id, run.tenant_id
    built = Run.under(t.runs, "r1", tenant_id=t.id)
    assert type(run) is type(built), "open_run hands out Run.under's Run"
    assert ((run.run_dir, run.runs_base, run.tenant_id) == (
        built.run_dir, built.runs_base, built.tenant_id)), "open_run hands out Run.under's Run"
    record = t.runs / "_tenant.json"
    path_reads = [(n, a) for n, a, _k in rec.calls
                  if n in ("read_guarded", "entry_present", "read_plain", "read_text_soft")
                  and a and isinstance(a[0], (str, os.PathLike)) and Path(a[0]) == record]
    assert not path_reads, f"the tenant record was read again by path: {path_reads}"
    assert _is_one_nofollow_hold_of(rec, t.runs), f"holds: {_hold_calls(rec)}"
    assert H.tree_state(root) == before, "open_run wrote something"


def test_1105_every_tenant_keyed_function_raises_type_error_before_any_read(tmp_path):
    """Each lookup and tenant-keyed record function raises TypeError, before reading anything,
    when its first argument is not an accepted Tenant (a tenant id str, a TenantId, a
    runs-folder Path, a RunTenant) or when a run id it takes (open_run's and run_exists' run_id,
    the writer's source and arm ids) is not a RunId, a str included; the proof that nothing was
    read is a runs folder planted as a link, which would otherwise refuse with TenantRefused,
    and a recording io= seam passed to each refused call records no call at all. Positive
    control: the same calls with an accepted Tenant and RunIds answer."""
    from defender.run_repository import (
        RunId, bound_runs, episode_runs, list_run_ids, open_run, record_episode_runs,
        run_exists, sibling_run_ids,
    )
    from defender.runtime.run_tenant import RunTenant

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    elsewhere = tmp_path / "elsewhere"
    H.plant_tenant_record(elsewhere, t.id)
    H.make_run(elsewhere, "r1")
    os.symlink(elsewhere, t.runs)
    rid, src, arm = RunId.parse("r1"), RunId.parse("r1"), RunId.parse("ep-a")
    carrier = RunTenant(tenant=t, grants=None, correlation=None, systems={}, elastic=None,
                        ticket_mapping=None)

    def enter(x, **kw):
        with bound_runs(x, **kw) as runs:
            return list(runs)

    not_tenants = (t.id, _tenant.TenantId(t.id), t.runs, carrier)
    for bad in not_tenants:
        for name, call in (
            ("open_run", lambda io, bad=bad: open_run(bad, rid, io=io)),
            ("list_run_ids", lambda io, bad=bad: list_run_ids(bad, io=io)),
            ("bound_runs", lambda io, bad=bad: enter(bad, io=io)),
            ("run_exists", lambda io, bad=bad: run_exists(bad, rid, io=io)),
            ("record_episode_runs",
             lambda io, bad=bad: record_episode_runs(bad, "ep", src, {"a": arm}, io=io)),
            ("episode_runs", lambda io, bad=bad: episode_runs(bad, "ep", io=io)),
            ("sibling_run_ids", lambda io, bad=bad: sibling_run_ids(bad, io=io)),
        ):
            rec = H.RecordingIO()
            err = H.raised(call, rec)
            assert type(err) is TypeError, f"{name}({type(bad).__name__}) raised {err!r}"
            assert not rec.calls, (
                f"{name}({type(bad).__name__}) touched the seam before its TypeError: {rec.calls}")
    for name, call in (
        ("open_run", lambda io: open_run(t, "r1", io=io)),
        ("run_exists", lambda io: run_exists(t, "r1", io=io)),
        ("record_episode_runs/source",
         lambda io: record_episode_runs(t, "ep", "r1", {"a": arm}, io=io)),
        ("record_episode_runs/arm",
         lambda io: record_episode_runs(t, "ep", src, {"a": "ep-a"}, io=io)),
    ):
        rec = H.RecordingIO()
        err = H.raised(call, rec)
        assert type(err) is TypeError, f"{name} with a str run id raised {err!r}"
        assert not rec.calls, f"{name} touched the seam before its TypeError: {rec.calls}"
    # The link would have refused: the TypeError fired before the hold read anything.
    err = H.raised(list_run_ids, t)
    assert H.is_a(err, TenantRefused), f"the linked runs folder did not refuse: {err!r}"
    # Positive control: a real runs folder and RunIds answer.
    os.unlink(t.runs)
    H.runs_folder(t)
    H.make_run(t.runs, "r1")
    assert open_run(t, rid).run_dir == t.runs / "r1", "open_run over a good folder"
    assert _ids(list_run_ids(t)) == ["r1"], "list_run_ids over a good folder"
    assert enter(t), "bound_runs / run_exists over a good folder"
    assert run_exists(t, rid) is True, "bound_runs / run_exists over a good folder"
    assert record_episode_runs(t, "ep", src, {"a": arm}) is None, "the writer answers"
    assert {k: str(v) for k, v in episode_runs(t, "ep").items()} == {"a": "ep-a"}
    assert _ids(sibling_run_ids(t)) == ["ep-a"], "sibling_run_ids reads the written record"


def test_1105_the_repository_answers_from_the_tenant_it_is_handed_and_reads_no_environment(
        tmp_path, monkeypatch):
    """With DEFENDER_DATA_ROOT unset or naming another data root, and with the tenant's knowledge
    folder removed after acceptance, every lookup and record function answers exactly as before
    from tenant.runs of the Tenant it was handed. Positive control: accept_tenant at the edge
    refuses the same tenant once its knowledge folder is gone."""
    from defender.run_repository import RunId, record_episode_runs

    root, t = _good(tmp_path, "r1", "r2")
    H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})
    H.make_run(t.runs, "ep-a")
    expected = {
        "open_run": (str(t.runs / "r1"), t.id), "list_run_ids": ["r1", "r2"],
        "bound_runs": ["r1", "r2"], "run_exists": True, "episode_runs": {"a": "ep-a"},
        "sibling_run_ids": ["ep-a"],
    }
    assert _reader_answers(t) == expected, f"baseline answers: {_reader_answers(t)}"
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)
    assert _reader_answers(t) == expected, "answers moved with DEFENDER_DATA_ROOT unset"
    other_root = tmp_path / "other-root"
    H.tenant(other_root, t.id)
    monkeypatch.setenv(DATA_ROOT_ENV, str(other_root))
    assert _reader_answers(t) == expected, "answers moved with DEFENDER_DATA_ROOT elsewhere"
    shutil.rmtree(t.knowledge)
    assert _reader_answers(t) == expected, "answers moved with the knowledge folder gone"
    assert record_episode_runs(t, "ep2", RunId.parse("r2"),
                               {"b": RunId.parse("ep2-b")}) is None, "the writer still answers"
    assert (t.runs / "_episodes" / "ep2.json").is_file(), "the record landed under tenant.runs"
    assert not (other_root / t.id / "runs" / "_episodes").exists(), "nothing reached the env root"
    err = H.raised(_tenant.accept_tenant, root, t.id, defender_dir=H.DEFENDER)
    assert H.is_a(err, TenantRefused), f"acceptance at the edge did not refuse: {err!r}"


def test_1105_a_copied_or_pickled_tenant_is_served_like_the_original(tmp_path):
    """A copy.copy, a copy.deepcopy and a pickle round trip of an accepted Tenant are served by
    open_run, list_run_ids and sibling_run_ids exactly as the original is."""
    from defender.run_repository import RunId, list_run_ids, open_run, sibling_run_ids

    _root, t = _good(tmp_path, "r1", "r2")
    H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})
    H.make_run(t.runs, "ep-a")

    def answers(x):
        run = open_run(x, RunId.parse("r2"))
        return (str(run.run_dir), str(getattr(run, "tenant_id", None)), _ids(list_run_ids(x)),
                sorted(str(i) for i in sibling_run_ids(x)))

    original = answers(t)
    assert original == (str(t.runs / "r2"), t.id, ["r1", "r2"], ["ep-a"]), original
    for twin in (copy.copy(t), copy.deepcopy(t), pickle.loads(pickle.dumps(t))):
        assert answers(twin) == original, f"a copied Tenant was served differently: {twin!r}"


def test_1105_every_repository_function_takes_an_injected_io_like_the_handle(tmp_path):
    """Every lookup and record function takes a keyword-only injected I/O seam (default: the real
    defender._io), passes it to the Run it hands out, and routes its own held open through it
    (_io.hold(..., os_=)), so a recording seam sees each function's single no-follow open of
    tenant.runs. The suite uses the seam to observe calls, never to inject an I/O fault (test
    shape)."""
    from defender.run_repository import (
        RunId, bound_runs, episode_runs, episode_sibling_ids, list_run_ids, open_run,
        record_episode_runs, run_exists, sibling_run_ids,
    )

    _root, t = _good(tmp_path, "r1")
    functions = (open_run, list_run_ids, bound_runs, run_exists, record_episode_runs,
                 episode_runs, sibling_run_ids, episode_sibling_ids)
    for fn in functions:
        params = inspect.signature(fn).parameters
        assert "io" in params, f"{getattr(fn, '__name__', fn)} takes no io= seam"
        assert params["io"].kind is inspect.Parameter.KEYWORD_ONLY, f"{fn.__name__}: io= kind"
        assert params["io"].default is _io, f"{fn.__name__}: io= defaults to {params['io'].default!r}"
    rid = RunId.parse("r1")
    cases = (
        ("open_run", lambda io: open_run(t, rid, io=io)),
        ("list_run_ids", lambda io: list_run_ids(t, io=io)),
        ("bound_runs", lambda io: _bound_ids(t, io=io)),
        ("run_exists", lambda io: run_exists(t, rid, io=io)),
        ("record_episode_runs", lambda io: record_episode_runs(
            t, "ep", rid, {"a": RunId.parse("ep-a")}, io=io)),
        ("episode_runs", lambda io: episode_runs(t, "ep", io=io)),
        ("sibling_run_ids", lambda io: sibling_run_ids(t, io=io)),
    )
    for name, call in cases:
        rec = H.RecordingIO()
        call(rec)
        assert _is_one_nofollow_hold_of(rec, t.runs), f"{name}: holds {_hold_calls(rec)}"
    rec = H.RecordingIO()
    run = open_run(t, rid, io=rec)
    seen = len(rec.calls)
    run.facts.alert.read()
    assert any(n == "rooted_read" for n, _a, _k in rec.calls[seen:]), (
        "the Run open_run hands out does not read through the injected seam")
    with _io.hold(t.runs) as held:
        rec = H.RecordingIO()
        claimed = episode_sibling_ids(held.view(), io=rec)
        assert _ids(claimed) == ["ep-a"], f"episode_sibling_ids(io=) answered {claimed!r}"
        assert not _hold_calls(rec), "episode_sibling_ids opened a folder of its own"
    err = H.raised(list_run_ids, t, H.RecordingIO())
    assert type(err) is TypeError, f"io passed positionally was accepted: {err!r}"


# ==========================================================================================
# The name rule, the entry rule and run_exists.
# ==========================================================================================

def test_1105_open_run_refuses_each_sidecar_suffixed_id_as_run_refused(tmp_path):
    """open_run refuses with RunRefused an id ending in each of the four host-only sidecar
    suffixes (.run-end.json, .scrub-verdict.json, .accounting_failures.json, .ticket-write.json)
    and an id of the staged shape (a sidecar suffix, then '.staged-', then lowercase hex
    digits), even when the runs folder is absent (the clause runs before the hold). Positive
    control: 'r1' over a good folder holding r1 opens, and so does each name just outside the
    clause, a real run folder named 'r1.run-end.json-2', 'run-end.json' or
    'r1.run-end.json.staged-g' (no sidecar suffix at the end; a staged tail that is not lowercase
    hex)."""
    from defender.run_repository import RunId, RunRefused, open_run

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    names = ([f"r1{s}" for s in H.SIDECAR_SUFFIXES]
             + [f"r1.run-end.json{H.STAGED_TAIL}", "r1.ticket-write.json.staged-0",
                f"r1.accounting_failures.json{H.STAGED_TAIL}"])
    for name in names:
        err = H.raised(open_run, t, RunId.parse(name))
        assert H.is_a(err, RunRefused), f"open_run({name!r}) over an absent folder gave {err!r}"
        assert name in H.message(err), f"the refusal does not name {name!r}: {H.message(err)}"
    assert not t.runs.exists(), "a refused name created the runs folder"
    H.runs_folder(t)
    H.make_run(t.runs, "r1")
    for name in names:
        os.mkdir(t.runs / name)  # even a real directory at the name is never opened as a run
        err = H.raised(open_run, t, RunId.parse(name))
        assert H.is_a(err, RunRefused), f"open_run({name!r}) over a good folder gave {err!r}"
        os.rmdir(t.runs / name)
    assert open_run(t, RunId.parse("r1")).run_dir == t.runs / "r1", "r1 opens"
    for name in _OUTSIDE_THE_SIDECAR_CLAUSE:
        H.make_run(t.runs, name)
        assert open_run(t, RunId.parse(name)).run_dir == t.runs / name, (
            f"{name!r} is a run, not a sidecar-shaped id (MF-21 B's boundary), and does not open")


def test_1105_a_directory_named_like_a_sidecar_or_staged_sidecar_makes_the_listings_refuse(
        tmp_path):
    """A real directory named 'r1.run-end.json', or 'r1.run-end.json.staged-0123456789abcdef', in
    tenant.runs makes list_run_ids, bound_runs and run_exists raise RunRefused naming it (a
    directory is not a known sidecar file, and the sidecar clause refuses it as a run). Positive
    control: the same folder with a regular file of each name beside the run r1 lists r1, and a
    real directory named 'r1.run-end.json-2', 'run-end.json' or 'r1.run-end.json.staged-g' is
    a run both listings list."""
    from defender.run_repository import RunId, RunRefused, list_run_ids, run_exists

    _root, t = _good(tmp_path, "r1")
    for name in ("r1.run-end.json", f"r1.run-end.json{H.STAGED_TAIL}"):
        os.mkdir(t.runs / name)
        for fn, call in (("list_run_ids", lambda: list_run_ids(t)),
                         ("bound_runs", lambda: _bound_ids(t)),
                         ("run_exists", lambda: run_exists(t, RunId.parse("r1")))):
            err = H.raised(call)
            assert H.is_a(err, RunRefused), f"{fn} over a directory named {name!r} gave {err!r}"
            assert name in H.message(err), f"{fn}'s refusal does not name {name!r}"
        os.rmdir(t.runs / name)
        (t.runs / name).write_text("{}\n", encoding="utf-8")
    assert _ids(list_run_ids(t)) == ["r1"], "regular sidecar files beside r1 list as r1"
    assert _bound_ids(t) == ["r1"], "bound_runs lists r1 beside its sidecar files"
    for name in _OUTSIDE_THE_SIDECAR_CLAUSE:
        H.make_run(t.runs, name)
    runs_now = sorted(["r1", *_OUTSIDE_THE_SIDECAR_CLAUSE])
    assert _ids(list_run_ids(t)) == runs_now, (
        f"names just outside the sidecar clause are runs (MF-21 B): {_ids(list_run_ids(t))}")
    assert _bound_ids(t) == runs_now, f"bound_runs: {_bound_ids(t)}"


def test_1105_run_exists_is_true_for_a_run_or_a_sidecar_file_and_false_for_nothing(tmp_path):
    """run_exists(tenant, id) reads the held listing: it answers True when a run or a known
    sidecar file (a staged one included) is at the name, and False when nothing is; it does not
    apply the sidecar clause to its argument. An unexpected entry, at the name or elsewhere in
    the folder, refuses (p2_run_entry_link_refuses)."""
    from defender.run_repository import RunId, run_exists

    _root, t = _good(tmp_path, "r1")
    H.plant_sidecars(t.runs, "r1")
    assert run_exists(t, RunId.parse("r1")) is True, "a run at the name"
    for suffix in H.SIDECAR_SUFFIXES:
        assert run_exists(t, RunId.parse(f"r1{suffix}")) is True, f"a sidecar r1{suffix}"
    assert run_exists(t, RunId.parse(f"r1.run-end.json{H.STAGED_TAIL}")) is True, "staged"
    assert run_exists(t, RunId.parse("r9")) is False, "nothing at r9"
    assert run_exists(t, RunId.parse("r9.run-end.json")) is False, (
        "a sidecar-suffixed id with nothing at it is False, not refused: no sidecar clause here")


def test_1105_a_refused_name_is_never_probed_on_disk(tmp_path):
    """Through the repository's injected seam, used to record calls and never to inject a fault,
    open_run(tenant, <sidecar-suffixed RunId>) makes no filesystem call before raising
    RunRefused. Positive control: open_run(tenant, RunId.parse('r1')) through the same seam
    opens tenant.runs once, no-follow, and stats the entry."""
    from defender.run_repository import RunId, RunRefused, open_run

    _root, t = _good(tmp_path, "r1")
    rec = H.RecordingIO()
    err = H.raised(open_run, t, RunId.parse("r1.run-end.json"), io=rec)
    assert H.is_a(err, RunRefused), f"a sidecar-suffixed id gave {err!r}"
    assert rec.calls == [], f"a refused name was probed: {rec.calls}"
    rec = H.RecordingIO()
    assert open_run(t, RunId.parse("r1"), io=rec).run_dir == t.runs / "r1", "r1 opens"
    assert _is_one_nofollow_hold_of(rec, t.runs), f"holds: {_hold_calls(rec)}"
    stats = [a for n, a, _k in rec.calls
             if (n == "stat_entry" and len(a) > 1 and str(a[1]) == "r1") or n == "stat_entries"]
    assert stats, f"the entry was not stat'ed through the seam: {rec.calls}"


def test_1105_every_listed_id_opens_with_open_run(tmp_path):
    """Over a runs folder holding real runs, their sidecar files (a staged one included),
    _tenant.json and _episodes/, every id list_run_ids returns opens with open_run, and its Run's
    run_dir is that real directory."""
    from defender.run_repository import list_run_ids, open_run

    _root, t = _good(tmp_path, "r1", "r2", "2026-x.y_z")
    H.plant_sidecars(t.runs, "r1")
    H.plant_sidecars(t.runs, "r2", staged=False)
    H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})
    listed = list_run_ids(t)
    assert _ids(listed) == ["2026-x.y_z", "r1", "r2"], f"listed {_ids(listed)}"
    for rid in listed:
        run = open_run(t, rid)
        assert run.run_dir == t.runs / str(rid), f"{rid!r} opened at {run.run_dir}"
        assert run.run_dir.is_dir(), f"{run.run_dir} is real"
        assert not run.run_dir.is_symlink(), f"{run.run_dir} is real"


def test_1105_the_lookups_refuse_a_tenant_record_exactly_when_read_tenant_does(tmp_path):
    """The lookups judge _tenant.json by read_tenant served through the held view: a record
    read_tenant admits with an extra key is served, a record read_tenant refuses (a UTF-8 BOM)
    refuses with TenantRefused, and a record whose read raises anything else (200,000-deep
    nesting, where read_tenant raises RecursionError) refuses with TenantRefused, never the raw
    error; the record's tenant_id is then compared with tenant.id exactly."""
    from defender.run_repository import RunId, list_run_ids, open_run, run_exists

    _root, t = _good(tmp_path, "r1")
    record = t.runs / "_tenant.json"
    good = json.loads(H.tenant_record_text(t.id))

    def lookups():
        return (("open_run", lambda: open_run(t, RunId.parse("r1"))),
                ("list_run_ids", lambda: list_run_ids(t)),
                ("run_exists", lambda: run_exists(t, RunId.parse("r1"))))

    record.write_text(json.dumps({**good, "extra": 1}), encoding="utf-8")
    assert read_tenant(t.runs).tenant_id == t.id, "read_tenant admits an extra key"
    assert _ids(list_run_ids(t)) == ["r1"], "a record with an extra key is served"
    assert open_run(t, RunId.parse("r1")).run_dir == t.runs / "r1", "open_run served it"
    record.write_bytes(b"\xef\xbb\xbf" + json.dumps(good).encode())
    assert H.is_a(H.raised(read_tenant, t.runs), TenantRefused), "read_tenant refuses a BOM"
    for name, call in lookups():
        err = H.raised(call)
        assert H.is_a(err, TenantRefused), f"{name} over a BOM record gave {err!r}"
    record.write_text(H.deep_json(), encoding="utf-8")
    assert H.raised(read_tenant, t.runs) is not None, "read_tenant does not admit it"
    for name, call in lookups():
        err = H.raised(call)
        assert H.is_a(err, TenantRefused), f"{name} over a 200,000-deep record gave {err!r}"
        assert not isinstance(err, RecursionError), f"{name} let the raw error out"
    record.write_text(json.dumps({**good, "tenant_id": f"{t.id}-2"}), encoding="utf-8")
    for name, call in lookups():
        err = H.raised(call)
        assert H.is_a(err, TenantRefused), f"{name} over a record naming {t.id}-2 gave {err!r}"


def test_1105_an_other_tenant_refusal_names_the_file_and_the_id_and_no_run_of_that_tenant(
        tmp_path):
    """When _tenant.json names another tenant, the TenantRefused message names the record file
    and the tenant id found and carries none of the run ids present in that folder. Positive
    control: the message does carry the found id. A _tenant.json whose tenant id holds a newline
    and an ESC still refuses with TenantRefused naming the record file, and the message carries
    no raw control character and no run id (design NF-8: text read from disk is quoted
    repr-style)."""
    from defender.run_repository import RunId, list_run_ids, open_run, run_exists

    root, t = _good(tmp_path, "zq-run-alpha", "zq-run-omega")
    _swap_record(t.runs, H.U_ID)
    record = str(t.runs / "_tenant.json")
    for name, call in (("open_run", lambda: open_run(t, RunId.parse("asked-1"))),
                       ("list_run_ids", lambda: list_run_ids(t)),
                       ("run_exists", lambda: run_exists(t, RunId.parse("asked-1")))):
        err = H.raised(call)
        assert H.is_a(err, TenantRefused), f"{name} gave {err!r}"
        text = H.message(err)
        assert record in text, f"{name}'s refusal does not name {record}: {text}"
        assert H.U_ID in text, f"{name}'s refusal does not name the found id: {text}"
        assert "zq-run" not in text, f"{name}'s refusal leaks a run id: {text}"
    _swap_record(t.runs, "beta\n\x1b[31m forged")
    for name, call in (("open_run", lambda: open_run(t, RunId.parse("asked-1"))),
                       ("list_run_ids", lambda: list_run_ids(t)),
                       ("run_exists", lambda: run_exists(t, RunId.parse("asked-1")))):
        err = H.raised(call)
        assert H.is_a(err, TenantRefused), f"{name} over a control-character id gave {err!r}"
        text = H.message(err)
        assert record in text, f"{name}'s refusal does not name {record}: {text!r}"
        assert not H.has_raw_control(text), (
            f"{name}'s refusal carries the disk-read id raw: {text!r}")
        assert "zq-run" not in text, f"{name}'s refusal leaks a run id: {text!r}"


def test_1105_refusal_text_quotes_names_repr_style_and_truncates_long_ones(tmp_path):
    """A refusal that quotes a caller-supplied name (RunId.parse('a\\nb'), an episode id 'ep\\n1',
    a label 'x\\ty') escapes control characters repr-style so the message holds no raw newline or
    tab, and a 10 000-character name is truncated with a marker rather than quoted whole: the
    message is under 2,000 characters and still holds the name's first 20 characters.
    A name carrying DEL, a C1 control (U+009B) and U+2028 is escaped the same way (91 BF-09)."""
    from defender.run_repository import RunId, RunRefused, record_episode_runs

    _root, t = _good(tmp_path, "src")
    src, arm = RunId.parse("src"), RunId.parse("ep-a")
    cases = (
        ("RunId.parse('a\\nb')", lambda: RunId.parse("a\nb"), "a\\nb"),
        ("episode id 'ep\\n1'", lambda: record_episode_runs(t, "ep\n1", src, {"a": arm}),
         "ep\\n1"),
        ("label 'x\\ty'", lambda: record_episode_runs(
            t, "ep", src, {"x\ty": RunId.parse("ep-xy")}), "x\\ty"),
        ("RunId.parse with DEL, a C1 control and U+2028",
         lambda: RunId.parse("a\x7f\x9b\u2028b"), "a\\x7f\\x9b\\u2028b"),
        ("an episode id with DEL, a C1 control and U+2028",
         lambda: record_episode_runs(t, "ep\x7f\x9b\u20281", src, {"a": arm}),
         "ep\\x7f\\x9b\\u20281"),
    )
    for what, call, escaped in cases:
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{what} gave {err!r}"
        text = H.message(err)
        assert not H.has_raw_control(text), f"{what}'s refusal carries a raw control: {text!r}"
        # The label's refusal may name the label or the arm it fails to match (NM-11: no
        # precedence between the two rules); either quote is escaped.
        quoted = (escaped,) if escaped != "x\\ty" else (escaped, "ep-xy")
        assert any(q in text for q in quoted), f"{what}'s refusal does not quote it: {text!r}"
    for what, call, long_name in (
            ("RunId.parse(10 000 chars)", lambda: RunId.parse("a" * 10_000), "a" * 10_000),
            ("episode id of 10 000 chars",
             lambda: record_episode_runs(t, "e" * 10_000, src, {"a": arm}), "e" * 10_000)):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{what} gave {err!r}"
        text = H.message(err)
        assert long_name not in text, f"{what}'s refusal quotes the name whole ({len(text)} chars)"
        assert len(text) < 2_000, f"{what}'s refusal quotes the name whole ({len(text)} chars)"
        assert long_name[:20] in text, f"{what}'s refusal does not name it at all: {text[:200]!r}"


def test_1105_both_listings_accept_only_runs_the_record_episodes_and_known_sidecar_files(
        tmp_path):
    """list_run_ids and bound_runs list each real directory (judged from its directory entry,
    never followed) whose name RunId.parse admits and the sidecar clause passes, a 206-byte name
    included, and accept without listing _tenant.json, _episodes and the known sidecar files
    (regular files <id><suffix>, a staged one included); every other entry is unexpected and
    refuses (p2_run_entry_link_refuses, d2_legacy_folder_refuses,
    d2_listings_refuse_sidecar_named_dir). One such entry, a plain regular file 'notes', shows
    the refusal here."""
    from defender.run_repository import RunRefused, list_run_ids

    long_id = "r" + "1" * 205
    _root, t = _good(tmp_path, "r1", "2026-x.y_z", long_id)
    H.plant_sidecars(t.runs, "r1")
    H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})
    expected = sorted(["r1", "2026-x.y_z", long_id])
    assert _ids(list_run_ids(t)) == expected, f"list_run_ids gave {_ids(list_run_ids(t))}"
    assert _bound_ids(t) == expected, f"bound_runs gave {_bound_ids(t)}"
    (t.runs / "notes").write_text("x\n", encoding="utf-8")
    for name, call in (("list_run_ids", lambda: list_run_ids(t)),
                       ("bound_runs", lambda: _bound_ids(t))):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{name} over a stray regular file gave {err!r}"
        assert "notes" in H.message(err), f"{name} over a stray regular file gave {err!r}"


def test_1105_run_for_tenant_refuses_a_runs_folder_with_no_tenant_record(tmp_path):
    """Run.for_tenant(tenant_id, run_id, runs_base=...) raises TenantRefused when runs_base has no
    _tenant.json (today it returns a handle); with a record naming tenant_id it returns the
    handle, and with a record naming another tenant it raises today's TenantRecordMismatch."""
    from defender.run_repository import Run

    runs = tmp_path / H.T_ID / "runs"
    runs.mkdir(parents=True)
    err = H.raised(Run.for_tenant, H.T_ID, "r1", runs_base=runs)
    assert H.is_a(err, TenantRefused), f"Run.for_tenant over no record gave {err!r}"
    H.plant_tenant_record(runs, H.T_ID)
    run = Run.for_tenant(H.T_ID, "r1", runs_base=runs)
    assert run.run_dir == runs / "r1", "a good record admits"
    assert run.tenant_id == H.T_ID, "a good record admits"
    _swap_record(runs, H.U_ID)
    err = H.raised(Run.for_tenant, H.T_ID, "r1", runs_base=runs)
    assert H.is_a(err, TenantRecordMismatch), f"another tenant's record gave {err!r}"


def test_1105_open_run_checks_types_then_name_then_folder_then_record_then_entry(tmp_path):
    """open_run checks in order: a str id over a linked runs folder raises TypeError; a
    sidecar-suffixed RunId over a linked runs folder raises RunRefused; a linked runs folder
    whose target holds a record naming this tenant raises TenantRefused (the hold refuses it); a
    real folder whose record names another tenant, with a link at the entry, raises
    TenantRefused; a good record with an absent entry raises RunRefused."""
    from defender.run_repository import RunId, RunRefused, open_run

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    target = tmp_path / "target"
    H.plant_tenant_record(target, t.id)
    H.make_run(target, "r1")
    os.symlink(target, t.runs)
    err = H.raised(open_run, t, "r1")
    assert type(err) is TypeError, f"1. a str id gave {err!r}"
    err = H.raised(open_run, t, RunId.parse("r1.run-end.json"))
    assert H.is_a(err, RunRefused), f"2. a sidecar id over the link gave {err!r}"
    err = H.raised(open_run, t, RunId.parse("r1"))
    assert H.is_a(err, TenantRefused), f"3. the linked folder gave {err!r}"
    os.unlink(t.runs)
    H.plant_tenant_record(t.runs, H.U_ID)
    os.symlink(target / "r1", t.runs / "r1")
    err = H.raised(open_run, t, RunId.parse("r1"))
    assert H.is_a(err, TenantRefused), f"4. another tenant's record (entry a link) gave {err!r}"
    os.unlink(t.runs / "r1")
    _swap_record(t.runs, t.id)
    err = H.raised(open_run, t, RunId.parse("r1"))
    assert H.is_a(err, RunRefused), f"5. an absent entry gave {err!r}"
    assert str(t.runs / "r1") in H.message(err), f"5. names the path: {H.message(err)}"


def test_1105_open_run_serves_a_real_directory_entry_and_refuses_an_absent_one_naming_it(
        tmp_path):
    """Over a good runs folder, open_run judges tenant.runs/<id> by stat_entry from the held view:
    it hands out a Run when the entry is a real directory, prefix-extending names such as r1-,
    r10 and r1.x included, and raises RunRefused naming the path when the entry is absent;
    nothing is created. An occupant that is not a real directory is P2's: the link is the
    representative pinned (p2_run_entry_link_refuses), the others are not pinned per
    condition."""
    from defender.run_repository import RunId, RunRefused, open_run

    root, t = _good(tmp_path, "r1-", "r10", "r1.x")
    before = H.tree_state(root)
    err = H.raised(open_run, t, RunId.parse("r1"))
    assert H.is_a(err, RunRefused), f"an absent r1 beside r1-, r10, r1.x gave {err!r}"
    assert str(t.runs / "r1") in H.message(err), f"the refusal names the path: {H.message(err)}"
    for name in ("r1-", "r10", "r1.x"):
        assert open_run(t, RunId.parse(name)).run_dir == t.runs / name, f"{name} opens"
    assert H.tree_state(root) == before, "open_run created something"


def test_1105_a_held_run_is_not_rechecked_and_a_fresh_open_run_is(tmp_path):
    """After open_run hands out a Run, replacing _tenant.json with one naming another tenant
    leaves the held Run's run_dir and tenant_id as they were (it is not re-checked), while a
    fresh open_run for the same id raises TenantRefused."""
    from defender.run_repository import RunId, open_run

    _root, t = _good(tmp_path, "r1")
    run = open_run(t, RunId.parse("r1"))
    assert (run.run_dir, run.tenant_id) == (t.runs / "r1", t.id), "the run was handed out"
    _swap_record(t.runs, H.U_ID)
    assert (run.run_dir, run.tenant_id) == (t.runs / "r1", t.id), "the held Run moved"
    err = H.raised(open_run, t, RunId.parse("r1"))
    assert H.is_a(err, TenantRefused), f"a fresh open_run was not refused: {err!r}"


def test_1105_no_lookup_or_record_reader_writes_anything(tmp_path):
    """Driving every lookup and record reader over an absent, an empty and a populated runs
    folder leaves the data root's tree byte-for-byte and entry-for-entry unchanged: no folder,
    record or file is created. Over the empty folder, whose _tenant.json is absent, open_run,
    list_run_ids, bound_runs, run_exists, episode_runs and sibling_run_ids each raise
    TenantRefused (O3: a runs folder with no _tenant.json refuses). Positive control: run setup
    does create the runs folder and _tenant.json, and record_episode_runs does create
    _episodes/."""
    from defender.run_repository import (
        RunId, episode_runs, episode_sibling_ids, list_run_ids, open_run, record_episode_runs,
        run_exists, sibling_run_ids,
    )

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)

    def drive_readers():
        rid = RunId.parse("r1")
        out = {}
        for name, call in (("open_run", lambda: open_run(t, rid)),
                           ("list_run_ids", lambda: _ids(list_run_ids(t))),
                           ("bound_runs", lambda: _bound_ids(t)),
                           ("run_exists", lambda: run_exists(t, rid)),
                           ("episode_runs", lambda: dict(episode_runs(t, "ep"))),
                           ("sibling_run_ids", lambda: _ids(sibling_run_ids(t)))):
            box: dict = {}
            err = H.raised(lambda box=box, call=call: box.setdefault("answer", call()))
            out[name] = box.get("answer", err)
        with _io.bind(t.runs) as bound:
            out["episode_sibling_ids"] = H.raised(episode_sibling_ids, bound)
        return out

    for state in ("absent", "empty", "populated"):
        if state == "empty":
            t.runs.mkdir()
        if state == "populated":
            H.plant_tenant_record(t.runs, t.id)
            H.make_run(t.runs, "r1")
            H.plant_sidecars(t.runs, "r1")
            H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})
        before = H.tree_state(root)
        answers = drive_readers()
        if state == "empty":
            for name in ("open_run", "list_run_ids", "bound_runs", "run_exists", "episode_runs",
                         "sibling_run_ids"):
                assert H.is_a(answers[name], TenantRefused), (
                    f"{name} over a runs folder with no _tenant.json gave {answers[name]!r}, "
                    "not TenantRefused")
        if state == "populated":
            assert answers["list_run_ids"] == ["r1"], f"populated folder answers: {answers}"
        assert H.tree_state(root) == before, f"a reader wrote over the {state} folder"
    u = H.tenant(root, H.U_ID)
    alert = H.alert_file(tmp_path / "alerts")
    run_common.materialize_run(alert, "r9", tenant=u)
    assert (u.runs / "_tenant.json").is_file(), "run setup creates the runs folder and record"
    assert record_episode_runs(u, "ep", RunId.parse("r9"),
                               {"a": RunId.parse("ep-a")}) is None, "the writer answers"
    assert (u.runs / "_episodes").is_dir(), "record_episode_runs creates _episodes/"


def test_1105_list_run_ids_returns_sorted_run_ids_minus_record_claimed_ids(tmp_path):
    """list_run_ids(tenant) returns a list of RunId, sorted by text, of the runs in tenant.runs,
    minus every id a good episode record claims (the record written in the test through
    record_episode_runs); a folder holding only its good _tenant.json lists []."""
    from defender.run_repository import RunId, list_run_ids, record_episode_runs

    _root, t = _good(tmp_path)
    empty = list_run_ids(t)
    assert isinstance(empty, list), f"a record-only folder lists {empty!r}"
    assert empty == [], f"a record-only folder lists {empty!r}"
    for rid in ("c", "a", "b"):
        H.make_run(t.runs, rid)
    assert record_episode_runs(t, "ep", RunId.parse("a"),
                               {"x": RunId.parse("ep-x"), "y": RunId.parse("ep-y")}) is None
    for arm in ("ep-x", "ep-y"):
        H.make_run(t.runs, arm)
    listed = list_run_ids(t)
    assert isinstance(listed, list), f"listed {listed!r}"
    assert _ids(listed) == ["a", "b", "c"], f"listed {listed!r}"
    assert all(H.is_a(i, RunId) for i in listed), "every entry is a RunId"


def test_1105_bound_runs_yields_run_id_and_wrapper_rows_in_list_run_ids_order_over_one_descriptor(
        tmp_path):
    """Inside `with bound_runs(tenant) as runs:`, runs.absent is False over a good folder and the
    listing carries no reason; iterating runs yields one (RunId, w) row per id list_run_ids
    returns, in that order, where w is the repository's wrapper over the held view's
    under(run_id), whose reads walk the run's name no-follow when made and read the run's
    alert.json as the judge's union reads it today; the block holds one descriptor however many
    rows it yields (R41-13), and iterating reads nothing inside a run. A row whose alert.json is
    a link is iterated without refusal, and reading it raises RunRefused."""
    from defender.run_repository import RunId, RunRefused, bound_runs, list_run_ids

    _root, t = _good(tmp_path)
    ids = [f"r{n:03d}" for n in range(200)]
    for rid in ids:
        H.make_run(t.runs, rid, alert=json.dumps({"alert_id": rid}) + "\n")
    H.plant_record(t.runs, "ep", t.id, "r000", {"a": "ep-a"})
    H.make_run(t.runs, "ep-a")
    linked = t.runs / "r199" / "alert.json"
    linked.unlink()
    os.symlink(t.runs / "r000" / "alert.json", linked)
    order = _ids(list_run_ids(t))
    assert order == ids, f"list_run_ids gave {order[:5]}..."
    # Owner ruling (CI): the counts are of the whole process, so another test's unscoped
    # handle (closed on collection, `_io._Handle`) must not be collected mid-count.
    gc.collect()
    gc.disable()
    try:
        c0 = H.open_fd_count()
        with bound_runs(t) as runs:
            held = H.open_fd_count()
            assert runs.absent is False, f"runs.absent over a good folder is {runs.absent!r}"
            assert not hasattr(runs, "reason"), "the listing carries a reason"
            rows = list(runs)
            assert [str(rid) for rid, _w in rows] == order, "rows come in list_run_ids' order"
            assert all(H.is_a(rid, RunId) for rid, _w in rows), "each row's id is a RunId"
            assert H.open_fd_count() == held == c0 + 1, "the block holds exactly one descriptor"
            (t.runs / "r001" / "alert.json").write_text('{"alert_id": "late"}\n', encoding="utf-8")
            by_id = {str(rid): w for rid, w in rows}
            assert json.loads(by_id["r000"].read("alert.json").text) == {"alert_id": "r000"}
            assert json.loads(by_id["r001"].read("alert.json").text) == {"alert_id": "late"}, (
                "a row's read is made when called, not at listing")
            assert by_id["r002"].read("missing.json").absent is True, "an absent member reads absent"
            err = H.raised(by_id["r199"].read, "alert.json")
            assert H.is_a(err, RunRefused), f"a linked alert.json read through the row gave {err!r}"
            assert H.open_fd_count() == c0 + 1, "reading 200 rows holds no descriptor of its own"
        assert H.open_fd_count() == c0, "the block's descriptor is closed after it"
    finally:
        gc.enable()


def test_1105_bound_runs_is_single_use_and_refuses_every_read_after_the_block(tmp_path):
    """bound_runs lists once, on entry (a run folder created inside the block is not a row);
    after the with block exits, iterating the listing, reading a row's wrapper, or listing it
    raises RunRefused, where a bare Bound would answer reason='Bad file descriptor' without
    raising (R41-12); entering the same object a second time, or iterating one never entered,
    raises RunRefused."""
    from defender.run_repository import RunRefused, bound_runs

    _root, t = _good(tmp_path, "r1")
    br = bound_runs(t)
    with br as runs:
        H.make_run(t.runs, "r9")
        rows = list(runs)
        assert [str(rid) for rid, _w in rows] == ["r1"], f"rows: {[str(r) for r, _ in rows]}"
    _rid, w = rows[0]
    for what, call in (("iterating", lambda: list(runs)),
                       ("reading a row", lambda: w.read("alert.json")),
                       ("listing a row", lambda: w.entries())):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{what} after the block gave {err!r}"
    held = _io.hold(t.runs)
    view = held.view()
    held.close()
    bare = view.under("r1").read("alert.json")
    assert bare.reason == "Bad file descriptor", f"a bare Bound after close answers {bare!r} (R41-12)"
    assert bare.text is None, f"a bare Bound after close answers {bare!r} (R41-12)"
    err = H.raised(lambda: br.__enter__())
    assert H.is_a(err, RunRefused), f"a second entry gave {err!r}"
    err = H.raised(lambda: list(iter(bound_runs(t))))
    assert H.is_a(err, RunRefused), f"iterating a never-entered bound_runs gave {err!r}"


# ==========================================================================================
# Tenant isolation (O3, S1, S2).
# ==========================================================================================

def test_1105_a_run_setup_made_for_t_opens_for_t_and_no_other_tenant_reaches_it(tmp_path):
    """A run materialize_run created for tenant T opens with open_run(T, id); for a second tenant
    U accepted under the same data root (hand-planted row), open_run(U, id) raises TenantRefused
    while U has no runs folder, and RunRefused once U has its own folder and record but no run of
    that id; it never hands out a Run whose run_dir is under T.runs."""
    from defender.run_repository import RunId, RunRefused, open_run

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    run_common.materialize_run(H.alert_file(tmp_path / "alerts"), "r1", tenant=t)
    assert open_run(t, RunId.parse("r1")).run_dir == t.runs / "r1", "T's run opens for T"
    u = H.tenant(root, H.U_ID)
    err = H.raised(open_run, u, RunId.parse("r1"))
    assert H.is_a(err, TenantRefused), f"U with no runs folder gave {err!r}"
    H.runs_folder(u)
    err = H.raised(open_run, u, RunId.parse("r1"))
    assert H.is_a(err, RunRefused), f"U with its own folder and no r1 gave {err!r}"
    assert str(t.runs) not in H.message(err), "U's refusal names T's runs folder"


def test_1105_open_run_never_hands_out_a_handle_into_another_tenants_folder(tmp_path):
    """With tenant A's run r1 on disk, open_run(B, r1) never returns a Run whose run_dir resolves
    under A.runs: B.runs as a link to A.runs, B's _tenant.json naming A, and B.runs/r1 as a link
    to A.runs/r1 each raise (TenantRefused, TenantRefused, RunRefused). Positive control:
    open_run(A, r1) reaches A's run."""
    from defender.run_repository import RunId, RunRefused, open_run

    root, a = _good(tmp_path, "r1")
    b = H.tenant(root, H.U_ID)
    r1 = RunId.parse("r1")
    os.symlink(a.runs, b.runs)
    err = H.raised(open_run, b, r1)
    assert H.is_a(err, TenantRefused), f"B.runs a link to A.runs gave {err!r}"
    os.unlink(b.runs)
    H.plant_tenant_record(b.runs, a.id)
    H.make_run(b.runs, "r1")
    err = H.raised(open_run, b, r1)
    assert H.is_a(err, TenantRefused), f"B's record naming A gave {err!r}"
    shutil.rmtree(b.runs)
    H.runs_folder(b)
    os.symlink(a.runs / "r1", b.runs / "r1")
    err = H.raised(open_run, b, r1)
    assert H.is_a(err, RunRefused), f"B.runs/r1 a link to A's run gave {err!r}"
    run = open_run(a, r1)
    assert run.run_dir.resolve() == (a.runs / "r1").resolve(), "A reaches its own run"


def test_1105_bound_runs_never_yields_a_row_under_another_tenants_folder(tmp_path):
    """A link at A.runs/x into B's runs folder makes bound_runs(A) raise RunRefused naming it on
    entry, before any row is yielded, and no read reaches a file under B.runs. Positive control:
    without the link, A's real run is a row and its alert.json reads."""
    from defender.run_repository import RunRefused, bound_runs

    root, a = _good(tmp_path, "r1")
    b = H.tenant(root, H.U_ID)
    H.runs_folder(b)
    H.make_run(b.runs, "x", alert='{"alert_id": "b-secret"}\n')
    os.symlink(b.runs / "x", a.runs / "x")
    b_before = H.tree_state(b.runs)
    yielded = []

    def enter():
        with bound_runs(a) as runs:
            for row in runs:
                yielded.append(row)

    err = H.raised(enter)
    assert H.is_a(err, RunRefused), f"a link at A.runs/x gave {err!r}"
    text = H.message(err)
    assert str(a.runs / "x") in text or repr("x") in text, f"the refusal names x: {text}"
    assert "b-secret" not in H.message(err), "a row or B's bytes leaked"
    assert not yielded, "a row or B's bytes leaked"
    assert H.tree_state(b.runs) == b_before, "B's runs folder changed"
    os.unlink(a.runs / "x")
    with bound_runs(a) as runs:
        rows = [(str(rid), w.read("alert.json").text) for rid, w in runs]
    assert rows == [("r1", '{"alert": "seed"}\n')], f"A's own rows: {rows}"


def test_1105_run_exists_answers_only_for_this_tenants_folder(tmp_path):
    """run_exists(A, x) is False when x exists only in tenant B's runs folder under the same data
    root, and a RunId cannot be built for '../x' or 'a/b', so run_exists has no way to name a
    path outside A.runs. Positive control: run_exists(B, x) is True."""
    from defender.run_repository import RunId, RunRefused, run_exists

    root, a = _good(tmp_path, "r1")
    b = H.tenant(root, H.U_ID)
    H.runs_folder(b)
    H.make_run(b.runs, "x")
    assert run_exists(a, RunId.parse("x")) is False, "A sees B's x"
    assert run_exists(b, RunId.parse("x")) is True, "B's own x"
    for text in ("../x", "a/b", f"../{H.U_ID}/runs/x"):
        err = H.raised(RunId.parse, text)
        assert H.is_a(err, RunRefused), f"RunId.parse({text!r}) gave {err!r}"


def test_1105_a_box_writable_tenant_claim_neither_grants_nor_refuses_a_lookup(tmp_path):
    """A run's provenance stamp, an episode manifest and an episode folder that name another
    tenant change no answer of open_run, list_run_ids or run_exists for the request's tenant.
    Positive control: a _tenant.json naming another tenant does refuse."""
    from defender.run_repository import RunId, list_run_ids, open_run, run_exists

    _root, t = _good(tmp_path, "r1", "r2")

    def answers():
        return (str(open_run(t, RunId.parse("r1")).run_dir), _ids(list_run_ids(t)),
                run_exists(t, RunId.parse("r2")))

    before = answers()
    assert before == (str(t.runs / "r1"), ["r1", "r2"], True), f"baseline: {before}"
    (t.runs / "r1" / "provenance.json").write_text(
        json.dumps({"tenant_id": H.U_ID, "world_id": "w"}) + "\n", encoding="utf-8")
    episode = t.episodes / "ep1"
    episode.mkdir(parents=True)
    (episode / "family.yaml").write_text(f"tenant_id: {H.U_ID}\nsource_run_id: r1\n",
                                         encoding="utf-8")
    H.plant_tenant_record(episode / "runs", H.U_ID)
    assert answers() == before, "a box-writable tenant claim changed an answer"
    _swap_record(t.runs, H.U_ID)
    err = H.raised(list_run_ids, t)
    assert H.is_a(err, TenantRefused), f"the host-only record naming {H.U_ID} gave {err!r}"


def test_1105_a_legacy_run_folder_named_off_the_rules_makes_the_listings_refuse_naming_it(
        tmp_path):
    """A real directory in tenant.runs whose name today's id rules refuse, one off the grammar
    ('Bad Name', 'Run1') and one of 207 bytes, makes list_run_ids, bound_runs and run_exists raise
    RunRefused naming that folder; renaming or moving it lets the listing answer. Positive
    control: a 206-byte directory beside the runs is listed. "Naming" is checked as the name's
    first 40 characters appearing in the message (design NF-8 may truncate a long name past
    them)."""
    from defender.run_repository import RunId, RunRefused, list_run_ids, run_exists

    ok_long = "r" + "1" * 205
    _root, t = _good(tmp_path, "r1", ok_long)
    expected = sorted(["r1", ok_long])
    assert _ids(list_run_ids(t)) == expected, f"the 206-byte folder lists: {_ids(list_run_ids(t))}"
    for legacy in ("Bad Name", "Run1", "r" + "2" * 206):
        os.mkdir(t.runs / legacy)
        for fn, call in (("list_run_ids", lambda: list_run_ids(t)),
                         ("bound_runs", lambda: _bound_ids(t)),
                         ("run_exists", lambda: run_exists(t, RunId.parse("r1")))):
            err = H.raised(call)
            assert H.is_a(err, RunRefused), f"{fn} beside {legacy[:12]!r} gave {err!r}"
            assert legacy[:40] in H.message(err), f"{fn}'s refusal does not name the folder"
        os.rename(t.runs / legacy, tmp_path / "moved-away")
        assert _ids(list_run_ids(t)) == expected, f"after moving {legacy[:12]!r} away"
        shutil.rmtree(tmp_path / "moved-away")


# ==========================================================================================
# P2's representatives and the expected states.
# ==========================================================================================

def test_1105_a_link_at_tenant_runs_refuses_every_function_naming_it(tmp_path):
    """With tenant.runs a link to another tenant's runs folder, each lookup and tenant-keyed
    record function raises TenantRefused naming tenant.runs and the link fault, never a raw
    OSError, and the other tenant's folder is byte-unchanged; a link to a folder whose own record
    names this tenant refuses the same way, so it is the no-follow hold that refuses, not the
    record compare. Positive control: the same calls answer over a real tenant.runs, and over a
    real tenant.runs under a linked ANCESTOR (a data root reached through a link), open_run
    handing out the run and list_run_ids listing it: only a link AT tenant.runs refuses (P1,
    R41-03)."""
    from defender.run_repository import RunId, list_run_ids, open_run

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    u = H.tenant(root, H.U_ID)
    H.runs_folder(u)
    H.make_run(u.runs, "r1")
    H.plant_record(u.runs, "ep", u.id, "r1", {"a": "ep-a"})
    own = tmp_path / "own-elsewhere"
    H.plant_tenant_record(own, t.id)
    H.make_run(own, "r1")
    for target in (u.runs, own):
        os.symlink(target, t.runs)
        target_before = H.tree_state(target)
        for name, call in _every_function(t):
            err = H.raised(call)
            assert H.is_a(err, TenantRefused), f"{name} over a link to {target.name} gave {err!r}"
            text = H.message(err)
            assert str(t.runs) in text, f"{name}: {text}"
            assert "link" in text.lower(), f"{name}: {text}"
        assert H.tree_state(target) == target_before, f"{target} changed"
        os.unlink(t.runs)
    H.runs_folder(t)
    H.make_run(t.runs, "r1")
    H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})
    for name, call in _every_function(t):
        err = H.raised(call)
        assert err is None, f"{name} over a real tenant.runs raised {err!r}"
    (tmp_path / "real-ancestor").mkdir()
    os.symlink(tmp_path / "real-ancestor", tmp_path / "linked-ancestor")
    w = H.tenant(tmp_path / "linked-ancestor", H.T_ID)
    H.runs_folder(w)
    H.make_run(w.runs, "r1")
    assert open_run(w, RunId.parse("r1")).run_dir == w.runs / "r1", (
        "a runs folder under a linked ancestor is served: open_run hands out its run")
    assert _ids(list_run_ids(w)) == ["r1"], "list_run_ids under a linked ancestor lists r1"
    for name, call in _every_function(w):
        err = H.raised(call)
        assert err is None, f"{name} under a linked ancestor raised {err!r}"


def test_1105_a_tenant_record_naming_another_tenant_refuses_every_function(tmp_path):
    """With tenant.runs/_tenant.json naming another tenant, each lookup and tenant-keyed record
    function raises TenantRefused naming the record, writes nothing and returns no run of that
    folder (O3's 'refused for any other tenant'); two accepted tenants with their records swapped
    are each refused. Positive control: the record naming this tenant answers."""
    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    u = H.tenant(root, H.U_ID)
    for me, other in ((t, u), (u, t)):
        H.plant_tenant_record(me.runs, other.id)
        H.make_run(me.runs, "r1")
        H.plant_record(me.runs, "ep", me.id, "r1", {"a": "ep-a"})
    before = H.tree_state(root)
    for me in (t, u):
        record = str(me.runs / "_tenant.json")
        for name, call in _every_function(me):
            err = H.raised(call)
            assert H.is_a(err, TenantRefused), f"{name}({me.id}) with a swapped record gave {err!r}"
            assert record in H.message(err), f"{name}'s refusal does not name {record}"
    assert H.tree_state(root) == before, "a refused call wrote something"
    for me in (t, u):
        _swap_record(me.runs, me.id)
        for name, call in _every_function(me):
            err = H.raised(call)
            assert err is None, f"{name}({me.id}) over its own record raised {err!r}"


def test_1105_a_link_at_a_runs_name_refuses_naming_it_and_is_never_followed(tmp_path):
    """With tenant.runs/r2 a link to a run folder (inside the same runs folder, or another
    tenant's), list_run_ids, bound_runs and run_exists raise RunRefused naming r2, open_run(tenant,
    r2) raises RunRefused naming the path, and record_episode_runs refuses an arm whose name is
    such a link (planted at ep-b: an arm is shaped f'{episode_id}-{label}', so no arm is named
    r2); nothing reads through the link. Positive control: the same folder without the link
    answers."""
    from defender.run_repository import (
        RunId, RunRefused, list_run_ids, open_run, record_episode_runs, run_exists,
    )

    root, t = _good(tmp_path, "r1")
    u = H.tenant(root, H.U_ID)
    H.runs_folder(u)
    H.make_run(u.runs, "r1", alert='{"alert_id": "u-secret"}\n')
    for target in (t.runs / "r1", u.runs / "r1"):
        os.symlink(target, t.runs / "r2")
        target_before = H.tree_state(target)
        for name, call in (("list_run_ids", lambda: list_run_ids(t)),
                           ("bound_runs", lambda: _bound_ids(t)),
                           ("run_exists", lambda: run_exists(t, RunId.parse("r1")))):
            err = H.raised(call)
            assert H.is_a(err, RunRefused), f"{name} beside a link at r2 gave {err!r}"
            assert "r2" in H.message(err), H.message(err)
            assert "u-secret" not in H.message(err), H.message(err)
        err = H.raised(open_run, t, RunId.parse("r2"))
        assert H.is_a(err, RunRefused), f"open_run(r2) through the link gave {err!r}"
        assert str(t.runs / "r2") in H.message(err), f"names the path: {H.message(err)}"
        assert H.tree_state(target) == target_before, f"{target} changed"
        os.unlink(t.runs / "r2")
    os.symlink(t.runs / "r1", t.runs / "ep-b")
    err = H.raised(record_episode_runs, t, "ep", RunId.parse("r1"), {"b": RunId.parse("ep-b")})
    assert H.is_a(err, RunRefused), f"an arm named by a link gave {err!r}"
    assert "ep-b" in H.message(err), f"the writer's refusal names the arm: {H.message(err)}"
    assert not (t.runs / "_episodes" / "ep.json").exists(), "the refused record was written"
    os.unlink(t.runs / "ep-b")
    assert _ids(list_run_ids(t)) == ["r1"], "without the link"
    assert _bound_ids(t) == ["r1"], "without the link"
    assert run_exists(t, RunId.parse("r1")) is True, "run_exists without the link"
    assert record_episode_runs(t, "ep", RunId.parse("r1"), {"b": RunId.parse("ep-b")}) is None


def test_1105_open_run_and_run_exists_answer_beside_a_torn_record_and_a_stray_name_in_episodes(
        tmp_path):
    """P2's Reach: each function judges what it reads, and only that (design D2: open_run and
    run_exists do not read _episodes, episode_runs(ep) reads only ep's record, and open_run
    judges only its own entry). With tenant.runs/_episodes holding a torn record (a good record
    claiming ep-a, cut short) and a stray file README, open_run(tenant, id) still hands out the
    run for r1 and for ep-a, the id the torn record would claim, and run_exists answers True for
    r1 and ep-a and False for the absent r9, as it would with no _episodes: neither reads
    _episodes. Beside the same torn record and README, episode_runs(tenant, 'nope') answers {}
    and a good record ep2 is answered by episode_runs(tenant, 'ep2'). With a directory
    'Bad Name' planted beside r1 (and _episodes removed), open_run(tenant, r1) still serves.
    Positive control: over the same tree the _episodes readers refuse, sibling_run_ids,
    list_run_ids and bound_runs raising RunRefused, episode_runs(tenant, 'ep') raising RunRefused
    for its own torn record, and list_run_ids, which lists both runs before 'Bad Name' is
    planted, refusing the folder once it holds it."""
    from defender.run_repository import (
        RunId, RunRefused, episode_runs, list_run_ids, open_run, run_exists, sibling_run_ids,
    )

    root, t = _good(tmp_path, "r1", "ep-a")
    record = H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})
    torn_text = H.truncated(record.read_text(encoding="utf-8"))
    record.write_text(torn_text, encoding="utf-8")
    (t.runs / "_episodes" / "README").write_text("notes\n", encoding="utf-8")
    before = H.tree_state(root)
    for rid in ("r1", "ep-a"):
        err = H.raised(open_run, t, RunId.parse(rid))
        assert err is None, f"open_run({rid}) read _episodes and refused a healthy run: {err!r}"
        assert open_run(t, RunId.parse(rid)).run_dir == t.runs / rid, f"open_run({rid}) serves"
    for rid, answer in (("r1", True), ("ep-a", True), ("r9", False)):
        err = H.raised(run_exists, t, RunId.parse(rid))
        assert err is None, f"run_exists({rid}) read _episodes and refused: {err!r}"
        assert run_exists(t, RunId.parse(rid)) is answer, f"run_exists({rid}) is not {answer}"
    assert H.tree_state(root) == before, "a lookup wrote something"
    err = H.raised(episode_runs, t, "nope")
    assert err is None, f"episode_runs('nope') read beyond its own record and refused: {err!r}"
    assert dict(episode_runs(t, "nope")) == {}, "episode_runs('nope') with no record is not {}"
    H.plant_record(t.runs, "ep2", t.id, "r1", {"b": "ep2-b"})
    err = H.raised(episode_runs, t, "ep2")
    assert err is None, f"episode_runs('ep2') read a sibling record or README and refused: {err!r}"
    got = {k: str(v) for k, v in dict(episode_runs(t, "ep2")).items()}
    assert got == {"b": "ep2-b"}, f"episode_runs('ep2') answered {got}"
    for name, call in (("sibling_run_ids", lambda: sibling_run_ids(t)),
                       ("list_run_ids", lambda: list_run_ids(t)),
                       ("bound_runs", lambda: _bound_ids(t)),
                       ("episode_runs", lambda: episode_runs(t, "ep"))):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), (
            f"positive control: the _episodes reader {name} answered over a torn record and a "
            f"stray name: {err!r}")
    shutil.rmtree(t.runs / "_episodes")
    assert _ids(list_run_ids(t)) == ["ep-a", "r1"], "the folder without _episodes lists both runs"
    os.mkdir(t.runs / "Bad Name")
    err = H.raised(open_run, t, RunId.parse("r1"))
    assert err is None, f"open_run(r1) judged an entry beside its own and refused: {err!r}"
    assert open_run(t, RunId.parse("r1")).run_dir == t.runs / "r1", "open_run(r1) beside Bad Name"
    err = H.raised(list_run_ids, t)
    assert H.is_a(err, RunRefused), (
        f"positive control: list_run_ids answered over a folder holding 'Bad Name': {err!r}")


def test_1105_an_absent_runs_folder_answers_empty_and_creates_nothing(tmp_path):
    """For an accepted tenant with no runs folder, list_run_ids returns [], bound_runs yields no
    row with absent=True, run_exists returns False, episode_runs returns {} and sibling_run_ids
    the empty set, episode_sibling_ids over a Bound of the absent folder returns the empty set,
    and open_run and record_episode_runs raise TenantRefused; none of them creates anything.
    Afterwards run setup creates the folder, its record and a run, and the same Tenant gets that
    run from open_run and list_run_ids."""
    from defender.run_repository import (
        RunId, bound_runs, episode_runs, episode_sibling_ids, list_run_ids, open_run,
        record_episode_runs, run_exists, sibling_run_ids,
    )

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    before = H.tree_state(root)
    listed = list_run_ids(t)
    assert isinstance(listed, list), f"list_run_ids gave {listed!r}"
    assert listed == [], f"list_run_ids gave {listed!r}"
    with bound_runs(t) as runs:
        assert runs.absent is True, f"bound_runs.absent is {runs.absent!r}"
        assert list(runs) == [], "bound_runs yielded a row over an absent folder"
    assert run_exists(t, RunId.parse("r1")) is False, "run_exists over an absent folder"
    assert dict(episode_runs(t, "ep")) == {}, "episode_runs over an absent folder"
    assert set(sibling_run_ids(t)) == set(), "sibling_run_ids over an absent folder"
    with _io.bind(t.runs) as bound:
        assert set(episode_sibling_ids(bound)) == set(), "episode_sibling_ids over absent"
    for name, call in (("open_run", lambda: open_run(t, RunId.parse("r1"))),
                       ("record_episode_runs", lambda: record_episode_runs(
                           t, "ep", RunId.parse("r1"), {"a": RunId.parse("ep-a")}))):
        err = H.raised(call)
        assert H.is_a(err, TenantRefused), f"{name} over an absent folder gave {err!r}"
    assert H.tree_state(root) == before, "something was created"
    assert not t.runs.exists(), "something was created"
    run_common.materialize_run(H.alert_file(tmp_path / "alerts"), "r1", tenant=t)
    assert (t.runs / "_tenant.json").is_file(), "run setup made the folder and record"
    assert open_run(t, RunId.parse("r1")).run_dir == t.runs / "r1", "the run opens"
    assert _ids(list_run_ids(t)) == ["r1"], "the run lists"


def test_1105_a_run_with_sidecar_files_beside_it_lists_as_the_one_run(tmp_path):
    """A run folder r1 with its four sidecar files beside it and a staged one
    (r1.run-end.json.staged-<16 hex>) lists as the one run r1 in list_run_ids and bound_runs,
    neither refuses, and run_exists answers True for r1 and for each sidecar name; sidecar files
    left for a run whose folder is gone are accepted the same way, that id is not listed, and
    run_exists answers True for it (owner ruling: the writer's "taken"). A
    run whose id is 206 bytes (the bound) with the longest sidecar suffix's staged file beside it
    (<id>.accounting_failures.json.staged-<16 hex>, a 255-byte name made on the real filesystem)
    lists as that one run in both listings, and run_exists answers True for it."""
    from defender.run_repository import RunId, list_run_ids, run_exists

    _root, t = _good(tmp_path, "r1")
    made = H.plant_sidecars(t.runs, "r1")
    H.plant_sidecars(t.runs, "gone")
    assert _ids(list_run_ids(t)) == ["r1"], f"list_run_ids gave {_ids(list_run_ids(t))}"
    assert _bound_ids(t) == ["r1"], f"bound_runs gave {_bound_ids(t)}"
    assert run_exists(t, RunId.parse("r1")) is True, "r1 exists"
    for path in made:
        assert run_exists(t, RunId.parse(path.name)) is True, f"{path.name} exists"
    # Owner ruling (xhigh review): "taken" has one definition, the record writer's, so an id
    # whose folder is gone but whose sidecar files remain is taken (was: False).
    assert run_exists(t, RunId.parse("gone")) is True, "the gone run's sidecars still hold its id"
    longest = max(H.SIDECAR_SUFFIXES, key=len)
    long_id = "r1-" + "a" * (H.RUN_ID_BOUND - 3)
    H.make_run(t.runs, long_id)
    staged = t.runs / f"{long_id}{longest}{H.STAGED_TAIL}"
    staged.write_text("{}\n", encoding="utf-8")
    assert len(staged.name.encode("utf-8")) == 255, f"the staged name is {len(staged.name)} bytes"
    assert staged.is_file(), "the 255-byte staged sidecar was not made"
    want = sorted(["r1", long_id])
    assert _ids(list_run_ids(t)) == want, (
        f"list_run_ids beside a 255-byte staged sidecar gave {[x[:12] for x in _ids(list_run_ids(t))]}")
    assert _bound_ids(t) == want, "bound_runs beside a 255-byte staged sidecar"
    assert run_exists(t, RunId.parse(long_id)) is True, "the 206-byte run exists"


def test_1105_every_lookup_and_record_function_closes_its_held_handle_on_each_path(tmp_path):
    """the process's open descriptor count (/proc/self/fd) is the same before and after each
    lookup and record function on its success path and on each refusal path (TypeError before
    any read opens none; TenantRefused; RunRefused); bound_runs holds exactly one while the block
    is open and none after it, also when the block raises; positive control: the count is one
    higher inside bound_runs' block. The RunRefused paths include one after the hold for each
    lookup and record function: a folder named 'Bad Name' (list_run_ids, bound_runs), a stray
    README in _episodes (sibling_run_ids), a link at run_exists' own entry, for
    record_episode_runs an arm another record claims, a link at _episodes and a different record
    already at the episode's name, and for episode_runs its own torn record."""
    from defender.run_repository import (
        RunId, RunRefused, bound_runs, episode_runs, list_run_ids, open_run,
        record_episode_runs, run_exists, sibling_run_ids,
    )

    class _Boom(Exception):
        pass

    _root, t = _good(tmp_path, "r1")
    H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})
    c0 = H.open_fd_count()
    inside = None
    try:
        with bound_runs(t) as runs:
            inside = H.open_fd_count()
            assert [str(r) for r, _w in runs] == ["r1"], "bound_runs lists r1"
            raise _Boom
    except _Boom:
        pass
    assert inside == c0 + 1, f"bound_runs held {None if inside is None else inside - c0} fds"
    assert H.open_fd_count() == c0, "bound_runs left its descriptor open after a raising block"

    def delta(call):
        before = H.open_fd_count()
        err = H.raised(call)
        return H.open_fd_count() - before, err

    rid = RunId.parse("r1")
    success = (("open_run", lambda: open_run(t, rid)), ("list_run_ids", lambda: list_run_ids(t)),
               ("bound_runs", lambda: _bound_ids(t)), ("run_exists", lambda: run_exists(t, rid)),
               ("record_episode_runs", lambda: record_episode_runs(
                   t, "ep2", rid, {"b": RunId.parse("ep2-b")})),
               ("episode_runs", lambda: episode_runs(t, "ep")),
               ("sibling_run_ids", lambda: sibling_run_ids(t)))
    for name, call in success:
        d, err = delta(call)
        assert err is None, f"{name} success path: delta {d}, raised {err!r}"
        assert d == 0, f"{name} success path: delta {d}, raised {err!r}"
    for name, call in (("open_run", lambda: open_run(t.id, rid)),
                       ("list_run_ids", lambda: list_run_ids(t.runs)),
                       ("record_episode_runs", lambda: record_episode_runs(t, "ep3", "r1", {}))):
        d, err = delta(call)
        assert type(err) is TypeError, f"{name} TypeError path: {d}, {err!r}"
        assert d == 0, f"{name} TypeError path: {d}, {err!r}"
    for name, call in (("open_run", lambda: open_run(t, RunId.parse("r7"))),
                       ("record_episode_runs", lambda: record_episode_runs(t, "ep4", rid, {})),
                       ("episode_runs", lambda: episode_runs(t, "../x"))):
        d, err = delta(call)
        assert H.is_a(err, RunRefused), f"{name} RunRefused path: {d}, {err!r}"
        assert d == 0, f"{name} RunRefused path: {d}, {err!r}"
    # RunRefused AFTER the hold: each lookup refuses a state it reads inside the held folder.
    after_hold = (
        ("list_run_ids", lambda: os.mkdir(t.runs / "Bad Name"),
         lambda: list_run_ids(t), lambda: os.rmdir(t.runs / "Bad Name")),
        ("bound_runs", lambda: os.mkdir(t.runs / "Bad Name"),
         lambda: _bound_ids(t), lambda: os.rmdir(t.runs / "Bad Name")),
        ("sibling_run_ids", lambda: (t.runs / "_episodes" / "README").write_text(
            "notes\n", encoding="utf-8"),
         lambda: sibling_run_ids(t), lambda: (t.runs / "_episodes" / "README").unlink()),
        ("run_exists", lambda: os.symlink(t.runs / "r1", t.runs / "r2"),
         lambda: run_exists(t, RunId.parse("r2")), lambda: os.unlink(t.runs / "r2")),
        ("record_episode_runs/claimed arm",
         lambda: H.plant_record(t.runs, "zz", t.id, "r1", {"a": "ep5-a"}),
         lambda: record_episode_runs(t, "ep5", rid, {"a": RunId.parse("ep5-a")}),
         lambda: (t.runs / "_episodes" / "zz.json").unlink()),
        ("record_episode_runs/link at _episodes", lambda: _episodes_to_link(t.runs, tmp_path),
         lambda: record_episode_runs(t, "ep6", rid, {"a": RunId.parse("ep6-a")}),
         lambda: _episodes_from_link(t.runs, tmp_path)),
        ("record_episode_runs/a different record", lambda: None,
         lambda: record_episode_runs(t, "ep", rid, {"b": RunId.parse("ep-b")}), lambda: None),
        ("episode_runs/its own torn record",
         lambda: (t.runs / "_episodes" / "et.json").write_text(
             H.truncated(H.record_text("et", t.id, "r1", {"a": "et-a"})), encoding="utf-8"),
         lambda: episode_runs(t, "et"), lambda: (t.runs / "_episodes" / "et.json").unlink()),
    )
    for name, plant, call, remove in after_hold:
        plant()
        d, err = delta(call)
        remove()
        assert H.is_a(err, RunRefused), f"{name} RunRefused after the hold: {d}, {err!r}"
        assert d == 0, f"{name} RunRefused after the hold: {d}, {err!r}"
    _swap_record(t.runs, H.U_ID)
    for name, call in success:
        d, err = delta(call)
        assert H.is_a(err, TenantRefused), f"{name} TenantRefused path: {d}, {err!r}"
        assert d == 0, f"{name} TenantRefused path: {d}, {err!r}"


def test_1105_run_for_tenant_over_a_deeply_nested_tenant_record_refuses_as_tenant_refused(
        tmp_path):
    """Run.for_tenant over a runs folder whose _tenant.json nests 200,000 levels deep raises
    TenantRefused (TenantRecordCorrupt is one) naming the record, never RecursionError; positive
    control: the same call over a good record returns the handle. The implementer chooses where
    the check lives; tenant_of_run_dir and family_base_world_id are not required to change (D5,
    PR 2). A declared O5 change (run setup's deep-record refusal is the other)"""
    from defender.run_repository import Run

    runs = tmp_path / H.T_ID / "runs"
    record = H.plant_tenant_record(runs, H.T_ID, raw=H.deep_json())
    err = H.raised(Run.for_tenant, H.T_ID, "r1", runs_base=runs)
    assert H.is_a(err, TenantRefused), f"a 200,000-deep record gave {err!r}"
    assert not isinstance(err, RecursionError), H.message(err)
    assert str(record) in H.message(err), H.message(err)
    record.write_text(H.tenant_record_text(H.T_ID), encoding="utf-8")
    run = Run.for_tenant(H.T_ID, "r1", runs_base=runs)
    assert run.run_dir == runs / "r1", "a good record returns the handle"


def test_1105_refusals_quoting_a_disk_read_entry_name_escape_it_and_stay_one_line(tmp_path):
    """a run folder named 'a<newline>[run.py] forged' or 'x<ESC>[31m' makes list_run_ids,
    bound_runs and run_exists raise RunRefused, and a stray entry of that kind in _episodes makes
    the _episodes readers list_run_ids, bound_runs and sibling_run_ids raise RunRefused (255-byte
    names included on both arms), each message holding no raw newline or escape character and
    still naming the entry (a visible run of its characters appears); run_exists does not read
    _episodes (P2's Reach); run setup's claimed-id refusal over the same _episodes is exactly one
    stderr line (splitlines() == 1) with no traceback; positive control: the same call over a
    plain-named stray entry names it verbatim
    A run folder and a stray entry carrying DEL, a C1 control (U+009B) and U+2028 are among the
    hostile names (91 BF-09)."""
    from defender.run_repository import (
        RunId, RunRefused, list_run_ids, run_exists, sibling_run_ids,
    )

    _root, t = _good(tmp_path, "r1")
    hostile = (("a\n[run.py] forged", "[run.py] forged"), ("x\x1b[31m", "[31m"),
               ("n\n" + "c" * 253, "ccc"), ("d\x7f\x9b\u2028[c1] forged", "[c1] forged"))
    for name, visible in hostile:
        os.mkdir(t.runs / name)
        for fn, call in (("list_run_ids", lambda: list_run_ids(t)),
                         ("bound_runs", lambda: _bound_ids(t)),
                         ("run_exists", lambda: run_exists(t, RunId.parse("r1")))):
            err = H.raised(call)
            assert H.is_a(err, RunRefused), f"{fn} beside a folder {name[:12]!r} gave {err!r}"
            text = H.message(err)
            assert not H.has_raw_control(text), f"{fn}'s refusal carries a raw control: {text!r}"
            assert visible in text, f"{fn}'s refusal does not name the entry: {text!r}"
        os.rmdir(t.runs / name)
    alert = H.alert_file(tmp_path / "alerts")
    for name, visible in (("e\n[run.py] forged", "[run.py] forged"),
                          ("s\x1b" + "d" * 253, "ddd"),
                          ("u\x7f\x9b\u2028[c1] stray", "[c1] stray")):
        (t.runs / "_episodes").mkdir(exist_ok=True)
        (t.runs / "_episodes" / name).write_text("{}\n", encoding="utf-8")
        for fn, call in (("sibling_run_ids", lambda: sibling_run_ids(t)),
                         ("list_run_ids", lambda: list_run_ids(t)),
                         ("bound_runs", lambda: _bound_ids(t))):
            err = H.raised(call)
            assert H.is_a(err, RunRefused), f"{fn} over a stray {name[:12]!r} gave {err!r}"
            text = H.message(err)
            assert not H.has_raw_control(text), f"{fn}: {text!r}"
            assert visible in text, f"{fn}: {text!r}"
        err = H.raised(run_common.materialize_run, alert, "r5", tenant=t)
        assert isinstance(err, SystemExit), f"run setup's claimed-id refusal over a stray {name[:12]!r} gave {err!r}"
        assert isinstance(err.code, str), f"run setup's claimed-id refusal over a stray {name[:12]!r} gave {err!r}"
        assert len(err.code.splitlines()) == 1, err.code
        assert not H.has_raw_control(err.code), err.code
        assert not (t.runs / "r5").exists(), "run setup created the run folder"
        (t.runs / "_episodes" / name).unlink()
    (t.runs / "_episodes" / "README").write_text("notes\n", encoding="utf-8")
    err = H.raised(sibling_run_ids, t)
    assert H.is_a(err, RunRefused), f"a plain stray entry gave {err!r}"
    assert "README" in H.message(err), f"a plain stray name is named verbatim: {H.message(err)}"
