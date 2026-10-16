"""Run lookup: open/list over a tenant's runs folder, link/torn-record/foreign-tenant refusals, escaping of quoted names, handle closing."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from defender import _io
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


def _ids(answer) -> list[str]:
    return [str(i) for i in answer]


def _every_function(t, *, run_id: str = "r1", episode_id: str = "ep9"):
    """`(name, thunk)` per lookup (a method of `t`'s repository) and tenant-keyed record
    function, each over `t`."""
    from defender.run_repository import RunId, episode_runs, record_episode_runs, sibling_run_ids

    return [
        ("runs.open", lambda: t.runs_repository().open(RunId.parse(run_id))),
        ("runs.list", lambda: t.runs_repository().list()),
        ("record_episode_runs", lambda: record_episode_runs(
            t, episode_id, RunId.parse(run_id), {"a": RunId.parse(f"{episode_id}-a")})),
        ("episode_runs", lambda: episode_runs(t, "ep")),
        ("sibling_run_ids", lambda: sibling_run_ids(t)),
    ]



def _hold_calls(rec: H.RecordingIO):
    return rec.named("hold")


def _container_refusal(name: str, err: object) -> bool:
    """Whether `err` is how the function `name` refuses a container fault: `TenantRefused`, but
    for an open, `RunUnreachable` raised from that `TenantRefused` (#1105 PR 2 review: opening
    a run answers one refusal family)."""
    from defender.run_repository import RunUnreachable

    if name.startswith("runs.open"):
        return H.is_a(err, RunUnreachable) and H.is_a(getattr(err, "__cause__", None),
                                                      TenantRefused)
    return H.is_a(err, TenantRefused)


def _is_one_nofollow_hold_of(rec: H.RecordingIO, runs: Path) -> bool:
    holds = _hold_calls(rec)
    if len(holds) != 1 or not holds[0][0] or not isinstance(holds[0][0][0], (str, os.PathLike)):
        return False
    return Path(holds[0][0][0]) == Path(runs) and holds[0][1].get("follow") is False


#: Run names just outside the sidecar clause (MF-21 B; I061, DV-5): no sidecar suffix at the
#: end, or a staged tail that is not lowercase hex, or a suffix the clause no longer holds
#: (#1235 retired `.oracle-held.json`: the oracle's held time is in-memory run state). Each is
#: a run.
_OUTSIDE_THE_SIDECAR_CLAUSE = ("r1.run-end.json-2", "run-end.json", "r1.run-end.json.staged-g",
                               "r1.oracle-held.json")


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
    from defender.run_repository import Run, RunId, RunsRepository

    root, t = _good(tmp_path, "r1")
    before = H.tree_state(root)
    rec = H.RecordingIO()
    run = RunsRepository(t, io=rec).open(RunId.parse("r1"))
    assert run.run_dir == t.runs / "r1", f"runs.open handed out run_dir {run.run_dir!r}"
    assert run.runs_base == t.runs == t.data_root / t.id / "runs", run.runs_base
    assert run.tenant_id == t.id, run.tenant_id
    built = Run.under(t.runs, "r1", tenant_id=t.id)
    assert type(run) is type(built), "runs.open hands out Run.under's Run"
    assert ((run.run_dir, run.runs_base, run.tenant_id) == (
        built.run_dir, built.runs_base, built.tenant_id)), "runs.open hands out Run.under's Run"
    record = t.runs / "_tenant.json"
    path_reads = [(n, a) for n, a, _k in rec.calls
                  if n in ("read_guarded", "entry_present", "read_plain", "read_text_soft")
                  and a and isinstance(a[0], (str, os.PathLike)) and Path(a[0]) == record]
    assert not path_reads, f"the tenant record was read again by path: {path_reads}"
    assert _is_one_nofollow_hold_of(rec, t.runs), f"holds: {_hold_calls(rec)}"
    assert H.tree_state(root) == before, "runs.open wrote something"



# ==========================================================================================
# The name rule and the entry rule.
# ==========================================================================================

def test_1105_open_run_refuses_each_sidecar_suffixed_id_as_run_refused(tmp_path):
    """open_run refuses with RunRefused an id ending in each of the host-only sidecar
    suffixes (.run-end.json, .scrub-verdict.json, .accounting_failures.json, .ticket-write.json,
    .session-pointer.json — `H.SIDECAR_SUFFIXES`)
    and an id of the staged shape (a sidecar suffix, then '.staged-', then lowercase hex
    digits), even when the runs folder is absent (the clause runs before the hold). Positive
    control: 'r1' over a good folder holding r1 opens, and so does each name just outside the
    clause, a real run folder named 'r1.run-end.json-2', 'run-end.json',
    'r1.run-end.json.staged-g' or 'r1.oracle-held.json' (no sidecar suffix at the end; a staged
    tail that is not lowercase hex; a suffix #1235 retired)."""
    from defender.run_repository import RunId, RunRefused

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    names = ([f"r1{s}" for s in H.SIDECAR_SUFFIXES]
             + [f"r1.run-end.json{H.STAGED_TAIL}", "r1.ticket-write.json.staged-0",
                f"r1.accounting_failures.json{H.STAGED_TAIL}"])
    for name in names:
        err = H.raised(t.runs_repository().open, RunId.parse(name))
        assert H.is_a(err, RunRefused), f"runs.open({name!r}) over an absent folder gave {err!r}"
        assert name in H.message(err), f"the refusal does not name {name!r}: {H.message(err)}"
    assert not t.runs.exists(), "a refused name created the runs folder"
    H.runs_folder(t)
    H.make_run(t.runs, "r1")
    for name in names:
        os.mkdir(t.runs / name)  # even a real directory at the name is never opened as a run
        err = H.raised(t.runs_repository().open, RunId.parse(name))
        assert H.is_a(err, RunRefused), f"runs.open({name!r}) over a good folder gave {err!r}"
        os.rmdir(t.runs / name)
    assert t.runs_repository().open(RunId.parse("r1")).run_dir == t.runs / "r1", "r1 opens"
    for name in _OUTSIDE_THE_SIDECAR_CLAUSE:
        H.make_run(t.runs, name)
        assert t.runs_repository().open(RunId.parse(name)).run_dir == t.runs / name, (
            f"{name!r} is a run, not a sidecar-shaped id (MF-21 B's boundary), and does not open")


def test_1105_a_directory_named_like_a_sidecar_or_staged_sidecar_makes_the_listings_refuse(
        tmp_path):
    """A real directory named 'r1.run-end.json', or 'r1.run-end.json.staged-0123456789abcdef', in
    tenant.runs makes list_run_ids raise RunRefused naming it (a
    directory is not a known sidecar file, and the sidecar clause refuses it as a run). Positive
    control: the same folder with a regular file of each name beside the run r1 lists r1, and a
    real directory named 'r1.run-end.json-2', 'run-end.json', 'r1.run-end.json.staged-g' or
    'r1.oracle-held.json' (#1235 retired its suffix) is a run the listing lists."""
    from defender.run_repository import RunRefused

    _root, t = _good(tmp_path, "r1")
    for name in ("r1.run-end.json", f"r1.run-end.json{H.STAGED_TAIL}"):
        os.mkdir(t.runs / name)
        for fn, call in (("runs.list", lambda: t.runs_repository().list()),):
            err = H.raised(call)
            assert H.is_a(err, RunRefused), f"{fn} over a directory named {name!r} gave {err!r}"
            assert name in H.message(err), f"{fn}'s refusal does not name {name!r}"
        os.rmdir(t.runs / name)
        (t.runs / name).write_text("{}\n", encoding="utf-8")
    assert _ids(t.runs_repository().list()) == ["r1"], "regular sidecar files beside r1 list as r1"
    for name in _OUTSIDE_THE_SIDECAR_CLAUSE:
        H.make_run(t.runs, name)
    runs_now = sorted(["r1", *_OUTSIDE_THE_SIDECAR_CLAUSE])
    assert _ids(t.runs_repository().list()) == runs_now, (
        f"names just outside the sidecar clause are runs (MF-21 B): {_ids(t.runs_repository().list())}")


def test_1105_a_refused_name_is_never_probed_on_disk(tmp_path):
    """Through the repository's injected seam, used to record calls and never to inject a fault,
    open_run(tenant, <sidecar-suffixed RunId>) makes no filesystem call before raising
    RunRefused. Positive control: open_run(tenant, RunId.parse('r1')) through the same seam
    opens tenant.runs once, no-follow, and stats the entry."""
    from defender.run_repository import RunId, RunRefused, RunsRepository

    _root, t = _good(tmp_path, "r1")
    rec = H.RecordingIO()
    err = H.raised(RunsRepository(t, io=rec).open, RunId.parse("r1.run-end.json"))
    assert H.is_a(err, RunRefused), f"a sidecar-suffixed id gave {err!r}"
    assert rec.calls == [], f"a refused name was probed: {rec.calls}"
    rec = H.RecordingIO()
    assert RunsRepository(t, io=rec).open(RunId.parse("r1")).run_dir == t.runs / "r1", (
        "r1 opens")
    assert _is_one_nofollow_hold_of(rec, t.runs), f"holds: {_hold_calls(rec)}"
    stats = [a for n, a, _k in rec.calls
             if (n == "stat_entry" and len(a) > 1 and str(a[1]) == "r1") or n == "stat_entries"]
    assert stats, f"the entry was not stat'ed through the seam: {rec.calls}"



def test_1105_the_lookups_refuse_a_tenant_record_exactly_when_read_tenant_does(tmp_path):
    """The lookups judge _tenant.json by read_tenant served through the held view: a record
    read_tenant admits with an extra key is served, a record read_tenant refuses (a UTF-8 BOM)
    refuses with TenantRefused, and a record whose read raises anything else (200,000-deep
    nesting, where read_tenant raises RecursionError) refuses with TenantRefused, never the raw
    error; the record's tenant_id is then compared with tenant.id exactly."""
    from defender.run_repository import RunId

    _root, t = _good(tmp_path, "r1")
    record = t.runs / "_tenant.json"
    good = json.loads(H.tenant_record_text(t.id))

    def lookups():
        return (("runs.open", lambda: t.runs_repository().open(RunId.parse("r1"))),
                ("runs.list", lambda: t.runs_repository().list()))

    record.write_text(json.dumps({**good, "extra": 1}), encoding="utf-8")
    assert read_tenant(t.runs).tenant_id == t.id, "read_tenant admits an extra key"
    assert _ids(t.runs_repository().list()) == ["r1"], "a record with an extra key is served"
    assert t.runs_repository().open(RunId.parse("r1")).run_dir == t.runs / "r1", "runs.open served it"
    record.write_bytes(b"\xef\xbb\xbf" + json.dumps(good).encode())
    assert H.is_a(H.raised(read_tenant, t.runs), TenantRefused), "read_tenant refuses a BOM"
    for name, call in lookups():
        err = H.raised(call)
        assert _container_refusal(name, err), f"{name} over a BOM record gave {err!r}"
    record.write_text(H.deep_json(), encoding="utf-8")
    assert H.raised(read_tenant, t.runs) is not None, "read_tenant does not admit it"
    for name, call in lookups():
        err = H.raised(call)
        assert _container_refusal(name, err), f"{name} over a 200,000-deep record gave {err!r}"
        assert not isinstance(err, RecursionError), f"{name} let the raw error out"
    record.write_text(json.dumps({**good, "tenant_id": f"{t.id}-2"}), encoding="utf-8")
    for name, call in lookups():
        err = H.raised(call)
        assert _container_refusal(name, err), f"{name} over a record naming {t.id}-2 gave {err!r}"


def test_1105_an_other_tenant_refusal_names_the_file_and_the_id_and_no_run_of_that_tenant(
        tmp_path):
    """When _tenant.json names another tenant, the TenantRefused message names the record file
    and the tenant id found and carries none of the run ids present in that folder. Positive
    control: the message does carry the found id. A _tenant.json whose tenant id holds a newline
    and an ESC still refuses with TenantRefused naming the record file, and the message carries
    no raw control character and no run id (design NF-8: text read from disk is quoted
    repr-style)."""
    from defender.run_repository import RunId

    root, t = _good(tmp_path, "zq-run-alpha", "zq-run-omega")
    _swap_record(t.runs, H.U_ID)
    record = str(t.runs / "_tenant.json")
    for name, call in (("runs.open", lambda: t.runs_repository().open(RunId.parse("asked-1"))),
                       ("runs.list", lambda: t.runs_repository().list())):
        err = H.raised(call)
        assert _container_refusal(name, err), f"{name} gave {err!r}"
        text = H.message(err)
        assert record in text, f"{name}'s refusal does not name {record}: {text}"
        assert H.U_ID in text, f"{name}'s refusal does not name the found id: {text}"
        assert "zq-run" not in text, f"{name}'s refusal leaks a run id: {text}"
    _swap_record(t.runs, "beta\n\x1b[31m forged")
    for name, call in (("runs.open", lambda: t.runs_repository().open(RunId.parse("asked-1"))),
                       ("runs.list", lambda: t.runs_repository().list())):
        err = H.raised(call)
        assert _container_refusal(name, err), f"{name} over a control-character id gave {err!r}"
        text = H.message(err)
        assert record in text, f"{name}'s refusal does not name {record}: {text!r}"
        assert not H.has_raw_control(text), (
            f"{name}'s refusal carries the disk-read id raw: {text!r}")
        assert "zq-run" not in text, f"{name}'s refusal leaks a run id: {text!r}"



def test_1105_both_listings_accept_only_runs_the_record_episodes_and_known_sidecar_files(
        tmp_path):
    """list_run_ids lists each real directory (judged from its directory entry,
    never followed) whose name RunId.parse admits and the sidecar clause passes, a 206-byte name
    included, and accept without listing _tenant.json, _episodes and the known sidecar files
    (regular files <id><suffix>, a staged one included); every other entry is unexpected and
    refuses (p2_run_entry_link_refuses, d2_legacy_folder_refuses,
    d2_listings_refuse_sidecar_named_dir). One such entry, a plain regular file 'notes', shows
    the refusal here."""
    from defender.run_repository import RunRefused

    long_id = "r" + "1" * 205
    _root, t = _good(tmp_path, "r1", "2026-x.y_z", long_id)
    H.plant_sidecars(t.runs, "r1")
    H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})
    expected = sorted(["r1", "2026-x.y_z", long_id])
    assert _ids(t.runs_repository().list()) == expected, f"runs.list gave {_ids(t.runs_repository().list())}"
    (t.runs / "notes").write_text("x\n", encoding="utf-8")
    for name, call in (("runs.list", lambda: t.runs_repository().list()),):
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



def test_1105_open_run_serves_a_real_directory_entry_and_refuses_an_absent_one_naming_it(
        tmp_path):
    """Over a good runs folder, open_run judges tenant.runs/<id> by stat_entry from the held view:
    it hands out a Run when the entry is a real directory, prefix-extending names such as r1-,
    r10 and r1.x included, and raises RunRefused naming the path when the entry is absent;
    nothing is created. An occupant that is not a real directory is P2's: the link is the
    representative pinned (p2_run_entry_link_refuses), the others are not pinned per
    condition."""
    from defender.run_repository import RunId, RunRefused

    root, t = _good(tmp_path, "r1-", "r10", "r1.x")
    before = H.tree_state(root)
    err = H.raised(t.runs_repository().open, RunId.parse("r1"))
    assert H.is_a(err, RunRefused), f"an absent r1 beside r1-, r10, r1.x gave {err!r}"
    assert str(t.runs / "r1") in H.message(err), f"the refusal names the path: {H.message(err)}"
    for name in ("r1-", "r10", "r1.x"):
        assert t.runs_repository().open(RunId.parse(name)).run_dir == t.runs / name, f"{name} opens"
    assert H.tree_state(root) == before, "runs.open created something"



def test_1105_no_lookup_or_record_reader_writes_anything(tmp_path):
    """Driving every lookup and record reader over an absent, an empty and a populated runs
    folder leaves the data root's tree byte-for-byte and entry-for-entry unchanged: no folder,
    record or file is created. Over the empty folder, whose _tenant.json is absent, open_run,
    list_run_ids, episode_runs and sibling_run_ids each refuse the container (O3: a runs folder
    with no _tenant.json refuses; `_container_refusal`). Positive control: run setup
    does create the runs folder and _tenant.json, and record_episode_runs does create
    _episodes/."""
    from defender.run_repository import (
        RunId, episode_runs, episode_sibling_ids, record_episode_runs, sibling_run_ids,
    )

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)

    def drive_readers():
        rid = RunId.parse("r1")
        out = {}
        for name, call in (("runs.open", lambda: t.runs_repository().open(rid)),
                           ("runs.list", lambda: _ids(t.runs_repository().list())),
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
            for name in ("runs.open", "runs.list", "episode_runs", "sibling_run_ids"):
                assert _container_refusal(name, answers[name]), (
                    f"{name} over a runs folder with no _tenant.json gave {answers[name]!r}, "
                    "not the container's refusal")
        if state == "populated":
            assert answers["runs.list"] == ["r1"], f"populated folder answers: {answers}"
        assert H.tree_state(root) == before, f"a reader wrote over the {state} folder"
    u = H.tenant(root, H.U_ID)
    alert = H.alert_file(tmp_path / "alerts")
    run_common.materialize_run(alert, "r9", tenant=u)
    assert (u.runs / "_tenant.json").is_file(), "run setup creates the runs folder and record"
    assert record_episode_runs(u, "ep", RunId.parse("r9"),
                               {"a": RunId.parse("ep-a")}) is None, "the writer answers"
    assert (u.runs / "_episodes").is_dir(), "record_episode_runs creates _episodes/"


def test_1105_list_run_ids_returns_sorted_run_ids_minus_record_claimed_ids(tmp_path):
    """list_run_ids(tenant) — PR 2: tenant.runs_repository().list(), a Listed (declared change
    0) — returns the RunIds, sorted by text, of the runs in tenant.runs, minus every id a good
    episode record claims (the record written in the test through record_episode_runs); a folder
    holding only its good _tenant.json lists []."""
    from defender.run_repository import Listed, RunId, record_episode_runs

    _root, t = _good(tmp_path)
    empty = t.runs_repository().list()
    assert isinstance(empty, Listed), f"a record-only folder lists {empty!r}"
    assert list(empty) == [], f"a record-only folder lists {empty!r}"
    for rid in ("c", "a", "b"):
        H.make_run(t.runs, rid)
    assert record_episode_runs(t, "ep", RunId.parse("a"),
                               {"x": RunId.parse("ep-x"), "y": RunId.parse("ep-y")}) is None
    for arm in ("ep-x", "ep-y"):
        H.make_run(t.runs, arm)
    listed = t.runs_repository().list()
    assert isinstance(listed, Listed), f"listed {listed!r}"
    assert _ids(listed) == ["a", "b", "c"], f"listed {listed!r}"
    assert all(H.is_a(i, RunId) for i in listed), "every entry is a RunId"


# ==========================================================================================
# Tenant isolation (O3, S1, S2).
# ==========================================================================================


def test_1105_open_run_never_hands_out_a_handle_into_another_tenants_folder(tmp_path):
    """With tenant A's run r1 on disk, open_run(B, r1) never returns a Run whose run_dir resolves
    under A.runs: B.runs as a link to A.runs, B's _tenant.json naming A, and B.runs/r1 as a link
    to A.runs/r1 each raise (RunUnreachable, RunUnreachable — each from TenantRefused — and
    RunRefused). Positive control:
    open_run(A, r1) reaches A's run."""
    from defender.run_repository import RunId, RunRefused

    root, a = _good(tmp_path, "r1")
    b = H.tenant(root, H.U_ID)
    r1 = RunId.parse("r1")
    os.symlink(a.runs, b.runs)
    err = H.raised(b.runs_repository().open, r1)
    assert _container_refusal("runs.open", err), f"B.runs a link to A.runs gave {err!r}"
    os.unlink(b.runs)
    H.plant_tenant_record(b.runs, a.id)
    H.make_run(b.runs, "r1")
    err = H.raised(b.runs_repository().open, r1)
    assert _container_refusal("runs.open", err), f"B's record naming A gave {err!r}"
    shutil.rmtree(b.runs)
    H.runs_folder(b)
    os.symlink(a.runs / "r1", b.runs / "r1")
    err = H.raised(b.runs_repository().open, r1)
    assert H.is_a(err, RunRefused), f"B.runs/r1 a link to A's run gave {err!r}"
    run = a.runs_repository().open(r1)
    assert run.run_dir.resolve() == (a.runs / "r1").resolve(), "A reaches its own run"


def test_1105_a_box_writable_tenant_claim_neither_grants_nor_refuses_a_lookup(tmp_path):
    """A run's provenance stamp, an episode manifest and an episode folder that name another
    tenant change no answer of open_run or list_run_ids for the request's tenant.
    Positive control: a _tenant.json naming another tenant does refuse."""
    from defender.run_repository import RunId

    _root, t = _good(tmp_path, "r1", "r2")

    def answers():
        return (str(t.runs_repository().open(RunId.parse("r1")).run_dir),
                _ids(t.runs_repository().list()))

    before = answers()
    assert before == (str(t.runs / "r1"), ["r1", "r2"]), f"baseline: {before}"
    (t.runs / "r1" / "provenance.json").write_text(
        json.dumps({"tenant_id": H.U_ID, "world_id": "w"}) + "\n", encoding="utf-8")
    episode = t.episodes / "ep1"
    episode.mkdir(parents=True)
    (episode / "family.yaml").write_text(f"tenant_id: {H.U_ID}\nsource_run_id: r1\n",
                                         encoding="utf-8")
    H.plant_tenant_record(episode / "runs", H.U_ID)
    assert answers() == before, "a box-writable tenant claim changed an answer"
    _swap_record(t.runs, H.U_ID)
    err = H.raised(t.runs_repository().list)
    assert H.is_a(err, TenantRefused), f"the host-only record naming {H.U_ID} gave {err!r}"



# ==========================================================================================
# P2's representatives and the expected states.
# ==========================================================================================

def test_1105_a_link_at_tenant_runs_refuses_every_function_naming_it(tmp_path):
    """With tenant.runs a link to another tenant's runs folder, each lookup and tenant-keyed
    record function refuses the container (`_container_refusal`) naming tenant.runs and the
    link fault, never a raw
    OSError, and the other tenant's folder is byte-unchanged; a link to a folder whose own record
    names this tenant refuses the same way, so it is the no-follow hold that refuses, not the
    record compare. Positive control: the same calls answer over a real tenant.runs, and over a
    real tenant.runs under a linked ANCESTOR (a data root reached through a link), open_run
    handing out the run and list_run_ids listing it: only a link AT tenant.runs refuses (P1,
    R41-03)."""
    from defender.run_repository import RunId

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
            assert _container_refusal(name, err), f"{name} over a link to {target.name} gave {err!r}"
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
    assert w.runs_repository().open(RunId.parse("r1")).run_dir == w.runs / "r1", (
        "a runs folder under a linked ancestor is served: runs.open hands out its run")
    assert _ids(w.runs_repository().list()) == ["r1"], "runs.list under a linked ancestor lists r1"
    for name, call in _every_function(w):
        err = H.raised(call)
        assert err is None, f"{name} under a linked ancestor raised {err!r}"


def test_1105_a_tenant_record_naming_another_tenant_refuses_every_function(tmp_path):
    """With tenant.runs/_tenant.json naming another tenant, each lookup and tenant-keyed record
    function refuses the container (`_container_refusal`) naming the record, writes nothing and
    returns no run of that
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
            assert _container_refusal(name, err), (
                f"{name}({me.id}) with a swapped record gave {err!r}")
            assert record in H.message(err), f"{name}'s refusal does not name {record}"
    assert H.tree_state(root) == before, "a refused call wrote something"
    for me in (t, u):
        _swap_record(me.runs, me.id)
        for name, call in _every_function(me):
            err = H.raised(call)
            assert err is None, f"{name}({me.id}) over its own record raised {err!r}"


def test_1105_a_link_at_a_runs_name_refuses_naming_it_and_is_never_followed(tmp_path):
    """With tenant.runs/r2 a link to a run folder (inside the same runs folder, or another
    tenant's), list_run_ids raises RunRefused naming r2, open_run(tenant,
    r2) raises RunRefused naming the path, and record_episode_runs refuses an arm whose name is
    such a link (planted at ep-b: an arm is shaped f'{episode_id}-{label}', so no arm is named
    r2); nothing reads through the link. Positive control: the same folder without the link
    answers."""
    from defender.run_repository import RunId, RunRefused, record_episode_runs

    root, t = _good(tmp_path, "r1")
    u = H.tenant(root, H.U_ID)
    H.runs_folder(u)
    H.make_run(u.runs, "r1", alert='{"alert_id": "u-secret"}\n')
    for target in (t.runs / "r1", u.runs / "r1"):
        os.symlink(target, t.runs / "r2")
        target_before = H.tree_state(target)
        for name, call in (("runs.list", lambda: t.runs_repository().list()),):
            err = H.raised(call)
            assert H.is_a(err, RunRefused), f"{name} beside a link at r2 gave {err!r}"
            assert "r2" in H.message(err), H.message(err)
            assert "u-secret" not in H.message(err), H.message(err)
        err = H.raised(t.runs_repository().open, RunId.parse("r2"))
        assert H.is_a(err, RunRefused), f"runs.open(r2) through the link gave {err!r}"
        assert str(t.runs / "r2") in H.message(err), f"names the path: {H.message(err)}"
        assert H.tree_state(target) == target_before, f"{target} changed"
        os.unlink(t.runs / "r2")
    os.symlink(t.runs / "r1", t.runs / "ep-b")
    err = H.raised(record_episode_runs, t, "ep", RunId.parse("r1"), {"b": RunId.parse("ep-b")})
    assert H.is_a(err, RunRefused), f"an arm named by a link gave {err!r}"
    assert "ep-b" in H.message(err), f"the writer's refusal names the arm: {H.message(err)}"
    assert not (t.runs / "_episodes" / "ep.json").exists(), "the refused record was written"
    os.unlink(t.runs / "ep-b")
    assert _ids(t.runs_repository().list()) == ["r1"], "without the link"
    assert record_episode_runs(t, "ep", RunId.parse("r1"), {"b": RunId.parse("ep-b")}) is None


def test_1105_open_run_and_run_exists_answer_beside_a_torn_record_and_a_stray_name_in_episodes(  # name kept: the spec graph cites it; run_exists is gone (#1105 PR 2 review)
        tmp_path):
    """P2's Reach: each function judges what it reads, and only that (design D2: open_run does
    not read _episodes, episode_runs(ep) reads only ep's record, and open_run judges only its own
    entry). With tenant.runs/_episodes holding a torn record (a good record claiming ep-a, cut
    short) and a stray file README, open_run(tenant, id) still hands out the run for r1 and for
    ep-a, the id the torn record would claim, as it would with no _episodes: it does not read
    _episodes. Beside the same torn record and README, episode_runs(tenant, 'nope') answers {}
    and a good record ep2 is answered by episode_runs(tenant, 'ep2'). With a directory
    'Bad Name' planted beside r1 (and _episodes removed), open_run(tenant, r1) still serves.
    Positive control: over the same tree the _episodes readers refuse, sibling_run_ids and
    list_run_ids raising RunRefused, episode_runs(tenant, 'ep') raising RunRefused
    for its own torn record, and list_run_ids, which lists both runs before 'Bad Name' is
    planted, refusing the folder once it holds it."""
    from defender.run_repository import RunId, RunRefused, episode_runs, sibling_run_ids

    root, t = _good(tmp_path, "r1", "ep-a")
    record = H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})
    torn_text = H.truncated(record.read_text(encoding="utf-8"))
    record.write_text(torn_text, encoding="utf-8")
    (t.runs / "_episodes" / "README").write_text("notes\n", encoding="utf-8")
    before = H.tree_state(root)
    for rid in ("r1", "ep-a"):
        err = H.raised(t.runs_repository().open, RunId.parse(rid))
        assert err is None, f"runs.open({rid}) read _episodes and refused a healthy run: {err!r}"
        assert t.runs_repository().open(RunId.parse(rid)).run_dir == t.runs / rid, f"runs.open({rid}) serves"
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
                       ("runs.list", lambda: t.runs_repository().list()),
                       ("episode_runs", lambda: episode_runs(t, "ep"))):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), (
            f"positive control: the _episodes reader {name} answered over a torn record and a "
            f"stray name: {err!r}")
    shutil.rmtree(t.runs / "_episodes")
    assert _ids(t.runs_repository().list()) == ["ep-a", "r1"], "the folder without _episodes lists both runs"
    os.mkdir(t.runs / "Bad Name")
    err = H.raised(t.runs_repository().open, RunId.parse("r1"))
    assert err is None, f"runs.open(r1) judged an entry beside its own and refused: {err!r}"
    assert t.runs_repository().open(RunId.parse("r1")).run_dir == t.runs / "r1", "runs.open(r1) beside Bad Name"
    err = H.raised(t.runs_repository().list)
    assert H.is_a(err, RunRefused), (
        f"positive control: runs.list answered over a folder holding 'Bad Name': {err!r}")


def test_1105_an_absent_runs_folder_answers_empty_and_creates_nothing(tmp_path):
    """For an accepted tenant with no runs folder, list_run_ids (PR 2: runs.list, a Listed)
    lists [] with absent=True, episode_runs returns {} and sibling_run_ids the empty set,
    episode_sibling_ids over a Bound of the absent folder returns the empty set, open_run raises
    RunAbsent (the run is gone with its folder) and record_episode_runs TenantRefused; none of
    them creates anything.
    Afterwards run setup creates the folder, its record and a run, and the same Tenant gets that
    run from open_run and list_run_ids."""
    from defender.run_repository import (
        Listed, RunAbsent, RunId, episode_runs, episode_sibling_ids, record_episode_runs,
        sibling_run_ids,
    )

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    before = H.tree_state(root)
    listed = t.runs_repository().list()
    assert isinstance(listed, Listed), f"runs.list gave {listed!r}"
    assert list(listed) == [], f"runs.list gave {listed!r}"
    assert listed.absent is True, f"runs.list's absent is {listed.absent!r}"
    assert dict(episode_runs(t, "ep")) == {}, "episode_runs over an absent folder"
    assert set(sibling_run_ids(t)) == set(), "sibling_run_ids over an absent folder"
    with _io.bind(t.runs) as bound:
        assert set(episode_sibling_ids(bound)) == set(), "episode_sibling_ids over absent"
    err = H.raised(t.runs_repository().open, RunId.parse("r1"))
    assert H.is_a(err, RunAbsent), f"runs.open over an absent folder gave {err!r}"
    err = H.raised(record_episode_runs, t, "ep", RunId.parse("r1"), {"a": RunId.parse("ep-a")})
    assert H.is_a(err, TenantRefused), f"record_episode_runs over an absent folder gave {err!r}"
    assert H.tree_state(root) == before, "something was created"
    assert not t.runs.exists(), "something was created"
    run_common.materialize_run(H.alert_file(tmp_path / "alerts"), "r1", tenant=t)
    assert (t.runs / "_tenant.json").is_file(), "run setup made the folder and record"
    assert t.runs_repository().open(RunId.parse("r1")).run_dir == t.runs / "r1", "the run opens"
    assert _ids(t.runs_repository().list()) == ["r1"], "the run lists"


def test_1105_a_run_with_sidecar_files_beside_it_lists_as_the_one_run(tmp_path):
    """A run folder r1 with its sidecar files (`H.SIDECAR_SUFFIXES`) beside it and a staged one
    (r1.run-end.json.staged-<16 hex>) lists as the one run r1 in list_run_ids, which does not
    refuse; sidecar files left for a run whose folder is gone are accepted the same way, and
    that id is not listed. A run whose id is 206 bytes (the bound) with the longest sidecar
    suffix's staged file beside it (<id>.accounting_failures.json.staged-<16 hex>, a 255-byte
    name made on the real filesystem) lists as that one run in list_run_ids."""
    _root, t = _good(tmp_path, "r1")
    H.plant_sidecars(t.runs, "r1")
    H.plant_sidecars(t.runs, "gone")
    assert _ids(t.runs_repository().list()) == ["r1"], f"runs.list gave {_ids(t.runs_repository().list())}"
    longest = max(H.SIDECAR_SUFFIXES, key=len)
    long_id = "r1-" + "a" * (H.RUN_ID_BOUND - 3)
    H.make_run(t.runs, long_id)
    staged = t.runs / f"{long_id}{longest}{H.STAGED_TAIL}"
    staged.write_text("{}\n", encoding="utf-8")
    assert len(staged.name.encode("utf-8")) == 255, f"the staged name is {len(staged.name)} bytes"
    assert staged.is_file(), "the 255-byte staged sidecar was not made"
    want = sorted(["r1", long_id])
    assert _ids(t.runs_repository().list()) == want, (
        f"runs.list beside a 255-byte staged sidecar gave {[x[:12] for x in _ids(t.runs_repository().list())]}")


def test_1105_every_lookup_and_record_function_closes_its_held_handle_on_each_path(tmp_path):
    """the process's open descriptor count (/proc/self/fd) is the same before and after each
    lookup and record function on its success path and on each refusal path (TypeError before
    any read opens none; TenantRefused; RunRefused). The RunRefused paths include one after the
    hold for each lookup and record function: a folder named 'Bad Name' (list_run_ids), a stray
    README in _episodes (sibling_run_ids), a link at runs.open's own entry, for
    record_episode_runs an arm another record claims, a link at _episodes and a different record
    already at the episode's name, and for episode_runs its own torn record."""
    from defender.run_repository import (
        RunId, RunRefused, RunsRepository, episode_runs, record_episode_runs, sibling_run_ids,
    )

    _root, t = _good(tmp_path, "r1")
    H.plant_record(t.runs, "ep", t.id, "r1", {"a": "ep-a"})

    def delta(call):
        before = H.open_fd_count()
        err = H.raised(call)
        return H.open_fd_count() - before, err

    rid = RunId.parse("r1")
    success = (("runs.open", lambda: t.runs_repository().open(rid)),
               ("runs.list", lambda: t.runs_repository().list()),
               ("record_episode_runs", lambda: record_episode_runs(
                   t, "ep2", rid, {"b": RunId.parse("ep2-b")})),
               ("episode_runs", lambda: episode_runs(t, "ep")),
               ("sibling_run_ids", lambda: sibling_run_ids(t)))
    for name, call in success:
        d, err = delta(call)
        assert err is None, f"{name} success path: delta {d}, raised {err!r}"
        assert d == 0, f"{name} success path: delta {d}, raised {err!r}"
    for name, call in (("RunsRepository(tenant id)", lambda: RunsRepository(t.id).open(rid)),
                       ("RunsRepository(runs folder)", lambda: RunsRepository(t.runs).list()),
                       ("record_episode_runs", lambda: record_episode_runs(t, "ep3", "r1", {}))):
        d, err = delta(call)
        assert type(err) is TypeError, f"{name} TypeError path: {d}, {err!r}"
        assert d == 0, f"{name} TypeError path: {d}, {err!r}"
    for name, call in (("runs.open", lambda: t.runs_repository().open(RunId.parse("r7"))),
                       ("record_episode_runs", lambda: record_episode_runs(t, "ep4", rid, {})),
                       ("episode_runs", lambda: episode_runs(t, "../x"))):
        d, err = delta(call)
        assert H.is_a(err, RunRefused), f"{name} RunRefused path: {d}, {err!r}"
        assert d == 0, f"{name} RunRefused path: {d}, {err!r}"
    # RunRefused AFTER the hold: each lookup refuses a state it reads inside the held folder.
    after_hold = (
        ("runs.list", lambda: os.mkdir(t.runs / "Bad Name"),
         lambda: t.runs_repository().list(), lambda: os.rmdir(t.runs / "Bad Name")),
        ("sibling_run_ids", lambda: (t.runs / "_episodes" / "README").write_text(
            "notes\n", encoding="utf-8"),
         lambda: sibling_run_ids(t), lambda: (t.runs / "_episodes" / "README").unlink()),
        ("runs.open/a link at its entry", lambda: os.symlink(t.runs / "r1", t.runs / "r2"),
         lambda: t.runs_repository().open(RunId.parse("r2")), lambda: os.unlink(t.runs / "r2")),
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
        assert _container_refusal(name, err), f"{name} TenantRefused path: {d}, {err!r}"
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
    """a run folder named 'a<newline>[run.py] forged' or 'x<ESC>[31m' makes list_run_ids
    raise RunRefused, and a stray entry of that kind in _episodes makes
    the _episodes readers list_run_ids and sibling_run_ids raise RunRefused (255-byte
    names included on both arms), each message holding no raw newline or escape character and
    still naming the entry (a visible run of its characters appears); run setup's claimed-id refusal over the same _episodes is exactly one
    stderr line (splitlines() == 1) with no traceback; positive control: the same call over a
    plain-named stray entry names it verbatim
    A run folder and a stray entry carrying DEL, a C1 control (U+009B) and U+2028 are among the
    hostile names (91 BF-09)."""
    from defender.run_repository import RunRefused, sibling_run_ids

    _root, t = _good(tmp_path, "r1")
    hostile = (("a\n[run.py] forged", "[run.py] forged"), ("x\x1b[31m", "[31m"),
               ("n\n" + "c" * 253, "ccc"), ("d\x7f\x9b\u2028[c1] forged", "[c1] forged"))
    for name, visible in hostile:
        os.mkdir(t.runs / name)
        for fn, call in (("runs.list", lambda: t.runs_repository().list()),):
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
                         ("runs.list", lambda: t.runs_repository().list())):
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
