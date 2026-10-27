"""Run lookup: open/list over a tenant's runs folder, link/torn-record/foreign-tenant refusals, escaping of quoted names, handle closing."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

import copy
import pickle
import inspect
from defender.tenancy import _tenant

import json
import os
import shutil
import uuid
from pathlib import Path

from defender import _io
from defender import run_common
from defender.records._tenant_id import TenantRefused
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.records._tenant_id import TenantId

DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"


def _good(tmp_path: Path, *run_ids: str, tenant_id: str = H.T_ID):
    """A data root holding `tenant_id` with a checked runs folder (its `_tenant.json` naming it)
    and a real run folder per id."""
    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, tenant_id)
    H.runs_folder(t)
    for rid in run_ids:
        H.make_run(location_path(t.runs), rid)
    return root, t


def _ids(answer) -> list[str]:
    return [str(i) for i in answer]


def _container_refusal(name: str, err: object) -> bool:
    """Whether `err` is how the function `name` refuses a container fault: `TenantRefused`, but
    for an open, `RunUnreachable` raised from that `TenantRefused` (#1105 PR 2 review: opening
    a run answers one refusal family)."""
    from defender.records import RunUnreachable

    if name.startswith("runs.open"):
        return H.is_a(err, RunUnreachable) and H.is_a(getattr(err, "__cause__", None),
                                                      TenantRefused)
    return H.is_a(err, TenantRefused)


def _uuids(n: int) -> list[str]:
    """`n` fresh canonical lowercase uuid4s, sorted by text (the listing's order) — #1187
    declared change 1: only such text is a run id."""
    return sorted(str(uuid.uuid4()) for _ in range(n))


def _fresh(tmp_path: Path, *run_ids: str, tenant_id: str = H.T_ID):
    """#1187's natural container: a data root holding `tenant_id`, a real `tenant.runs` and a
    real run folder per id in it — and NO `_tenant.json` (R1: the container holds run folders
    and their sidecars only)."""
    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, tenant_id)
    Path(location_path(t.runs)).mkdir(parents=True, exist_ok=True)
    for rid in run_ids:
        H.make_run(location_path(t.runs), rid)
    return root, t


def _repository_calls(t, run_id: str):
    """`(name, thunk)` per natural lookup of `t`'s repository. #1187 R6 deletes the tenant-keyed
    record functions (`record_episode_runs`, `episode_runs`, `sibling_run_ids`), so these are
    every function a container fault reaches."""
    from defender.records import RunId

    return [
        ("runs.open", lambda: t.runs_repository().open(RunId.parse(run_id))),
        ("runs.list", lambda: t.runs_repository().list()),
        ("runs.all_runs", lambda: t.runs_repository().all_runs()),
    ]


def _level_refusal(err: object) -> bool:
    """How #1187 refuses a link at a level below `<T>` (S-iso; declared change 8):
    `TenantRefused` or `RunRefused` (an open's `RunUnreachable` is one), naming the level."""
    from defender.records import RunRefused

    return isinstance(err, (TenantRefused, RunRefused))


#: The `_io` calls that open a folder.
_OPENERS = ("hold", "hold_new", "bind")


def _opens_through_the_seam_no_follow(rec: H.RecordingIO, t) -> bool:
    """Whether the openers `rec` recorded have the no-follow SHAPE (#1187 S-iso, declared
    change 8, replacing PR 1's "one `hold(tenant.runs, follow=False)`"): at least one opener
    call went through the injected seam; every `hold` passes `follow=False` and holds `<T>` or
    `<T>/runs`; a `bind` is rooted at the data root (it follows only its root's spelling, as
    configuration); no `hold_new` (its `makedirs` follows links). How many openers the walk
    takes is not pinned."""
    opens = [(n, a, k) for n, a, k in rec.calls if n in _OPENERS]
    if not opens:
        return False
    tenant_dir = Path(location_path(t.runs)).parent
    for name, args, kwargs in opens:
        root = args[0] if args else kwargs.get("root")
        if not isinstance(root, (str, os.PathLike)):
            return False
        if name == "hold":
            if kwargs.get("follow") is not False or Path(root) not in (tenant_dir, Path(location_path(t.runs))):
                return False
        elif name == "bind":
            if Path(root) != Path(location_path(t.data_root)):
                return False
        else:
            return False
    return True


def _openers(rec: H.RecordingIO) -> list:
    return [(n, a, k) for n, a, k in rec.calls if n in _OPENERS]


def _outside_the_sidecar_clause(run_id: str) -> tuple[str, ...]:
    """PR 1's names just outside the sidecar clause (MF-21 B; I061, DV-5), over `run_id`: no
    sidecar suffix at the end, a staged tail that is not lowercase hex, a suffix #1235 retired.
    Under #1187 (declared change 1) none of them is a run id: only a canonical UUID is."""
    return (f"{run_id}.run-end.json-2", "run-end.json", f"{run_id}.run-end.json.staged-g",
            f"{run_id}.oracle-held.json")


def test_1105_open_run_returns_the_tenants_run_under_tenant_runs(tmp_path):
    """open_run(tenant, RunId.parse(id)) over a runs folder whose entry tenant.runs/<id> is a
    real directory returns the Run that Run.under(tenant.runs, id, tenant_id=tenant.id) builds:
    its tenant_id is tenant.id, its runs_base is tenant.runs (tenant.data_root / tenant.id /
    'runs'), its run_dir is tenant.runs / id; nothing is written."""
    from defender.records import Run, RunId, RunsRepository

    rid = str(uuid.uuid4())
    root, t = _fresh(tmp_path, rid)
    before = H.tree_state(root)
    rec = H.RecordingIO()
    run = RunsRepository(t, io=rec).open(RunId.parse(rid))
    assert run.run_dir == location_path(t.runs) / rid, f"runs.open handed out run_dir {run.run_dir!r}"
    assert location_path(run.runs_base) == location_path(t.runs) == location_path(t.data_root) / t.id / "runs", location_path(run.runs_base)
    assert run.tenant_id == t.id, run.tenant_id
    built = Run.under(t.runs, rid, tenant_id=t.id)
    assert type(run) is type(built), "runs.open hands out Run.under's Run"
    assert ((run.run_dir, location_path(run.runs_base), run.tenant_id) == (
        built.run_dir, location_path(built.runs_base), built.tenant_id)), "runs.open hands out Run.under's Run"
    record_reads = [(n, a) for n, a, _k in rec.calls
                    if any(isinstance(x, (str, os.PathLike)) and Path(x).name == "_tenant.json"
                           for x in a)]
    assert not record_reads, f"the open read a tenant record: {record_reads}"
    assert _opens_through_the_seam_no_follow(rec, t), f"openers: {_openers(rec)}"
    assert H.tree_state(root) == before, "runs.open wrote something"


def test_1105_every_tenant_keyed_function_raises_type_error_before_any_read(tmp_path):
    """The runs repository's constructor (PR 2: the lookups are its methods, so the tenant is
    checked where the repository is built) raises TypeError, before reading anything, when the
    tenant handed to it is not an accepted Tenant (a tenant id str, a TenantId, a runs-folder
    Path, a RunTenant), and runs.open raises it when the run id it takes is not a RunId, a str
    included; the proof that nothing was read is a runs folder planted as a link, which would
    otherwise refuse, and a recording io= seam passed to each refused call records no call at
    all. Positive control: the same calls with an accepted Tenant and a RunId answer."""
    from defender.records import RunId, RunsRepository
    from defender.systems.run_tenant import RunTenant

    rid = str(uuid.uuid4())
    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    elsewhere = tmp_path / "elsewhere"
    H.make_run(elsewhere, rid)
    os.symlink(elsewhere, location_path(t.runs))
    carrier = RunTenant(tenant=t, grants=None, correlation=None, systems={},
                        ticket_mapping=None)

    for bad in (t.id, TenantId(t.id), location_path(t.runs), carrier):
        rec = H.RecordingIO()
        err = H.raised(lambda io, bad=bad: RunsRepository(bad, io=io), rec)
        assert type(err) is TypeError, f"RunsRepository({type(bad).__name__}) raised {err!r}"
        assert not rec.calls, (
            f"RunsRepository({type(bad).__name__}) touched the seam before its TypeError: "
            f"{rec.calls}")
    rec = H.RecordingIO()
    err = H.raised(lambda io: RunsRepository(t, io=io).open(rid), rec)
    assert type(err) is TypeError, f"runs.open with a str run id raised {err!r}"
    assert not rec.calls, f"runs.open touched the seam before its TypeError: {rec.calls}"
    # The link would have refused: the TypeError fired before anything was read.
    err = H.raised(t.runs_repository().list)
    assert _level_refusal(err), f"the linked runs folder did not refuse: {err!r}"
    # Positive control: a real runs folder (no record) and a RunId answer.
    os.unlink(location_path(t.runs))
    H.make_run(location_path(t.runs), rid)
    runs = t.runs_repository()
    assert runs.open(RunId.parse(rid)).run_dir == location_path(t.runs) / rid, "runs.open over a good folder"
    assert _ids(runs.list()) == [rid], "runs.list over a good folder"


def test_1105_the_repository_answers_from_the_tenant_it_is_handed_and_reads_no_environment(
        tmp_path, monkeypatch):
    """With DEFENDER_DATA_ROOT unset or naming another data root, and with the tenant's knowledge
    folder removed after acceptance, every repository function answers exactly as before from
    tenant.runs of the Tenant it was handed. Positive control: accept_tenant at the edge
    refuses the same tenant once its knowledge folder is gone."""
    from defender.records import RunId

    r1, r2 = _uuids(2)
    root, t = _fresh(tmp_path, r1, r2)

    def answers() -> dict:
        runs = t.runs_repository()
        run = runs.open(RunId.parse(r1))
        return {"runs.open": (str(run.run_dir), str(getattr(run, "tenant_id", None))),
                "runs.list": _ids(runs.list()),
                "runs.all_runs": [str(r.run_dir) for r in runs.all_runs()]}

    expected = {"runs.open": (str(location_path(t.runs) / r1), t.id), "runs.list": [r1, r2],
                "runs.all_runs": [str(location_path(t.runs) / r1), str(location_path(t.runs) / r2)]}
    assert answers() == expected, f"baseline answers: {answers()}"
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)
    assert answers() == expected, "answers moved with DEFENDER_DATA_ROOT unset"
    other_root = tmp_path / "other-root"
    H.tenant(other_root, t.id)
    monkeypatch.setenv(DATA_ROOT_ENV, str(other_root))
    assert answers() == expected, "answers moved with DEFENDER_DATA_ROOT elsewhere"
    shutil.rmtree(t.knowledge)
    assert answers() == expected, "answers moved with the knowledge folder gone"
    created = t.runs_repository().create()
    assert created.run_dir.parent == location_path(t.runs), f"runs.create landed at {created.run_dir}"
    assert not (other_root / t.id / "runs").exists(), "something reached the env's data root"
    err = H.raised(_tenant.accept_tenant, fixture_data_root(root), t.id, defender_dir=H.DEFENDER)
    assert H.is_a(err, TenantRefused), f"acceptance at the edge did not refuse: {err!r}"


def test_1105_a_copied_or_pickled_tenant_is_served_like_the_original(tmp_path):
    """A copy.copy, a copy.deepcopy and a pickle round trip of an accepted Tenant are served by
    open_run (runs.open), list_run_ids (runs.list) and runs.all_runs exactly as the original
    is.

    #1187 declared changes 1, 6 and 13 (R1, R6): `sibling_run_ids` is deleted with the
    `_episodes` record (runs.all_runs takes its place in the comparison); ids are UUIDs and the
    container holds no `_tenant.json`. (Name kept.)"""
    from defender.records import RunId

    r1, r2 = _uuids(2)
    _root, t = _fresh(tmp_path, r1, r2)

    def answers(x):
        runs = x.runs_repository()
        run = runs.open(RunId.parse(r2))
        return (str(run.run_dir), str(getattr(run, "tenant_id", None)), _ids(runs.list()),
                [str(r.run_dir) for r in runs.all_runs()])

    original = answers(t)
    assert original == (str(location_path(t.runs) / r2), t.id, [r1, r2],
                        [str(location_path(t.runs) / r1), str(location_path(t.runs) / r2)]), original
    for twin in (copy.copy(t), copy.deepcopy(t), pickle.loads(pickle.dumps(t))):
        assert answers(twin) == original, f"a copied Tenant was served differently: {twin!r}"


def test_1105_every_repository_function_takes_an_injected_io_like_the_handle(tmp_path):
    """The repository takes a keyword-only injected I/O seam (default: the real defender._io) —
    PR 2: RunsRepository(tenant, *, io=) — passes it to the Run it hands out, and routes each
    method's own open through it, so a recording seam sees it. The suite uses the seam to
    observe calls, never to inject an I/O fault (test shape)."""
    from defender.records import RunId, RunsRepository

    rid = str(uuid.uuid4())
    _root, t = _fresh(tmp_path, rid)
    params = inspect.signature(RunsRepository).parameters
    assert "io" in params, "RunsRepository takes no io= seam"
    assert params["io"].kind is inspect.Parameter.KEYWORD_ONLY, "RunsRepository: io= kind"
    assert params["io"].default is _io, f"RunsRepository: io= defaults to {params['io'].default!r}"
    run_id = RunId.parse(rid)
    cases = (
        ("runs.open", lambda io: RunsRepository(t, io=io).open(run_id)),
        ("runs.list", lambda io: RunsRepository(t, io=io).list()),
        ("runs.all_runs", lambda io: RunsRepository(t, io=io).all_runs()),
    )
    for name, call in cases:
        rec = H.RecordingIO()
        call(rec)
        assert _opens_through_the_seam_no_follow(rec, t), f"{name}: openers {_openers(rec)}"
    rec = H.RecordingIO()
    run = RunsRepository(t, io=rec).open(run_id)
    seen = len(rec.calls)
    run.facts.alert.read()
    assert any(n == "rooted_read" for n, _a, _k in rec.calls[seen:]), (
        "the Run runs.open hands out does not read through the injected seam")
    err = H.raised(RunsRepository, t, H.RecordingIO())
    assert type(err) is TypeError, f"io passed positionally was accepted: {err!r}"


# ==========================================================================================
# The name rule and the entry rule.
# ==========================================================================================

def test_1105_open_run_refuses_each_sidecar_suffixed_id_as_run_refused(tmp_path):
    """open_run refuses with RunRefused an id ending in each of the host-only sidecar suffixes
    (`H.SIDECAR_SUFFIXES`) and an id of the staged shape (a sidecar suffix, then '.staged-',
    then lowercase hex digits), even when the runs folder is absent (before the folder), and
    even when a real directory sits at the name over a good folder."""
    from defender.records import RunId, RunRefused

    rid = str(uuid.uuid4())
    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    names = ([f"{rid}{s}" for s in H.SIDECAR_SUFFIXES]
             + [f"{rid}.run-end.json{H.STAGED_TAIL}", f"{rid}.ticket-write.json.staged-0",
                f"{rid}.accounting_failures.json{H.STAGED_TAIL}"])

    def opened(name: str):
        return H.raised(lambda: t.runs_repository().open(RunId.parse(name)))

    for name in names:
        err = opened(name)
        assert H.is_a(err, RunRefused), f"runs.open({name!r}) over an absent folder gave {err!r}"
        assert name in H.message(err), f"the refusal does not name {name!r}: {H.message(err)}"
    assert not location_path(t.runs).exists(), "a refused name created the runs folder"
    H.make_run(location_path(t.runs), rid)
    for name in names:
        os.mkdir(location_path(t.runs) / name)  # even a real directory at the name is never opened as a run
        err = opened(name)
        assert H.is_a(err, RunRefused), f"runs.open({name!r}) over a good folder gave {err!r}"
        os.rmdir(location_path(t.runs) / name)
    assert t.runs_repository().open(RunId.parse(rid)).run_dir == location_path(t.runs) / rid, "the uuid opens"
    for name in _outside_the_sidecar_clause(rid):
        H.make_run(location_path(t.runs), name)
        err = opened(name)
        assert H.is_a(err, RunRefused), (
            f"{name!r} is no run id under #1187 (only a canonical UUID is), yet runs.open gave "
            f"{err!r}")


def test_1105_a_directory_named_like_a_sidecar_or_staged_sidecar_makes_the_listings_refuse(
        tmp_path):
    from defender.records import RunRefused

    rid = str(uuid.uuid4())
    _root, t = _fresh(tmp_path, rid)
    for name in (f"{rid}.run-end.json", f"{rid}.run-end.json{H.STAGED_TAIL}"):
        os.mkdir(location_path(t.runs) / name)
        err = H.raised(t.runs_repository().list)
        assert H.is_a(err, RunRefused), f"runs.list over a directory named {name!r} gave {err!r}"
        assert name in H.message(err), f"runs.list's refusal does not name {name!r}"
        os.rmdir(location_path(t.runs) / name)
        (location_path(t.runs) / name).write_text("{}\n", encoding="utf-8")
    assert _ids(t.runs_repository().list()) == [rid], "regular sidecar files beside it list as it"
    for name in _outside_the_sidecar_clause(rid):
        H.make_run(location_path(t.runs), name)
        err = H.raised(t.runs_repository().list)
        assert H.is_a(err, RunRefused), (
            f"a directory {name!r} (no run id under #1187) did not refuse the listing: {err!r}")
        assert name in H.message(err), f"the refusal does not name {name!r}: {H.message(err)}"
        shutil.rmtree(location_path(t.runs) / name)
    assert _ids(t.runs_repository().list()) == [rid], "without them the listing answers"


def test_1105_a_refused_name_is_never_probed_on_disk(tmp_path):
    from defender.records import RunId, RunRefused, RunsRepository

    rid = str(uuid.uuid4())
    _root, t = _fresh(tmp_path, rid)
    rec = H.RecordingIO()
    err = H.raised(lambda: RunsRepository(t, io=rec).open(RunId.parse(f"{rid}.run-end.json")))
    assert H.is_a(err, RunRefused), f"a sidecar-suffixed id gave {err!r}"
    assert rec.calls == [], f"a refused name was probed: {rec.calls}"
    rec = H.RecordingIO()
    assert RunsRepository(t, io=rec).open(RunId.parse(rid)).run_dir == location_path(t.runs) / rid, (
        "the uuid opens")
    assert _opens_through_the_seam_no_follow(rec, t), f"openers: {_openers(rec)}"
    stats = [a for n, a, _k in rec.calls
             if (n == "stat_entry" and len(a) > 1 and str(a[1]) == rid) or n == "stat_entries"]
    assert stats, f"the entry was not stat'ed through the seam: {rec.calls}"


def test_1105_every_listed_id_opens_with_open_run(tmp_path):
    """Over a runs folder holding real runs and their sidecar files (a staged one included),
    every id list_run_ids returns opens with open_run, and its Run's run_dir is that real
    directory.

    #1187 declared changes 1 and 6: the runs are UUIDs, and the folder holds neither
    `_tenant.json` nor `_episodes/` — the listing accepts neither any more (each refuses it,
    test_1105_both_listings_accept_only_runs_the_record_episodes_and_known_sidecar_files).
    (Name kept.)"""
    ids = _uuids(3)
    _root, t = _fresh(tmp_path, *ids)
    H.plant_sidecars(location_path(t.runs), ids[0])
    H.plant_sidecars(location_path(t.runs), ids[1], staged=False)
    listed = t.runs_repository().list()
    assert _ids(listed) == ids, f"listed {_ids(listed)}"
    for rid in listed:
        run = t.runs_repository().open(rid)
        assert run.run_dir == location_path(t.runs) / str(rid), f"{rid!r} opened at {run.run_dir}"
        assert run.run_dir.is_dir(), f"{run.run_dir} is real"
        assert not run.run_dir.is_symlink(), f"{run.run_dir} is real"


def test_1105_refusal_text_quotes_names_repr_style_and_truncates_long_ones(tmp_path):
    """A refusal that quotes a caller-supplied name (RunId.parse('a\nb'), an episode id 'ep\n1')
    escapes control characters repr-style so the message holds no raw newline or tab, and a
    10 000-character name is truncated with a marker rather than quoted whole: the message is
    under 2,000 characters and still holds the name's first 20 characters. A name carrying DEL,
    a C1 control (U+009B) and U+2028 is escaped the same way (91 BF-09)."""
    from defender.records._run_id import episode_id_fault
    from defender.records import RunId, RunRefused

    for what, bad, escaped in (
            ("RunId.parse('a\\nb')", "a\nb", "a\\nb"),
            ("RunId.parse with DEL, a C1 control and U+2028", "a\x7f\x9b\u2028b",
             "a\\x7f\\x9b\\u2028b")):
        err = H.raised(RunId.parse, bad)
        assert H.is_a(err, RunRefused), f"{what} gave {err!r}"
        text = H.message(err)
        assert not H.has_raw_control(text), f"{what}'s refusal carries a raw control: {text!r}"
        assert escaped in text, f"{what}'s refusal does not quote it: {text!r}"
    for what, bad, escaped in (
            ("episode id 'ep\\n1'", "ep\n1", "ep\\n1"),
            ("an episode id with DEL, a C1 control and U+2028", "ep\x7f\x9b\u20281",
             "ep\\x7f\\x9b\\u20281")):
        text = episode_id_fault(bad)
        assert text, f"{what} was admitted as an episode id"
        assert not H.has_raw_control(text), f"{what}'s fault carries a raw control: {text!r}"
        assert escaped in text, f"{what}'s fault does not quote it: {text!r}"
    long_run = "a" * 10_000
    text = H.message(H.raised(RunId.parse, long_run))
    long_episode = "e" * 10_000
    episode_text = episode_id_fault(long_episode) or ""
    for what, said, long_name in (("RunId.parse(10 000 chars)", text, long_run),
                                  ("an episode id of 10 000 chars", episode_text, long_episode)):
        assert said, f"{what} was admitted"
        assert long_name not in said, f"{what}'s refusal quotes the name whole ({len(said)} chars)"
        assert len(said) < 2_000, f"{what}'s refusal quotes the name whole ({len(said)} chars)"
        assert long_name[:20] in said, f"{what}'s refusal does not name it at all: {said[:200]!r}"


def test_1105_both_listings_accept_only_runs_the_record_episodes_and_known_sidecar_files(
        tmp_path):
    from defender.records import RunRefused

    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, H.T_ID)
    ids = [str(uuid.uuid4()) for _ in range(3)]
    for rid in ids:
        H.make_run(location_path(t.runs), rid)
    H.plant_sidecars(location_path(t.runs), ids[0])
    assert _ids(t.runs_repository().list()) == sorted(ids), (
        f"runs.list gave {_ids(t.runs_repository().list())}")
    stray_record = H.plant_tenant_record(location_path(t.runs), t.id)
    err = H.raised(t.runs_repository().list)
    assert H.is_a(err, RunRefused), f"runs.list beside _tenant.json gave {err!r}"
    assert "_tenant.json" in H.message(err), H.message(err)
    stray_record.unlink()
    (location_path(t.runs) / "_episodes").mkdir()
    err = H.raised(t.runs_repository().list)
    assert H.is_a(err, RunRefused), f"runs.list beside _episodes gave {err!r}"
    assert "_episodes" in H.message(err), H.message(err)
    (location_path(t.runs) / "_episodes").rmdir()
    (location_path(t.runs) / "notes").write_text("x\n", encoding="utf-8")
    for name, call in (("runs.list", lambda: t.runs_repository().list()),):
        err = H.raised(call)
        assert H.is_a(err, RunRefused), f"{name} over a stray regular file gave {err!r}"
        assert "notes" in H.message(err), f"{name} over a stray regular file gave {err!r}"


def test_1105_open_run_checks_types_then_name_then_folder_then_record_then_entry(tmp_path):
    """open_run checks in order: a str id over a linked runs folder raises TypeError; a
    sidecar-suffixed id over a linked runs folder raises RunRefused; a linked runs folder raises
    RunUnreachable from TenantRefused (the hold refuses it); an absent entry raises RunRefused."""
    import uuid

    from defender.records import RunId, RunRefused

    r1 = str(uuid.uuid4())
    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    target = tmp_path / "target"
    H.make_run(target, r1)
    os.symlink(target, location_path(t.runs))
    err = H.raised(t.runs_repository().open, r1)
    assert type(err) is TypeError, f"1. a str id gave {err!r}"
    err = H.raised(lambda: t.runs_repository().open(RunId.parse(f"{r1}.run-end.json")))
    assert H.is_a(err, RunRefused), f"2. a sidecar id over the link gave {err!r}"
    err = H.raised(t.runs_repository().open, RunId.parse(r1))
    assert _level_refusal(err), f"3. the linked folder gave {err!r}"
    assert str(location_path(t.runs)) in H.message(err), f"3. the refusal names the level: {H.message(err)}"
    os.unlink(location_path(t.runs))
    location_path(t.runs).mkdir()
    os.symlink(target / r1, location_path(t.runs) / r1)
    err = H.raised(t.runs_repository().open, RunId.parse(r1))
    assert H.is_a(err, RunRefused), f"4. a link at the entry (no record) gave {err!r}"
    assert not _container_refusal("runs.open", err), f"4. judged as a container fault: {err!r}"
    os.unlink(location_path(t.runs) / r1)
    err = H.raised(t.runs_repository().open, RunId.parse(r1))
    assert H.is_a(err, RunRefused), f"5. an absent entry gave {err!r}"
    assert str(location_path(t.runs) / r1) in H.message(err), f"5. names the path: {H.message(err)}"


def test_1105_open_run_serves_a_real_directory_entry_and_refuses_an_absent_one_naming_it(
        tmp_path):
    from defender.records import RunId, RunRefused

    base = str(uuid.uuid4())[:-1]
    absent, *neighbours = [base + c for c in "0123"]
    root, t = _fresh(tmp_path, *neighbours)
    before = H.tree_state(root)
    err = H.raised(t.runs_repository().open, RunId.parse(absent))
    assert H.is_a(err, RunRefused), f"an absent id beside its near neighbours gave {err!r}"
    assert str(location_path(t.runs) / absent) in H.message(err), (
        f"the refusal names the path: {H.message(err)}")
    for name in neighbours:
        assert t.runs_repository().open(RunId.parse(name)).run_dir == location_path(t.runs) / name, (
            f"{name} opens")
    assert H.tree_state(root) == before, "runs.open created something"


def test_1105_a_held_run_is_not_rechecked_and_a_fresh_open_run_is(tmp_path):
    """After open_run hands out a Run, a container fault leaves the held Run's run_dir and
    tenant_id as they were (it is not re-checked), while a fresh open_run for the same id
    refuses.

    #1187 declared changes 6 and 8 (R1, S-iso): `_tenant.json` is neither written nor judged,
    so swapping it for one naming another tenant is no container fault any more; the fault the
    fresh open meets is a link at `tenant.runs` (to the very folder that holds the run),
    refused at its level. The id is a UUID. (Name kept.)"""
    from defender.records import RunId

    rid = str(uuid.uuid4())
    _root, t = _fresh(tmp_path, rid)
    run = t.runs_repository().open(RunId.parse(rid))
    assert (run.run_dir, run.tenant_id) == (location_path(t.runs) / rid, t.id), "the run was handed out"
    aside = tmp_path / "aside-runs"
    os.rename(location_path(t.runs), aside)
    os.symlink(aside, location_path(t.runs))
    assert (run.run_dir, run.tenant_id) == (location_path(t.runs) / rid, t.id), "the held Run moved"
    err = H.raised(t.runs_repository().open, RunId.parse(rid))
    assert _level_refusal(err), f"a fresh runs.open was not refused: {err!r}"


def test_1105_no_lookup_or_record_reader_writes_anything(tmp_path):
    """Driving every lookup over an absent, an empty and a populated runs folder leaves the data
    root's tree byte-for-byte and entry-for-entry unchanged: no folder, record or file is
    created.

    #1187 declared changes 1, 6 and 13 (R1, R6): the record readers are deleted, and a runs
    folder holding no `_tenant.json` is the expected state, not the container's refusal: over
    the empty folder runs.list answers [] and runs.open refuses only the absent entry
    (`RunAbsent`). Positive control: run setup does create the runs folder and the run — and
    writes no `_tenant.json`. Ids are UUIDs. (Name kept.)"""
    from defender.records import RunAbsent, RunId

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    rid = str(uuid.uuid4())

    def drive() -> dict:
        out: dict = {}
        for name, call in (
                ("runs.open", lambda: t.runs_repository().open(RunId.parse(rid))),
                ("runs.list", lambda: _ids(t.runs_repository().list())),
                ("runs.all_runs", lambda: [str(r.run_dir)
                                           for r in t.runs_repository().all_runs()])):
            box: dict = {}
            err = H.raised(lambda box=box, call=call: box.setdefault("answer", call()))
            out[name] = box.get("answer", err)
        return out

    for state in ("absent", "empty", "populated"):
        if state == "empty":
            location_path(t.runs).mkdir()
        if state == "populated":
            H.make_run(location_path(t.runs), rid)
            H.plant_sidecars(location_path(t.runs), rid)
        before = H.tree_state(root)
        answers = drive()
        if state == "empty":
            assert answers["runs.list"] == [], f"an empty folder (no record) lists {answers}"
            assert H.is_a(answers["runs.open"], RunAbsent), (
                f"runs.open over an empty folder gave {answers['runs.open']!r}, not the "
                "absent entry")
        if state == "populated":
            assert answers["runs.list"] == [rid], f"populated folder answers: {answers}"
        assert H.tree_state(root) == before, f"a reader wrote over the {state} folder"
    u = H.tenant(root, H.U_ID)
    alert = H.alert_file(tmp_path / "alerts")
    made = run_common.materialize_run(alert, tenant=u)
    assert made.run_dir.parent == location_path(u.runs)
    assert made.run_dir.is_dir(), "run setup creates the runs folder and the run"
    assert not (location_path(u.runs) / "_tenant.json").exists(), "run setup wrote the retired tenant record"


# ==========================================================================================
# Tenant isolation (O3, S1, S2).
# ==========================================================================================

def test_1105_a_run_setup_made_for_t_opens_for_t_and_no_other_tenant_reaches_it(tmp_path):
    """A run materialize_run created for tenant T opens with open_run(T, id); for a second tenant
    U accepted under the same data root (hand-planted row), open_run(U, id) raises RunAbsent
    while U has no runs folder (the run is gone with it), and RunRefused once U has its own
    folder but no run of that id; it never hands out a Run whose run_dir is under T.runs.

    #1187 (declared change 1): the run's id is a canonical UUID — an old `r1` is refused for its
    shape before any tenant is consulted, which would leave the isolation half unreached."""
    from defender.records import RunAbsent, RunId, RunRefused

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    rid = run_common.materialize_run(H.alert_file(tmp_path / "alerts"), tenant=t).run_dir.name
    assert t.runs_repository().open(RunId.parse(rid)).run_dir == location_path(t.runs) / rid, "T's run opens for T"
    u = H.tenant(root, H.U_ID)
    err = H.raised(u.runs_repository().open, RunId.parse(rid))
    assert H.is_a(err, RunAbsent), f"U with no runs folder gave {err!r}"
    assert str(location_path(t.runs)) not in H.message(err), "U's refusal names T's runs folder"
    H.runs_folder(u)
    err = H.raised(u.runs_repository().open, RunId.parse(rid))
    assert H.is_a(err, RunRefused), f"U with its own folder and no {rid} gave {err!r}"
    assert str(location_path(t.runs)) not in H.message(err), "U's refusal names T's runs folder"


def test_1105_open_run_never_hands_out_a_handle_into_another_tenants_folder(tmp_path):
    """With tenant A's run on disk, open_run(B, id) never returns a Run whose run_dir resolves
    under A.runs: B.runs as a link to A.runs refuses at its level, and B.runs/<id> as a link to
    A.runs/<id> raises RunRefused. Positive control: open_run(A, id) reaches A's run.

    #1187 declared changes 1, 6 and 8 (R1, S-iso): B's `_tenant.json` naming A is no case any
    more — no record is judged; isolation is where a folder sits plus the no-follow walk. The
    id is a UUID and neither container holds a record. (Name kept.)"""
    from defender.records import RunId, RunRefused

    rid = str(uuid.uuid4())
    root, a = _fresh(tmp_path, rid)
    b = H.tenant(root, H.U_ID)
    run_id = RunId.parse(rid)
    os.symlink(location_path(a.runs), location_path(b.runs))
    err = H.raised(b.runs_repository().open, run_id)
    assert _level_refusal(err), f"B.runs a link to A.runs gave {err!r}"
    os.unlink(location_path(b.runs))
    location_path(b.runs).mkdir()
    os.symlink(location_path(a.runs) / rid, location_path(b.runs) / rid)
    err = H.raised(b.runs_repository().open, run_id)
    assert H.is_a(err, RunRefused), f"B.runs/<id> a link to A's run gave {err!r}"
    run = a.runs_repository().open(run_id)
    assert run.run_dir.resolve() == (location_path(a.runs) / rid).resolve(), "A reaches its own run"


def test_1105_a_box_writable_tenant_claim_neither_grants_nor_refuses_a_lookup(tmp_path):
    """A run's provenance stamp, an episode manifest and an episode folder that name another
    tenant change no answer of open_run or list_run_ids for the request's tenant.

    #1187 declared change 6 (R1): there is no host-only tenant record left to grant or refuse —
    a container holding no `_tenant.json` is served, and a `_tenant.json` dropped into it (naming
    any tenant) is a stray the listing refuses with RunRefused naming it: the positive control
    that the listing does read what is in the folder. Ids are UUIDs; the episode folder sits
    under `<T>/episodes`. (Name kept.)"""
    from defender.records import RunId, RunRefused

    r1, r2 = _uuids(2)
    _root, t = _fresh(tmp_path, r1, r2)

    def answers():
        return (str(t.runs_repository().open(RunId.parse(r1)).run_dir),
                _ids(t.runs_repository().list()))

    before = answers()
    assert before == (str(location_path(t.runs) / r1), [r1, r2]), f"baseline: {before}"
    (location_path(t.runs) / r1 / "provenance.json").write_text(
        json.dumps({"tenant_id": H.U_ID, "world_id": "w"}) + "\n", encoding="utf-8")
    episode = location_path(t.episodes) / str(uuid.uuid4())
    episode.mkdir(parents=True)
    (episode / "family.yaml").write_text(f"tenant_id: {H.U_ID}\nsource_run_id: {r1}\n",
                                         encoding="utf-8")
    H.plant_tenant_record(episode / "runs", H.U_ID)
    assert answers() == before, "a box-writable tenant claim changed an answer"
    H.plant_tenant_record(location_path(t.runs), H.U_ID)
    err = H.raised(t.runs_repository().list)
    assert H.is_a(err, RunRefused), f"a _tenant.json in the container gave {err!r}"
    assert "_tenant.json" in H.message(err), f"the refusal does not name it: {H.message(err)}"


def test_1105_a_legacy_run_folder_named_off_the_rules_makes_the_listings_refuse_naming_it(
        tmp_path):
    """A real directory in tenant.runs whose name the id rules refuse makes list_run_ids raise
    RunRefused naming that folder; moving it lets the listing answer. "Naming" is checked as
    the name's first 40 characters appearing in the message (design NF-8 may truncate a long
    name past them)."""
    from defender.records import RunRefused

    ids = _uuids(2)
    _root, t = _fresh(tmp_path, *ids)
    assert _ids(t.runs_repository().list()) == ids, (
        f"the uuid runs list: {_ids(t.runs_repository().list())}")
    for legacy in ("Bad Name", "Run1", "r" + "1" * 205, "r" + "2" * 206,
                   "live-lever-up-20260930-sudo", "20260101t000000z-x"):
        os.mkdir(location_path(t.runs) / legacy)
        err = H.raised(t.runs_repository().list)
        assert H.is_a(err, RunRefused), f"runs.list beside {legacy[:12]!r} gave {err!r}"
        assert legacy[:40] in H.message(err), "runs.list's refusal does not name the folder"
        os.rename(location_path(t.runs) / legacy, tmp_path / "moved-away")
        assert _ids(t.runs_repository().list()) == ids, f"after moving {legacy[:12]!r} away"
        shutil.rmtree(tmp_path / "moved-away")


# ==========================================================================================
# P2's representatives and the expected states.
# ==========================================================================================

def test_1105_a_link_at_tenant_runs_refuses_every_function_naming_it(tmp_path):
    """With tenant.runs a link to another tenant's runs folder, each lookup refuses at that
    level naming tenant.runs and the link fault, never a raw OSError, and the other tenant's
    folder is byte-unchanged; a link to a folder holding this tenant's own run refuses the same
    way, so it is the no-follow walk that refuses. Positive control: the same calls answer over
    a real tenant.runs, and over a real tenant.runs under a linked data root (configuration,
    followed as spelled): open_run hands out the run and list_run_ids lists it."""
    from defender.records import RunId

    rid = str(uuid.uuid4())
    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    u = H.tenant(root, H.U_ID)
    H.make_run(location_path(u.runs), rid)
    own = tmp_path / "own-elsewhere"
    H.make_run(own, rid)
    for target in (location_path(u.runs), own):
        os.symlink(target, location_path(t.runs))
        target_before = H.tree_state(target)
        for name, call in _repository_calls(t, rid):
            err = H.raised(call)
            assert _level_refusal(err), f"{name} over a link to {target.name} gave {err!r}"
            text = H.message(err)
            assert str(location_path(t.runs)) in text, f"{name}: {text}"
            assert "link" in text.lower(), f"{name}: {text}"
        assert H.tree_state(target) == target_before, f"{target} changed"
        os.unlink(location_path(t.runs))
    H.make_run(location_path(t.runs), rid)
    for name, call in _repository_calls(t, rid):
        err = H.raised(call)
        assert err is None, f"{name} over a real tenant.runs raised {err!r}"
    (tmp_path / "real-ancestor").mkdir()
    os.symlink(tmp_path / "real-ancestor", tmp_path / "linked-ancestor")
    w = H.tenant(tmp_path / "linked-ancestor", H.T_ID)
    H.make_run(location_path(w.runs), rid)
    assert w.runs_repository().open(RunId.parse(rid)).run_dir == location_path(w.runs) / rid, (
        "a runs folder under a linked data root is served: runs.open hands out its run")
    assert _ids(w.runs_repository().list()) == [rid], "runs.list under a linked data root"
    for name, call in _repository_calls(w, rid):
        err = H.raised(call)
        assert err is None, f"{name} under a linked data root raised {err!r}"


def test_1105_a_link_at_a_runs_name_refuses_naming_it_and_is_never_followed(tmp_path):
    """With tenant.runs/<r2> a link to a run folder (inside the same runs folder, or another
    tenant's), list_run_ids raises RunRefused naming r2 and open_run(tenant, r2) raises
    RunRefused naming the path; nothing reads through the link. Positive control: the same
    folder without the link answers.

    #1187 declared changes 1, 6 and 13 (R1, R6): the arm half (the episode-record writer
    refusing an arm named by such a link) is retired with the writer — a link at an arm's own
    name is test_1187_layout_isolation's
    test_a_link_at_a_runs_own_name_is_refused_and_the_real_folder_opens. Ids are UUIDs and the
    containers hold no `_tenant.json`. (Name kept.)"""
    from defender.records import RunId, RunRefused

    r1, r2 = str(uuid.uuid4()), str(uuid.uuid4())
    root, t = _fresh(tmp_path, r1)
    u = H.tenant(root, H.U_ID)
    H.make_run(location_path(u.runs), r1, alert='{"alert_id": "u-secret"}\n')
    for target in (location_path(t.runs) / r1, location_path(u.runs) / r1):
        os.symlink(target, location_path(t.runs) / r2)
        target_before = H.tree_state(target)
        err = H.raised(t.runs_repository().list)
        assert H.is_a(err, RunRefused), f"runs.list beside a link at r2 gave {err!r}"
        assert r2 in H.message(err), H.message(err)
        assert "u-secret" not in H.message(err), H.message(err)
        err = H.raised(t.runs_repository().open, RunId.parse(r2))
        assert H.is_a(err, RunRefused), f"runs.open(r2) through the link gave {err!r}"
        assert str(location_path(t.runs) / r2) in H.message(err), f"names the path: {H.message(err)}"
        assert H.tree_state(target) == target_before, f"{target} changed"
        os.unlink(location_path(t.runs) / r2)
    assert _ids(t.runs_repository().list()) == [r1], "without the link"


def test_1105_open_run_and_run_exists_answer_beside_a_torn_record_and_a_stray_name_in_episodes(  # name kept: the spec graph cites it; run_exists is gone (#1105 PR 2 review)
        tmp_path):
    """P2's Reach: each function judges what it reads, and only that (design D2: open_run does
    not read _episodes, and open_run judges only its own entry). With tenant.runs/_episodes
    holding a torn record (a good record claiming an id, cut short) and a stray file README,
    open_run(tenant, id) still hands out the run for r1 and for the id the torn record would
    claim, as it would with no _episodes: it does not read _episodes. With a directory
    'Bad Name' planted beside r1 (and _episodes removed), open_run(tenant, r1) still serves.
    Positive control: over the same tree list_run_ids refuses, and list_run_ids, which lists
    both runs once _episodes is gone, refuses the folder once it holds 'Bad Name'."""
    import uuid

    from defender.records import RunId, RunRefused

    r1, claimed = str(uuid.uuid4()), str(uuid.uuid4())
    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, H.T_ID)
    for rid in (r1, claimed):
        H.make_run(location_path(t.runs), rid)
    record = H.plant_record(location_path(t.runs), str(uuid.uuid4()), t.id, r1, {"a": claimed})
    torn_text = H.truncated(record.read_text(encoding="utf-8"))
    record.write_text(torn_text, encoding="utf-8")
    (location_path(t.runs) / "_episodes" / "README").write_text("notes\n", encoding="utf-8")
    before = H.tree_state(root)
    for rid in (r1, claimed):
        err = H.raised(t.runs_repository().open, RunId.parse(rid))
        assert err is None, f"runs.open({rid}) read _episodes and refused a healthy run: {err!r}"
        assert t.runs_repository().open(RunId.parse(rid)).run_dir == location_path(t.runs) / rid, f"runs.open({rid}) serves"
    assert H.tree_state(root) == before, "a lookup wrote something"
    err = H.raised(t.runs_repository().list)
    assert H.is_a(err, RunRefused), (
        f"positive control: runs.list answered over a folder holding _episodes: {err!r}")
    shutil.rmtree(location_path(t.runs) / "_episodes")
    assert _ids(t.runs_repository().list()) == sorted([r1, claimed]), "the folder without _episodes lists both runs"
    os.mkdir(location_path(t.runs) / "Bad Name")
    err = H.raised(t.runs_repository().open, RunId.parse(r1))
    assert err is None, f"runs.open(r1) judged an entry beside its own and refused: {err!r}"
    assert t.runs_repository().open(RunId.parse(r1)).run_dir == location_path(t.runs) / r1, "runs.open(r1) beside Bad Name"
    err = H.raised(t.runs_repository().list)
    assert H.is_a(err, RunRefused), (
        f"positive control: runs.list answered over a folder holding 'Bad Name': {err!r}")


def test_1105_an_absent_runs_folder_answers_empty_and_creates_nothing(tmp_path):
    """For an accepted tenant with no runs folder, list_run_ids (PR 2: runs.list, a Listed)
    lists [] with absent=True and open_run raises RunAbsent (the run is gone with its folder);
    neither creates anything. Afterwards run setup creates the folder and a run, and the same
    Tenant gets that run from open_run and list_run_ids.

    #1187 declared changes 1, 6 and 13 (R1, R6): the record readers and the writer are deleted
    (their absent-folder answers with them); run setup makes the folder and the run and writes
    no `_tenant.json`; the run id is a UUID. (Name kept.)"""
    from defender.records import Listed, RunAbsent, RunId

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    rid = str(uuid.uuid4())
    before = H.tree_state(root)
    listed = t.runs_repository().list()
    assert isinstance(listed, Listed), f"runs.list gave {listed!r}"
    assert list(listed) == [], f"runs.list gave {listed!r}"
    assert listed.absent is True, f"runs.list's absent is {listed.absent!r}"
    err = H.raised(t.runs_repository().open, RunId.parse(rid))
    assert H.is_a(err, RunAbsent), f"runs.open over an absent folder gave {err!r}"
    assert H.tree_state(root) == before, "something was created"
    assert not location_path(t.runs).exists(), "something was created"
    rid = run_common.materialize_run(H.alert_file(tmp_path / "alerts"), tenant=t).run_dir.name
    assert (location_path(t.runs) / rid).is_dir(), "run setup made the folder and the run"
    assert not (location_path(t.runs) / "_tenant.json").exists(), "run setup wrote the retired tenant record"
    assert t.runs_repository().open(RunId.parse(rid)).run_dir == location_path(t.runs) / rid, "the run opens"
    assert _ids(t.runs_repository().list()) == [rid], "the run lists"


def test_1105_a_run_with_sidecar_files_beside_it_lists_as_the_one_run(tmp_path):
    """A run folder with its sidecar files (`H.SIDECAR_SUFFIXES`) beside it and a staged one
    (<id>.run-end.json.staged-<16 hex>) lists as the one run in list_run_ids, which does not
    refuse; sidecar files left for a run whose folder is gone are accepted the same way, and
    that id is not listed.

    #1187 declared changes 1 and 4: the ids are UUIDs, and the 206-byte bound is gone, so the
    longest-name case (a 206-byte id with a 255-byte staged sidecar beside it) has nothing left
    to measure. The container holds no `_tenant.json`. (Name kept.)"""
    rid, gone = _uuids(2)
    _root, t = _fresh(tmp_path, rid)
    H.plant_sidecars(location_path(t.runs), rid)
    H.plant_sidecars(location_path(t.runs), gone)
    assert _ids(t.runs_repository().list()) == [rid], (
        f"runs.list gave {_ids(t.runs_repository().list())}")


def test_1105_every_lookup_and_record_function_closes_its_held_handle_on_each_path(tmp_path):
    """the process's open descriptor count (/proc/self/fd) is the same before and after each
    lookup on its success path and on each refusal path (TypeError before any read opens none;
    the container's refusal; RunRefused). The RunRefused paths include one after the folder is
    held for each lookup: a folder named 'Bad Name' (list_run_ids, all_runs) and a link at
    runs.open's own entry."""
    from defender.records import RunId, RunRefused, RunsRepository

    rid, other, absent = (str(uuid.uuid4()) for _ in range(3))
    _root, t = _fresh(tmp_path, rid)

    def delta(call):
        before = H.open_fd_count()
        err = H.raised(call)
        return H.open_fd_count() - before, err

    run_id = RunId.parse(rid)
    success = (("runs.open", lambda: t.runs_repository().open(run_id)),
               ("runs.list", lambda: t.runs_repository().list()),
               ("runs.all_runs", lambda: t.runs_repository().all_runs()))
    for name, call in success:
        d, err = delta(call)
        assert err is None, f"{name} success path: delta {d}, raised {err!r}"
        assert d == 0, f"{name} success path: delta {d}, raised {err!r}"
    for name, call in (("RunsRepository(tenant id)", lambda: RunsRepository(t.id).open(run_id)),
                       ("RunsRepository(runs folder)", lambda: RunsRepository(location_path(t.runs)).list()),
                       ("runs.open(a str id)", lambda: t.runs_repository().open(rid))):
        d, err = delta(call)
        assert type(err) is TypeError, f"{name} TypeError path: {d}, {err!r}"
        assert d == 0, f"{name} TypeError path: {d}, {err!r}"
    d, err = delta(lambda: t.runs_repository().open(RunId.parse(absent)))
    assert H.is_a(err, RunRefused), f"runs.open RunRefused path: {d}, {err!r}"
    assert d == 0, f"runs.open RunRefused path: {d}, {err!r}"
    # RunRefused AFTER the folder is held: each lookup refuses a state it reads inside it.
    after_hold = (
        ("runs.list", lambda: os.mkdir(location_path(t.runs) / "Bad Name"),
         lambda: t.runs_repository().list(), lambda: os.rmdir(location_path(t.runs) / "Bad Name")),
        ("runs.all_runs", lambda: os.mkdir(location_path(t.runs) / "Bad Name"),
         lambda: t.runs_repository().all_runs(), lambda: os.rmdir(location_path(t.runs) / "Bad Name")),
        ("runs.open/a link at its entry", lambda: os.symlink(location_path(t.runs) / rid, location_path(t.runs) / other),
         lambda: t.runs_repository().open(RunId.parse(other)),
         lambda: os.unlink(location_path(t.runs) / other)),
    )
    for name, plant, call, remove in after_hold:
        plant()
        d, err = delta(call)
        remove()
        assert H.is_a(err, RunRefused), f"{name} RunRefused after the hold: {d}, {err!r}"
        assert d == 0, f"{name} RunRefused after the hold: {d}, {err!r}"
    aside = tmp_path / "aside-runs"
    os.rename(location_path(t.runs), aside)
    os.symlink(aside, location_path(t.runs))
    for name, call in success:
        d, err = delta(call)
        assert _level_refusal(err), f"{name} container refusal path: {d}, {err!r}"
        assert d == 0, f"{name} container refusal path: {d}, {err!r}"


def test_1105_refusals_quoting_a_disk_read_entry_name_escape_it_and_stay_one_line(tmp_path):
    """a run folder named 'a<newline>[run.py] forged' or 'x<ESC>[31m' (a 255-byte name
    included) makes list_run_ids raise RunRefused, each message holding no raw newline or escape
    character and still naming the entry (a visible run of its characters appears); positive
    control: a plain-named stray entry is named verbatim. A run folder carrying DEL, a C1
    control (U+009B) and U+2028 is among the hostile names (91 BF-09)."""
    from defender.records import RunRefused

    rid = str(uuid.uuid4())
    _root, t = _fresh(tmp_path, rid)
    hostile = (("a\n[run.py] forged", "[run.py] forged"), ("x\x1b[31m", "[31m"),
               ("n\n" + "c" * 253, "ccc"), ("d\x7f\x9b\u2028[c1] forged", "[c1] forged"))
    for name, visible in hostile:
        os.mkdir(location_path(t.runs) / name)
        err = H.raised(t.runs_repository().list)
        assert H.is_a(err, RunRefused), f"runs.list beside a folder {name[:12]!r} gave {err!r}"
        text = H.message(err)
        assert not H.has_raw_control(text), f"runs.list's refusal carries a raw control: {text!r}"
        assert visible in text, f"runs.list's refusal does not name the entry: {text!r}"
        os.rmdir(location_path(t.runs) / name)
    os.mkdir(location_path(t.runs) / "README")
    err = H.raised(t.runs_repository().list)
    assert H.is_a(err, RunRefused), f"a plain stray entry gave {err!r}"
    assert "README" in H.message(err), f"a plain stray name is named verbatim: {H.message(err)}"
