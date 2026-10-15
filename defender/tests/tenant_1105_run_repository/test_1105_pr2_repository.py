"""#1105 PR 2 — the new surface: the tenant-scoped run repository (rev 5.1 decision C, D-repo,
D-create; amended by the fork decisions of 6100061869).

The accepted `Tenant` hands out its repository — `runs = tenant.runs_repository()` (the spelling
F-11 names: it imports the package lazily). Below it everything is ids:

* natural container: `runs.open(run_id) -> Run`, `runs.list() -> Listed`,
  `runs.create(run_id) -> Run`, `runs.resolve(address) -> Run` — PR 1's rules (H1–H6), no
  `Tenant` argument, no environment read;
* errors: `RunRefused` as today, and `RunAbsent(RunRefused)` for an absent entry (in `_errors.py`,
  served by the door); container faults stay `TenantRefused` (`TenantRecordMismatch`,
  `TenantRecordCorrupt`) — except from an open, which answers `RunUnreachable(RunRefused)`
  raised from that `TenantRefused`, and `RunAbsent` for an absent container (#1105 PR 2
  review, PR #1236; `test_1105_pr2_review_fixes.py`);
* the episode view `runs.episode(episode_id) -> EpisodeRuns`, opened through the episode owner
  from `(tenant.data_root, episode_id)`: `view.open(arm_id)`, `view.create(arm_id)`,
  `view.create_container()`, `view.base_world_id()`, `view.arm_id(label) -> RunId`,
  `view.episode` (the owner's handle); a PRESENT container's `_tenant.json` is judged when the
  view opens; an ABSENT one has nothing to judge; an UNREADABLE one (a link, a non-directory) is
  recorded (`view.state`), not raised;
* `runs.episode_files(episode_id) -> Episode`: the owner's handle, the judge's door — it judges
  the container's `_tenant.json` as `runs.episode` does (PR 2's second review round) and reads
  nothing else in `runs/`;
* `RunAddress(tenant_id, run_id, episode_id | None)`: frozen, fields checked at construction, the
  stored/transport form; rehydration is "accept its tenant, then open".

SPELLINGS. The design names every method above, `Tenant.runs_repository()`, `RunAbsent`,
`RunAddress` and its three fields, and `Listed`'s `absent`. It
leaves `Listed`'s run-id spelling to the implementer: this file reads a `Listed` as an iterable
of `RunId` in `list_run_ids`' order (`_ids()` below — the ONE place to rename it). Where the
design leaves an error class open (a view's open over an absent container; `resolve` of another
tenant's address) the test accepts either repository refusal class, `RunRefused` or
`TenantRefused`, and nothing broader.

NOT PINNED HERE, deliberately: `Run.reader()` and `runs.container()` (F-13 drops each "unless a
caller remains after J3's removal"; the decision leaves the page's per-arm reader open),
`runs.bound()` (no production caller), `runs.resolve`'s episode branch (F-13: no stored address
carries an episode id with a run id), and the view's container-required mode (no spelling in
the design; its observable is the sibling's, declared change 6).

Every name is imported INSIDE the test that drives it, so a missing name is one failure per test.

Expected at base 301f196c: every test in this module FAILS — `Tenant` has no `runs_repository`
(AttributeError) or the door has no `RunAbsent` / `RunAddress` (ImportError). Each asserts the
behaviour the name owes once it exists.

#1187 (design rev 2) changes this surface; the tests that pin a changed rule say so in their own
docstrings ("#1187 declared change N"): every id is canonical lowercase UUID text (1); no
container holds or is judged by a `_tenant.json`, and the natural listing refuses one (6, R1);
`view.base_world_id()` goes (11, R1b); an episode is `<T>/episodes/<uuid>/`, read through no
environment (5, O9); `view.create_container()` is replaced by `view.start_runs(labels)`, which
writes the host-written arm roster `arms.json`, and `view.arm_id(label)` reads it (10, 15, R2).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender import _tenant
from defender._tenant import TenantRefused
from defender.tests._fixture_uuid import fixture_uuid
from defender.tests.tenant_1105_run_repository import _spec1105 as H

#: #1187 declared change 1: `RunId` admits only canonical lowercase uuid4 text, so the fixture's
#: natural runs and the names its refusals are asked about are uuids derived from their old
#: handles (an old-shaped name would be refused by the id rule before the guard under test).
R1, R2 = fixture_uuid("pr2-repo-r1"), fixture_uuid("pr2-repo-r2")
NOPE, AFILE, ALINK = (fixture_uuid("pr2-repo-nope"), fixture_uuid("pr2-repo-afile"),
                      fixture_uuid("pr2-repo-alink"))

LABEL = "a"


@pytest.fixture
def episodes(tmp_path, monkeypatch) -> Path:
    """The configured episodes root, outside the data root and the checkout."""
    root = tmp_path / "episodes"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(root))
    return root


def _good(tmp_path: Path, *run_ids: str, tenant_id: str = H.T_ID):
    """A data root holding `tenant_id`, its natural runs folder made as run setup leaves it
    (#1187 R1: no `_tenant.json`) and a real run folder per id."""
    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, tenant_id)
    H.runs_folder(t)
    for rid in run_ids:
        H.make_run(t.runs, rid)
    return root, t


def _rid(text: str):
    from defender.run_repository import RunId

    return RunId.parse(text)


def _ids(listed) -> list[str]:
    """A `Listed`'s run ids, as text, in its order (the one place its spelling is read)."""
    return [str(i) for i in listed]


def _refusal_classes():
    from defender.run_repository import RunRefused

    return (RunRefused, TenantRefused)


def _uuid_container(tmp_path: Path, count: int, *, tenant_id: str = H.T_ID):
    """#1187's natural container (declared changes 1 and 6): a data root holding `tenant_id`,
    its `<T>/runs` a real folder holding NO `_tenant.json`, and `count` real run folders named
    by fresh UUIDs. Returns `(root, tenant, sorted ids)`."""
    import uuid

    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, tenant_id)
    Path(t.runs).mkdir(parents=True, exist_ok=True)
    ids = sorted(str(uuid.uuid4()) for _ in range(count))
    for rid in ids:
        H.make_run(t.runs, rid)
    return root, t, ids


def _new_episode(root: Path, *, roster: bool = False) -> tuple[str, Path, dict[str, str] | None]:
    """#1187's layout: `<root>/<T>/episodes/<uuid>/` holding a manifest the family model loads
    (`_triplet_947.family_doc`, worlds a, b, c) naming that uuid, and — with `roster` — `runs/`
    and the arm roster the launcher writes at the start of RUNS (no `_tenant.json` anywhere).
    Returns `(episode id, folder, roster or None)`."""
    from defender import _yaml
    from defender.tests import _triplet_947 as T
    from defender.tests.ids_1187 import _spec1187 as S

    episode_id = S.new_id()
    manifest = _yaml.safe_dump(T.family_doc(episode_id=episode_id, source_run_id=S.new_id()))
    ep = S.make_episode(root, H.T_ID, episode_id, manifest=manifest, labels=T.WORLDS,
                        roster=roster, arms=roster)
    return episode_id, ep, (S.read_roster(ep) if roster else None)


# ==========================================================================================
# The natural container.
# ==========================================================================================

def test_the_accepted_tenant_hands_out_a_repository_that_opens_its_own_runs_by_id(tmp_path):
    """`tenant.runs_repository().open(run_id)` is PR 1's `open_run(tenant, run_id)`: the `Run`
    at `<T>/runs/<id>`, carrying T's id, reading the run's own records. No method takes a
    `Tenant` beside an id (O1(e)): handing one in is a `TypeError`, before any read."""
    _root, t = _good(tmp_path, R1, R2)
    runs = t.runs_repository()

    run = runs.open(_rid(R1))
    assert Path(run.run_dir) == Path(t.runs) / R1
    assert str(run.tenant_id) == H.T_ID
    assert "seed" in (run.facts.alert.read() or "")
    assert Path(runs.open(_rid(R2)).run_dir) == Path(t.runs) / R2
    assert isinstance(H.raised(runs.open, t, _rid(R1)), TypeError), (
        "the repository's open took a Tenant beside the id")


def test_the_repository_reads_no_environment(tmp_path, monkeypatch):
    """The repository holds its tenant and reads no environment (rev 4 S2): with the data root
    and the episodes base unset AFTER acceptance, it still opens, lists and creates in T's
    natural container.

    #1187 declared changes 1 and 6 (R1): the container is the one #1187 leaves — UUID-named
    runs and no `_tenant.json` (a record there would make the listing refuse). (Name kept.)"""
    import uuid

    _root, t, (r1,) = _uuid_container(tmp_path, 1)
    monkeypatch.delenv("DEFENDER_DATA_ROOT", raising=False)
    monkeypatch.delenv("DEFENDER_EPISODES_BASE", raising=False)
    runs = t.runs_repository()

    assert Path(runs.open(_rid(r1)).run_dir) == Path(t.runs) / r1
    assert _ids(runs.list()) == [r1]
    r2 = str(uuid.uuid4())
    assert Path(runs.create(_rid(r2)).run_dir) == Path(t.runs) / r2


def test_run_absent_tells_an_absent_run_from_a_refused_entry(tmp_path):
    """S4: `open` raises `RunAbsent` — a `RunRefused` — for an absent entry, and a plain
    `RunRefused` that is NOT `RunAbsent` for an entry that is there but no run: a regular file,
    a link to a real run folder. An existing `except RunRefused` handler still catches
    `RunAbsent`. The positive control opens the real run beside them."""
    from defender.run_repository import RunAbsent, RunRefused

    _root, t = _good(tmp_path, R1)
    (Path(t.runs) / AFILE).write_text("x\n", encoding="utf-8")
    os.symlink(Path(t.runs) / R1, Path(t.runs) / ALINK)
    runs = t.runs_repository()

    absent = H.raised(runs.open, _rid(NOPE))
    assert isinstance(absent, RunAbsent), f"an absent run raised {absent!r}"
    assert isinstance(absent, RunRefused)
    assert issubclass(RunAbsent, RunRefused)
    for name in (AFILE, ALINK):
        err = H.raised(runs.open, _rid(name))
        assert isinstance(err, RunRefused), (
            f"{name}: {err!r} — a present non-run must not read as absent")
        assert not isinstance(err, RunAbsent), (
            f"{name}: {err!r} — a present non-run must not read as absent")
        assert name in str(err)
    with pytest.raises(RunRefused) as caught:  # the handler every existing caller has
        runs.open(_rid(NOPE))
    assert isinstance(caught.value, RunAbsent)
    assert Path(runs.open(_rid(R1)).run_dir) == Path(t.runs) / R1


def test_a_container_fault_is_the_tenants_refusal_not_an_absent_run(tmp_path):  # name kept; the owner changed the class (#1105 PR 2 review)
    """Container faults are the container's refusal, never a `RunAbsent` (P2; S4) — reaching an
    open as `RunUnreachable`, a `RunRefused` raised from the container's `TenantRefused` (#1105
    PR 2 review: an open answers one refusal family): a link at `<T>/runs` (never followed), a
    record naming another tenant (`TenantRecordMismatch`), and a folder with no record. An
    ABSENT runs folder is the one container state an open answers `RunAbsent` (the run is gone
    with it). The positive control: the folder made right, the run opens.

    #1187 declared change 6 (R1): the record halves are retired. A record naming another
    tenant is no longer judged by an open (isolation is the no-follow walk from `<T>`), and a
    folder with no record is the folder #1187 makes: its run OPENS. The run id is a UUID
    (declared change 1)."""
    import uuid

    from defender.run_repository import RunAbsent, RunUnreachable

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    runs = t.runs_repository()
    r1 = str(uuid.uuid4())
    absent = H.raised(runs.open, _rid(r1))
    assert isinstance(absent, RunAbsent), repr(absent)

    elsewhere = tmp_path / "elsewhere-runs"
    H.make_run(elsewhere, r1)
    os.symlink(elsewhere, t.runs)
    linked = H.raised(runs.open, _rid(r1))
    assert isinstance(linked, RunUnreachable), f"a linked runs folder was followed: {linked!r}"
    assert isinstance(linked.__cause__, TenantRefused), repr(linked.__cause__)
    os.unlink(t.runs)

    # #1187 declared change 6 (R1): no container record is judged. A real runs folder with no
    # `_tenant.json` is the one #1187 writes, and its run opens.
    H.make_run(t.runs, r1)
    assert not (Path(t.runs) / "_tenant.json").exists()
    assert Path(runs.open(_rid(r1)).run_dir) == Path(t.runs) / r1


def test_list_tells_an_absent_container_from_an_empty_one_and_judges_every_entry(tmp_path):
    """`runs.list()`: the run ids in `list_run_ids`' order (sorted by text), sidecar files
    beside a run taken and not listed; `absent` true only when the folder does not exist —
    an empty folder is not absent (R51-05, R51-18). A stray file refuses the listing
    (`RunRefused` naming it: rev 4.1 H4, the rule the tracer applies after J3).

    #1187 declared changes 1 and 6 (R1): the empty folder is a real folder holding NOTHING —
    no `_tenant.json` — and the run names are UUIDs. A `_tenant.json` in the container is no
    longer taken by the listing: it refuses, naming it, as the stray does. (Name kept.)"""
    import uuid

    from defender.run_repository import RunRefused

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    runs = t.runs_repository()

    none_yet = runs.list()
    assert none_yet.absent is True
    assert _ids(none_yet) == []

    Path(t.runs).mkdir()
    empty = runs.list()
    assert empty.absent is False
    assert _ids(empty) == []

    ids = sorted(str(uuid.uuid4()) for _ in range(2))
    for rid in reversed(ids):
        H.make_run(t.runs, rid)
    H.plant_sidecars(t.runs, ids[0])
    listed = runs.list()
    assert listed.absent is False
    assert _ids(listed) == ids

    record = H.plant_tenant_record(t.runs, H.T_ID)
    refused = H.raised(runs.list)
    assert isinstance(refused, RunRefused), f"the listing took a _tenant.json: {refused!r}"
    assert "_tenant.json" in str(refused), repr(refused)
    record.unlink()
    assert _ids(runs.list()) == ids, "control: the record gone, the container lists again"

    (Path(t.runs) / "stray.txt").write_text("x\n", encoding="utf-8")
    stray = H.raised(runs.list)
    assert isinstance(stray, RunRefused), repr(stray)
    assert "stray.txt" in str(stray), repr(stray)


def test_create_holds_the_container_writes_its_record_and_hands_out_the_run(tmp_path):
    """D-create (a), natural: `runs.create(run_id)` makes `<T>/runs` when absent (as run setup
    does today) and hands out the `Run` at `<T>/runs/<id>` for T. A linked `<T>/runs` is
    refused, and nothing is written through the link.

    #1187 declared change 6 (R1): create writes NO `_tenant.json` — the folder's place under
    `<T>` is its tenant — and the "record naming another tenant" refusal is retired with the
    record. The run id is a UUID (declared change 1). (Name kept.)"""
    import uuid

    r9 = str(uuid.uuid4())
    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    runs = t.runs_repository()

    run = runs.create(_rid(r9))
    assert Path(run.run_dir) == Path(t.runs) / r9
    assert str(run.tenant_id) == H.T_ID
    assert Path(t.runs).is_dir()
    assert not Path(t.runs).is_symlink()
    # F18(a): `create` holds the container and hands out the `Run`; it does not make the run's
    # folder (the run makes it at its own setup) and writes no record (#1187 R1), so the
    # container is still empty.
    assert sorted(os.listdir(t.runs)) == [], (
        f"create left something in the container: {sorted(os.listdir(t.runs))}")

    other_root = tmp_path / "data2"
    other_root.mkdir()
    u = H.tenant(other_root, H.T_ID)
    target = tmp_path / "link-target"
    target.mkdir()
    os.symlink(target, u.runs)
    linked = H.raised(u.runs_repository().create, _rid(r9))
    assert isinstance(linked, _refusal_classes()), repr(linked)
    assert list(target.iterdir()) == [], "the create wrote through a linked runs folder"


# ==========================================================================================
# RunAddress and rehydration (G22).
# ==========================================================================================

def test_a_run_address_round_trips_and_rehydrates_only_in_its_own_tenant(tmp_path):
    """`RunAddress(tenant_id, run_id, None)` is the stored form: its fields written as text
    (`{tenant_id, run_id}`, the curation row) and read back give an equal address; to
    rehydrate, accept its tenant, then `runs.resolve(address)` — the same run `open` gives.
    G22: a repository refuses an address naming ANOTHER tenant, even when that tenant has a
    run of the same id (R51-01's shape), and never hands out the other tenant's folder.

    #1187 declared changes 1 and 6: the address's run id is a UUID (an old id is no run id)
    and neither container holds a `_tenant.json`. (Name kept.)"""
    from defender.run_repository import RunAddress, RunId

    root, t, (r1,) = _uuid_container(tmp_path, 1)
    u = H.tenant(root, H.U_ID)
    H.make_run(u.runs, r1)

    addr = RunAddress(tenant_id=_tenant.TenantId(H.T_ID), run_id=RunId.parse(r1),
                      episode_id=None)
    stored = {"tenant_id": str(addr.tenant_id), "run_id": str(addr.run_id)}
    back = RunAddress(tenant_id=_tenant.TenantId(stored["tenant_id"]),
                      run_id=RunId.parse(stored["run_id"]), episode_id=None)
    assert back == addr

    accepted = H.tenant(root, stored["tenant_id"])
    resolved = accepted.runs_repository().resolve(back)
    assert Path(resolved.run_dir) == Path(t.runs) / r1
    assert str(resolved.tenant_id) == H.T_ID

    beta_addr = RunAddress(tenant_id=_tenant.TenantId(H.U_ID), run_id=RunId.parse(r1),
                           episode_id=None)
    crossed = H.raised(t.runs_repository().resolve, beta_addr)
    assert isinstance(crossed, _refusal_classes()), f"another tenant's address: {crossed!r}"
    assert Path(u.runs_repository().resolve(beta_addr).run_dir) == Path(u.runs) / r1


def test_a_run_address_checks_its_fields_at_construction_and_is_frozen():
    """`RunAddress`'s fields are checked when it is built — the tenant id grammar, `RunId`'s
    rules, the episode-id grammar — so a bad stored field never reaches a lookup; and it is
    frozen. The positive control builds a well-formed address with and without an episode.

    #1187 declared changes 1 and 2: the run id and the episode id are canonical lowercase UUID
    text, and an arm's id is a UUID of its own (never `<episode>-<label>`). An old episode id
    (`20260101t000000z-x`) is refused like the other bad fields. (Name kept.)"""
    import uuid

    from defender.run_repository import RunAddress, RunId

    run_id, arm_id, episode_id = (str(uuid.uuid4()) for _ in range(3))
    good = RunAddress(tenant_id=_tenant.TenantId(H.T_ID), run_id=RunId.parse(run_id),
                      episode_id=None)
    arm = RunAddress(tenant_id=_tenant.TenantId(H.T_ID), run_id=RunId.parse(arm_id),
                     episode_id=episode_id)
    assert arm.episode_id == episode_id
    assert good.episode_id is None

    for bad in ({"tenant_id": "Not A Tenant", "run_id": RunId.parse(run_id), "episode_id": None},
                {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": "../r1", "episode_id": None},
                {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": RunId.parse(run_id),
                 "episode_id": "a/b"},
                {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": RunId.parse(arm_id),
                 "episode_id": "20260101t000000z-x"}):
        assert H.raised(RunAddress, **bad) is not None, f"RunAddress accepted {bad!r}"
    assert H.raised(setattr, good, "tenant_id", _tenant.TenantId(H.U_ID)) is not None
    assert str(good.tenant_id) == H.T_ID


@pytest.mark.parametrize("episode_id", [
    "..", ".", "a/b", "Upper-Case", "", "x" * 300, "-leading", "a\x00b", b"ep", 7,
    "20260101t000000z-x", "20260728t161845z-src-n59", "latest",
    "AF3BA774-355D-4DBC-B8B6-3BECC9D3E7A1", "{af3ba774-355d-4dbc-b8b6-3becc9d3e7a1}",
    "af3ba774355d4dbcb8b63becc9d3e7a1",
], ids=["dotdot", "dot", "slash", "upper", "empty", "over-long", "dash-first", "nul", "bytes",
        "int", "old-minted", "old-episode", "latest", "uuid-upper", "uuid-braced",
        "uuid-no-hyphens"])
def test_a_run_address_holds_its_episode_id_to_the_owners_episode_grammar(episode_id):
    """F6(b) / D-repo: `RunAddress` checks `episode_id` at construction against the owner's
    episode-id grammar — exactly a `str` — and refuses every member of that domain, not only
    `/`. POSITIVE CONTROL: the same fields with a UUID episode id build an address. RED at
    base: the door has no `RunAddress` (ImportError).

    #1187 declared change 1: the grammar is canonical lowercase UUID text. Today's ids (a
    minted `<stamp>-<label>`, a derived `<source>-n<message>` episode id), `latest`, and a UUID
    in upper case, in braces or without hyphens are refused too; the record-name length the
    300-byte case once stood for is gone with the `_episodes` record (R6). (Name kept.)"""
    import uuid

    from defender.run_repository import RunAddress, RunId

    good = str(uuid.uuid4())
    fields = {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": RunId.parse(str(uuid.uuid4()))}
    assert RunAddress(**fields, episode_id=good).episode_id == good
    assert H.raised(RunAddress, **fields, episode_id=episode_id) is not None, (
        f"RunAddress accepted the episode id {episode_id!r}")


# ==========================================================================================
# The episode view.
# ==========================================================================================

def test_an_arm_created_for_t_opens_for_t_through_its_episode_and_never_as_a_natural_run(
        tmp_path, episodes):
    """O3 / O4: `runs.episode(ep)` opens the arm `view.arm_id(label)` (a `RunId`) at
    `<episode>/runs/<arm id>` for T; `view.episode` is the owner's handle on the episode folder.
    The same id through the natural container is `RunAbsent` (an arm is reachable only through
    its episode).

    #1187 declared changes 2, 11 and 15: the arm id is the one the episode's arm roster holds
    for the label — a UUID with neither the label nor the episode id in it, never
    `<ep>-<label>` — the episode is `<T>/episodes/<uuid>`, and there is no container record and
    no `base_world_id` (R1b). (Name kept.)"""
    from defender.run_repository import RunAbsent, RunId

    root, t = _good(tmp_path, R1)
    episode_id, ep, roster = _new_episode(root, roster=True)
    runs = t.runs_repository()

    view = runs.episode(episode_id)
    arm_id = view.arm_id(LABEL)
    assert isinstance(arm_id, RunId)
    assert str(arm_id) == roster[LABEL]
    assert episode_id not in str(arm_id)
    arm = view.open(arm_id)
    assert Path(arm.run_dir) == ep / "runs" / roster[LABEL]
    assert str(arm.tenant_id) == H.T_ID
    assert Path(view.episode.dir) == ep
    assert isinstance(H.raised(runs.open, arm_id), RunAbsent)


def test_an_absent_container_opens_the_view_but_no_arm_until_the_launcher_creates_it(
        tmp_path, episodes):
    """An episode before RUNS has no container (N-ep): the view opens, its `state` is absent,
    and `view.open` / `view.create` refuse — the create making nothing (G5: an arm is never
    made in a container nobody bound).

    #1187 declared change 10 (R2): `create_container()` is replaced by `start_runs(labels)`,
    which makes `runs/` — with no record — then writes the arm roster once, one fresh UUID per
    manifest world; before it, `view.arm_ids()` is `None`. Then `view.create(view.arm_id(b))`
    hands out the arm at `<ep>/runs/<roster id>`. A second `start_runs` REFUSES (C-19's
    adoption is gone) and changes neither the roster nor the arm. (Name kept.)"""
    import uuid

    from defender.tests import _triplet_947 as T

    root, t = _good(tmp_path)
    episode_id, ep, _ = _new_episode(root)
    view = t.runs_repository().episode(episode_id)
    stranger = _rid(str(uuid.uuid4()))

    assert view.state == "absent"
    assert not view.present
    assert view.arm_ids() is None
    assert isinstance(H.raised(view.open, stranger), _refusal_classes())
    assert isinstance(H.raised(view.create, stranger), _refusal_classes())
    assert not (ep / "runs").exists(), "a create over an absent container made it"

    ids = {label: str(arm) for label, arm in view.start_runs(list(T.WORLDS)).items()}
    assert sorted(ids) == sorted(T.WORLDS)
    assert (ep / "runs").is_dir()
    assert not (ep / "runs" / "_tenant.json").exists(), "start_runs wrote a container record"
    arm = view.create(view.arm_id(LABEL))
    assert Path(arm.run_dir) == ep / "runs" / ids[LABEL]
    assert str(arm.tenant_id) == H.T_ID

    roster_bytes = (ep / "arms.json").read_bytes()
    again = H.raised(t.runs_repository().episode(episode_id).start_runs, list(T.WORLDS))
    assert isinstance(again, _refusal_classes()), f"a second start_runs gave {again!r}"
    assert (ep / "arms.json").read_bytes() == roster_bytes
    assert (ep / "runs" / ids[LABEL]).is_dir()


def test_an_unreadable_container_is_recorded_not_raised_and_never_written_through(
        tmp_path, episodes):
    """R51-20 / G25: a link at `<episode>/runs` — to a real folder holding an arm and no
    record — is an UNREADABLE container. The view opens (the page reads it as absent), its
    `state` unreadable with the reason recorded; `view.open` refuses; nothing is written
    through the link.

    #1187 declared changes 2, 10 and 15 (R2): the episode is `<T>/episodes/<uuid>/`, before
    RUNS (no roster); the arm in the link's target is named by a UUID. `create_container()` is
    replaced by `start_runs(labels)`, which REFUSES the link before any roster is written (no
    `arms.json` appears, nothing lands in the target). Positive control: with a real, empty
    `runs/` in the link's place, `start_runs` writes the roster. (Name kept.)"""
    import uuid

    from defender.tests import _triplet_947 as T

    root, t = _good(tmp_path)
    episode_id, ep, _ = _new_episode(root)
    target = tmp_path / "elsewhere"
    target.mkdir()
    stray_arm = str(uuid.uuid4())
    H.make_run(target, stray_arm)
    os.symlink(target, ep / "runs")
    before = H.tree_state(target)

    view = t.runs_repository().episode(episode_id)
    assert view.state == "unreadable", f"a linked container read as {view.state}"
    assert view.unreadable_reason, "a linked container's reason was not recorded"
    assert isinstance(H.raised(view.open, _rid(stray_arm)), _refusal_classes())
    assert isinstance(H.raised(view.start_runs, list(T.WORLDS)), _refusal_classes())
    assert not os.path.lexists(ep / "arms.json"), "a roster was written over a linked runs/"
    assert H.tree_state(target) == before
    assert (ep / "runs").is_symlink()

    os.unlink(ep / "runs")
    (ep / "runs").mkdir()
    ids = t.runs_repository().episode(episode_id).start_runs(list(T.WORLDS))
    assert sorted(ids) == sorted(T.WORLDS), f"control: start_runs over a real runs/ gave {ids!r}"
    assert (ep / "arms.json").is_file()


def test_episode_files_is_the_owners_handle_alone_and_creates_nothing(tmp_path, episodes):
    """`runs.episode_files(ep)` is the judge's door: the owner's handle on the episode folder.
    A missing episode and a file at the episode's name are refused, and nothing is created
    (#1133 O4.8.2, G23).

    #1187 declared change 6 (R1): the door judges no container record — the half that refused
    a `_tenant.json` naming another tenant is retired (O8: another tenant's episode is not under
    `<T>/episodes` at all, pinned by
    `ids_1187/test_1187_layout_isolation.py::test_another_tenants_episode_is_absent_to_this_tenants_repository`).
    The tenant's own episode, its arm container holding no record, opens. Ids are UUIDs and the
    episode is `<T>/episodes/<uuid>` (declared changes 1 and 5). (Name kept.)"""
    import uuid

    from defender.tests.ids_1187 import _spec1187 as S

    root, t = _good(tmp_path)
    episode_id, ep, _ = _new_episode(root, roster=True)
    runs = t.runs_repository()
    tenant_episodes = S.episodes_dir(root, H.T_ID)

    handle = runs.episode_files(episode_id)
    try:
        assert Path(handle.dir) == ep
    finally:
        handle.close()

    before = H.tree_state(tenant_episodes)
    assert H.raised(runs.episode_files, str(uuid.uuid4())) is not None
    assert H.tree_state(tenant_episodes) == before, "a missing episode was created"
    afile = str(uuid.uuid4())
    (tenant_episodes / afile).write_text("x\n", encoding="utf-8")
    with_file = H.tree_state(tenant_episodes)
    assert H.raised(runs.episode_files, afile) is not None
    assert H.tree_state(tenant_episodes) == with_file, "a file at the episode's name was changed"


def test_a_bad_episode_id_or_an_unset_episodes_base_is_refused_before_anything_is_read(
        tmp_path, episodes, monkeypatch):
    """The episode owner refuses a bad id before anything is read (D-ep), at both doors: a
    separator, `..`, upper case. Nothing is created under the episodes root.

    #1187 declared change 5: the unset half flips — without `DEFENDER_EPISODES_BASE` an
    episode of the tenant's own opens (nothing reads the variable). The episode beside the bad
    ids is the tenant's own `<T>/episodes/<uuid>/` (no container record, R1). (Name kept.)"""
    root, t = _good(tmp_path)
    _new_episode(root, roster=True)
    runs = t.runs_repository()
    before = H.tree_state(tmp_path)

    for bad in ("../x", "a/b", "Upper-Case", ""):
        assert H.raised(runs.episode, bad) is not None, f"episode({bad!r}) opened"
        assert H.raised(runs.episode_files, bad) is not None, f"episode_files({bad!r}) opened"
    assert H.tree_state(tmp_path) == before

    # #1187 declared change 5 (O9): the variable is read by nothing. With it unset, the
    # tenant's own `<T>/episodes/<uuid>` opens.
    monkeypatch.delenv("DEFENDER_EPISODES_BASE")
    episode_id, ep, _ = _new_episode(root, roster=True)
    view = runs.episode(episode_id)
    assert view.present
    assert Path(view.episode.dir) == ep
