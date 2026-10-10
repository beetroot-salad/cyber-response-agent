"""#1105 PR 2 — the new surface: the tenant-scoped run repository (rev 5.1 decision C, D-repo,
D-create; amended by the fork decisions of 6100061869).

The accepted `Tenant` hands out its repository — `runs = tenant.runs_repository()` (the spelling
F-11 names: it imports the package lazily). Below it everything is ids:

* natural container: `runs.open(run_id) -> Run`, `runs.list() -> Listed`, `runs.exists(run_id)`,
  `runs.create(run_id) -> Run`, `runs.resolve(address) -> Run` — PR 1's rules (H1–H6), no
  `Tenant` argument, no environment read;
* errors: `RunRefused` as today, and `RunAbsent(RunRefused)` for an absent entry (in `_errors.py`,
  served by the door); container faults stay `TenantRefused` (`TenantRecordMismatch`,
  `TenantRecordCorrupt`);
* the episode view `runs.episode(episode_id) -> EpisodeRuns`, opened through the episode owner
  from `(tenant.data_root, episode_id)`: `view.open(arm_id)`, `view.list()`, `view.create(arm_id)`,
  `view.create_container()`, `view.base_world_id()`, `view.arm_id(label) -> RunId`,
  `view.episode` (the owner's handle); a PRESENT container's `_tenant.json` is judged when the
  view opens; an ABSENT one has nothing to judge; an UNREADABLE one (a link, a non-directory) is
  recorded, not raised;
* `runs.episode_files(episode_id) -> Episode`: the owner's handle alone, the judge's door — it
  reads nothing in `runs/`;
* `RunAddress(tenant_id, run_id, episode_id | None)`: frozen, fields checked at construction, the
  stored/transport form; rehydration is "accept its tenant, then open".

SPELLINGS. The design names every method above, `Tenant.runs_repository()`, `RunAbsent`,
`RunAddress` and its three fields, and `Listed`'s `absent` (and, from a view, `unreadable`). It
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
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender import _tenant
from defender._tenant import TenantRecordMismatch, TenantRefused
from defender.tests.tenant_1105_run_repository import _spec1105 as H

EP = "20260728t161845z-src-n59"
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
    (`_tenant.json` naming it) and a real run folder per id."""
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


def _episode(episodes: Path, *, container: str | None = None, arms: tuple[str, ...] = (),
             raw_record: str | None = None) -> Path:
    """`<episodes>/<EP>/` with a manifest-shaped file and, when asked, its container `runs/`:
    `container` names the tenant its `_tenant.json` names (written by the real writer);
    `raw_record` plants that file's bytes verbatim instead; arms are real folders inside."""
    ep = episodes / EP
    ep.mkdir()
    (ep / "family.yaml").write_text("episode_id: x\n", encoding="utf-8")
    if container is not None or raw_record is not None or arms:
        (ep / "runs").mkdir()
    if container is not None:
        _tenant.ensure_runs_base_record(ep / "runs", container)
    if raw_record is not None:
        (ep / "runs" / "_tenant.json").write_text(raw_record, encoding="utf-8")
    for label in arms:
        H.make_run(ep / "runs", f"{EP}-{label}", alert=f'{{"arm": "{label}"}}\n')
    return ep


# ==========================================================================================
# The natural container.
# ==========================================================================================

def test_the_accepted_tenant_hands_out_a_repository_that_opens_its_own_runs_by_id(tmp_path):
    """`tenant.runs_repository().open(run_id)` is PR 1's `open_run(tenant, run_id)`: the `Run`
    at `<T>/runs/<id>`, carrying T's id, reading the run's own records. No method takes a
    `Tenant` beside an id (O1(e)): handing one in is a `TypeError`, before any read."""
    _root, t = _good(tmp_path, "r1", "r2")
    runs = t.runs_repository()

    run = runs.open(_rid("r1"))
    assert Path(run.run_dir) == Path(t.runs) / "r1"
    assert str(run.tenant_id) == H.T_ID
    assert "seed" in (run.facts.alert.read() or "")
    assert Path(runs.open(_rid("r2")).run_dir) == Path(t.runs) / "r2"
    assert isinstance(H.raised(runs.open, t, _rid("r1")), TypeError), (
        "the repository's open took a Tenant beside the id")


def test_the_repository_reads_no_environment(tmp_path, monkeypatch):
    """The repository holds its tenant and reads no environment (rev 4 S2): with the data root
    and the episodes base unset AFTER acceptance, it still opens, lists and creates in T's
    natural container."""
    _root, t = _good(tmp_path, "r1")
    monkeypatch.delenv("DEFENDER_DATA_ROOT", raising=False)
    monkeypatch.delenv("DEFENDER_EPISODES_BASE", raising=False)
    runs = t.runs_repository()

    assert Path(runs.open(_rid("r1")).run_dir) == Path(t.runs) / "r1"
    assert _ids(runs.list()) == ["r1"]
    assert Path(runs.create(_rid("r2")).run_dir) == Path(t.runs) / "r2"


def test_run_absent_tells_an_absent_run_from_a_refused_entry(tmp_path):
    """S4: `open` raises `RunAbsent` — a `RunRefused` — for an absent entry, and a plain
    `RunRefused` that is NOT `RunAbsent` for an entry that is there but no run: a regular file,
    a link to a real run folder. An existing `except RunRefused` handler still catches
    `RunAbsent`. The positive control opens the real run beside them."""
    from defender.run_repository import RunAbsent, RunRefused

    _root, t = _good(tmp_path, "r1")
    (Path(t.runs) / "afile").write_text("x\n", encoding="utf-8")
    os.symlink(Path(t.runs) / "r1", Path(t.runs) / "alink")
    runs = t.runs_repository()

    absent = H.raised(runs.open, _rid("nope"))
    assert isinstance(absent, RunAbsent), f"an absent run raised {absent!r}"
    assert isinstance(absent, RunRefused)
    assert issubclass(RunAbsent, RunRefused)
    for name in ("afile", "alink"):
        err = H.raised(runs.open, _rid(name))
        assert isinstance(err, RunRefused), (
            f"{name}: {err!r} — a present non-run must not read as absent")
        assert not isinstance(err, RunAbsent), (
            f"{name}: {err!r} — a present non-run must not read as absent")
        assert name in str(err)
    with pytest.raises(RunRefused) as caught:  # the handler every existing caller has
        runs.open(_rid("nope"))
    assert isinstance(caught.value, RunAbsent)
    assert Path(runs.open(_rid("r1")).run_dir) == Path(t.runs) / "r1"


def test_a_container_fault_is_the_tenants_refusal_not_an_absent_run(tmp_path):
    """Container faults stay `TenantRefused` (P2; S4): an absent runs folder (open needs it), a
    link at `<T>/runs` (never followed), a record naming another tenant
    (`TenantRecordMismatch`), and a folder with no record. None is a `RunAbsent`. The positive
    control: the folder made right, the run opens."""
    from defender.run_repository import RunAbsent

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    runs = t.runs_repository()
    absent = H.raised(runs.open, _rid("r1"))
    assert isinstance(absent, TenantRefused), repr(absent)
    assert not isinstance(absent, RunAbsent), repr(absent)

    elsewhere = tmp_path / "elsewhere-runs"
    H.plant_tenant_record(elsewhere, H.T_ID)
    H.make_run(elsewhere, "r1")
    os.symlink(elsewhere, t.runs)
    linked = H.raised(runs.open, _rid("r1"))
    assert isinstance(linked, TenantRefused), f"a linked runs folder was followed: {linked!r}"
    os.unlink(t.runs)

    H.plant_tenant_record(t.runs, H.U_ID)
    H.make_run(t.runs, "r1")
    foreign = H.raised(runs.open, _rid("r1"))
    assert isinstance(foreign, TenantRecordMismatch), repr(foreign)

    (Path(t.runs) / "_tenant.json").unlink()
    recordless = H.raised(runs.open, _rid("r1"))
    assert isinstance(recordless, TenantRefused), repr(recordless)

    H.plant_tenant_record(t.runs, H.T_ID)
    assert Path(runs.open(_rid("r1")).run_dir) == Path(t.runs) / "r1"


def test_list_tells_an_absent_container_from_an_empty_one_and_judges_every_entry(tmp_path):
    """`runs.list()`: the run ids in `list_run_ids`' order (sorted by text), sidecar files
    beside a run taken and not listed; `absent` true only when the folder does not exist —
    an empty folder is not absent (R51-05, R51-18). A stray file refuses the listing
    (`RunRefused` naming it: rev 4.1 H4, the rule the tracer applies after J3)."""
    from defender.run_repository import RunRefused

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    runs = t.runs_repository()

    none_yet = runs.list()
    assert none_yet.absent is True
    assert _ids(none_yet) == []

    H.runs_folder(t)
    empty = runs.list()
    assert empty.absent is False
    assert _ids(empty) == []

    for rid in ("r2", "r1"):
        H.make_run(t.runs, rid)
    H.plant_sidecars(t.runs, "r1")
    listed = runs.list()
    assert listed.absent is False
    assert _ids(listed) == ["r1", "r2"]

    (Path(t.runs) / "stray.txt").write_text("x\n", encoding="utf-8")
    stray = H.raised(runs.list)
    assert isinstance(stray, RunRefused), repr(stray)
    assert "stray.txt" in str(stray), repr(stray)


def test_exists_answers_occupancy(tmp_path):
    """`runs.exists(run_id)` is `run_exists`: a run folder at the id, or a sidecar file the id
    owns with no folder (the id is still taken), answers True; a free id, False; an absent
    runs folder, False."""
    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    runs = t.runs_repository()
    assert runs.exists(_rid("r1")) is False

    H.runs_folder(t)
    H.make_run(t.runs, "r1")
    (Path(t.runs) / "gone.run-end.json").write_text("{}\n", encoding="utf-8")
    assert runs.exists(_rid("r1")) is True
    assert runs.exists(_rid("gone")) is True
    assert runs.exists(_rid("free")) is False


def test_create_holds_the_container_writes_its_record_and_hands_out_the_run(tmp_path):
    """D-create (a), natural: `runs.create(run_id)` makes `<T>/runs` when absent (as run setup
    does today), ensures its `_tenant.json` naming T, and hands out the `Run` at `<T>/runs/<id>`
    for T. A linked `<T>/runs` and a record naming another tenant are refused, and nothing is
    written through the link or over the record."""
    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    runs = t.runs_repository()

    run = runs.create(_rid("r9"))
    assert Path(run.run_dir) == Path(t.runs) / "r9"
    assert str(run.tenant_id) == H.T_ID
    assert Path(t.runs).is_dir()
    assert not Path(t.runs).is_symlink()
    assert _tenant.read_tenant(Path(t.runs)).tenant_id == H.T_ID

    other_root = tmp_path / "data2"
    other_root.mkdir()
    u = H.tenant(other_root, H.T_ID)
    target = tmp_path / "link-target"
    target.mkdir()
    os.symlink(target, u.runs)
    linked = H.raised(u.runs_repository().create, _rid("r9"))
    assert isinstance(linked, TenantRefused), repr(linked)
    assert list(target.iterdir()) == [], "the create wrote through a linked runs folder"

    third_root = tmp_path / "data3"
    third_root.mkdir()
    w = H.tenant(third_root, H.T_ID)
    record = H.plant_tenant_record(w.runs, H.U_ID)
    foreign_bytes = record.read_bytes()
    foreign = H.raised(w.runs_repository().create, _rid("r9"))
    assert isinstance(foreign, TenantRefused), repr(foreign)
    assert record.read_bytes() == foreign_bytes
    assert not (Path(w.runs) / "r9").exists()


# ==========================================================================================
# RunAddress and rehydration (G22).
# ==========================================================================================

def test_a_run_address_round_trips_and_rehydrates_only_in_its_own_tenant(tmp_path):
    """`RunAddress(tenant_id, run_id, None)` is the stored form: its fields written as text
    (`{tenant_id, run_id}`, the curation row) and read back give an equal address; to
    rehydrate, accept its tenant, then `runs.resolve(address)` — the same run `open` gives.
    G22: a repository refuses an address naming ANOTHER tenant, even when that tenant has a
    run of the same id (R51-01's shape), and never hands out the other tenant's folder."""
    from defender.run_repository import RunAddress, RunId

    root, t = _good(tmp_path, "r1")
    u = H.tenant(root, H.U_ID)
    H.runs_folder(u)
    H.make_run(u.runs, "r1")

    addr = RunAddress(tenant_id=_tenant.TenantId(H.T_ID), run_id=RunId.parse("r1"),
                      episode_id=None)
    stored = {"tenant_id": str(addr.tenant_id), "run_id": str(addr.run_id)}
    back = RunAddress(tenant_id=_tenant.TenantId(stored["tenant_id"]),
                      run_id=RunId.parse(stored["run_id"]), episode_id=None)
    assert back == addr

    accepted = H.tenant(root, stored["tenant_id"])
    resolved = accepted.runs_repository().resolve(back)
    assert Path(resolved.run_dir) == Path(t.runs) / "r1"
    assert str(resolved.tenant_id) == H.T_ID

    beta_addr = RunAddress(tenant_id=_tenant.TenantId(H.U_ID), run_id=RunId.parse("r1"),
                           episode_id=None)
    crossed = H.raised(t.runs_repository().resolve, beta_addr)
    assert isinstance(crossed, _refusal_classes()), f"another tenant's address: {crossed!r}"
    assert Path(u.runs_repository().resolve(beta_addr).run_dir) == Path(u.runs) / "r1"


def test_a_run_address_checks_its_fields_at_construction_and_is_frozen():
    """`RunAddress`'s fields are checked when it is built — the tenant id grammar, `RunId`'s
    rules, the episode-id grammar — so a bad stored field never reaches a lookup; and it is
    frozen. The positive control builds a well-formed address with and without an episode."""
    from defender.run_repository import RunAddress, RunId

    good = RunAddress(tenant_id=_tenant.TenantId(H.T_ID), run_id=RunId.parse("r1"),
                      episode_id=None)
    arm = RunAddress(tenant_id=_tenant.TenantId(H.T_ID), run_id=RunId.parse(f"{EP}-a"),
                     episode_id=EP)
    assert arm.episode_id == EP
    assert good.episode_id is None

    for bad in ({"tenant_id": "Not A Tenant", "run_id": RunId.parse("r1"), "episode_id": None},
                {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": "../r1", "episode_id": None},
                {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": RunId.parse("r1"),
                 "episode_id": "a/b"}):
        assert H.raised(RunAddress, **bad) is not None, f"RunAddress accepted {bad!r}"
    assert H.raised(setattr, good, "tenant_id", _tenant.TenantId(H.U_ID)) is not None
    assert str(good.tenant_id) == H.T_ID


@pytest.mark.parametrize("episode_id", [
    "..", ".", "a/b", "Upper-Case", "", "x" * 300, "-leading", "a\x00b", b"ep", 7,
], ids=["dotdot", "dot", "slash", "upper", "empty", "over-long", "dash-first", "nul", "bytes",
        "int"])
def test_a_run_address_holds_its_episode_id_to_the_owners_episode_grammar(episode_id):
    """F6(b) / D-repo: `RunAddress` checks `episode_id` at construction against the owner's
    episode-id grammar — exactly a `str`, a valid run id (`..`, `.`, a separator, a leading
    `-`, NUL and the empty string are not), case-stable (`Upper-Case` is not), and short enough
    to name its record (300 bytes is not) — and refuses every member of that domain, not only
    `/`. POSITIVE CONTROL: the same fields with the episode id `EP` build an address. RED at
    base: the door has no `RunAddress` (ImportError)."""
    from defender.run_repository import RunAddress, RunId

    fields = {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": RunId.parse(f"{EP}-a")}
    assert RunAddress(**fields, episode_id=EP).episode_id == EP
    assert H.raised(RunAddress, **fields, episode_id=episode_id) is not None, (
        f"RunAddress accepted the episode id {episode_id!r}")


# ==========================================================================================
# The episode view.
# ==========================================================================================

def test_an_arm_created_for_t_opens_for_t_through_its_episode_and_never_as_a_natural_run(
        tmp_path, episodes):
    """O3 / O4: `runs.episode(ep)` over a container naming T opens the arm `view.arm_id(label)`
    (`<ep>-<label>`, a `RunId`) at `<episode>/runs/<ep>-<label>` for T; `view.list()` lists it;
    `view.episode` is the owner's handle on the episode folder; `view.base_world_id()` is the
    container record's own. The same id through the natural container is `RunAbsent` (an arm
    is reachable only through its episode)."""
    from defender.run_repository import RunAbsent, RunId

    _root, t = _good(tmp_path, "r1")
    ep = _episode(episodes, container=H.T_ID, arms=(LABEL,))
    runs = t.runs_repository()

    view = runs.episode(EP)
    arm_id = view.arm_id(LABEL)
    assert isinstance(arm_id, RunId)
    assert str(arm_id) == f"{EP}-{LABEL}"
    arm = view.open(arm_id)
    assert Path(arm.run_dir) == ep / "runs" / f"{EP}-{LABEL}"
    assert str(arm.tenant_id) == H.T_ID
    assert _ids(view.list()) == [f"{EP}-{LABEL}"]
    assert Path(view.episode.dir) == ep
    assert view.base_world_id() == _tenant.read_tenant(ep / "runs").base_world_id
    assert isinstance(H.raised(runs.open, arm_id), RunAbsent)


def test_the_view_refuses_a_container_naming_another_tenant_or_none_at_once(tmp_path, episodes):
    """O3 / G20 / N-c″: a PRESENT container's `_tenant.json` is judged when the view opens. One
    naming another tenant is `TenantRecordMismatch`; a present `runs/` with no record (an
    episode launched before #1078) is a `TenantRefused` too — old episodes are not supported.
    The positive control is the same episode once the record names T."""
    _root, t = _good(tmp_path)
    ep = _episode(episodes, container=H.U_ID, arms=(LABEL,))
    runs = t.runs_repository()

    foreign = H.raised(runs.episode, EP)
    assert isinstance(foreign, TenantRecordMismatch), repr(foreign)

    (ep / "runs" / "_tenant.json").unlink()
    recordless = H.raised(runs.episode, EP)
    assert isinstance(recordless, TenantRefused), f"a recordless container opened: {recordless!r}"

    _tenant.ensure_runs_base_record(ep / "runs", H.T_ID)
    assert _ids(runs.episode(EP).list()) == [f"{EP}-{LABEL}"]


def test_an_absent_container_opens_the_view_but_no_arm_until_the_launcher_creates_it(
        tmp_path, episodes):
    """An episode before RUNS has no container and so no record to judge (N-ep): the view opens,
    `list()` answers absent, and `view.open` / `view.create` refuse — the create making nothing
    (G5: an arm is never made in a container nobody bound). `view.create_container()` makes
    `runs/` with T's record (D-create b); then `view.create(arm_id)` hands out the arm's `Run`
    inside it. A second `create_container()` adopts what is there (C-19)."""
    _root, t = _good(tmp_path)
    ep = _episode(episodes)
    view = t.runs_repository().episode(EP)
    arm_id = view.arm_id(LABEL)

    listed = view.list()
    assert listed.absent is True
    assert _ids(listed) == []
    assert isinstance(H.raised(view.open, arm_id), _refusal_classes())
    assert isinstance(H.raised(view.create, arm_id), _refusal_classes())
    assert not (ep / "runs").exists(), "a create over an absent container made it"

    view.create_container()
    assert _tenant.read_tenant(ep / "runs").tenant_id == H.T_ID
    arm = view.create(arm_id)
    assert Path(arm.run_dir) == ep / "runs" / f"{EP}-{LABEL}"
    assert str(arm.tenant_id) == H.T_ID

    H.make_run(ep / "runs", f"{EP}-{LABEL}")
    record = (ep / "runs" / "_tenant.json").read_bytes()
    t.runs_repository().episode(EP).create_container()
    assert (ep / "runs" / "_tenant.json").read_bytes() == record
    assert (ep / "runs" / f"{EP}-{LABEL}" / "alert.json").is_file()


def test_an_unreadable_container_is_recorded_not_raised_and_never_written_through(
        tmp_path, episodes):
    """R51-20 / G25: a link at `<episode>/runs` — to a real folder holding an arm and no
    record — is an UNREADABLE container. The view opens (the page reads it as absent); its
    listing is empty with `unreadable` set; `view.open` refuses; `view.create_container()`
    refuses before minting a record; nothing is written through the link."""
    _root, t = _good(tmp_path)
    ep = _episode(episodes)
    target = tmp_path / "elsewhere"
    target.mkdir()
    H.make_run(target, f"{EP}-{LABEL}")
    os.symlink(target, ep / "runs")
    before = H.tree_state(target)

    view = t.runs_repository().episode(EP)
    listed = view.list()
    assert _ids(listed) == [], f"a linked container listed {_ids(listed)}"
    assert listed.unreadable, f"a linked container listed {_ids(listed)}"
    assert isinstance(H.raised(view.open, view.arm_id(LABEL)), _refusal_classes())
    assert isinstance(H.raised(view.create_container), _refusal_classes())
    assert H.tree_state(target) == before
    assert (ep / "runs").is_symlink()


def test_episode_files_is_the_owners_handle_alone_and_creates_nothing(tmp_path, episodes):
    """`runs.episode_files(ep)` is the judge's door: the owner's handle on the episode folder,
    reading nothing in `runs/` (C-26) — so it opens whatever the container holds, even a record
    naming another tenant. A missing episode and a file at the episode's name are refused, and
    nothing is created (#1133 O4.8.2, G23)."""
    _root, t = _good(tmp_path)
    ep = _episode(episodes, container=H.U_ID)
    runs = t.runs_repository()

    handle = runs.episode_files(EP)
    try:
        assert Path(handle.dir) == ep
    finally:
        handle.close()

    before = H.tree_state(episodes)
    assert H.raised(runs.episode_files, "20260728t161845z-missing-n1") is not None
    assert H.tree_state(episodes) == before, "a missing episode was created"
    (episodes / "20260728t161845z-afile-n1").write_text("x\n", encoding="utf-8")
    with_file = H.tree_state(episodes)
    assert H.raised(runs.episode_files, "20260728t161845z-afile-n1") is not None
    assert H.tree_state(episodes) == with_file, "a file at the episode's name was changed"


def test_a_bad_episode_id_or_an_unset_episodes_base_is_refused_before_anything_is_read(
        tmp_path, episodes, monkeypatch):
    """The episode owner refuses a bad id before anything is read (D-ep), at both doors: a
    separator, `..`, upper case. Without `DEFENDER_EPISODES_BASE` the owner refuses (only an
    episode open reads it). Nothing is created under the episodes root."""
    _root, t = _good(tmp_path)
    _episode(episodes, container=H.T_ID)
    runs = t.runs_repository()
    before = H.tree_state(tmp_path)

    for bad in ("../x", "a/b", "Upper-Case", ""):
        assert H.raised(runs.episode, bad) is not None, f"episode({bad!r}) opened"
        assert H.raised(runs.episode_files, bad) is not None, f"episode_files({bad!r}) opened"
    assert H.tree_state(tmp_path) == before

    monkeypatch.delenv("DEFENDER_EPISODES_BASE")
    assert H.raised(runs.episode, EP) is not None
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(episodes))
    assert _ids(runs.episode(EP).list()) == []
