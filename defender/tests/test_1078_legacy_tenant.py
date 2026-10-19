"""#1077's tenant-record/stamp/family demands, RESTORED under #1078's tenant-on-the-request API."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender._episode_handle import Episode
from defender.tests import _spec1077 as S
from defender.tests import _tenants1106 as T1106
from defender.tests import _triplet_947 as T
from defender.tests._data_root_1078 import current_data_root, set_up_tenant
from defender.tests.tenant_1078_pass_a import _spec1078 as H
from defender.run_repository import RunPaths

T_ID = H.VALID_ID


@pytest.fixture
def tenant_root(tmp_path, monkeypatch) -> Path:
    """A data root under this test's tmp dir, holding T_ID set up the way an operator does
    (#1120: the fixture tenant's knowledge placed, then the row created through the real
    owner) — the same fixture shape `test_1078_materialize.py` uses."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    set_up_tenant(root, T_ID)
    return root


def _materialize(alert: Path, run_id: str | None, **kw):
    """`materialize_run` for T_ID, handed the `Tenant` the real `accept_tenant` returns over
    this test's data root (#1120: the builder takes an accepted tenant, not an id)."""
    tenant = T1106.accept(current_data_root(), T_ID)
    return H.run_common().materialize_run(alert, run_id, tenant=tenant, **kw).run_dir


def _arm(alert: Path, world, ep: Path):
    """`materialize_run` for a sibling arm of episode `ep` (#1105 PR 2): made through the
    episode's view (`episode_runs=`), whose container the launcher makes with T_ID's record
    before the first sibling — here `_triplet_947.episode_view` stands in for it."""
    tenant = T1106.accept(current_data_root(), T_ID)
    with Episode.open(ep) as episode:
        return _materialize(alert, world.run_id, world=world,
                            episode_runs=T.episode_view(episode, tenant=tenant))


def _record(base: Path) -> dict:
    return json.loads((base / H.RECORD_NAME).read_text(encoding="utf-8"))


def _stamp(run_dir: Path) -> dict:
    return json.loads((run_dir / "provenance.json").read_text(encoding="utf-8"))


def _sibling_world(tmp_path: Path, root: Path, label: str):
    """A pass-(A) episode whose manifest names a source at T_ID's tenant location, and the
    `ResumeWorld` a sibling resolves from it — same shape as `test_1078_materialize.py`'s own
    `_sibling_world` (kept file-local rather than shared, matching that file's own convention)."""
    _base, src = H.tenant_source(root, T_ID, row=False)
    ep = tmp_path / "episodes" / T.EPISODE_ID
    manifest = H.family_for(src, ep)
    world = H.run_py().resume_world(
        Episode.open(manifest.parent), label,
        tenant=lambda: T1106.run_tenant(T1106.accept(root, T_ID)))
    return src, ep, world


# D3 — the stamp's two new fields (RunProvenance itself — untouched by #1078)

def test_the_stamp_spells_tenant_id_and_world_id_on_the_wire():
    """The stamp `as_json` writes spells `tenant_id` and `world_id`, and `from_obj` reads them
    back the way it reads `scope`."""
    prov = S.provenance_mod()
    record = prov.RunProvenance(
        commit="c0ffee", dirty=False, scope="defender", model="m-1",
        tenant_id="acme", world_id="ep.1.overlay_a")
    on_the_wire = json.loads(record.as_json())
    assert on_the_wire["tenant_id"] == "acme"
    assert on_the_wire["world_id"] == "ep.1.overlay_a", (
        f"`as_json` hand-spells its keys, so a new field is silent unless it is added there: "
        f"{sorted(on_the_wire)}")
    back = prov.RunProvenance.from_obj(on_the_wire)
    assert back is not None
    assert back.tenant_id == "acme"
    assert back.world_id == "ep.1.overlay_a"
    folded = prov.RunProvenance.from_obj({**on_the_wire, "tenant_id": 17, "world_id": []})
    assert folded is not None
    assert folded.tenant_id is None
    assert folded.world_id is None
    assert prov.RunProvenance.from_obj({**on_the_wire, "a_key_from_the_future": 1}) is not None


# O4 / D2 — the record, created once, read by the stamp

def test_materialize_stamps_the_tenant_and_world_from_the_record(tenant_root, tmp_path):
    """A run the host materialises carries a `tenant_id` and a world token equal to the tenant
    record's values, stamped before the box exists and never `None`."""
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(_materialize(alert, "run-o4"))
    base = tenant_root / T_ID / "runs"
    record, stamp = _record(base), _stamp(run_dir)
    assert stamp["tenant_id"] == record["tenant_id"] is not None
    assert stamp["world_id"] == record["base_world_id"] is not None, (
        f"O4 requires both stamp fields to EQUAL THE RECORD's values, not merely to be present; "
        f"the stamp says {stamp.get('world_id')!r} and the record {record['base_world_id']!r}")
    assert not (run_dir / ".box-sentinel").exists(), (
        "the stamp is written by the host before the box exists — the sentinel is planted later")


def test_the_tenant_record_is_created_once_under_the_runs_base(tenant_root, tmp_path):
    """The first materialisation creates `<runs_base>/_tenant.json` naming the request's tenant, a
    fresh `base_world_id` and a `created_at`, and a second materialisation reuses it unchanged."""
    base = tenant_root / T_ID / "runs"
    assert not (base / H.RECORD_NAME).exists()
    alert = H.plant_alert(tmp_path / "in")
    Path(_materialize(alert, "run-first"))
    first = _record(base)
    assert first["tenant_id"] == T_ID
    for slot in ("base_world_id", "created_at"):
        assert isinstance(first[slot], str), slot
        assert first[slot], slot

    second_run = Path(_materialize(alert, "run-second"))
    assert _record(base) == first, "the second materialisation re-minted the tenant's base world"
    assert _stamp(second_run)["world_id"] == first["base_world_id"]


def test_the_tenant_record_is_removed_between_two_runs_of_one_tenant(tenant_root, tmp_path):
    """'Created once when absent' is the only stated rule, so a materialisation after the record
    was deleted recreates it with a freshly-minted `base_world_id`, silently re-minting the
    tenant's base world."""
    base = tenant_root / T_ID / "runs"
    alert = H.plant_alert(tmp_path / "in")
    first = Path(_materialize(alert, "run-before-delete"))
    before = _record(base)["base_world_id"]
    (base / H.RECORD_NAME).unlink()

    second = Path(_materialize(alert, "run-after-delete"))
    after = _record(base)["base_world_id"]
    assert after != before, (
        "D2 states no distinct recreate-after-deletion case, so the only rule that applies is "
        "'created once when absent' and the base world is silently re-minted")
    assert _stamp(first)["world_id"] == before
    assert _stamp(second)["world_id"] == after, (
        "the identity discontinuity this produces is real and observable: two runs of one "
        "tenant carry two different base worlds")


def test_the_stale_sidecar_clear_meets_the_new_neighbour(tenant_root, tmp_path):
    """The stale-sidecar clear is exact-run-id-keyed and never a glob over the runs base, so
    starting a run cannot delete `<runs_base>/_tenant.json` as a side effect."""
    from defender.runtime import run_end

    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    S.tenant().ensure_runs_base_record(base, T_ID)
    record_before = _record(base)

    stale_dir = base / "run-reused"
    stale_dir.mkdir()
    stale = run_end.sidecar_path(stale_dir)
    stale.write_text('{"exit_class": "from a previous occupant"}\n', encoding="utf-8")
    other = run_end.sidecar_path(base / "run-untouched")
    other.write_text('{"exit_class": "someone else"}\n', encoding="utf-8")
    stale_dir.rmdir()

    alert = H.plant_alert(tmp_path / "in")
    _materialize(alert, "run-reused")

    assert (base / H.RECORD_NAME).is_file(), (
        "starting a run deleted the tenant record; the clear is keyed to the exact run_id, "
        "never a glob over the base")
    assert _record(base) == record_before
    assert not stale.exists(), "positive control: the matching run's own stale sidecar IS cleared"
    assert other.is_file(), "the clear reached another run's sidecar"


# Decision 4's sole exception — a corrupt tenant record refuses the run

def test_an_unparseable_tenant_record_refuses_the_run(tenant_root, tmp_path):
    """A tenant record that fails to parse refuses the run rather than degrading to a default."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    alert = H.plant_alert(tmp_path / "in")
    S.plant_tenant_record(base, body="{ this is not json")
    S.refused_run(lambda: _materialize(alert, "run-unparseable"), runs_base=base,
                 run_id="run-unparseable")
    assert (base / H.RECORD_NAME).read_text(encoding="utf-8") == "{ this is not json"


def test_a_tenant_record_missing_a_field_or_carrying_a_wrong_type_refuses_the_run(
        tenant_root, tmp_path):
    """The tenant record is the sole exception to the read-as-`None` policy: one missing a
    required field, or carrying a field of the wrong type, refuses the whole run."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    alert = H.plant_alert(tmp_path / "in")
    for i, field in enumerate(S.TENANT_FIELDS):
        S.plant_tenant_record(base, tenant_id=T_ID, drop=field)
        S.refused_run(lambda rid=f"run-drop-{i}": _materialize(alert, rid), runs_base=base,
                      run_id=f"run-drop-{i}")
    for i, field in enumerate(S.TENANT_FIELDS):
        S.plant_tenant_record(base, tenant_id=T_ID, wrong_type=field)
        S.refused_run(lambda rid=f"run-type-{i}": _materialize(alert, rid), runs_base=base,
                      run_id=f"run-type-{i}")
    S.plant_tenant_record(base, tenant_id=T_ID)
    assert Path(_materialize(alert, "run-well-shaped")).is_dir(), (
        "positive control: the exception extends BEYOND D2's literal 'fails to parse' to a "
        "record that parses but lacks a required field or carries a wrong-typed one — and no "
        "further: a well-shaped record still materialises")


def test_the_tenant_records_path_is_occupied_by_something_that_is_not_a_regular_file(tenant_root):
    """With something that is not a regular file at `<runs_base>/_tenant.json`, the
    complete-or-absent create lane fails, and because the tenant record is an identity-bearing
    write the run fails loudly rather than degrading or retrying."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    target = base / H.RECORD_NAME
    target.mkdir()
    with pytest.raises(S.tenant().TenantRefused):
        S.tenant().ensure_runs_base_record(base, T_ID)
    assert target.is_dir(), "the create replaced a non-regular entry instead of refusing"

    target.rmdir()
    elsewhere = base.parent / "planted.json"
    elsewhere.write_text('{"tenant_id": "attacker"}\n', encoding="utf-8")
    target.symlink_to(elsewhere)
    with pytest.raises(S.tenant().TenantRefused):
        S.tenant().ensure_runs_base_record(base, T_ID)
    assert json.loads(elsewhere.read_text(encoding="utf-8"))["tenant_id"] == "attacker", (
        "the create wrote through the link")


def test_a_failed_tenant_or_stamp_write_fails_the_run_loudly_and_is_never_retried(
        tenant_root):
    """A failed write of the tenant record fails the run loudly and is never silently retried."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    (base / H.RECORD_NAME).mkdir()
    recorder = S.RecordingIo()
    with pytest.raises(S.tenant().TenantRefused):
        S.tenant().ensure_runs_base_record(base, T_ID, io=recorder)
    attempts = [op for op in recorder.ops if op.startswith("write")]
    assert len(attempts) == 1, (
        f"the identity-bearing write was attempted {len(attempts)} times; it fails LOUDLY and "
        "is never silently retried — a best-effort record makes O4 unobservable")
    assert (base / H.RECORD_NAME).is_dir(), "the failed write replaced the obstruction"

    # Positive control: with the obstruction gone, the same call through the same seam succeeds.
    (base / H.RECORD_NAME).rmdir()
    clean = S.tenant().ensure_runs_base_record(base, T_ID, io=S.RecordingIo())
    assert (base / H.RECORD_NAME).is_file()
    # A LATER materialisation gets its own fresh attempt (decision 3's resumable setup).
    assert S.tenant().ensure_runs_base_record(
        base, T_ID, io=S.RecordingIo()).base_world_id == clean.base_world_id


# Decision 13 — the record's scope, its create race, and the collision guard


def test_the_loser_of_a_tenant_record_create_race_discards_its_value_and_rereads(tenant_root):
    """The loser of a tenant-record create race discards the value it was about to write and reads
    the winner's record instead, with no retry and no error surfaced."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    winner_world = "f" * 32

    def winner_lands(_path: Path) -> None:
        if not (base / H.RECORD_NAME).exists():
            S.plant_tenant_record(base, tenant_id=T_ID, base_world_id=winner_world)

    loser = S.tenant().ensure_runs_base_record(
        base, T_ID, io=S.RecordingIo(S.IoFault(before_write=winner_lands)))

    assert loser.base_world_id == winner_world, (
        "the loser kept its own freshly-minted world; loser-re-reads is the only resolution "
        "under which O4 ('both stamp fields equal the RECORD's values') holds for both racers")
    assert _record(base)["base_world_id"] == winner_world, "the loser overwrote the winner"


def test_run_creation_refuses_a_run_directory_named_like_the_tenant_record(tenant_root, tmp_path):
    """Run creation refuses a run directory whose name would collide with the tenant record's
    filename, by an explicit check rather than by the three coincidences that keep them apart
    today."""
    from defender._run_id import is_valid_run_id

    alert = H.plant_alert(tmp_path / "in")
    with pytest.raises((SystemExit, Exception)):  # noqa: B017,PT011
        _materialize(alert, H.RECORD_NAME)
    base = tenant_root / T_ID / "runs"
    assert not (base / H.RECORD_NAME).is_dir()
    assert not is_valid_run_id(H.RECORD_NAME), "claim C18, the first coincidence"
    guard = S.tenant().refuse_colliding_run_id
    assert guard(H.RECORD_NAME) is not None, (
        "an explicit run-creation collision guard replaces the three coincidences: the leading "
        "underscore (C18), both runs-base walkers' `is_dir()` filter (F6) and the exact-keyed "
        "sidecar clear (RG-1) — none of them a constraint anything enforces")
    assert guard("run-ordinary") is None
    assert Path(_materialize(alert, "run-ordinary")).is_dir(), "positive control"


def test_a_stamp_disagreeing_with_the_record_at_its_current_base_is_left_alone(
        tenant_root, tmp_path):
    """A run whose stamp carries a tenant the record at its current base does not name is read
    back unchanged: no reconciliation, no migration, no divergence check."""
    base = tenant_root / T_ID / "runs"
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(_materialize(alert, "run-moved"))
    original = _record(base)["tenant_id"]
    assert _stamp(run_dir)["tenant_id"] == original

    record_path = base / H.RECORD_NAME
    doc = json.loads(record_path.read_text(encoding="utf-8"))
    doc["tenant_id"], doc["base_world_id"] = "someone-else", "a" * 32
    # Hand-planted directly on disk (never through `ensure_runs_base_record`, which would
    # refuse a disagreeing value) — a stale-base scenario, not a write this design permits.
    record_path.write_text(json.dumps(doc), encoding="utf-8")

    record = S.Run().at(run_dir).record
    assert record.tenant_id == original, "the read reconciled against the current base"
    assert record.faults == (), (
        "no divergence CHECK either — decision 13 leaves the disagreement alone rather than "
        "recording it as a fault")
    assert _stamp(run_dir)["tenant_id"] == original, "the read migrated the stamp"


# Decision 3 — setup retry and reuse

def test_a_second_materialize_for_one_run_id_finishes_what_the_first_left_undone(
        tenant_root, tmp_path):
    """A second setup call for one run id finishes whatever the first left undone and re-stamps,
    rather than refusing or duplicating."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    run_dir = base / "run-resumable"
    run_dir.mkdir()                       # the state an interrupted first call leaves
    (run_dir / "gather_raw").mkdir()
    assert not RunPaths(run_dir).alert.exists()
    assert not (run_dir / "provenance.json").exists()

    alert = H.plant_alert(tmp_path / "in")
    again = Path(_materialize(alert, "run-resumable"))

    assert again == run_dir, "the second call refused or minted a second directory"
    assert RunPaths(run_dir).alert.is_file(), "the alert copy the first call never made"
    assert _stamp(run_dir)["tenant_id"] == _record(base)["tenant_id"], "it re-stamps"
    third = Path(_materialize(alert, "run-resumable"))
    assert third == run_dir
    assert len([p for p in base.iterdir() if p.is_dir()]) == 1, (
        "a transient failure must not permanently burn a run id, and setup must not duplicate")


def test_reusing_a_run_id_clears_all_three_sidecars_not_only_the_named_one(tenant_root, tmp_path):
    """Reusing a run id clears all three per-run sidecar files beside the runs base, not only the
    run-end one today's code names."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    run_dir = base / "run-recycled"
    sidecars = {
        name: getattr(S.RunPaths(run_dir), name)(base) for name in S.SIDECAR_ACCESSORS}
    for name, path in sidecars.items():
        path.write_text(f'{{"from": "a previous occupant", "which": "{name}"}}\n',
                        encoding="utf-8")
        assert path.parent == base, f"{name} lands beside the runs base, keyed `<run_id><suffix>`"

    alert = H.plant_alert(tmp_path / "in")
    _materialize(alert, "run-recycled")

    left = {name: path for name, path in sidecars.items() if path.exists()}
    assert left == {}, (
        f"these sidecars survived the reuse and now attribute a previous occupant's verdict and "
        f"accounting failures to a new run: {sorted(left)}")


# D3 / decision 15 — the world token, and a resume without a family record

def _arm_stamp_has_the_unforked_shape(run_dir: Path, *, token: str, natural_world: str) -> None:
    """#1255 P3: "`provenance.json` (world id, parent run, fork turn) moves out of the run folder
    into the episode's host-side record." An arm's in-folder stamp, IF it keeps one, has the
    shape an unforked run's has: no parent run, no fork turn, and a world id that is absent or
    the tenant's natural base world — never the arm's world token, under any key (the run folder
    is the box's mount, and the token names the episode and the world)."""
    path = run_dir / "provenance.json"
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    stamp = json.loads(text)
    assert stamp.get("parent_run_id") is None, (
        f"the arm's run folder names its parent run {stamp.get('parent_run_id')!r} (#1255 P3)")
    assert stamp.get("fork_turn") is None, (
        f"the arm's run folder names its fork turn {stamp.get('fork_turn')!r} (#1255 P3)")
    assert stamp.get("world_id") in (None, natural_world), (
        f"the arm's stamp carries the world id {stamp.get('world_id')!r}, neither absent nor the "
        f"tenant's natural base world {natural_world!r} — the world id moves out of the run "
        "folder (#1255 P3)")
    assert token not in text, f"the arm's run-folder stamp carries its world token {token!r}"


def _recorded_world(ep: Path, label: str):
    """The world `label` as the episode's own host-side record names it, read back through the
    reader a sibling resolves from (`run.resume_world` over the held episode) — the record's
    file name and format are the episode's, not pinned here."""
    with Episode.open(ep) as episode:
        return H.run_py().resume_world(
            episode, label, tenant=lambda: T1106.run_tenant(T1106.accept(current_data_root(), T_ID)))


def test_a_forked_sibling_stamps_the_episode_token_and_an_unforked_run_the_base_world(
        tenant_root, tmp_path):
    """An unforked run stamps the tenant's `base_world_id` and no lineage. A forked sibling's
    world token — the escaped `<episode token>.<label>` the ledger and the staged aliases key
    on — and its lineage (the source run, the branch turn) are the episode's, host-side.

    #1255 P3 FLIPPED the sibling half: "`provenance.json` (world id, parent run, fork turn)
    moves out of the run folder into the episode's host-side record". Before #1255 the sibling
    stamped its token and lineage into its own `provenance.json`; its run folder is the box's
    mount, so that told the model it was an arm. Now the sibling's run-folder stamp, if any,
    has the unforked shape (no token, no parent run, no fork turn; world id absent or the
    tenant's natural base world), and the token, source run and branch turn are read off the
    episode's own record."""
    alert = H.plant_alert(tmp_path / "in")
    unforked = Path(_materialize(alert, "run-unforked"))
    base = tenant_root / T_ID / "runs"
    assert _stamp(unforked)["world_id"] == _record(base)["base_world_id"]
    assert "." not in _stamp(unforked)["world_id"], "an unforked run stamps a bare world id"
    assert _stamp(unforked)["parent_run_id"] is None
    assert _stamp(unforked)["fork_turn"] is None

    src, ep, world = _sibling_world(tmp_path, tenant_root, "b")
    sibling = Path(_arm(RunPaths(src).alert, world, ep))
    _arm_stamp_has_the_unforked_shape(sibling, token=world.world_id,
                                      natural_world=_record(base)["base_world_id"])

    recorded = _recorded_world(ep, "b")
    assert recorded.world_id == world.world_id == T.world_token("b"), (
        "the episode's record no longer names the token the sibling ran as — the one "
        "`served/<token>.jsonl` keys on")
    assert "-" not in recorded.world_id, (
        "the token is the ESCAPED spelling (`episode_token_for`), never `<episode_id>.<label>` "
        "re-composed from the run id — that spelling joins to nothing")
    assert recorded.family.source_run_id == src.name, (
        "the episode's host-side record no longer names the run the sibling forked")
    assert recorded.family.branch_message_id == T.BRANCH_MESSAGE_ID, (
        "the episode's host-side record no longer names the branch turn")


def test_a_resume_without_a_family_record_stamps_the_tenants_base_world(tenant_root, tmp_path):
    """A resume that has no family record is not 'forked' under the world-token rule and stamps
    the tenant's base world like an unforked run."""
    base = tenant_root / T_ID / "runs"
    alert = H.plant_alert(tmp_path / "in")
    source = Path(_materialize(alert, "run-source"))
    resumed = Path(_materialize(alert, "run-resumed"))
    no_family = (
        "'forked' means 'has a family record', stated explicitly (decision 15(1)) — a resume "
        "that is not an episode fork has none")
    assert not (base / "family.yaml").exists(), no_family
    assert not (resumed / "family.yaml").exists(), no_family
    assert _stamp(resumed)["world_id"] == _record(base)["base_world_id"]
    assert _stamp(resumed)["world_id"] == _stamp(source)["world_id"]


# Decision 15 — the family's view of the two new fields (verify_family, real primitive)

FAMILY_TENANT = "acme"


def _family_dirs(tmp_path, tenant_id=FAMILY_TENANT, episode_id=None):
    """`(the siblings' runs base, the episode, the sibling run dirs)`."""
    T.runs_base(tmp_path, tenant_id=tenant_id)
    episode_id = episode_id or T.EPISODE_ID
    ep = T.episode(tmp_path, episode_id=episode_id)
    with Episode.open(ep) as episode:
        T.episode_view(episode)
    base = ep / "runs"
    # `sibling_run_dir` names a dir `<T.EPISODE_ID>-<world_id>`; this episode's arm ids carry
    # its own id, so the suffix past `T.EPISODE_ID` rides in front of the label.
    suffix = episode_id[len(T.EPISODE_ID) + 1:]
    dirs = [T.sibling_run_dir(base, f"{suffix}-{w}" if suffix else w) for w in T.WORLDS]
    return base, ep, dirs


def _verify_family(ep: Path, dirs, **kw):
    """`cli.verify_family` over the episode's arms (#1105 PR 2: `{label: Run | RunRefused}`,
    each opened by id through the episode's view, and the family's base world from the
    container's record — as the launcher's VERIFY step hands them)."""
    with Episode.open(ep) as episode:
        view = T.episode_view(episode)
        arms = T.family_arms(episode, [d.name.rsplit("-", 1)[-1] for d in dirs])
        return S.branch_cli().verify_family(episode, arms, base_world_id=view.base_world_id(),
                                            **kw)


def test_the_family_stamp_agrees_on_the_tenant_and_not_on_the_world(tmp_path):
    """The family stamp's `agreed` record carries the family's `tenant_id` and no `world_id`,
    because siblings differ on the world by design."""
    base, ep, dirs = _family_dirs(tmp_path, episode_id=f"{T.EPISODE_ID}-agree")
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=FAMILY_TENANT,
                      world_id=f"{T.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert report["comparable"] is True, report["reason"]
    agreed = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))["agreed"]
    assert agreed["tenant_id"] == FAMILY_TENANT, (
        "the tenant is constant across a family and stays in `agreed`")
    assert "world_id" not in agreed, (
        "`_write_family_stamp` publishes ONE sibling's WHOLE stamp as `agreed` minus `world_id` "
        "— the siblings differ on the world by design, so publishing one sibling's world as the "
        "family's would be a false record")


def test_a_family_spanning_two_tenants_is_a_member_fault(tmp_path):
    """A family whose siblings stamp two different tenants is reported as a member fault."""
    base, ep, dirs = _family_dirs(tmp_path, episode_id=f"{T.EPISODE_ID}-cross")
    for i, d in enumerate(dirs):
        S.plant_stamp(d, **T.provenance_record(),
                      tenant_id="tenant-one" if i == 0 else "tenant-two",
                      world_id=f"{T.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert report["comparable"] is False, report["reason"]
    assert "tenant" in report["reason"], (
        f"a family spanning tenants is a fault, added to `_member_faults`: {report['reason']}")
    assert not (ep / "provenance.json").exists(), "a cross-tenant family was stamped as agreed"


def test_a_sibling_stamp_with_no_tenant_field_is_its_own_named_fault(tmp_path):
    """A sibling whose stamp carries no tenant field at all is its own named fault, distinct from
    a cross-tenant disagreement."""
    base, ep, dirs = _family_dirs(tmp_path, episode_id=f"{T.EPISODE_ID}-absent")
    for i, d in enumerate(dirs):
        fields = dict(T.provenance_record())
        if i:
            fields["tenant_id"] = FAMILY_TENANT
        S.plant_stamp(d, **fields, world_id=f"{T.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert report["comparable"] is False, report["reason"]
    reason = report["reason"]
    named_fault = (
        f"treating 'absent' as 'compatible' is exactly how a real cross-tenant family slips "
        f"past the check the migration is adding; the reason says: {reason}")
    assert "tenant" in reason, named_fault
    assert any(w in reason for w in ("absent", "missing", "no tenant")), named_fault
    assert "disagree" not in reason, (
        "the absent case is its OWN named fault, distinct from a cross-tenant disagreement")


def test_the_cross_tenant_comparison_runs_over_the_stamped_siblings_and_records_the_skipped(
        tmp_path):
    """The cross-tenant comparison runs over whichever siblings have already stamped, does not
    wait for the rest, and records how many it skipped."""
    base, ep, dirs = _family_dirs(tmp_path, episode_id=f"{T.EPISODE_ID}-partial")
    for d in dirs[:2]:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=FAMILY_TENANT,
                      world_id=f"{T.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")
    (dirs[2] / "provenance.json").unlink()      # not yet stamped

    report = _verify_family(ep, dirs, source=T.provenance_record())
    reason = report["reason"]
    counted = (
        f"the comparison must record how many siblings it skipped, so an unstamped sibling "
        f"cannot silently shrink it: {reason}")
    assert "1" in reason, counted
    assert any(w in reason.lower() for w in ("skip", "unstamped")), counted
    assert "wait" not in reason.lower(), "the comparison does not wait for the rest"


