"""#1077's tenant-record/stamp/family demands, RESTORED under #1078's tenant-on-the-request API."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import json
from pathlib import Path

import pytest

from defender.episodes._episode_handle import Episode
from defender.tests.support.shared.contracts import _spec1077 as S
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root, set_up_tenant
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H
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
    episode's view (`episode_runs=`), whose container and arm roster the launcher's RUNS step
    makes before the first sibling (#1187 R2) — here `_triplet_947.episode_view` stands in."""
    tenant = T1106.accept(current_data_root(), T_ID)
    with Episode.open(ep) as episode:
        view = T.episode_view(episode, tenant=tenant)
        # #1187 (review-4 F42): the arm's id is the one the roster holds for its label, never the
        # world's composed `run_id` (design: `ResumeWorld.run_id` is deleted or the roster's).
        return _materialize(alert, T.roster_arm_id(ep, world.world_id), world=world,
                            episode_runs=view)


def _stamp(run_dir: Path) -> dict:
    return json.loads((run_dir / "provenance.json").read_text(encoding="utf-8"))


def _sibling_world(tmp_path: Path, root: Path, label: str):
    """A pass-(A) episode whose manifest names a source at T_ID's tenant location, and the
    `ResumeWorld` a sibling resolves from it — same shape as `test_1078_materialize.py`'s own
    `_sibling_world` (kept file-local rather than shared, matching that file's own convention)."""
    _base, src = H.tenant_source(root, T_ID, row=False)
    # #1187 (Layout A): the episode is `<root>/<T>/episodes/<uuid>`, as RUNS leaves it.
    manifest = H.family_for(src)
    ep = manifest.parent
    world = H.run_py().resume_world(
        Episode.open(manifest.parent), label,
        tenant=lambda: T1106.run_tenant(T1106.accept(root, T_ID)))
    return src, ep, world


# D3 — the stamp's two new fields (RunProvenance itself — untouched by #1078)

def test_the_stamp_spells_tenant_id_and_world_id_on_the_wire():
    prov = S.provenance_mod()
    record = prov.RunProvenance(
        commit="c0ffee", dirty=False, scope="defender", model="m-1",
        tenant_id=fixture_uuid("tenant:acme"), world_id=fixture_uuid("world:overlay_a"))
    on_the_wire = json.loads(record.as_json())
    assert on_the_wire["tenant_id"] == fixture_uuid("tenant:acme")
    assert on_the_wire["world_id"] == fixture_uuid("world:overlay_a"), (
        f"`as_json` hand-spells its keys, so a new field is silent unless it is added there: "
        f"{sorted(on_the_wire)}")
    back = prov.RunProvenance.from_obj(on_the_wire)
    assert back is not None
    assert back.tenant_id == fixture_uuid("tenant:acme")
    assert back.world_id == fixture_uuid("world:overlay_a")
    folded = prov.RunProvenance.from_obj({**on_the_wire, "tenant_id": 17, "world_id": []})
    assert folded is not None
    assert folded.tenant_id is None
    assert folded.world_id is None
    assert prov.RunProvenance.from_obj({**on_the_wire, "a_key_from_the_future": 1}) is not None


# O4 / D2 — the record, created once, read by the stamp

def test_materialize_stamps_the_tenant_and_world_from_the_record(tenant_root, tmp_path):
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(_materialize(alert, None))
    base = tenant_root / T_ID / "runs"
    stamp = _stamp(run_dir)
    assert stamp["tenant_id"] == T_ID
    assert stamp.get("world_id") is None, (
        f"a natural run still stamps a world id: {stamp.get('world_id')!r}")
    assert not (base / H.RECORD_NAME).exists(), "run setup wrote the retired tenant record"
    assert not (run_dir / ".box-sentinel").exists(), (
        "the stamp is written by the host before the box exists — the sentinel is planted later")


def test_the_stale_sidecar_clear_meets_the_new_neighbour(tenant_root, tmp_path):
    import uuid

    from defender.runtime import run_end

    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    reused, untouched = str(uuid.uuid4()), str(uuid.uuid4())

    stale_dir = base / reused
    stale_dir.mkdir()
    stale = run_end.sidecar_path(stale_dir)
    stale.write_text('{"exit_class": "from a previous occupant"}\n', encoding="utf-8")
    other = run_end.sidecar_path(base / untouched)
    other.write_text('{"exit_class": "someone else"}\n', encoding="utf-8")
    stale_dir.rmdir()

    alert = H.plant_alert(tmp_path / "in")
    _materialize(alert, reused)

    assert not stale.exists(), "positive control: the matching run's own stale sidecar IS cleared"
    assert other.is_file(), (
        "the clear reached another run's sidecar; it is keyed to the exact run_id, never a glob "
        "over the base")
    assert not (base / H.RECORD_NAME).exists(), "run setup wrote the retired tenant record"


# Decision 4's sole exception — a corrupt tenant record refuses the run


# Decision 13 — the record's scope, its create race, and the collision guard


def test_run_creation_refuses_a_run_directory_named_like_the_tenant_record(tenant_root, tmp_path):
    import uuid

    from defender.records._run_id import is_valid_run_id

    alert = H.plant_alert(tmp_path / "in")
    with pytest.raises(SystemExit) as refused:
        _materialize(alert, H.RECORD_NAME)
    assert str(refused.value.code).startswith("invalid run id: "), (
        f"`_tenant.json` as a run id was not refused by the run-id rule: {refused.value.code!r}")
    base = tenant_root / T_ID / "runs"
    assert not (base / H.RECORD_NAME).exists(), "a refused id left an entry at its name"
    assert not is_valid_run_id(H.RECORD_NAME), "claim C18, the first coincidence"
    pinned = str(uuid.uuid4())
    run_dir = Path(_materialize(alert, pinned))
    assert run_dir == base / pinned, f"positive control: a pinned UUID runs: {run_dir}"
    assert run_dir.is_dir(), run_dir


# Decision 3 — setup retry and reuse

def test_a_second_materialize_for_one_run_id_finishes_what_the_first_left_undone(
        tenant_root, tmp_path):
    import uuid

    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    resumable = str(uuid.uuid4())
    run_dir = base / resumable
    run_dir.mkdir()                       # the state an interrupted first call leaves
    (run_dir / "gather_raw").mkdir()
    assert not RunPaths(run_dir).alert.exists()
    assert not (run_dir / "provenance.json").exists()

    alert = H.plant_alert(tmp_path / "in")
    again = Path(_materialize(alert, resumable))

    assert again == run_dir, "the second call refused or minted a second directory"
    assert RunPaths(run_dir).alert.is_file(), "the alert copy the first call never made"
    assert _stamp(run_dir)["tenant_id"] == T_ID, "it re-stamps"
    third = Path(_materialize(alert, resumable))
    assert third == run_dir
    assert len([p for p in base.iterdir() if p.is_dir()]) == 1, (
        "a transient failure must not permanently burn a run id, and setup must not duplicate")


def test_reusing_a_run_id_clears_all_three_sidecars_not_only_the_named_one(tenant_root, tmp_path):
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    run_id = fixture_uuid("run-recycled")  # #1187: a run id is a uuid4
    run_dir = base / run_id
    sidecars = {
        name: getattr(S.RunPaths(run_dir), name)(base) for name in S.SIDECAR_ACCESSORS}
    for name, path in sidecars.items():
        path.write_text(f'{{"from": "a previous occupant", "which": "{name}"}}\n',
                        encoding="utf-8")
        assert path.parent == base, f"{name} lands beside the runs base, keyed `<run_id><suffix>`"

    alert = H.plant_alert(tmp_path / "in")
    _materialize(alert, run_id)

    left = {name: path for name, path in sidecars.items() if path.exists()}
    assert left == {}, (
        f"these sidecars survived the reuse and now attribute a previous occupant's verdict and "
        f"accounting failures to a new run: {sorted(left)}")


# D3 / decision 15 — the world token, and a resume without a family record


def test_a_forked_sibling_stamps_the_episode_token_and_an_unforked_run_the_base_world(
        tenant_root, tmp_path):
    alert = H.plant_alert(tmp_path / "in")
    unforked = Path(_materialize(alert, fixture_uuid("run-unforked")))
    assert _stamp(unforked).get("world_id") is None
    assert _stamp(unforked)["parent_run_id"] is None
    assert _stamp(unforked)["fork_turn"] is None

    src, ep, world = _sibling_world(tmp_path, tenant_root, "b")
    sibling = Path(_arm(RunPaths(src).alert, world, ep))
    _arm_stamp_has_the_unforked_shape(sibling, token=world.world_id,
                                      natural_world=None)

    recorded = _recorded_world(ep, "b")
    assert recorded.world_id == world.world_id == T.fixture_world_id("b"), (
        "the episode's record no longer names the token the sibling ran as — the one "
        "`served/<token>.jsonl` keys on")
    assert recorded.world_id == T.world_id(ep, "b")
    assert recorded.family.source_run_id == src.name, (
        "the episode's host-side record no longer names the run the sibling forked")
    assert recorded.family.branch_message_id == T.BRANCH_MESSAGE_ID, (
        "the episode's host-side record no longer names the branch turn")


def test_a_resume_without_a_family_record_stamps_the_tenants_base_world(tenant_root, tmp_path):
    import uuid

    base = tenant_root / T_ID / "runs"
    alert = H.plant_alert(tmp_path / "in")
    source = Path(_materialize(alert, str(uuid.uuid4())))
    resumed = Path(_materialize(alert, str(uuid.uuid4())))
    no_family = (
        "'forked' means 'has a family record', stated explicitly (decision 15(1)) — a resume "
        "that is not an episode fork has none")
    assert not (base / "family.yaml").exists(), no_family
    assert not (resumed / "family.yaml").exists(), no_family
    assert resumed != source, "the two runs share one folder"
    assert _stamp(resumed).get("world_id") is None, (
        f"an unforked resume stamps a world id: {_stamp(resumed).get('world_id')!r}")
    assert _stamp(source).get("world_id") is None, (
        f"an unforked run stamps a world id: {_stamp(source).get('world_id')!r}")


# Decision 15 — the family's view of the two new fields (verify_family, real primitive)

FAMILY_TENANT = fixture_uuid("tenant:acme")


def _family_dirs(tmp_path, tenant_id=FAMILY_TENANT, episode_id=None):
    """`(the siblings' runs base, the episode, the sibling run dirs)`. #1105 PR 2: an arm is
    opened by id through its episode's view, so the siblings live where the launcher's do — the
    episode's container `<ep>/runs`. #1187 (Layout A, R2): the episode is
    `<data root>/<T>/episodes/<uuid>`, its RUNS step taken (`episode_view`: `runs/` and the
    arm roster), each arm at the id the roster holds for its label — never `<episode>-<label>`.
    `dirs` is in `T.WORLDS` order; `_label(ep, d)` names an arm's label."""
    T.runs_base(tmp_path, tenant_id=tenant_id)
    episode_id = episode_id or T.EPISODE_ID
    ep = T.episode(tmp_path, episode_id=episode_id)
    with Episode.open(ep) as episode:
        T.episode_view(episode)
    base = ep / "runs"
    dirs = [T.arm_run_dir(ep, w) for w in T.WORLDS]
    return base, ep, dirs


def _verify_family(ep: Path, dirs, **kw):
    """`cli.verify_family` over the episode's arms (#1105 PR 2: `{label: Run | RunRefused}`,
    each opened by id through the episode's view — as the launcher's VERIFY step hands them).
    #1187 (R1b): no `base_world_id` is handed — it lived only in the retired `_tenant.json`."""
    with Episode.open(ep) as episode:
        arms = T.family_arms(episode, [_label(ep, d) for d in dirs])
        return S.branch_cli().verify_family(episode, arms, **kw)


def test_the_family_stamp_agrees_on_the_tenant_and_not_on_the_world(tmp_path):
    base, ep, dirs = _family_dirs(tmp_path, episode_id=fixture_uuid("1078-family-agree"))
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=FAMILY_TENANT,
                      world_id=_world_id(ep, d))

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
    base, ep, dirs = _family_dirs(tmp_path, episode_id=fixture_uuid("1078-family-cross"))
    for i, d in enumerate(dirs):
        S.plant_stamp(d, **T.provenance_record(),
                      tenant_id=fixture_uuid("tenant:tenant-one") if i == 0 else fixture_uuid("tenant:tenant-two"),
                      world_id=_world_id(ep, d))

    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert report["comparable"] is False, report["reason"]
    assert "tenant" in report["reason"], (
        f"a family spanning tenants is a fault, added to `_member_faults`: {report['reason']}")
    assert not (ep / "provenance.json").exists(), "a cross-tenant family was stamped as agreed"


def test_a_sibling_stamp_with_no_tenant_field_is_its_own_named_fault(tmp_path):
    base, ep, dirs = _family_dirs(tmp_path, episode_id=fixture_uuid("1078-family-absent"))
    for i, d in enumerate(dirs):
        fields = dict(T.provenance_record())
        if i:
            fields["tenant_id"] = FAMILY_TENANT
        S.plant_stamp(d, **fields, world_id=_world_id(ep, d))

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
    base, ep, dirs = _family_dirs(tmp_path, episode_id=fixture_uuid("1078-family-partial"))
    for d in dirs[:2]:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=FAMILY_TENANT,
                      world_id=_world_id(ep, d))
    (dirs[2] / "provenance.json").unlink()      # not yet stamped

    report = _verify_family(ep, dirs, source=T.provenance_record())
    reason = report["reason"]
    counted = (
        f"the comparison must record how many siblings it skipped, so an unstamped sibling "
        f"cannot silently shrink it: {reason}")
    assert "1" in reason, counted
    assert any(w in reason.lower() for w in ("skip", "unstamped")), counted
    assert "wait" not in reason.lower(), "the comparison does not wait for the rest"


def _label(ep: Path, arm: Path) -> str:
    """The world label the episode's roster binds to `arm`'s id (#1187: an arm's folder name
    holds no label)."""
    world_id = _world_id(ep, arm)
    from defender import _yaml

    worlds = _yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))["worlds"]
    return next(world["label"] for world in worlds if world["world_id"] == world_id)


def _world_id(ep: Path, arm: Path) -> str:
    """The persisted world UUID whose roster entry binds this arm run."""
    return {arm_id: world_id for world_id, arm_id in T.read_roster(ep).items()}[arm.name]


def _arm_stamp_has_the_unforked_shape(run_dir: Path, *, token: str, natural_world: str | None) -> None:
    """Require arm stamps to expose no world token or fork lineage to the box."""
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
    """Read the world and fork lineage from the host-side episode record."""
    with Episode.open(ep) as episode:
        return H.run_py().resume_world(
            episode, label, tenant=lambda: T1106.run_tenant(T1106.accept(current_data_root(), T_ID)))
