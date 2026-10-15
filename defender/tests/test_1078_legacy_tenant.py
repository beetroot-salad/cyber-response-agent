"""#1077's tenant-record/stamp/family demands, RESTORED under #1078's tenant-on-the-request API.

`defender/tests/test_1077_tenant.py` (committed spec: `spec_graph_1077.yaml`, whose `tests:`
field scopes it FLAT to `defender/tests` — this file therefore lives here, not under
`tenant_1078_pass_a/`, or the graph's checker cannot see it) tested a design where the runs-base
record (`<runs_base>/_tenant.json`) bootstrapped itself with a built-in `tenant_id="default"`
and was written through `_tenant.ensure_tenant(runs_base, io=...)`. #1078 keeps the record's
name and fields (D2) but makes the REQUEST decide its tenant
(`ensure_runs_base_record(runs_base, tenant_id)`, no default, no `io=` seam) and requires a
tenant to exist first (D1's row). That file was deleted while `_tenant.py` was rewritten; every
demand it discharged that is STILL TRUE under #1078 is restored here, under its ORIGINAL
function name, so `spec_graph_1077.yaml`'s existing `discharged_by:` pointers resolve
unchanged. Adapted only where the API changed: a real tenant id in place of the retired
`"default"` bootstrap, `ensure_runs_base_record`/`materialize_run(tenant_id=...)` in place
of `ensure_tenant`/the `DEFENDER_RUNS_BASE`-env-routed `hosted` fixture, and a direct
`_create_once`/`_link_tmpfile`-wrapping seam in place of the retired `io=` fault-injection
kwarg. (#1120 then hands `materialize_run` the accepted `Tenant` — `tenant=` — in place of
the id, so the fixture tenant is set up with its knowledge folder, not a bare row.)

One demand's claim itself is superseded, not merely its mechanism relocated:
`tenant_record_write_seam` originally pinned `_io.write_guarded`/`read_guarded` as the record's
create lane. #1078's own committed spec (J16/J63, complete-or-absent writes) deliberately
replaces that with `_create_once` (`O_TMPFILE` + `linkat`), because a concurrent reader must
never observe an empty or partial record — a guarantee `write_guarded`'s staged O_EXCL create
does not make. The restored test under that name below pins the NEW mechanism instead of the
retired claim (see `spec_graph_1077.yaml`'s reworded `seed_docstring` and the PR body's "Edits
to spec_graph_1077.yaml" section for the full deviation writeup);
`test_1078_records.py::test_s7_j16_create_lane_complete_or_absent` (a separate suite —
`spec_graph_1078-pass-a.yaml`'s own) is the fuller, multi-threaded proof of the same lane.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender._episode_handle import Episode
from defender.tests import _spec1077 as S
from defender.tests import _tenants1106 as T1106
from defender.tests import _triplet_947 as T
from defender.tests._data_root_1078 import current_data_root, set_up_tenant
from defender.tests._fixture_uuid import fixture_uuid
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
    episode's view (`episode_runs=`), whose container and arm roster the launcher's RUNS step
    makes before the first sibling (#1187 R2) — here `_triplet_947.episode_view` stands in."""
    tenant = T1106.accept(current_data_root(), T_ID)
    with Episode.open(ep) as episode:
        return _materialize(alert, world.run_id, world=world,
                            episode_runs=T.episode_view(episode, tenant=tenant))


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


# ---------------------------------------------------------------------------------------
# D3 — the stamp's two new fields (RunProvenance itself — untouched by #1078)
# ---------------------------------------------------------------------------------------

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


def test_a_stamp_without_the_two_fields_reads_back_with_them_none():
    """A stamp written before this change reads back as a record whose `tenant_id` and
    `world_id` are `None`."""
    prov = S.provenance_mod()
    old = T.provenance_record(commit="deadbee")
    pre_change = "the fixture is a pre-change stamp"
    assert "tenant_id" not in old, pre_change
    assert "world_id" not in old, pre_change
    record = prov.RunProvenance.from_obj(old)
    assert record is not None, "an old stamp still parses — N2/C7"
    assert record.tenant_id is None
    assert record.world_id is None
    assert record.commit == "deadbee", "everything else reads back unchanged"


# ---------------------------------------------------------------------------------------
# O4 / D2 — the stamp's tenant (#1187 R1: the record it was read from is retired)
# ---------------------------------------------------------------------------------------

def test_materialize_stamps_the_tenant_and_world_from_the_record(tenant_root, tmp_path):
    """A run the host materialises carries a `tenant_id` — the request's tenant — stamped
    before the box exists and never `None`.

    #1187 declared changes 6 and 11 (R1, R1b): there is no tenant record to read the values
    from, and a natural run stamps no world id (`base_world_id` lived only in `_tenant.json`,
    which is retired): the stamp carries no `world_id`, and no `_tenant.json` is written
    under the runs base. (Name kept.)"""
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


def test_nothing_is_written_beside_the_runs_base(tenant_root, tmp_path):
    """Materialising a run writes nothing beside the runs base — in particular no stray
    `_tenant.json` one level up, at the tenant's own folder.

    NEGATIVE. Positive control inline: the run itself IS written, one level down, under the
    runs base.

    #1187 declared change 6 (R1): no `_tenant.json` is written anywhere — not beside the runs
    base and not under it either (the record is retired); the positive control is the run
    folder, a minted id, under `<runs_base>`. (Name kept.)
    """
    base = tenant_root / T_ID / "runs"
    alert = H.plant_alert(tmp_path / "in")
    # What the tenant's folder held before the run: its row and its placed knowledge (#1120).
    set_up = {p.name for p in (tenant_root / T_ID).iterdir()}
    assert set_up == {H.ROW_NAME, "knowledge"}, f"precondition: the set-up tenant holds {set_up}"
    run_dir = Path(_materialize(alert, None))
    tenant_dir_entries = {p.name for p in (tenant_root / T_ID).iterdir()}
    assert tenant_dir_entries <= set_up | {"runs"}, (
        f"materialising wrote {sorted(tenant_dir_entries - set_up - {'runs'})} beside the "
        "runs base; the first draft's `<runs_base>/../tenant.json` mistake resolves to a stray "
        "record one level up from where D2 puts it")
    assert not (tenant_root / T_ID / S.TENANT_RECORD_NAME).exists()
    assert not (base / H.RECORD_NAME).exists(), "run setup wrote the retired tenant record"
    assert run_dir.parent == base, f"positive control: the run lands under the runs base: {run_dir}"
    assert run_dir.is_dir(), run_dir


def test_the_stale_sidecar_clear_meets_the_new_neighbour(tenant_root, tmp_path):
    """The stale-sidecar clear is exact-run-id-keyed and never a glob over the runs base, so
    starting a run cannot delete a neighbour of the run in the runs base as a side effect.

    NEGATIVE, cite `defender/run_common.py`'s `_clear_stale_sidecars`. Positive control inline:
    the clear DOES remove the matching run's own stale sidecar.

    #1187 declared changes 6 and 1 (R1): the neighbour this demand was minted for,
    `<runs_base>/_tenant.json`, is retired — nothing writes or plants it — so the exact keying
    is pinned on the neighbour that remains, another run's own sidecar, and no record appears.
    The ids are UUIDs. (Name kept.)
    """
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


# ---------------------------------------------------------------------------------------
# #1187 R1/R1b (declared changes 6 and 11): the runs-base record `_tenant.json` is retired —
# neither written nor read by run setup, and with it `base_world_id`. The demands that pinned
# the record itself (its write and read seams, its three-slot payload, its tenant authority,
# its write-only `created_at`, decision 4's corrupt/empty/ill-typed/occupied-path refusals,
# decision 13's per-base scope and create race, a stamp disagreeing with it, and the family
# stamp's `base_world_id`) are retired with it. What replaces them is pinned in
# `ids_1187/test_1187_layout_isolation.py` (no record is written:
# `test_create_makes_the_runs_folder_and_writes_no_tenant_record`,
# `test_run_setup_writes_no_tenant_record_for_a_minted_or_a_pinned_run`; a stray one makes the
# listing refuse: `test_the_listing_refuses_a_tenant_record_or_an_episodes_folder`) and
# `ids_1187/test_1187_display_facts.py` (`test_a_natural_run_is_stamped_with_no_world_id`,
# `test_the_launchers_family_stamp_has_no_base_world_id`).
# ---------------------------------------------------------------------------------------

# ---------------------------------------------------------------------------------------
# Decision 13 — the collision guard
# ---------------------------------------------------------------------------------------

def test_run_creation_refuses_a_run_directory_named_like_the_tenant_record(tenant_root, tmp_path):
    """Run creation refuses a run directory whose name would collide with the tenant record's
    filename, by an explicit check rather than by the three coincidences that keep them apart
    today.

    NEGATIVE. Positive control inline: an ordinary run dir IS created.

    #1187 declared changes 1 and 6: the explicit check is now the run-id rule itself — `RunId`
    admits only canonical lowercase UUID text, so `_tenant.json` as a pinned id is the
    invalid-run-id exit like any other non-UUID, and `refuse_colliding_run_id` is retired with
    the record. The positive control is a pinned UUID. (Name kept.)
    """
    import uuid

    from defender._run_id import is_valid_run_id

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


# ---------------------------------------------------------------------------------------
# Decision 3 — setup retry and reuse
# ---------------------------------------------------------------------------------------

def test_a_second_materialize_for_one_run_id_finishes_what_the_first_left_undone(
        tenant_root, tmp_path):
    """A second setup call for one run id finishes whatever the first left undone and re-stamps,
    rather than refusing or duplicating.

    #1187 declared changes 6 and 1: the re-stamp names the request's tenant — there is no
    runs-base record to read it from — and the id is a UUID. (Name kept.)"""
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


# ---------------------------------------------------------------------------------------
# D3 / decision 15 — the world token, and a resume without a family record
# ---------------------------------------------------------------------------------------

def test_a_forked_sibling_stamps_the_episode_token_and_an_unforked_run_the_base_world(
        tenant_root, tmp_path):
    """A forked sibling stamps its `ResumeWorld.world_id` — the escaped `<episode token>.
    <label>` the ledger and the staged aliases key on — and its lineage (the source run, the
    branch turn); an unforked run stamps no world id and no lineage.

    #1187 declared change 11 (R1b): a natural run no longer stamps the tenant's `base_world_id`
    as its `world_id` — the value lived only in `_tenant.json`, which is retired."""
    alert = H.plant_alert(tmp_path / "in")
    unforked = Path(_materialize(alert, fixture_uuid("run-unforked")))  # #1187 dc1: a uuid
    assert _stamp(unforked).get("world_id") is None, (
        "a natural run carries no world id (a forked sibling's, below, is its own token)")
    assert _stamp(unforked)["parent_run_id"] is None
    assert _stamp(unforked)["fork_turn"] is None

    src, ep, world = _sibling_world(tmp_path, tenant_root, "b")
    sibling = Path(_arm(RunPaths(src).alert, world, ep))
    assert _stamp(sibling)["world_id"] == world.world_id, (
        "a forked sibling stamps its ResumeWorld token, which is what `served/<token>.jsonl` "
        "keys on and what D3 writes into provenance")
    assert "-" not in _stamp(sibling)["world_id"], (
        "the token is the ESCAPED spelling (`episode_token_for`), never `<episode_id>.<label>` "
        "re-composed from the run id — that spelling joins to nothing")
    assert _stamp(sibling)["parent_run_id"] == world.family.source_run_id
    assert _stamp(sibling)["fork_turn"] == world.family.branch_message_id


def test_a_resume_without_a_family_record_stamps_the_tenants_base_world(tenant_root, tmp_path):
    """A resume that has no family record is not 'forked' under the world-token rule and stamps
    like an unforked run.

    #1187 declared change 11 (R1b): an unforked run stamps no world id — the tenant's
    `base_world_id` lived only in `_tenant.json`, which is retired — so the resumed run carries
    no `world_id`, exactly as the source does. (Name kept.)"""
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


def test_the_base_role_sibling_of_a_family(tenant_root, tmp_path):
    """D3's token rule keys only on forked-or-not, never on sibling role: the base-role sibling
    gets the same `<episode>.<label>` token as any other forked sibling, with no special case.

    #1187 declared change 11 (R1b): the tenant's `base_world_id` is retired, so the closing
    "no family member carries the tenant's base world" check has nothing to compare against
    and is dropped; the token rule it accompanied is unchanged. (Name kept.)"""
    src, ep, _world_a = _sibling_world(tmp_path, tenant_root, "a")

    def _episode_tenant():
        return T1106.run_tenant(T1106.accept(tenant_root, T_ID))

    tokens = {}
    for label in ("a", "b"):          # 'a' is the base role
        world = H.run_py().resume_world(Episode.open(ep), label, tenant=_episode_tenant)
        run = Path(_arm(RunPaths(src).alert, world, ep))
        tokens[label] = _stamp(run)["world_id"]
    expected = {label: H.run_py().resume_world(Episode.open(ep), label, tenant=_episode_tenant).world_id
               for label in ("a", "b")}
    assert tokens == expected, (
        "the base-role sibling is still a forked sibling and gets the episode-qualified token, "
        "with no role-based special case — which is why no family member ever carries the "
        "tenant's base_world_id")


# ---------------------------------------------------------------------------------------
# Decision 15 — the family's view of the two new fields (verify_family, real primitive)
# ---------------------------------------------------------------------------------------

FAMILY_TENANT = "acme"


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


def _label(ep: Path, arm: Path) -> str:
    """The world label the episode's roster binds to `arm`'s id (#1187: an arm's folder name
    holds no label)."""
    return {arm_id: label for label, arm_id in T.read_roster(ep).items()}[arm.name]


def _world_id(ep: Path, arm: Path) -> str:
    """A world token for `arm`: `<episode token>.<label>`, the shape a forked sibling stamps."""
    return f"{ep.name.replace('-', '.')}.{_label(ep, arm)}"


def _verify_family(ep: Path, dirs, **kw):
    """`cli.verify_family` over the episode's arms (#1105 PR 2: `{label: Run | RunRefused}`,
    each opened by id through the episode's view — as the launcher's VERIFY step hands them).
    #1187 (R1b): no `base_world_id` is handed — it lived only in the retired `_tenant.json`."""
    with Episode.open(ep) as episode:
        arms = T.family_arms(episode, [_label(ep, d) for d in dirs])
        return S.branch_cli().verify_family(episode, arms, **kw)


def test_the_family_stamp_agrees_on_the_tenant_and_not_on_the_world(tmp_path):
    """The family stamp's `agreed` record carries the family's `tenant_id` and no `world_id`,
    because siblings differ on the world by design."""
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


def test_family_stamps_agreed_dict_is_all_slots_bound_minus_world_id(tmp_path):
    """The family stamp's `agreed` dict `_write_family_stamp` writes carries `tenant_id` bound
    on every write and never carries `world_id`, and no two siblings' stamps are conflated into
    `agreed` beyond the one field D3 keeps."""
    base, ep, dirs = _family_dirs(tmp_path, episode_id=fixture_uuid("1078-family-slots"))
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=FAMILY_TENANT,
                      world_id=_world_id(ep, d))

    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert report["comparable"] is True, report["reason"]
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    agreed = stamp["agreed"]
    assert agreed["tenant_id"] == FAMILY_TENANT, "the slot is bound on every write"
    assert "world_id" not in agreed
    for field in ("commit", "scope", "model"):
        assert field in agreed, f"{field} is still published as before"


def test_a_family_spanning_two_tenants_is_a_member_fault(tmp_path):
    """A family whose siblings stamp two different tenants is reported as a member fault."""
    base, ep, dirs = _family_dirs(tmp_path, episode_id=fixture_uuid("1078-family-cross"))
    for i, d in enumerate(dirs):
        S.plant_stamp(d, **T.provenance_record(),
                      tenant_id="tenant-one" if i == 0 else "tenant-two",
                      world_id=_world_id(ep, d))

    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert report["comparable"] is False, report["reason"]
    assert "tenant" in report["reason"], (
        f"a family spanning tenants is a fault, added to `_member_faults`: {report['reason']}")
    assert not (ep / "provenance.json").exists(), "a cross-tenant family was stamped as agreed"


def test_a_sibling_stamp_with_no_tenant_field_is_its_own_named_fault(tmp_path):
    """A sibling whose stamp carries no tenant field at all is its own named fault, distinct from
    a cross-tenant disagreement."""
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
    """The cross-tenant comparison runs over whichever siblings have already stamped, does not
    wait for the rest, and records how many it skipped."""
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


def test_verify_family_still_compares_only_commit_scope_and_model(tmp_path):
    """The two new stamp fields reach none of `verify_family`'s held-constant comparisons:
    `world_id` differs between siblings by design and `tenant_id` has its own rule.

    #1204 D4 replaced the hardcoded `("commit", "scope", "model")` loop with the field table
    that drives it (`STAMP_FIELD_CLASSES`; `knowledge` joined the compared fields there), so
    the classification is read off the table rather than the source text — and the behaviour
    below still proves world_id is not compared.

    NEGATIVE. Positive control: the one comparison that DOES move is the cross-tenant member
    fault, which is not part of the table-driven loop.
    """
    table = S.branch_cli().STAMP_FIELD_CLASSES
    held = {f for f, c in table.items() if c in ("anchored", "constant")}
    assert held == {"commit", "scope", "model", "knowledge"}, held
    assert table["tenant_id"] == "dedicated", (
        "tenant_id is judged by `_cross_tenant_fault`, never the held-constant loop")
    assert table["world_id"] == "expected_to_differ", (
        "world_id reached the held-constant comparison, where siblings differ by design and "
        "every family would be a fault")

    base, ep, dirs = _family_dirs(tmp_path, episode_id=fixture_uuid("1078-family-worlds-differ"))
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=FAMILY_TENANT,
                      world_id=_world_id(ep, d))
    report = _verify_family(ep, dirs, source=T.provenance_record())
    assert report["comparable"] is True, (
        f"siblings differ on world_id BY DESIGN; if it reached the comparison every family "
        f"would be withheld its stamp: {report['reason']}")
