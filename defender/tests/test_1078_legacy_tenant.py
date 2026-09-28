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
kwarg.

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
from defender.tests import _triplet_947 as T
from defender.tests.tenant_1078_pass_a import _spec1078 as H

T_ID = H.VALID_ID


@pytest.fixture
def tenant_root(tmp_path, monkeypatch) -> Path:
    """A data root under this test's tmp dir, holding T_ID (created through the real owner) —
    the same fixture shape `test_1078_materialize.py` uses."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, T_ID)
    return root


def _materialize(alert: Path, run_id: str | None, tenant_id: str = T_ID, **kw):
    return H.run_common().materialize_run(alert, run_id, tenant_id=tenant_id, **kw).run_dir


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
    world = H.run_py().resume_world(Episode.open(manifest.parent), label, settings=lambda: H.T1106.PLAYGROUND_SETTINGS)
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
# O4 / D2 — the record, created once, read by the stamp
# ---------------------------------------------------------------------------------------

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


def test_the_tenant_record_is_written_through_write_guarded_and_read_through_read_guarded(
        tenant_root):
    """The tenant record is created through `_io.write_guarded` and read through `read_guarded`,
    never through a raw `os.open`. (#1078 J16/J63's complete-or-absent guarantee lives in
    `write_guarded`'s own `create` lane, so the record keeps #1077's one write seam.)"""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    writer = S.RecordingIo()
    S.tenant().ensure_runs_base_record(base, T_ID, io=writer)
    assert any(op.startswith("write_guarded") for op in writer.ops), (
        f"the create reached {writer.ops}; D2 says `write_guarded`, not a raw `os.open`")
    assert "write_atomic" not in writer.ops
    assert "open_guarded" not in writer.ops

    reader = S.RecordingIo()
    S.tenant().read_tenant(base, io=reader)
    assert "read_guarded" in reader.ops, f"the read reached {reader.ops}"

    # The alias refusal the seam inherits, driven for real: a symlink at the record's path.
    other = base.parent / "elsewhere.json"
    other.write_text("{}\n", encoding="utf-8")
    (base / H.RECORD_NAME).unlink()
    (base / H.RECORD_NAME).symlink_to(other)
    with pytest.raises(S.tenant().TenantRefused):
        S.tenant().ensure_runs_base_record(base, T_ID)
    assert other.read_text(encoding="utf-8") == "{}\n", "the create followed the alias"


def test_nothing_is_written_beside_the_runs_base(tenant_root, tmp_path):
    """Materialising a run writes nothing beside the runs base — in particular no stray
    `_tenant.json` one level up, at the tenant's own folder.

    NEGATIVE. Positive control inline: the record IS written, one level down, at
    `<runs_base>/_tenant.json`.
    """
    base = tenant_root / T_ID / "runs"
    alert = H.plant_alert(tmp_path / "in")
    _materialize(alert, "run-placement")
    tenant_dir_entries = {p.name for p in (tenant_root / T_ID).iterdir()}
    assert tenant_dir_entries <= {H.ROW_NAME, "runs"}, (
        f"materialising wrote {sorted(tenant_dir_entries - {H.ROW_NAME, 'runs'})} beside the "
        "runs base; the first draft's `<runs_base>/../tenant.json` mistake resolves to a stray "
        "record one level up from where D2 puts it")
    assert not (tenant_root / T_ID / S.TENANT_RECORD_NAME).exists()
    assert (base / H.RECORD_NAME).is_file(), (
        "positive control: the record lands under the runs base, beside the sidecars")


def test_tenant_record_and_first_run_are_born_in_the_same_materialize_call(tenant_root, tmp_path):
    """The tenant record and its `base_world_id` exist before the same call's provenance stamp is
    written: create-then-stamp is the only ordering consistent with D2's 'created once when
    absent' and O4's 'stamped before the box exists'."""
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(_materialize(alert, "run-born-together"))
    base = tenant_root / T_ID / "runs"
    record_path, stamp_path = base / H.RECORD_NAME, run_dir / "provenance.json"
    assert record_path.is_file()
    assert stamp_path.is_file()
    assert record_path.stat().st_mtime_ns <= stamp_path.stat().st_mtime_ns, (
        "the stamp was written before the record it must equal")
    assert _stamp(run_dir)["world_id"] == _record(base)["base_world_id"]


def test_the_tenant_record_is_created_once_under_the_runs_base(tenant_root, tmp_path):
    """The first materialisation creates `<runs_base>/_tenant.json` naming the request's tenant,
    a fresh `base_world_id` and a `created_at`, and a second materialisation reuses it
    unchanged.

    #1078 reworks this from #1077's original: the record no longer bootstraps a built-in
    `tenant_id="default"` — D1/O1 require `--tenant` on every request, with no default — so
    this drives the request's own tenant id (`T_ID`) rather than asserting a hard-coded
    `"default"`; 'created once, second materialisation reuses it unchanged' is unaffected."""
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


def test_tenant_records_payload_has_all_three_slots_bound(tenant_root):
    """The tenant record `_tenant` writes has `tenant_id`, `base_world_id` and `created_at` all
    bound on every write, matching structure's declared `invariants: [all-slots-bound]` for the
    `tenant_record.payload` facet.

    #1078 drops the original's `RecordingIo`/`io=` seam-observation half — `ensure_runs_base_
    record` no longer takes an `io=` kwarg (the create lane is `_create_once`, not a
    `write_guarded` call a fake can intercept; see `test_1078_records.py`'s own tests of that
    lane) — and keeps only the payload-shape assertion, driven against the real file on disk.
    """
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    S.tenant().ensure_runs_base_record(base, T_ID)
    body = _record(base)
    assert set(body) == set(S.TENANT_FIELDS), (
        f"every slot bound, no more and no less: {sorted(body)}")
    for slot in S.TENANT_FIELDS:
        assert body[slot] not in (None, ""), f"{slot} is unbound on the wire"


def test_a_tenant_record_whose_tenant_id_is_not_the_built_in_default(tenant_root, tmp_path):
    """A tenant record is read and stamped exactly as it names its tenant: the record is the
    sole authority for the stamped tenant, and the handle neither refuses nor rewrites it. Runs
    stamped under a previous value keep that value, with no reconciliation performed.

    #1078 reworks this from #1077's original: there is no built-in `'default'` bootstrap any
    more to contrast against (D1/O1: every request names its own tenant, with no default), so
    this drives two ordinary, differently-spelled tenant ids directly rather than contrasting
    one against the retired bootstrap value — the surviving claim is 'the record is the sole
    authority, no rewrite happens', unchanged.
    """
    base = tenant_root / T_ID / "runs"
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(_materialize(alert, "run-acme"))
    assert _stamp(run_dir)["tenant_id"] == T_ID, (
        "O4 requires the stamp fields to equal the RECORD's values")
    assert _record(base)["tenant_id"] == T_ID, "the handle rewrote the record"

    # A run stamped under a PREVIOUS value keeps it; nothing reconciles. Hand-planted directly
    # on disk (never through `ensure_runs_base_record`, which would refuse a disagreeing value)
    # — a stale-base scenario, not a write this design permits.
    record_path = base / H.RECORD_NAME
    doc = json.loads(record_path.read_text(encoding="utf-8"))
    doc["tenant_id"] = "acme-renamed"
    record_path.write_text(json.dumps(doc), encoding="utf-8")
    assert S.Run().at(run_dir).record.tenant_id == T_ID
    assert _stamp(run_dir)["tenant_id"] == T_ID


def test_world_token_requested_for_the_first_ever_run_of_a_brand_new_tenant(tenant_root, tmp_path):
    """The very first run mints the tenant record and its base world inside its own materialize
    call, and is stamped with that freshly-minted `base_world_id` before the box exists."""
    base = tenant_root / T_ID / "runs"
    assert not (base / H.RECORD_NAME).exists()
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(_materialize(alert, "run-very-first"))
    minted = _record(base)["base_world_id"]
    assert _stamp(run_dir)["world_id"] == minted
    assert _stamp(run_dir)["tenant_id"] == T_ID
    assert not (run_dir / ".box-sentinel").exists()


def test_the_tenant_records_created_at_is_read_by_nobody(tenant_root):
    """D2 writes `created_at` at creation and no design section reads it: as written it is a
    write-only field, and nothing in this change consumes it.

    NEGATIVE. Positive control inline: the two fields that ARE read — `tenant_id` and
    `base_world_id` — reach the stamp (proven elsewhere; here only their readability is
    checked).
    """
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    S.tenant().ensure_runs_base_record(base, T_ID)
    assert "created_at" in _record(base), "the field is written"
    readers = []
    for py in S.DEFENDER.rglob("*.py"):
        rel = py.relative_to(S.DEFENDER).as_posix()
        if rel.startswith(("tests/", ".venv/")) or rel == f"{S.TENANT_MODULE}.py":
            continue
        if "created_at" in py.read_text(encoding="utf-8", errors="replace") and "tenant" in rel:
            readers.append(rel)
    assert readers == [], (
        f"dispositions red flag 4: a field written once and read never is either a missing "
        f"obligation or dead weight. Readers: {readers}")
    record = S.tenant().read_tenant(base)
    read_by_someone = "positive control: these two ARE read"
    assert record.tenant_id, read_by_someone
    assert record.base_world_id, read_by_someone


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
    starting a run cannot delete `<runs_base>/_tenant.json` as a side effect.

    NEGATIVE, cite `defender/run_common.py`'s `_clear_stale_sidecars`. Positive control inline:
    the clear DOES remove the matching run's own stale sidecar.
    """
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


# ---------------------------------------------------------------------------------------
# Decision 4's sole exception — a corrupt tenant record refuses the run
# ---------------------------------------------------------------------------------------

def test_an_unparseable_tenant_record_refuses_the_run(tenant_root, tmp_path):
    """A tenant record that fails to parse refuses the run rather than degrading to a default."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    alert = H.plant_alert(tmp_path / "in")
    S.plant_tenant_record(base, body="{ this is not json")
    S.refused_run(lambda: _materialize(alert, "run-unparseable"), runs_base=base,
                 run_id="run-unparseable")
    assert (base / H.RECORD_NAME).read_text(encoding="utf-8") == "{ this is not json"


def test_tenant_record_malformed_json(tenant_root, tmp_path):
    """A tenant record whose bytes are not parseable JSON refuses the run — the caller observes
    the run refused, not degraded, unlike the provenance stamp which degrades on old or partial
    data."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    alert = H.plant_alert(tmp_path / "in")
    for body in ('{"tenant_id": "a",', "not json at all\n", '{"tenant_id": }',
                 '\x00\x01binary\xff'):
        run_id = f"run-{abs(hash(body)) % 9999}"
        S.plant_tenant_record(base, body=body)
        S.refused_run(lambda rid=run_id: _materialize(alert, rid), runs_base=base, run_id=run_id)
    # The contrast decision 4 draws: the STAMP degrades on the same shape of damage.
    S.plant_tenant_record(base, tenant_id=T_ID)
    good = Path(_materialize(alert, "run-contrast"))
    (good / "provenance.json").write_text("{ not json", encoding="utf-8")
    assert S.Run().at(good).record.tenant_id is None, (
        "a damaged provenance stamp reads None and records a fault; a damaged TENANT record "
        "refuses the whole run — a run with a forged tenant is worse than no run")


def test_tenant_record_empty_file(tenant_root, tmp_path):
    """An empty tenant-record file fails `json.loads` unambiguously, so D2's 'fails to parse ->
    refuses the run' applies directly."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    alert = H.plant_alert(tmp_path / "in")
    S.plant_tenant_record(base, body="")
    assert (base / H.RECORD_NAME).stat().st_size == 0
    S.refused_run(lambda: _materialize(alert, "run-empty"), runs_base=base, run_id="run-empty")
    S.plant_tenant_record(base, tenant_id=T_ID)
    assert Path(_materialize(alert, "run-after-empty")).is_dir()


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
    """A failed write of the tenant record fails the run loudly and is never silently retried.

    The fault is a REAL obstruction through the REAL primitive — a directory squatting the
    record's own path, which `_io.write_guarded`'s alias-refusing create meets on disk — not an
    injected exception. The recorder is a pass-through with NO fault-spec: it is there only to
    COUNT the attempts, which is the half of "never retried" a raised exception cannot show on
    its own. The refusal surfaces from the fallback read (`TenantRecordCorrupt`, since
    `read_guarded` refuses to read through a directory): "fails loudly, once" either way.
    """
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


# ---------------------------------------------------------------------------------------
# Decision 13 — the record's scope, its create race, and the collision guard
# ---------------------------------------------------------------------------------------

def test_a_second_runs_base_is_live_in_the_same_process(tenant_root, tmp_path):
    """Two runs bases live at once — a sibling's `<episode>/runs` alongside the tenant's own
    `<data root>/<tenant>/runs` — and each independently creates and reads its OWN
    `_tenant.json`, each minting its own `base_world_id`; the tenant record is 1:1 with its
    runs base, not a process-wide singleton, and no refusal fires when both are live.

    #1078 D1/O1 retire the built-in `tenant_id="default"` bootstrap this demand originally
    contrasted against — every base's record now names the SAME real request tenant, never a
    per-base default — so this drives both bases under `T_ID`; the surviving claim is
    1:1-with-its-runs-base/no-process-singleton/no-refusal-when-both-live.
    """
    parent = tenant_root / T_ID / "runs"
    parent.mkdir(parents=True, exist_ok=True)
    sibling = tmp_path / "episodes" / T.EPISODE_ID / "runs"
    sibling.mkdir(parents=True, exist_ok=True)

    a = S.tenant().ensure_runs_base_record(parent, T_ID)
    b = S.tenant().ensure_runs_base_record(sibling, T_ID)

    assert a.tenant_id == b.tenant_id == T_ID
    assert a.base_world_id != b.base_world_id, "each base mints its own base world"
    assert S.tenant().read_tenant(parent).base_world_id == a.base_world_id
    assert S.tenant().read_tenant(sibling).base_world_id == b.base_world_id
    assert (parent / H.RECORD_NAME).is_file()
    assert (sibling / H.RECORD_NAME).is_file()


def test_the_loser_of_a_tenant_record_create_race_discards_its_value_and_rereads(tenant_root):
    """The loser of a tenant-record create race discards the value it was about to write and
    reads the winner's record instead, with no retry and no error surfaced.

    The race window, opened deterministically through #1077's `io=` seam: the winner's record
    appears between the loser's absence check and its own create. `test_1078_records.py::
    test_o6_record_create_exclusive` is the fuller real N-way threaded race over the same lane."""
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
    today.

    NEGATIVE. Positive control inline: an ordinary run dir IS created beside the record.
    """
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


# ---------------------------------------------------------------------------------------
# Decision 3 — setup retry and reuse
# ---------------------------------------------------------------------------------------

def test_a_second_materialize_for_one_run_id_finishes_what_the_first_left_undone(
        tenant_root, tmp_path):
    """A second setup call for one run id finishes whatever the first left undone and re-stamps,
    rather than refusing or duplicating."""
    base = tenant_root / T_ID / "runs"
    base.mkdir(parents=True, exist_ok=True)
    run_dir = base / "run-resumable"
    run_dir.mkdir()                       # the state an interrupted first call leaves
    (run_dir / "gather_raw").mkdir()
    assert not (run_dir / "alert.json").exists()
    assert not (run_dir / "provenance.json").exists()

    alert = H.plant_alert(tmp_path / "in")
    again = Path(_materialize(alert, "run-resumable"))

    assert again == run_dir, "the second call refused or minted a second directory"
    assert (run_dir / "alert.json").is_file(), "the alert copy the first call never made"
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


# ---------------------------------------------------------------------------------------
# D3 / decision 15 — the world token, and a resume without a family record
# ---------------------------------------------------------------------------------------

def test_a_forked_sibling_stamps_the_episode_token_and_an_unforked_run_the_base_world(
        tenant_root, tmp_path):
    """A forked sibling stamps its `ResumeWorld.world_id` — the escaped `<episode token>.
    <label>` the ledger and the staged aliases key on — and its lineage (the source run, the
    branch turn); an unforked run stamps the tenant's `base_world_id` and no lineage."""
    alert = H.plant_alert(tmp_path / "in")
    unforked = Path(_materialize(alert, "run-unforked"))
    base = tenant_root / T_ID / "runs"
    assert _stamp(unforked)["world_id"] == _record(base)["base_world_id"]
    assert "." not in _stamp(unforked)["world_id"], "an unforked run stamps a bare world id"
    assert _stamp(unforked)["parent_run_id"] is None
    assert _stamp(unforked)["fork_turn"] is None

    src, ep, world = _sibling_world(tmp_path, tenant_root, "b")
    sibling = Path(_materialize(src / "alert.json", world.run_id, world=world))
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


def test_the_base_role_sibling_of_a_family(tenant_root, tmp_path):
    """D3's token rule keys only on forked-or-not, never on sibling role: the base-role sibling
    gets the same `<episode>.<label>` token as any other forked sibling, with no special case."""
    src, ep, _world_a = _sibling_world(tmp_path, tenant_root, "a")
    tokens = {}
    for label in ("a", "b"):          # 'a' is the base role
        world = H.run_py().resume_world(Episode.open(ep), label, settings=lambda: H.T1106.PLAYGROUND_SETTINGS)
        run = Path(_materialize(src / "alert.json", world.run_id, world=world))
        tokens[label] = _stamp(run)["world_id"]
    expected = {label: H.run_py().resume_world(Episode.open(ep), label, settings=lambda: H.T1106.PLAYGROUND_SETTINGS).world_id
               for label in ("a", "b")}
    assert tokens == expected, (
        "the base-role sibling is still a forked sibling and gets the episode-qualified token, "
        "with no role-based special case — which is why no family member ever carries the "
        "tenant's base_world_id, and why decision 15(4) puts it in the family record instead")
    base = tenant_root / T_ID / "runs"
    assert _record(base)["base_world_id"] not in tokens.values()


# ---------------------------------------------------------------------------------------
# Decision 15 — the family's view of the two new fields (verify_family, real primitive)
# ---------------------------------------------------------------------------------------

FAMILY_TENANT = "acme"


def _family_dirs(tmp_path, tenant_id=FAMILY_TENANT, episode_id=None):
    base, _src = T.runs_base(tmp_path, tenant_id=tenant_id)
    ep = T.episode(tmp_path, episode_id=episode_id or T.EPISODE_ID)
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]
    return base, ep, dirs


def test_the_family_record_carries_the_familys_base_world(tmp_path):
    """The family record carries the family's base world, so a family whose every member is a
    forked sibling still has one carrier for the base world lessons attribution keys on."""
    base, ep, dirs = _family_dirs(tmp_path)
    tenant_record = S.tenant().read_tenant(base)
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=FAMILY_TENANT,
                      world_id=f"{T.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    with Episode.open(ep) as episode:
        report = S.branch_cli().verify_family(episode, dirs, source=T.provenance_record())
    assert report["outcome"] == "accepted", report["reason"]
    family = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert family["base_world_id"] == tenant_record.base_world_id, (
        "dispositions red flag 5: under D3 as written no member of a family ever stamps the "
        "tenant's base world, yet lessons attribution keys promotion on it — decision 15(4) "
        "closes the gap here")


def test_the_family_stamp_agrees_on_the_tenant_and_not_on_the_world(tmp_path):
    """The family stamp's `agreed` record carries the family's `tenant_id` and no `world_id`,
    because siblings differ on the world by design."""
    base, ep, dirs = _family_dirs(tmp_path, episode_id=f"{T.EPISODE_ID}-agree")
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=FAMILY_TENANT,
                      world_id=f"{T.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    with Episode.open(ep) as episode:
        report = S.branch_cli().verify_family(episode, dirs, source=T.provenance_record())
    assert report["outcome"] == "accepted", report["reason"]
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
    base, ep, dirs = _family_dirs(tmp_path, episode_id=f"{T.EPISODE_ID}-slots")
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=FAMILY_TENANT,
                      world_id=f"{T.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    with Episode.open(ep) as episode:
        report = S.branch_cli().verify_family(episode, dirs, source=T.provenance_record())
    assert report["outcome"] == "accepted", report["reason"]
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    agreed = stamp["agreed"]
    assert agreed["tenant_id"] == FAMILY_TENANT, "the slot is bound on every write"
    assert "world_id" not in agreed
    for field in ("commit", "scope", "model"):
        assert field in agreed, f"{field} is still published as before"


def test_a_family_spanning_two_tenants_is_a_member_fault(tmp_path):
    """A family whose siblings stamp two different tenants is reported as a member fault."""
    base, ep, dirs = _family_dirs(tmp_path, episode_id=f"{T.EPISODE_ID}-cross")
    for i, d in enumerate(dirs):
        S.plant_stamp(d, **T.provenance_record(),
                      tenant_id="tenant-one" if i == 0 else "tenant-two",
                      world_id=f"{T.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    with Episode.open(ep) as episode:
        report = S.branch_cli().verify_family(episode, dirs, source=T.provenance_record())
    assert report["outcome"] == "incomplete", report["reason"]
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

    with Episode.open(ep) as episode:
        report = S.branch_cli().verify_family(episode, dirs, source=T.provenance_record())
    assert report["outcome"] == "incomplete", report["reason"]
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

    with Episode.open(ep) as episode:
        report = S.branch_cli().verify_family(episode, dirs, source=T.provenance_record())
    reason = report["reason"]
    counted = (
        f"the comparison must record how many siblings it skipped, so an unstamped sibling "
        f"cannot silently shrink it: {reason}")
    assert "1" in reason, counted
    assert any(w in reason.lower() for w in ("skip", "unstamped")), counted
    assert "wait" not in reason.lower(), "the comparison does not wait for the rest"


def test_verify_family_still_compares_only_commit_scope_and_model(tmp_path):
    """`verify_family` still compares only `commit`, `scope` and `model`, and the two new stamp
    fields reach none of its fault comparisons.

    NEGATIVE. Positive control: the one comparison that DOES move is the cross-tenant member
    fault, which is not part of this named-field loop.
    """
    import inspect
    src_text = inspect.getsource(S.branch_cli())
    assert 'for field in ("commit", "scope", "model")' in src_text, (
        "the named-field loop must still be anchored on exactly these three; the two new stamp "
        "fields must reach none of it")
    assert 'for field in ("commit", "scope", "model", "tenant_id")' not in src_text
    assert '"world_id"' not in src_text.split("def _family_faults")[-1].split("\ndef ")[0], (
        "world_id reached the named-field comparison, where siblings differ by design and "
        "every family would be a fault")

    base, ep, dirs = _family_dirs(tmp_path, episode_id=f"{T.EPISODE_ID}-worlds-differ")
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=FAMILY_TENANT,
                      world_id=f"{T.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")
    with Episode.open(ep) as episode:
        report = S.branch_cli().verify_family(episode, dirs, source=T.provenance_record())
    assert report["outcome"] == "accepted", (
        f"siblings differ on world_id BY DESIGN; if it reached the comparison every family "
        f"would be incomplete: {report['reason']}")
