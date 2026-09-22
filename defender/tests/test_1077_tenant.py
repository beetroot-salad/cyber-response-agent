"""#1077 — the tenant record, the stamp's two new fields, and the family's view of them.

Carries 35 demands of `spec-flow/specs/spec_graph_1077.yaml`. D2 mints one new record —
`<runs_base>/_tenant.json`, created once when absent, through `_io.write_guarded` — and D3
gives `RunProvenance` two optional fields the host always supplies. Decision 4 makes the tenant
record the SOLE exception to read-as-`None`: a corrupt one refuses the whole run, where every
other record's field reads `None` (and records the fault).

Every corruption here is real bytes on disk (`S.plant_tenant_record`), every collision is a
real directory, and the one fake — `S.RecordingIo`, entering through the owner's `io=`
injection seam — injects only faults `_io` itself produces (claim C19's `O_CREAT|O_EXCL|
O_NOFOLLOW` staging collision), never an author's guess at what a write failure looks like.

The family arms drive `learning/branch/cli.verify_family` through `_triplet_947`'s existing
episode/sibling scaffolding rather than inventing a parallel one.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests import _spec1077 as S
from defender.tests import _triplet_947 as T


@pytest.fixture
def base(tmp_path: Path) -> Path:
    return S.make_runs_base(tmp_path)


@pytest.fixture
def alert(tmp_path: Path) -> Path:
    p = tmp_path / "alert.json"
    p.write_text('{"rule": {"id": "v2-cross-tier-ssh-pivot"}}', encoding="utf-8")
    return p


@pytest.fixture
def hosted(base: Path, monkeypatch):
    """The host's own materialisation path, with the runs base steered by the environment the
    shipped resolver already reads (never `monkeypatch.setattr` — `tests.idioms`)."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(base))
    return S.run_common().materialize_run_dir


def _stamp(run_dir: Path) -> dict:
    return json.loads((run_dir / "provenance.json").read_text(encoding="utf-8"))


def _record(base: Path) -> dict:
    return json.loads((base / S.TENANT_RECORD_NAME).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------------------
# D3 — the stamp's two new fields
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
    # Read the way `scope` is read: a wrong-typed value folds to None rather than refusing.
    folded = prov.RunProvenance.from_obj({**on_the_wire, "tenant_id": 17, "world_id": []})
    assert folded is not None
    assert folded.tenant_id is None
    assert folded.world_id is None
    # Claim C7 is what makes the old-stamp read safe, and it must still hold.
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

def test_materialize_stamps_the_tenant_and_world_from_the_record(hosted, base, alert):
    """A run the host materialises carries a `tenant_id` and a world token equal to the tenant
    record's values, stamped before the box exists and never `None`."""
    run_dir = hosted(alert, "run-o4")
    record, stamp = _record(base), _stamp(run_dir)
    assert stamp["tenant_id"] == record["tenant_id"] is not None
    assert stamp["world_id"] == record["base_world_id"] is not None, (
        f"O4 requires both stamp fields to EQUAL THE RECORD's values, not merely to be present; "
        f"the stamp says {stamp.get('world_id')!r} and the record {record['base_world_id']!r}")
    assert not (run_dir / ".box-sentinel").exists(), (
        "the stamp is written by the host before the box exists — the sentinel is planted later")


def test_the_tenant_record_is_created_once_under_the_runs_base(hosted, base, alert):
    """The first materialisation creates `<runs_base>/_tenant.json` with `tenant_id="default"`,
    a fresh `base_world_id` and a `created_at`, and a second materialisation reuses it
    unchanged."""
    assert not (base / S.TENANT_RECORD_NAME).exists()
    hosted(alert, "run-first")
    first = _record(base)
    assert first["tenant_id"] == S.DEFAULT_TENANT_ID
    for slot in ("base_world_id", "created_at"):
        assert isinstance(first[slot], str), slot
        assert first[slot], slot

    second_run = hosted(alert, "run-second")
    assert _record(base) == first, "the second materialisation re-minted the tenant's base world"
    assert _stamp(second_run)["world_id"] == first["base_world_id"]


def test_tenant_records_payload_has_all_three_slots_bound(base):
    """The tenant record `_tenant` writes has `tenant_id`, `base_world_id` and `created_at` all
    bound on every write, matching structure's declared `invariants: [all-slots-bound]` for the
    `tenant_record.payload` facet."""
    recorder = S.RecordingIo()
    S.tenant().ensure_tenant(base, io=recorder)
    written = [p for name, p in recorder.calls if name.startswith("write")]
    assert written, "the owner made no write at all through its `io=` seam"
    assert written[-1].name == S.TENANT_RECORD_NAME, (
        f"the captured outbound write landed on {written[-1]}")
    body = _record(base)
    assert set(body) == set(S.TENANT_FIELDS), (
        f"every slot bound, no more and no less: {sorted(body)}")
    for slot in S.TENANT_FIELDS:
        assert body[slot] not in (None, ""), f"{slot} is unbound on the wire"


def test_the_tenant_record_is_written_through_write_guarded_and_read_through_read_guarded(base):
    """The tenant record is created through `_io.write_guarded` and read through `read_guarded`,
    never through a raw `os.open`."""
    writer = S.RecordingIo()
    S.tenant().ensure_tenant(base, io=writer)
    assert any(op.startswith("write_guarded") for op in writer.ops), (
        f"the create reached {writer.ops}; D2 says `write_guarded` (alias-refusing, staged "
        "O_EXCL create), not a raw `os.open`")
    assert "write_atomic" not in writer.ops
    assert "open_guarded" not in writer.ops

    reader = S.RecordingIo()
    S.tenant().read_tenant(base, io=reader)
    assert "read_guarded" in reader.ops, f"the read reached {reader.ops}"

    # The alias refusal the seam inherits, driven for real: a symlink at the record's path.
    other = base.parent / "elsewhere.json"
    other.write_text("{}\n", encoding="utf-8")
    (base / S.TENANT_RECORD_NAME).unlink()
    (base / S.TENANT_RECORD_NAME).symlink_to(other)
    with pytest.raises(OSError, match="(?i)alias|symlink|not a plain"):
        S.tenant().ensure_tenant(base)
    assert other.read_text(encoding="utf-8") == "{}\n", "the write followed the alias"


def test_tenant_record_and_first_run_are_born_in_the_same_materialize_call(hosted, base, alert):
    """The tenant record and its `base_world_id` exist before the same call's provenance stamp is
    written: create-then-stamp is the only ordering consistent with D2's 'created once when
    absent' and O4's 'stamped before the box exists'."""
    run_dir = hosted(alert, "run-born-together")
    record_path, stamp_path = base / S.TENANT_RECORD_NAME, run_dir / "provenance.json"
    assert record_path.is_file()
    assert stamp_path.is_file()
    assert record_path.stat().st_mtime_ns <= stamp_path.stat().st_mtime_ns, (
        "the stamp was written before the record it must equal")
    assert _stamp(run_dir)["world_id"] == _record(base)["base_world_id"]


def test_world_token_requested_for_the_first_ever_run_of_a_brand_new_tenant(hosted, base, alert):
    """The very first run mints the tenant record and its base world inside its own materialize
    call, and is stamped with that freshly-minted `base_world_id` before the box exists."""
    assert not (base / S.TENANT_RECORD_NAME).exists()
    run_dir = hosted(alert, "run-very-first")
    minted = _record(base)["base_world_id"]
    assert _stamp(run_dir)["world_id"] == minted
    assert _stamp(run_dir)["tenant_id"] == S.DEFAULT_TENANT_ID
    assert not (run_dir / ".box-sentinel").exists()


def test_the_tenant_records_created_at_is_read_by_nobody(base):
    """D2 writes `created_at` at creation and no design section reads it: as written it is a
    write-only field, and nothing in this change consumes it.

    NEGATIVE. Positive control inline (and demand d18): the two fields that ARE read —
    `tenant_id` and `base_world_id` — reach the stamp.
    """
    S.tenant().ensure_tenant(base)
    assert "created_at" in _record(base), "the field is written"
    readers = []
    for py in (S.DEFENDER).rglob("*.py"):
        rel = py.relative_to(S.DEFENDER).as_posix()
        if rel.startswith("tests/") or rel == f"{S.TENANT_MODULE}.py":
            continue
        if "created_at" in py.read_text(encoding="utf-8", errors="replace") and "tenant" in rel:
            readers.append(rel)
    assert readers == [], (
        f"dispositions red flag 4: a field written once and read never is either a missing "
        f"obligation or dead weight, and #1081/#1082 inherit whichever it is. Readers: {readers}")
    record = S.tenant().read_tenant(base)
    read_by_someone = "positive control: these two ARE read"
    assert record.tenant_id, read_by_someone
    assert record.base_world_id, read_by_someone


def test_nothing_is_written_beside_the_runs_base(hosted, base, alert):
    """Materialising a run writes nothing beside the runs base — in particular no `tenant.json`
    at `runs_base.parent`.

    NEGATIVE. Positive control inline (and demand d18): the record IS written, one level down,
    at `<runs_base>/_tenant.json`.
    """
    parent_before = {p.name for p in base.parent.iterdir()}
    hosted(alert, "run-placement")
    parent_after = {p.name for p in base.parent.iterdir()}
    new = parent_after - parent_before
    assert new <= {"sessions"}, (
        f"materialising wrote {sorted(new)} beside the runs base; the first draft's "
        "`<runs_base>/../tenant.json` resolves to /tmp/tenant.json under the default base")
    assert not (base.parent / "tenant.json").exists()
    assert not (base.parent / S.TENANT_RECORD_NAME).exists()
    assert (base / S.TENANT_RECORD_NAME).is_file(), (
        "positive control: the record lands under the runs base, beside the sidecars — the "
        "same trust level as today's `<runs_base>/<run>.run-end.json` (N9), not weaker, "
        "because `open_store` anchors the sessions dir one level ABOVE this (claims C15/F7)")


# ---------------------------------------------------------------------------------------
# Decision 4's sole exception — a corrupt tenant record refuses the run
# ---------------------------------------------------------------------------------------

def test_an_unparseable_tenant_record_refuses_the_run(hosted, base, alert):
    """A tenant record that fails to parse refuses the run rather than degrading to a default."""
    S.plant_tenant_record(base, body="{ this is not json")
    S.refused_run(lambda: hosted(alert, "run-unparseable"), runs_base=base, run_id="run-unparseable")
    assert _record_unchanged(base, "{ this is not json")


def _record_unchanged(base: Path, expected: str) -> bool:
    return (base / S.TENANT_RECORD_NAME).read_text(encoding="utf-8") == expected


def test_tenant_record_malformed_json(hosted, base, alert):
    """A tenant record whose bytes are not parseable JSON refuses the run — the caller observes
    the run refused, not degraded, unlike the provenance stamp which degrades on old or partial
    data."""
    for body in ('{"tenant_id": "a",', "not json at all\n", '{"tenant_id": }',
                 '\x00\x01binary\xff'):
        run_id = f"run-{abs(hash(body)) % 9999}"
        S.plant_tenant_record(base, body=body)
        S.refused_run(lambda rid=run_id: hosted(alert, rid), runs_base=base, run_id=run_id)
    # The contrast decision 4 draws: the STAMP degrades on the same shape of damage.
    S.plant_tenant_record(base)
    good = hosted(alert, "run-contrast")
    (good / "provenance.json").write_text("{ not json", encoding="utf-8")
    assert S.Run().at(good).record.tenant_id is None, (
        "a damaged provenance stamp reads None and records a fault; a damaged TENANT record "
        "refuses the whole run — a run with a forged tenant is worse than no run")


def test_tenant_record_empty_file(hosted, base, alert):
    """An empty tenant-record file fails `json.loads` unambiguously, so D2's 'fails to parse ->
    refuses the run' applies directly."""
    S.plant_tenant_record(base, body="")
    assert (base / S.TENANT_RECORD_NAME).stat().st_size == 0
    S.refused_run(lambda: hosted(alert, "run-empty"), runs_base=base, run_id="run-empty")
    # Positive control: the same path with a well-formed record materialises.
    S.plant_tenant_record(base)
    assert hosted(alert, "run-after-empty").is_dir()


def test_a_tenant_record_missing_a_field_or_carrying_a_wrong_type_refuses_the_run(
        hosted, base, alert):
    """The tenant record is the sole exception to the read-as-`None` policy: one missing a
    required field, or carrying a field of the wrong type, refuses the whole run."""
    for i, field in enumerate(S.TENANT_FIELDS):
        S.plant_tenant_record(base, drop=field)
        S.refused_run(lambda rid=f"run-drop-{i}": hosted(alert, rid), runs_base=base,
                      run_id=f"run-drop-{i}")
    for i, field in enumerate(S.TENANT_FIELDS):
        S.plant_tenant_record(base, wrong_type=field)
        S.refused_run(lambda rid=f"run-type-{i}": hosted(alert, rid), runs_base=base,
                      run_id=f"run-type-{i}")
    S.plant_tenant_record(base)
    assert hosted(alert, "run-well-shaped").is_dir(), (
        "positive control: the exception extends BEYOND D2's literal 'fails to parse' to a "
        "record that parses but lacks a required field or carries a wrong-typed one — and no "
        "further: a well-shaped record still materialises")


def test_the_tenant_records_path_is_occupied_by_something_that_is_not_a_regular_file(base):
    """With something that is not a regular file at `<runs_base>/_tenant.json`, the
    alias-refusing staged create fails, and because the tenant record is an identity-bearing
    write the run fails loudly rather than degrading or retrying."""
    target = base / S.TENANT_RECORD_NAME
    target.mkdir()
    with pytest.raises(OSError, match="(?i)directory|not a plain|alias"):
        S.tenant().ensure_tenant(base)
    assert target.is_dir(), "the create replaced a non-regular entry instead of refusing"

    target.rmdir()
    elsewhere = base.parent / "planted.json"
    elsewhere.write_text('{"tenant_id": "attacker"}\n', encoding="utf-8")
    target.symlink_to(elsewhere)
    with pytest.raises(OSError, match="(?i)alias|symlink|not a plain"):
        S.tenant().ensure_tenant(base)
    assert json.loads(elsewhere.read_text(encoding="utf-8"))["tenant_id"] == "attacker", (
        "the alias-refusing staged create wrote through the link")


def test_a_failed_tenant_or_stamp_write_fails_the_run_loudly_and_is_never_retried(base):
    """A failed write of the tenant record or of the provenance stamp fails the run loudly and
    is never silently retried.

    The fault is a REAL obstruction through the REAL primitive — a directory squatting the
    record's own path, which `_io.write_guarded`'s alias-refusing staged create meets on disk
    — not an injected exception. The recorder is a pass-through with NO fault-spec: it is
    there only to COUNT the attempts, which is the half of "never retried" a raised exception
    cannot show on its own.
    """
    (base / S.TENANT_RECORD_NAME).mkdir()
    recorder = S.RecordingIo()
    with pytest.raises(OSError):  # noqa: PT011 — the real primitive picks the errno, not us
        S.tenant().ensure_tenant(base, io=recorder)
    attempts = [op for op in recorder.ops if op.startswith("write")]
    assert len(attempts) == 1, (
        f"the identity-bearing write was attempted {len(attempts)} times; decision 7 says it "
        "fails LOUDLY and is never silently retried — a best-effort stamp makes O4 unobservable")
    assert (base / S.TENANT_RECORD_NAME).is_dir(), "the failed write replaced the obstruction"

    # The same, with the fault-spec, so the declarative fake is exercised on content the
    # ledger observed: claim C19 read `_io.py:818-822`'s `O_CREAT|O_EXCL|O_NOFOLLOW` staged
    # create, whose collision is a `FileExistsError`. Same outcome, one attempt.
    injected = S.RecordingIo(S.IoFault(fail_on=("write_guarded",)))
    with pytest.raises(FileExistsError):
        S.tenant().ensure_tenant(base, io=injected)
    assert len([op for op in injected.ops if op == "write_guarded"]) == 1

    # Positive control: with the obstruction gone, the same call through the same seam succeeds.
    (base / S.TENANT_RECORD_NAME).rmdir()
    clean = S.RecordingIo()
    S.tenant().ensure_tenant(base, io=clean)
    assert (base / S.TENANT_RECORD_NAME).is_file()
    # And a LATER materialisation gets its own fresh attempt (decision 3's resumable setup).
    assert S.tenant().ensure_tenant(base, io=S.RecordingIo()).base_world_id == _record(
        base)["base_world_id"]


# ---------------------------------------------------------------------------------------
# Decision 13 — the record's scope, its create race, and the collision guard
# ---------------------------------------------------------------------------------------

def test_the_loser_of_a_tenant_record_create_race_discards_its_value_and_rereads(base):
    """The loser of a tenant-record create race discards the value it was about to write and
    reads the winner's record instead, with no retry and no error surfaced."""
    winner_world = "ffffffffffffffffffffffffffffffff"

    def winner_lands(_path: Path) -> None:
        # The race window, opened deterministically: the winner's record appears between the
        # loser's absence check and its own create.
        if not (base / S.TENANT_RECORD_NAME).exists():
            S.plant_tenant_record(base, base_world_id=winner_world)

    loser = S.tenant().ensure_tenant(
        base, io=S.RecordingIo(S.IoFault(before_write=winner_lands)))

    assert loser.base_world_id == winner_world, (
        f"the loser kept its own freshly-minted world {loser.base_world_id!r}; loser-re-reads is "
        "the only resolution under which O4 ('both stamp fields equal the RECORD's values') "
        "holds for BOTH racers")
    assert _record(base)["base_world_id"] == winner_world, "the loser overwrote the winner"


def test_run_creation_refuses_a_run_directory_named_like_the_tenant_record(hosted, base, alert):
    """Run creation refuses a run directory whose name would collide with the tenant record's
    filename, by an explicit check rather than by the three coincidences that keep them apart
    today.

    NEGATIVE. Positive control inline (and demand d18): an ordinary run dir IS created beside
    the record.
    """
    from defender._run_id import is_valid_run_id
    with pytest.raises((SystemExit, Exception)):  # noqa: B017,PT011
        hosted(alert, S.TENANT_RECORD_NAME)
    assert not (base / S.TENANT_RECORD_NAME).is_dir()
    # The check is EXPLICIT, not the three coincidences. Claim C18 is one of them and it still
    # holds, but a run id the validator admits and that still collides must be refused too.
    assert not is_valid_run_id(S.TENANT_RECORD_NAME), "claim C18, the first coincidence"
    guard = S.tenant().refuse_colliding_run_id
    assert guard(S.TENANT_RECORD_NAME) is not None, (
        "an explicit run-creation collision guard replaces the three coincidences: the leading "
        "underscore (C18), both runs-base walkers' `is_dir()` filter (F6) and the exact-keyed "
        "sidecar clear (RG-1) — none of them a constraint anything enforces")
    assert guard("run-ordinary") is None
    assert hosted(alert, "run-ordinary").is_dir(), "positive control"


def test_a_second_runs_base_is_live_in_the_same_process(tmp_path: Path):
    """Two runs bases live at once — a sibling's `<episode>/runs` alongside its parent's — and
    each independently creates and reads its OWN `_tenant.json`, each defaulting to
    `tenant_id="default"` and each minting its own `base_world_id`; the tenant record is 1:1
    with its runs base, not a process-wide singleton, and no refusal fires when both are live.
    """
    parent = S.make_runs_base(tmp_path, "defender-runs")
    sibling = S.make_runs_base(tmp_path / "episodes" / S.EPISODE_ID, "runs")

    a = S.tenant().ensure_tenant(parent)
    b = S.tenant().ensure_tenant(sibling)

    assert a.tenant_id == b.tenant_id == S.DEFAULT_TENANT_ID, (
        "'a single built-in tenant' names the per-base bootstrap default — a sibling's own "
        "record is a new BASE-WORLD record for the SAME tenant, because the design's data "
        "model already lets one tenant own several base worlds (decision 13, premise s29)")
    assert a.base_world_id != b.base_world_id, "each base mints its own base world"
    assert S.tenant().read_tenant(parent).base_world_id == a.base_world_id
    assert S.tenant().read_tenant(sibling).base_world_id == b.base_world_id
    assert (parent / S.TENANT_RECORD_NAME).is_file()
    assert (sibling / S.TENANT_RECORD_NAME).is_file()


def test_a_tenant_record_whose_tenant_id_is_not_the_built_in_default(hosted, base, alert):
    """A tenant record whose `tenant_id` is not the built-in 'default' is read and stamped
    as-is: the record is the sole authority for the stamped tenant, `'default'` is only D2's
    creation-time bootstrap value, and the handle neither refuses the record nor rewrites it.
    Runs stamped under a previous value keep that value, with no reconciliation performed."""
    S.plant_tenant_record(base, tenant_id="acme-corp")
    run_dir = hosted(alert, "run-acme")
    assert _stamp(run_dir)["tenant_id"] == "acme-corp", (
        "O4 requires the stamp fields to equal the RECORD's values, not `default`")
    assert _record(base)["tenant_id"] == "acme-corp", "the handle rewrote the record"

    # A run stamped under a PREVIOUS value keeps it; nothing reconciles.
    S.plant_tenant_record(base, tenant_id="acme-renamed")
    assert S.Run().at(run_dir).record.tenant_id == "acme-corp"
    assert _stamp(run_dir)["tenant_id"] == "acme-corp"


def test_a_stamp_disagreeing_with_the_record_at_its_current_base_is_left_alone(
        hosted, base, alert):
    """A run whose stamp carries a tenant the record at its current base does not name is read
    back unchanged: no reconciliation, no migration, no divergence check."""
    S.plant_tenant_record(base, tenant_id="tenant-one")
    run_dir = hosted(alert, "run-moved")
    assert _stamp(run_dir)["tenant_id"] == "tenant-one"

    S.plant_tenant_record(base, tenant_id="tenant-two",
                          base_world_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    record = S.Run().at(run_dir).record
    assert record.tenant_id == "tenant-one", "the read reconciled against the current base"
    assert record.faults == (), (
        "no divergence CHECK either — decision 13 leaves the disagreement alone rather than "
        "recording it as a fault")
    assert _stamp(run_dir)["tenant_id"] == "tenant-one", "the read migrated the stamp"


def test_the_tenant_record_is_removed_between_two_runs_of_one_tenant(hosted, base, alert):
    """'Created once when absent' is the only stated rule, so a materialisation after the record
    was deleted recreates it with a freshly-minted `base_world_id`, silently re-minting the
    tenant's base world."""
    first = hosted(alert, "run-before-delete")
    before = _record(base)["base_world_id"]
    (base / S.TENANT_RECORD_NAME).unlink()

    second = hosted(alert, "run-after-delete")
    after = _record(base)["base_world_id"]
    assert after != before, (
        "D2 states no distinct recreate-after-deletion case, so the only rule that applies is "
        "'created once when absent' and the base world is silently re-minted")
    assert _stamp(first)["world_id"] == before
    assert _stamp(second)["world_id"] == after, (
        "the identity discontinuity this produces is real and observable: two runs of one "
        "tenant carry two different base worlds")


def test_the_stale_sidecar_clear_meets_the_new_neighbour(hosted, base, alert):
    """The stale-sidecar clear is exact-run-id-keyed and never a glob over the runs base, so
    starting a run cannot delete `<runs_base>/_tenant.json` as a side effect.

    NEGATIVE, cite `defender/run_common.py:66-77`. Positive control inline: the clear DOES
    remove the matching run's own stale sidecar.
    """
    from defender.runtime import run_end
    S.plant_tenant_record(base)
    record_before = _record(base)

    stale_dir = base / "run-reused"
    stale_dir.mkdir()
    stale = run_end.sidecar_path(stale_dir)
    stale.write_text('{"exit_class": "from a previous occupant"}\n', encoding="utf-8")
    other = run_end.sidecar_path(base / "run-untouched")
    other.write_text('{"exit_class": "someone else"}\n', encoding="utf-8")
    stale_dir.rmdir()

    hosted(alert, "run-reused")

    assert (base / S.TENANT_RECORD_NAME).is_file(), (
        "starting a run deleted the tenant record; the clear is keyed to the exact run_id "
        "(`run_end.sidecar_path(run_dir).unlink()`), never a glob over the base")
    assert _record(base) == record_before
    assert not stale.exists(), "positive control: the matching run's own stale sidecar IS cleared"
    assert other.is_file(), "the clear reached another run's sidecar"


# ---------------------------------------------------------------------------------------
# Decision 3 — setup retry and reuse
# ---------------------------------------------------------------------------------------

def test_a_second_materialize_for_one_run_id_finishes_what_the_first_left_undone(
        hosted, base, alert):
    """A second setup call for one run id finishes whatever the first left undone and re-stamps,
    rather than refusing or duplicating."""
    run_dir = base / "run-resumable"
    run_dir.mkdir()                       # the state an interrupted first call leaves
    (run_dir / "gather_raw").mkdir()
    assert not (run_dir / "alert.json").exists()
    assert not (run_dir / "provenance.json").exists()

    again = hosted(alert, "run-resumable")

    assert again == run_dir, "the second call refused or minted a second directory"
    assert (run_dir / "alert.json").is_file(), "the alert copy the first call never made"
    assert _stamp(run_dir)["tenant_id"] == _record(base)["tenant_id"], "it re-stamps"
    # And a fully-complete run id is re-stamped rather than refused or duplicated.
    third = hosted(alert, "run-resumable")
    assert third == run_dir
    assert len([p for p in base.iterdir() if p.is_dir()]) == 1, (
        "a transient failure must not permanently burn a run id, and setup must not duplicate")


def test_reusing_a_run_id_clears_all_three_sidecars_not_only_the_named_one(hosted, base, alert):
    """Reusing a run id clears all three per-run sidecar files beside the runs base, not only the
    run-end one today's code names."""
    run_dir = base / "run-recycled"
    sidecars = {
        name: getattr(S.RunPaths(run_dir), name)(base) for name in S.SIDECAR_ACCESSORS}
    for name, path in sidecars.items():
        path.write_text(f'{{"from": "a previous occupant", "which": "{name}"}}\n',
                        encoding="utf-8")
        assert path.parent == base, f"{name} lands beside the runs base, keyed `<run_id><suffix>`"

    hosted(alert, "run-recycled")

    left = {name: path for name, path in sidecars.items() if path.exists()}
    assert left == {}, (
        f"these sidecars survived the reuse and now attribute a previous occupant's verdict and "
        f"accounting failures to a new run: {sorted(left)}")


# ---------------------------------------------------------------------------------------
# D3 / decision 15 — the world token, and the family's view of the two new fields
# ---------------------------------------------------------------------------------------

def _resume_world(episode_dir: Path, label: str):
    """The `ResumeWorld` a sibling process holds — resolved from the manifest exactly as
    `run.py --resume <manifest> --world <label>` resolves it, and handed to the builder the
    way `run.py` hands it. The world token is `_family.world_token_for`'s ESCAPED spelling
    (`-` of the episode id folded onto `.`), the one the ledger filename and every staged
    alias are keyed on; the builder never re-composes it from a path."""
    from defender.runtime.branch import _family
    family = _family.load_family(S.EpisodePaths(episode_dir).family)
    return _family.resume_world_from(family, label, episode_dir)


def test_a_forked_sibling_stamps_the_episode_token_and_an_unforked_run_the_base_world(
        hosted, base, alert, tmp_path: Path, monkeypatch):
    """A forked sibling stamps its `ResumeWorld.world_id` — the escaped `<episode token>.
    <label>` the ledger and the staged aliases key on — and its lineage (the source run, the
    branch turn); an unforked run stamps the tenant's `base_world_id` and no lineage."""
    unforked = hosted(alert, "run-unforked")
    assert _stamp(unforked)["world_id"] == _record(base)["base_world_id"]
    assert "." not in _stamp(unforked)["world_id"], "an unforked run stamps a bare world id"
    assert _stamp(unforked)["parent_run_id"] is None
    assert _stamp(unforked)["fork_turn"] is None

    episode_dir = T.episode(tmp_path)
    sibling_base = S.make_runs_base(episode_dir, "runs")
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(sibling_base))
    world = _resume_world(episode_dir, "b")
    sibling = S.run_common().materialize_run_dir(alert, world.run_id, world=world)
    assert _stamp(sibling)["world_id"] == world.world_id, (
        "a forked sibling stamps its ResumeWorld token, which is what `served/<token>.jsonl` "
        "keys on and what D3 writes into provenance")
    assert "-" not in _stamp(sibling)["world_id"], (
        "the token is the ESCAPED spelling (`episode_token_for`), never `<episode_id>.<label>` "
        "re-composed from the run id — that spelling joins to nothing")
    assert _stamp(sibling)["parent_run_id"] == world.family.source_run_id
    assert _stamp(sibling)["fork_turn"] == world.family.branch_message_id


def test_a_resume_without_a_family_record_stamps_the_tenants_base_world(hosted, base, alert):
    """A resume that has no family record is not 'forked' under the world-token rule and stamps
    the tenant's base world like an unforked run."""
    source = hosted(alert, "run-source")
    resumed = hosted(alert, "run-resumed")
    no_family = (
        "'forked' means 'has a family record', stated explicitly (decision 15(1)) — a resume "
        "that is not an episode fork has none")
    assert not (base / "family.yaml").exists(), no_family
    assert not (resumed / "family.yaml").exists(), no_family
    assert _stamp(resumed)["world_id"] == _record(base)["base_world_id"]
    assert _stamp(resumed)["world_id"] == _stamp(source)["world_id"]


def test_the_base_role_sibling_of_a_family(tmp_path: Path, alert, monkeypatch):
    """D3's token rule keys only on forked-or-not, never on sibling role: the base-role sibling
    gets the same `<episode>.<label>` token as any other forked sibling, with no special case."""
    episode_dir = T.episode(tmp_path)
    sibling_base = S.make_runs_base(episode_dir, "runs")
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(sibling_base))
    tokens = {}
    for label in ("a", "b"):          # 'a' is the base role (`_family.py:59`)
        world = _resume_world(episode_dir, label)
        run = S.run_common().materialize_run_dir(alert, world.run_id, world=world)
        tokens[label] = _stamp(run)["world_id"]
    expected = {label: _resume_world(episode_dir, label).world_id for label in ("a", "b")}
    assert tokens == expected, (
        "the base-role sibling is still a forked sibling and gets the episode-qualified token, "
        "with no role-based special case — which is why no family member ever carries the "
        "tenant's base_world_id, and why decision 15(4) puts it in the family record instead")
    assert _record(sibling_base)["base_world_id"] not in tokens.values()


def test_the_family_record_carries_the_familys_base_world(tmp_path: Path):
    """The family record carries the family's base world, so a family whose every member is a
    forked sibling still has one carrier for the base world lessons attribution keys on."""
    base, _src = T.runs_base(tmp_path)
    tenant_record = S.tenant().ensure_tenant(base)
    ep = T.episode(tmp_path, episode_id=S.EPISODE_ID)
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=S.DEFAULT_TENANT_ID,
                      world_id=f"{S.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    report = S.branch_cli().verify_family(ep, dirs, source=T.provenance_record())
    assert report["outcome"] == "accepted", report["reason"]
    family = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    assert family["base_world_id"] == tenant_record.base_world_id, (
        "dispositions red flag 5: under D3 as written no member of a family ever stamps the "
        "tenant's base world, yet lessons attribution keys promotion on it — decision 15(4) "
        "closes the gap HERE rather than leaving #1079/#1085 to discover it")


def test_the_family_stamp_agrees_on_the_tenant_and_not_on_the_world(tmp_path: Path):
    """The family stamp's `agreed` record carries the family's `tenant_id` and no `world_id`,
    because siblings differ on the world by design."""
    base, _src = T.runs_base(tmp_path)
    S.tenant().ensure_tenant(base)
    ep = T.episode(tmp_path, episode_id=S.EPISODE_ID)
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=S.DEFAULT_TENANT_ID,
                      world_id=f"{S.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    report = S.branch_cli().verify_family(ep, dirs, source=T.provenance_record())
    assert report["outcome"] == "accepted", report["reason"]
    agreed = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))["agreed"]
    assert agreed["tenant_id"] == S.DEFAULT_TENANT_ID, (
        "the tenant is constant across a family and stays in `agreed`")
    assert "world_id" not in agreed, (
        "claims C9/F12: `_write_family_stamp` publishes ONE sibling's WHOLE stamp as `agreed`, "
        "so a new field reaches it unfiltered — the siblings differ on the world by design, so "
        "publishing one sibling's world as the family's is a false record")


def test_family_stamps_agreed_dict_is_all_slots_bound_minus_world_id(tmp_path: Path):
    """The family stamp's `agreed` dict `_write_family_stamp` writes carries `tenant_id` bound
    on every write and never carries `world_id`, and no two siblings' stamps are conflated into
    `agreed` beyond the one field D3 keeps."""
    base, _src = T.runs_base(tmp_path)
    S.tenant().ensure_tenant(base)
    ep = T.episode(tmp_path, episode_id=S.EPISODE_ID)
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id="acme",
                      world_id=f"{S.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    report = S.branch_cli().verify_family(ep, dirs, source=T.provenance_record())
    assert report["outcome"] == "accepted", report["reason"]
    stamp = json.loads((ep / "provenance.json").read_text(encoding="utf-8"))
    agreed = stamp["agreed"]
    assert agreed["tenant_id"] == "acme", "the slot is bound on every write"
    assert "world_id" not in agreed
    for field in ("commit", "scope", "model"):
        assert field in agreed, f"{field} is still published as before"
    assert {v for v in (json.loads(
        (d / "provenance.json").read_text(encoding="utf-8"))["world_id"] for d in dirs)} - {
        agreed.get("world_id")} , "no sibling's world reached `agreed`"


def test_a_family_spanning_two_tenants_is_a_member_fault(tmp_path: Path):
    """A family whose siblings stamp two different tenants is reported as a member fault."""
    base, _src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, episode_id=S.EPISODE_ID)
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]
    for i, d in enumerate(dirs):
        S.plant_stamp(d, **T.provenance_record(),
                      tenant_id="tenant-one" if i == 0 else "tenant-two",
                      world_id=f"{S.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    report = S.branch_cli().verify_family(ep, dirs, source=T.provenance_record())
    assert report["outcome"] == "incomplete", report["reason"]
    assert "tenant" in report["reason"], (
        f"a family spanning tenants is a fault, added to `_member_faults`: {report['reason']}")
    assert not (ep / "provenance.json").exists(), "a cross-tenant family was stamped as agreed"


def test_a_sibling_stamp_with_no_tenant_field_is_its_own_named_fault(tmp_path: Path):
    """A sibling whose stamp carries no tenant field at all is its own named fault, distinct from
    a cross-tenant disagreement."""
    base, _src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, episode_id=f"{S.EPISODE_ID}-absent")
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]
    for i, d in enumerate(dirs):
        fields = dict(T.provenance_record())
        if i:
            fields["tenant_id"] = S.DEFAULT_TENANT_ID
        S.plant_stamp(d, **fields, world_id=f"{S.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")

    report = S.branch_cli().verify_family(ep, dirs, source=T.provenance_record())
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
        tmp_path: Path):
    """The cross-tenant comparison runs over whichever siblings have already stamped, does not
    wait for the rest, and records how many it skipped."""
    base, _src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, episode_id=f"{S.EPISODE_ID}-partial")
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]
    for d in dirs[:2]:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=S.DEFAULT_TENANT_ID,
                      world_id=f"{S.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")
    (dirs[2] / "provenance.json").unlink()      # not yet stamped

    report = S.branch_cli().verify_family(ep, dirs, source=T.provenance_record())
    reason = report["reason"]
    counted = (
        f"the comparison must record how many siblings it skipped, so an unstamped sibling "
        f"cannot silently shrink it: {reason}")
    assert "1" in reason, counted
    assert any(w in reason.lower() for w in ("skip", "unstamped")), counted
    assert "wait" not in reason.lower(), "the comparison does not wait for the rest"


def test_verify_family_still_compares_only_commit_scope_and_model(tmp_path: Path):
    """`verify_family` still compares only `commit`, `scope` and `model`, and the two new stamp
    fields reach none of its fault comparisons.

    NEGATIVE. Positive control: demand d24 — the one comparison that DOES move is the new
    cross-tenant member fault, which is not part of this named-field loop.
    """
    import inspect
    src = inspect.getsource(S.branch_cli())
    assert 'for field in ("commit", "scope", "model")' in src, (
        "claim C9 anchors the named-field loop at cli.py:887; the two new stamp fields must "
        "reach none of it")
    assert 'for field in ("commit", "scope", "model", "tenant_id")' not in src
    assert '"world_id"' not in src.split("def _family_faults")[-1].split("\ndef ")[0], (
        "world_id reached the named-field comparison, where siblings differ by design and "
        "every family would be a fault")

    # Driven: siblings differing ONLY on world_id are still a comparable family.
    base, _src = T.runs_base(tmp_path)
    S.tenant().ensure_tenant(base)
    ep = T.episode(tmp_path, episode_id=f"{S.EPISODE_ID}-worlds-differ")
    dirs = [T.sibling_run_dir(base, w) for w in T.WORLDS]
    for d in dirs:
        S.plant_stamp(d, **T.provenance_record(), tenant_id=S.DEFAULT_TENANT_ID,
                      world_id=f"{S.EPISODE_ID}.{d.name.rsplit('-', 1)[-1]}")
    report = S.branch_cli().verify_family(ep, dirs, source=T.provenance_record())
    assert report["outcome"] == "accepted", (
        f"siblings differ on world_id BY DESIGN; if it reached the comparison every family "
        f"would be incomplete: {report['reason']}")
