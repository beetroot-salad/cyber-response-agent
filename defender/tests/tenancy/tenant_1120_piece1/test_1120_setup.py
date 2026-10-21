"""D7 `tenant.py setup <id>`: ADOPT the operator-placed knowledge folder."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tenancy import _tenant
from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

#: The remedy every "no knowledge folder" refusal carries (DC2, N12 re-read): clone the tenant
REMEDY_WORDS = ("clone", "tenant.py setup")

# #1186 O5: setup has an explicitly named migration source, never a checkout/env fallback.
# The eight live state entries plus the retired forward-check bundles are preserved.
LEARNING_ENTRIES = (
    ".author-drain.lock", ".lead-author-drain.lock", "_author.lock", "_pending",
    "_pending_delivery", "_pending_leads", "_pending_pitfalls", "author-queue", "runs",
)
LEARNING_LOCKS = (
    ".author-drain.lock", ".lead-author-drain.lock", "_author.lock", "_pending/.lock",
    "_pending/.findings.lock", "_pending/.questioner_findings.lock",
    "_pending_leads/.lock", "_pending_pitfalls/.pitfalls.lock",
)


def _legacy_learning(source: Path) -> dict:
    source.mkdir(parents=True, exist_ok=True)
    for name in LEARNING_ENTRIES:
        target = source / name if name.endswith(".lock") else source / name / "record.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"preserve {name}\n", encoding="utf-8")
        target.chmod(0o640)
        os.utime(target, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
    (source / "run.py").write_text("# package source stays here\n", encoding="utf-8")
    (source / "unrelated").mkdir()
    (source / "unrelated" / "keep").write_text("not learning state", encoding="utf-8")
    return H.tree_census(source)


def _adopt_learning(root: Path, source: Path, **env: str) -> subprocess.CompletedProcess:
    return H.tenant_py(
        tenant_py, "setup", H.TID, "--learning-state-from", str(source), root=root, **env)


@pytest.mark.parametrize("migrate", [False, True], ids=["fresh", "explicit-migration"])
@pytest.mark.parametrize("target_shape", ["existing", "dangling"])
def test_1186_setup_refuses_a_linked_learning_destination(
        tmp_path: Path, migrate: bool, target_shape: str) -> None:
    """O5/O6: refuse existing/dangling root links, accept an empty real destination."""
    root, source, outside = tmp_path / "data", tmp_path / "legacy", tmp_path / "outside"
    H.adopted(root)
    source_before = _legacy_learning(source) if migrate else {}
    if target_shape == "existing":
        outside.mkdir()
    learning = H.tenant_folder(root) / "learning"
    learning.symlink_to(outside, target_is_directory=True)
    root_before = H.tree_census(root)

    def setup_selected():
        return _adopt_learning(root, source) if migrate else H.setup(tenant_py, root)

    H.assert_refused(setup_selected(), str(learning))
    assert H.tree_census(root) == root_before
    assert H.tree_census(source) == source_before
    assert os.path.lexists(outside) == (target_shape == "existing")
    assert H.tree_census(outside) == {}
    # A real destination succeeds through the same CLI; empty-target refusal is not no-merge.
    learning.unlink()
    learning.mkdir()
    H.assert_clean(setup_selected())
    assert learning.is_dir()
    assert not learning.is_symlink()
    if migrate:
        assert (learning / "author-queue" / "record.json").read_text() == "preserve author-queue\n"
    else:
        assert list(learning.iterdir()) == []


@pytest.mark.parametrize("legacy_location", ["env", "checkout"])
def test_1186_setup_without_source_ignores_legacy_locations(
        tmp_path: Path, legacy_location: str) -> None:
    """O5: fresh setup provisions this tenant, without discovering a migration source."""
    root, source = tmp_path / "data", tmp_path / "legacy"
    H.place_knowledge(root)
    checkout = H.tmp_checkout(tmp_path / "checkout")
    if legacy_location == "checkout":
        source = checkout / "defender" / "learning"
    before = _legacy_learning(source)
    env = {"DEFENDER_LEARNING_STATE_DIR": str(source)} if legacy_location == "env" else {}
    H.assert_clean(H.run_script(
        checkout / "defender" / "cli" / "tenant.py", "setup", H.TID,
        root=root, unset=(H.LEARNING_STATE_ENV,), **env))
    assert H.tree_census(source) == before
    assert list((H.tenant_folder(root) / "learning").iterdir()) == []


def test_1186_setup_moves_only_named_state_and_preserves_metadata(tmp_path: Path) -> None:
    """O5: migrate queues/locks/deliveries and legacy bundles, preserving package source."""
    root, source, decoy = tmp_path / "data", tmp_path / "legacy", tmp_path / "env-decoy"
    H.place_knowledge(root)
    _legacy_learning(source)
    decoy_before = _legacy_learning(decoy)
    outside = tmp_path / "outside"
    outside.write_text("must not be followed", encoding="utf-8")
    (source / "_pending" / "alias").symlink_to(outside)
    record = source / "_pending" / "record.json"
    nested = source / "_pending" / "nested"
    nested.mkdir()
    (nested / "data").write_text("nested state", encoding="utf-8")
    nested.chmod(0o750)
    os.utime(nested, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
    if os.geteuid() == 0:
        os.chown(record, 1234, 2345)
        os.chown(nested, 1234, 2345)
    owner = (record.stat().st_uid, record.stat().st_gid)
    nested_stat = nested.stat()
    before = H.tree_census(source)

    done = _adopt_learning(root, source, DEFENDER_LEARNING_STATE_DIR=str(decoy))

    text = H.assert_clean(done)
    assert str(source) in text, "the operator must see which source was adopted"
    destination = H.tenant_folder(root) / "learning"
    after = H.tree_census(destination)
    moved = {k: v for k, v in before.items() if k.split("/")[0] in LEARNING_ENTRIES}
    assert {k: after.get(k) for k in moved} == moved
    copied = (destination / "_pending" / "record.json").stat()
    assert (copied.st_uid, copied.st_gid) == owner
    copied_dir = (destination / "_pending" / "nested").stat()
    assert (copied_dir.st_mtime_ns, copied_dir.st_mode, copied_dir.st_uid, copied_dir.st_gid) == (
        nested_stat.st_mtime_ns, nested_stat.st_mode, nested_stat.st_uid, nested_stat.st_gid)
    assert all(not (source / entry).exists() for entry in LEARNING_ENTRIES)
    assert H.tree_census(source) == {k: v for k, v in before.items() if k not in moved}
    assert H.tree_census(decoy) == decoy_before
    assert outside.read_text(encoding="utf-8") == "must not be followed"
    assert not (destination / ".adoption").exists()
    assert not (destination.parent / "learning.adopting").exists()
    assert not (source / f".adopting-to-{H.TID}").exists()
    _row_is_acme(root)
    snapshot = H.tree_census(root)
    H.assert_clean(_adopt_learning(root, source))
    assert H.tree_census(root) == snapshot, "completed adoption is idempotent"


@pytest.mark.parametrize("fault", [
    "missing-source", "file-source", "unknown-partial", "foreign-token", "unowned-aside-child",
    "unowned-stage-child",
])
def test_1186_setup_refuses_ambiguous_adoption_without_data_loss(tmp_path: Path, fault: str) -> None:
    """O5: an explicit bad source or unexplained migration state cannot be guessed away."""
    root, source = tmp_path / "data", tmp_path / "legacy"
    H.adopted(root)
    destination = H.tenant_folder(root) / "learning"
    if fault == "file-source":
        source.write_text("not a directory", encoding="utf-8")
    elif fault in {"unknown-partial", "foreign-token", "unowned-aside-child", "unowned-stage-child"}:
        _legacy_learning(source)
        if fault == "unknown-partial":
            partial = destination.with_name("learning.adopting")
            partial.mkdir()
            (partial / "unowned").write_text("do not discard", encoding="utf-8")
        else:
            aside = source / f".adopting-to-{H.TID}"
            if fault == "unowned-stage-child":
                aside = aside.with_name(f"{aside.name}.stage")
            aside.mkdir()
            if fault in {"unowned-aside-child", "unowned-stage-child"}:
                (aside / ".adoption").write_text(
                    "63ac3146-4d58-4bb8-9f94-124902ceef1a\n", encoding="utf-8")
                (aside / "unrelated").mkdir()
                (aside / "unrelated" / "keep").write_text("do not adopt or delete", encoding="utf-8")
            else:
                (aside / ".adoption").write_text("source-token\n", encoding="utf-8")
                destination.mkdir()
                (destination / ".adoption").write_text("different-token\n", encoding="utf-8")
                (destination / "existing").write_text("do not merge", encoding="utf-8")
    before = H.tree_census(tmp_path)
    H.assert_refused(_adopt_learning(root, source))
    assert H.tree_census(tmp_path) == before


@pytest.mark.parametrize("lock_name", LEARNING_LOCKS)
def test_1186_setup_refuses_held_source_lock_before_moving(tmp_path: Path, lock_name: str) -> None:
    """O5: neither a queue appender nor an author/drain may be migrated mid-operation."""
    import fcntl

    root, source = tmp_path / "data", tmp_path / "legacy"
    H.adopted(root)
    _legacy_learning(source)
    lock = source / lock_name
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("a+", encoding="utf-8") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        source_before, root_before = H.tree_census(source), H.tree_census(root)
        H.assert_refused(_adopt_learning(root, source), str(lock))
        assert H.tree_census(source) == source_before
        assert H.tree_census(root) == root_before
    H.assert_clean(_adopt_learning(root, source))  # Same observation channel, lock released.
    assert (H.tenant_folder(root) / "learning" / "author-queue" / "record.json").is_file()


@pytest.mark.parametrize("location", ["data-root", "ancestor", "tenant-child", "checkout"])
def test_1186_setup_refuses_overlapping_migration_source(tmp_path: Path, location: str) -> None:
    """O5: adoption cannot recursively move a tenant, its data root, or the running checkout."""
    root = tmp_path / "data"
    H.adopted(root)
    child = H.tenant_folder(root) / "runs"
    child.mkdir()
    checkout = H.tmp_checkout(tmp_path / "checkout") if location == "checkout" else None
    source = {"data-root": root, "ancestor": tmp_path, "tenant-child": child,
              "checkout": checkout}[location]
    before = H.tree_census(root)
    if checkout is None:
        done = _adopt_learning(root, source)
    else:
        done = H.run_script(
            checkout / "defender" / "cli" / "tenant.py", "setup", H.TID,
            "--learning-state-from", str(source), root=root)
    H.assert_refused(done, str(source))
    assert H.tree_census(root) == before


def test_1186_setup_never_merges_state_and_accepts_already_in_place(tmp_path: Path) -> None:
    """O5: occupied destination refuses without loss; selecting the destination is a no-op."""
    root, source = tmp_path / "data", tmp_path / "legacy"
    H.adopted(root)
    _legacy_learning(source)
    destination = H.tenant_folder(root) / "learning"
    destination.mkdir()
    (destination / "existing").write_text("already here", encoding="utf-8")
    source_before, root_before = H.tree_census(source), H.tree_census(root)
    H.assert_refused(_adopt_learning(root, source), str(destination))
    assert H.tree_census(source) == source_before
    assert H.tree_census(root) == root_before
    H.assert_clean(_adopt_learning(root, destination))
    assert H.tree_census(root) == root_before


@pytest.mark.parametrize("phase", [
    "staging-empty", "staging-partial", "staging-complete",
    "moving", "copying", "published", "deleting", "racing-write",
])
def test_1186_setup_completes_interrupted_adoption(tmp_path: Path, phase: str) -> None:
    """O5/D10: recover token staging, split moves and cleanup; preserve/report recreated writes."""
    root, source = tmp_path / "data", tmp_path / "legacy"
    H.adopted(root)
    before = _legacy_learning(source)
    aside = source / f".adopting-to-{H.TID}"
    stage = aside.with_name(f"{aside.name}.stage")
    token = "63ac3146-4d58-4bb8-9f94-124902ceef1a\n"
    staging_tokens = {"staging-empty": "", "staging-partial": "63ac3146-4d58-",
                      "staging-complete": token}
    if phase in staging_tokens:
        stage.mkdir()
        (stage / ".adoption").write_text(staging_tokens[phase], encoding="utf-8")
    else:
        aside.mkdir()
        (aside / ".adoption").write_text(token, encoding="utf-8")
        for name in LEARNING_ENTRIES[:2] if phase == "moving" else LEARNING_ENTRIES:
            (source / name).rename(aside / name)
    destination = H.tenant_folder(root) / "learning"
    if phase in {"published", "deleting", "racing-write"}:
        shutil.copytree(aside, destination, symlinks=True)
        if phase == "deleting":
            shutil.rmtree(aside / "_pending")
    elif phase == "copying":
        partial = destination.with_name("learning.adopting")
        partial.mkdir()
        (partial / "partial").write_text("incomplete copy", encoding="utf-8")
    residual = source / "author-queue" / "new-request.json"
    if phase == "racing-write":
        residual.parent.mkdir()
        residual.write_text("racing writer's new data\n", encoding="utf-8")

    done = _adopt_learning(root, source)
    if phase == "racing-write":
        text = H.assert_refused(done, str(residual.parent))
        assert "author-queue" in text
        assert residual.read_text(encoding="utf-8") == "racing writer's new data\n"
    else:
        H.assert_clean(done)

    moved = {k: v for k, v in before.items() if k.split("/")[0] in LEARNING_ENTRIES}
    after = H.tree_census(destination)
    assert {k: after.get(k) for k in moved} == moved
    remaining = H.tree_census(source)
    if phase == "racing-write":
        remaining = {k: v for k, v in remaining.items() if k.split("/")[0] != "author-queue"}
    assert remaining == {k: v for k, v in before.items() if k not in moved}
    assert not aside.exists()
    assert not stage.exists()
    assert not destination.with_name("learning.adopting").exists()
    assert not (destination / ".adoption").exists()


def _rowless_empty_own_folder(root: Path) -> None:
    (root / H.TID).mkdir(parents=True)


def _row_only_tenant(root: Path) -> None:
    H.plant_row(root, H.TID)


ABSENT_KNOWLEDGE = [
    pytest.param(lambda root: None, id="absent-data-root"),
    pytest.param(lambda root: root.mkdir(parents=True), id="empty-data-root"),
    pytest.param(_rowless_empty_own_folder, id="empty-rowless-own-folder"),
    pytest.param(_row_only_tenant, id="row-only-tenant"),
]


@pytest.mark.parametrize("plant", ABSENT_KNOWLEDGE)
def test_1120_setup_over_an_absent_knowledge_folder_exits_one_naming_it_and_the_remedy_and_writes_nothing(
        tmp_path: Path, plant) -> None:
    root = tmp_path / "data"
    plant(root)
    before = H.tree_census(root)
    proc = H.setup(tenant_py, root)
    text = H.assert_refused(proc, str(H.knowledge_dir(root)))
    for word in REMEDY_WORDS:
        assert word in text, f"the refusal does not carry the remedy word {word!r}:\n{text}"
    assert H.census_diff(before, H.tree_census(root)) == [], (
        "the refused setup wrote into the data root")


#: A verb the change-mgmt adapter declares (`change_mgmt_adapter.VERBS`) and the fixture's
GAP_LINE = "    get-change:"
GAP_PAIR = "change-mgmt.get-change"


def _row_is_acme(root: Path) -> None:
    """Exactly one row under `root`, and it is valid JSON naming acme."""
    rows = sorted(Path(root).glob("*/tenant.json"))
    assert rows == [location_path(H.row_path)(root)], f"the data root holds rows {rows}, not exactly acme's"
    doc = json.loads(location_path(H.row_path)(root).read_text(encoding="utf-8"))
    assert doc.get("tenant_id") == H.TID, f"the row names {doc.get('tenant_id')!r}, not acme"


def _gap_table(settings: Path) -> None:
    """Drop one declared verb's row from a tenant's table (a real edit on disk)."""
    before = (Path(settings) / "verb-grants.yaml").read_text(encoding="utf-8")
    H.edit_table(settings, drop=(GAP_LINE,))
    after = (Path(settings) / "verb-grants.yaml").read_text(encoding="utf-8")
    assert after != before, "the gap edit changed nothing"
    assert GAP_LINE not in after, "the gap edit left the verb's row in place"


def _knowledge_census(root: Path) -> dict:
    return H.tree_census(H.knowledge_dir(root))


def _plain_folder(tmp: Path, root: Path) -> Path:
    return H.place_knowledge(root)


def _local_clone(tmp: Path, root: Path) -> Path:
    knowledge = H.cloned_tenant(tmp, root)
    # The cell IS a hard-linked clone (C3/C4, P-DC2-1 leg D) — assert it, never assume it.
    assert H.hardlinked_git_objects(knowledge), (
        "precondition: the plain local clone left no hard-linked file under .git/objects — "
        "this cell would not be the local-clone-hardlinked-git member")
    return knowledge


PLACEMENTS = [
    pytest.param(_local_clone, id="local-clone-hardlinked-git"),
    pytest.param(_plain_folder, id="plain-folder"),
]


@pytest.mark.parametrize("place", PLACEMENTS)
def test_1120_setup_adopts_knowledge_and_provisions_tenant_learning(
        tmp_path: Path, place) -> None:
    """Over a data root whose only entry is acme/knowledge, placed by the operator, `tenant.py setup
    acme` exits 0 and prints nothing."""
    # rejected: detecting an in-progress or interrupted clone (NF3) — setup judges the tree
    # as found; the docs say run setup after the clone exits 0.
    root = tmp_path / "data"
    knowledge = place(tmp_path, root)
    before = H.tree_census(root)
    proc = H.setup(tenant_py, root)
    text = H.assert_clean(proc)
    assert text == "", f"a successful adopt printed something:\n{text}"
    assert H.census_diff(before, H.tree_census(root)) == [
        f"added: {H.TID}/learning", f"added: {H.TID}/{H.ROW_NAME}",
    ], "#1186 O5: fresh setup provisions learning beside the tenant's knowledge"
    assert list((H.tenant_folder(root) / "learning").iterdir()) == []
    _row_is_acme(root)
    if (knowledge / ".git").exists():
        assert H.git_status(knowledge) == "", "setup dirtied the operator's clone"
    tenant = H.accept(_tenant, root)
    assert tenant.id == H.TID


def _knowledge_dir_entry(root: Path, tmp: Path) -> None:
    H.knowledge_dir(root).mkdir(parents=True)


def _knowledge_symlink(root: Path, tmp: Path) -> None:
    elsewhere = tmp / "elsewhere-knowledge"
    elsewhere.mkdir()
    H.tenant_folder(root).mkdir(parents=True)
    H.knowledge_dir(root).symlink_to(elsewhere, target_is_directory=True)


def _knowledge_file(root: Path, tmp: Path) -> None:
    H.tenant_folder(root).mkdir(parents=True)
    H.knowledge_dir(root).write_text("not a folder\n", encoding="utf-8")


def _row_alias_beside_knowledge(root: Path, tmp: Path) -> None:
    # J60: an alias planted at the row's own name is the guarded write's to refuse, never the
    # guard's — the row's name stays exempt from the inner scan.
    H.knowledge_dir(root).mkdir(parents=True)
    location_path(H.row_path)(root).symlink_to(tmp / "nowhere.json")


def _runs_beside_knowledge(root: Path, tmp: Path) -> None:
    H.knowledge_dir(root).mkdir(parents=True)
    (H.tenant_folder(root) / "runs").mkdir()


def _other_knowledge(root: Path, tmp: Path) -> None:
    H.knowledge_dir(root).mkdir(parents=True)
    H.knowledge_dir(root, H.OTHER).mkdir(parents=True)


GUARD_CELLS = [
    pytest.param(_knowledge_dir_entry, None, id="knowledge-directory"),
    pytest.param(_knowledge_symlink, None, id="knowledge-symlink"),
    pytest.param(_knowledge_file, None, id="knowledge-file"),
    pytest.param(_row_alias_beside_knowledge, None, id="row-name-exempt"),
    pytest.param(_runs_beside_knowledge, f"{H.TID}/runs", id="runs-beside-knowledge"),
    pytest.param(_other_knowledge, H.OTHER, id="other-knowledge"),
]


@pytest.mark.parametrize(("plant", "foreign"), GUARD_CELLS)
def test_1120_the_one_tenant_guard_admits_only_knowledge_beside_a_missing_row(
        tmp_path: Path, plant, foreign: str | None) -> None:
    root = tmp_path / "data"
    plant(root, tmp_path)
    before = H.tree_census(root)
    refused: BaseException | None = None
    try:
        _tenant.refuse_foreign_data_root(fixture_data_root(root), _tenant.TenantId(H.TID))
    except _tenant.TenantRefused as exc:
        refused = exc
    assert H.census_diff(before, H.tree_census(root)) == [], "the guard wrote into the root"
    if foreign is None:
        assert refused is None, (
            f"the one-tenant guard refused the operator-placed knowledge in a rowless own "
            f"folder (MF1 (a) admits exactly that name): {refused}")
    else:
        assert refused is not None, f"the guard admitted {foreign!r} beside the placed knowledge"
        text = str(refused)
        assert foreign in text, f"the guard's refusal does not name {foreign!r}: {text}"
        assert f"{H.TID}/knowledge" not in text, (
            f"the guard named the placed knowledge as foreign: {text}")


TENANT_ID_CELLS = [
    pytest.param(None, (), id="absent"),
    pytest.param(f"{H.OTHER}\n", (H.TID, H.OTHER), id="other-id"),
]


@pytest.mark.parametrize(("content", "also_named"), TENANT_ID_CELLS)
def test_1120_setup_refuses_a_placed_knowledge_folder_whose_tenant_id_is_absent_or_names_another_tenant(
        tmp_path: Path, content: str | None, also_named: tuple[str, ...]) -> None:
    root = tmp_path / "data"
    knowledge = H.cloned_tenant(tmp_path / "bad", root, tenant_id_file=content)
    before = H.tree_census(root)
    proc = H.setup(tenant_py, root)
    H.assert_refused(proc, str(knowledge / H.TENANT_ID_FILE), *also_named)
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused setup wrote something"
    assert not location_path(H.row_path)(root).exists(), "a refused setup left a row (rules-first, MF1 Q2)"
    assert H.git_status(knowledge) == "", "setup wrote into the operator's clone"

    control = tmp_path / "control"
    H.cloned_tenant(tmp_path / "good", control)
    H.assert_clean(H.setup(tenant_py, control))
    _row_is_acme(control)


def test_1120_setup_over_a_finished_tenant_succeeds_and_writes_nothing(tmp_path: Path) -> None:
    # rejected: re-cloning, re-copying or overwriting an existing knowledge/ (and, per N6,
    # pulling).
    root = tmp_path / "data"
    H.adopted(root)
    # O5: a finished tenant already has the learning root that fresh setup provisions.
    (H.tenant_folder(root) / "learning").mkdir()
    before = H.tree_census(root)
    text = H.assert_clean(H.setup(tenant_py, root))
    assert text == "", f"a clean re-run printed something:\n{text}"
    assert H.census_diff(before, H.tree_census(root)) == [], "a clean re-run wrote something"

    _gap_table(H.settings_dir(root))
    gapped = H.tree_census(root)
    text = H.assert_clean(H.setup(tenant_py, root))
    assert text == "", f"a re-run over a gapped table printed something (DC1):\n{text}"
    assert H.census_diff(gapped, H.tree_census(root)) == [], "the gapped re-run wrote something"
    H.assert_refused(H.check(tenant_py, root, H.TID), GAP_PAIR)


def _emptied(root: Path) -> str:
    knowledge = H.knowledge_dir(root)
    shutil.rmtree(knowledge)
    knowledge.mkdir()
    return str(knowledge)


def _dangling(root: Path) -> str:
    knowledge = H.knowledge_dir(root)
    shutil.rmtree(knowledge)
    knowledge.symlink_to(root.parent / "gone-knowledge", target_is_directory=True)
    return str(knowledge)


def _a_file(root: Path) -> str:
    knowledge = H.knowledge_dir(root)
    shutil.rmtree(knowledge)
    knowledge.write_text("knowledge used to be here\n", encoding="utf-8")
    return str(knowledge)


def _lost_settings(root: Path) -> str:
    settings = H.settings_dir(root)
    shutil.rmtree(settings)
    return str(settings)


REVERIFY_CELLS = [
    pytest.param(_emptied, id="empty"),
    pytest.param(_dangling, id="dangling-symlink"),
    pytest.param(_a_file, id="file"),
    pytest.param(_lost_settings, id="settings-absent"),
]


@pytest.mark.parametrize("damage", REVERIFY_CELLS)
def test_1120_setup_rerun_runs_the_folder_rules_and_names_a_knowledge_folder_that_no_longer_passes(
        tmp_path: Path, damage) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    H.assert_clean(H.setup(tenant_py, root))
    named = damage(root)
    before = H.tree_census(root)
    H.assert_refused(H.setup(tenant_py, root), named)
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused re-run wrote something"


def test_1120_setup_refuses_a_placed_folder_that_fails_acceptance_and_leaves_grant_gaps_to_check(
        tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    H.place_knowledge(missing)
    lead_zero = H.settings_dir(missing) / "lead-zero.yaml"
    lead_zero.unlink()
    before = H.tree_census(missing)
    H.assert_refused(H.setup(tenant_py, missing), str(lead_zero))
    assert H.census_diff(before, H.tree_census(missing)) == [], "the refused setup wrote something"

    torn = tmp_path / "torn"
    H.place_knowledge(torn)
    table = H.settings_dir(torn) / "verb-grants.yaml"
    table.write_text("dispositions:\n  cmdb: [unclosed\n", encoding="utf-8")
    before = H.tree_census(torn)
    H.assert_refused(H.setup(tenant_py, torn), str(table))
    assert H.census_diff(before, H.tree_census(torn)) == [], "the refused setup wrote something"

    gapped = tmp_path / "gapped"
    H.place_knowledge(gapped)
    _gap_table(H.settings_dir(gapped))
    H.assert_clean(H.setup(tenant_py, gapped))
    _row_is_acme(gapped)
    H.assert_refused(H.check(tenant_py, gapped, H.TID), GAP_PAIR)


def _outside_file(tmp: Path) -> Path:
    target = tmp / "elsewhere" / "not-this-tenants.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("not this tenant's bytes\n", encoding="utf-8")
    return target


def _first_knowledge_symlink(root: Path, tmp: Path) -> Path:
    """The operator cloned elsewhere and symlinked the clone in (47 P3): the target is a
    complete, valid knowledge folder, so only the link itself can be the refusal."""
    real = H.place_knowledge(tmp / "clone-elsewhere")
    link = H.knowledge_dir(root)
    link.parent.mkdir(parents=True)
    link.symlink_to(real, target_is_directory=True)
    return link


def _first_knowledge_file(root: Path, tmp: Path) -> Path:
    path = H.knowledge_dir(root)
    path.parent.mkdir(parents=True)
    path.write_text("knowledge is not a folder\n", encoding="utf-8")
    return path


def _first_symlink_in_settings(root: Path, tmp: Path) -> Path:
    H.place_knowledge(root)
    link = H.settings_dir(root) / "planted-link.yaml"
    link.symlink_to(_outside_file(tmp))
    return link


def _first_hardlink_in_agent(root: Path, tmp: Path) -> Path:
    H.place_knowledge(root)
    inside = H.agent_dir(root) / "planted-hardlink.md"
    inside.write_text("shared bytes\n", encoding="utf-8")
    second = tmp / "elsewhere" / "second-name.md"
    second.parent.mkdir(parents=True, exist_ok=True)
    os.link(inside, second)
    return inside


def _first_fifo_in_settings(root: Path, tmp: Path) -> Path:
    H.place_knowledge(root)
    fifo = H.settings_dir(root) / "planted.fifo"
    os.mkfifo(fifo)
    return fifo


def _first_unparseable_lead_zero(root: Path, tmp: Path) -> Path:
    H.place_knowledge(root)
    path = H.settings_dir(root) / "lead-zero.yaml"
    path.write_text("correlation_template: [unclosed\n", encoding="utf-8")
    return path


def _first_unparseable_mapping(root: Path, tmp: Path) -> Path:
    H.place_knowledge(root)
    path = H.settings_dir(root) / "systems" / "case-history" / "mapping.yaml"
    path.write_text("fields: {unclosed: [\n", encoding="utf-8")
    return path


FIRST_RUN_FAULTS = [
    pytest.param(_first_knowledge_symlink, id="knowledge_dir:symlink"),
    pytest.param(_first_knowledge_file, id="knowledge_dir:file"),
    pytest.param(_first_symlink_in_settings, id="settings_half:symlink-inside"),
    pytest.param(_first_hardlink_in_agent, id="agent_half:hardlink-inside"),
    pytest.param(_first_fifo_in_settings, id="settings_half:non-regular-entry:fifo"),
    pytest.param(_first_unparseable_lead_zero, id="tables-load:lead-zero.yaml"),
    pytest.param(_first_unparseable_mapping, id="tables-load:mapping.yaml"),
]


@pytest.mark.parametrize("plant", FIRST_RUN_FAULTS)
def test_1120_a_first_setup_applies_every_folder_rule_before_it_writes_the_row(
        tmp_path: Path, plant) -> None:
    root = tmp_path / "data"
    named = plant(root, tmp_path)
    assert not location_path(H.row_path)(root).exists(), "precondition: this is a first, row-less setup"
    before = H.tree_census(root)
    try:
        proc = H.setup(tenant_py, root)
    except subprocess.TimeoutExpired:
        pytest.fail(f"setup blocked on {named} instead of refusing it (a FIFO opened for reading)")
    # The case-history mapping is refused by the one tenant check (#1222 A5): a fixed reason
    # naming the file relative to settings/, never the host path.
    needle = "systems/case-history/mapping.yaml" if named.name == "mapping.yaml" else str(named)
    text = H.assert_refused(proc, needle)
    assert "the data root is not empty" not in text, (
        f"the refusal is the one-tenant guard's; it must admit the placed knowledge (MF1) and "
        f"the folder rule must refuse {named}:\n{text}")
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused first setup wrote"
    assert not location_path(H.row_path)(root).exists(), "a refused first setup left a row (MF1 Q2)"

    control = tmp_path / "control"
    H.place_knowledge(control)
    H.assert_clean(H.setup(tenant_py, control))
    _row_is_acme(control)


def test_1120_two_concurrent_first_setups_leave_one_row_and_one_refusal_naming_it(
        tmp_path: Path) -> None:
    """Two concurrent first `setup acme` runs over one operator-placed knowledge/ leave exactly one
    tenant.json, valid and naming acme, and knowledge/ byte-identical."""
    # rejected: a foreign tenant created mid-setup (N1).
    root = tmp_path / "data"
    H.place_knowledge(root)
    knowledge_before = _knowledge_census(root)
    argv = [sys.executable, str(H.script_of(tenant_py)), "setup", H.TID]
    env = H.tenant_env(root)
    procs = [subprocess.Popen(argv, env=env, cwd=str(H.REPO_ROOT), stdout=subprocess.PIPE,  # noqa: S603
                              stderr=subprocess.STDOUT, text=True) for _ in range(2)]
    results = [(p.wait(timeout=180), p.stdout.read() if p.stdout else "") for p in procs]
    for p in procs:
        if p.stdout:
            p.stdout.close()
    for rc, text in results:
        assert "Traceback (most recent call last)" not in text, f"a setup crashed:\n{text}"
        assert rc in (0, 1), f"a racing setup exited {rc}:\n{text}"
        if rc == 1:
            assert str(location_path(H.row_path)(root)) in text, (
                f"the racing loser's refusal does not name the row:\n{text}")
            assert "already exists" in text, f"the loser's refusal is not the create race:\n{text}"
    assert any(rc == 0 for rc, _ in results), f"neither racing setup succeeded: {results}"
    _row_is_acme(root)
    assert H.census_diff(knowledge_before, _knowledge_census(root)) == []


def test_1120_a_data_root_inside_the_checkouts_defender_tree_is_still_refused(
        tmp_path: Path) -> None:
    checkout = H.tmp_checkout(tmp_path / "checkout")
    script = checkout / H.script_of(tenant_py).relative_to(H.REPO_ROOT)
    root = checkout / "defender" / "tenant-data"
    H.place_knowledge(root)
    before = H.tree_census(root)
    text = H.assert_refused(H.run_script(script, "setup", H.TID, root=root),
                            "[tenant.py]", str(checkout / "defender"))
    assert "not empty" not in text, (
        f"the refusal is the one-tenant guard's, not O11a's — the guard must admit the placed "
        f"knowledge (MF1 (a)):\n{text}")
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused setup wrote something"

    allowed = checkout / ".defender-data"
    H.place_knowledge(allowed)
    H.assert_clean(H.run_script(script, "setup", H.TID, root=allowed))
    _row_is_acme(allowed)


@pytest.mark.skipif(os.geteuid() == 0, reason="uid 0 bypasses mode bits; CI runs non-root")
def test_1120_s2_data_root_parent_not_writable(tmp_path: Path) -> None:
    """The clone has already created <root>/acme/, so setup's first write is the row into it."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    before = _knowledge_census(root)
    folder = H.tenant_folder(root)
    folder.chmod(0o555)
    try:
        text = H.assert_refused(H.setup(tenant_py, root), str(location_path(H.row_path)(root)))
        assert "ermission" in text, f"the refusal does not name the permission error:\n{text}"
    finally:
        folder.chmod(0o755)
    assert not location_path(H.row_path)(root).exists()
    assert H.census_diff(before, _knowledge_census(root)) == []


def _lost_and_found(root: Path) -> str:
    (root / "lost+found").mkdir()
    return "lost+found"


def _nfs_silly_rename(root: Path) -> str:
    (root / ".nfs000000000000abcd00000001").write_bytes(b"\0")
    return ".nfs000000000000abcd00000001"


def _orphan_partial(root: Path) -> str:
    (root / ".knowledge.partial" / "settings").mkdir(parents=True)
    return ".knowledge.partial"


DEBRIS = [
    pytest.param(_lost_and_found, id="lost+found"),
    pytest.param(_nfs_silly_rename, id="nfs-silly-rename"),
    pytest.param(_orphan_partial, id="orphan-knowledge-partial"),
]


@pytest.mark.parametrize("plant", DEBRIS)
def test_1120_s12_refuse_foreign_data_root_meets_filesystem_debris(tmp_path: Path, plant) -> None:
    root = tmp_path / "data"
    H.place_knowledge(root)
    entry = plant(root)
    before = H.tree_census(root)
    H.assert_refused(H.setup(tenant_py, root), entry)
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused setup wrote something"

    target = root / entry
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
    H.assert_clean(H.setup(tenant_py, root))
    _row_is_acme(root)
