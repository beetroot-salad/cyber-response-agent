"""A placed knowledge folder is accepted as it stands: nothing is set up, no row is made (#1214 O6, F-12).

`tenant.py setup` (row, learning provisioning, `--learning-state-from` adoption) is retired; the surviving
folder rules are asserted through acceptance. The successor map is in slice-Re-report.md.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from defender.tenancy import _tenant
from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

#: A verb the change-mgmt adapter declares (`change_mgmt_adapter.VERBS`); dropping its row from
#: the fixture's table leaves a grant gap.
GAP_LINE = "    get-change:"
GAP_PAIR = "change-mgmt.get-change"


def _gap_table(settings: Path) -> None:
    """Drop one declared verb's row from a tenant's table (a real edit on disk)."""
    before = (Path(settings) / "verb-grants.yaml").read_text(encoding="utf-8")
    H.edit_table(settings, drop=(GAP_LINE,))
    after = (Path(settings) / "verb-grants.yaml").read_text(encoding="utf-8")
    assert after != before, "the gap edit changed nothing"
    assert GAP_LINE not in after, "the gap edit left the verb's row in place"


def _no_row(root: Path) -> None:
    assert not list(Path(root).glob("*/tenant.json")), f"a row appeared under {root}"


def _folder_only(root: Path) -> None:
    (root / H.TID).mkdir(parents=True)


def _stale_row_only(root: Path) -> None:
    H.plant_row(root, H.TID)


ABSENT_KNOWLEDGE = [
    pytest.param(lambda root: None, id="absent-data-root"),
    pytest.param(lambda root: root.mkdir(parents=True), id="empty-data-root"),
    pytest.param(_folder_only, id="empty-own-folder"),
    pytest.param(_stale_row_only, id="stale-row-only"),
]


@pytest.mark.parametrize("plant", ABSENT_KNOWLEDGE)
def test_1214_accepting_over_an_absent_knowledge_folder_names_it_and_writes_nothing(
        tmp_path: Path, plant) -> None:
    """No knowledge folder is a refusal naming it, whatever else is or is not there, and nothing is written (Flow 4)."""
    root = tmp_path / "data"
    plant(root)
    before = H.tree_census(root)
    text = H.accept_refusal(_tenant, root)
    assert str(H.knowledge_dir(root)) in text, text
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused acceptance wrote into the data root"
    H.place_knowledge(root)  # control: the same address with knowledge placed is accepted
    assert H.accept(_tenant, root).id == H.TID


def _knowledge_census(root: Path) -> dict:
    return H.tree_census(H.knowledge_dir(root))


def _plain_folder(tmp: Path, root: Path) -> Path:
    return H.place_knowledge(root)


def _local_clone(tmp: Path, root: Path) -> Path:
    knowledge = H.cloned_tenant(tmp, root)
    # The cell is a hard-linked clone: assert it, never assume it.
    assert H.hardlinked_git_objects(knowledge), (
        "precondition: the plain local clone left no hard-linked file under .git/objects — "
        "this cell would not be the local-clone-hardlinked-git member")
    return knowledge


PLACEMENTS = [
    pytest.param(_local_clone, id="local-clone-hardlinked-git"),
    pytest.param(_plain_folder, id="plain-folder"),
]


@pytest.mark.parametrize("place", PLACEMENTS)
def test_1214_a_placed_knowledge_folder_is_accepted_and_nothing_is_added(tmp_path: Path, place) -> None:
    """Over a data root holding only `<T>/knowledge`, acceptance adds no row, no learning/, and leaves the clone clean (Flow 4, O6)."""
    root = tmp_path / "data"
    knowledge = place(tmp_path, root)
    before = H.tree_census(root)
    assert H.accept(_tenant, root).id == H.TID
    assert H.census_diff(before, H.tree_census(root)) == [], "acceptance wrote into the data root"
    _no_row(root)
    if (knowledge / ".git").exists():
        assert H.git_status(knowledge) == "", "acceptance dirtied the clone"


def _two_tenants(root: Path, tmp: Path) -> None:
    H.place_knowledge(root, H.OTHER)


def _other_tenant_with_runs(root: Path, tmp: Path) -> None:
    H.place_knowledge(root, H.OTHER)
    (H.tenant_folder(root, H.OTHER) / "runs").mkdir()
    (H.tenant_folder(root) / "runs").mkdir()


def _lost_and_found(root: Path, tmp: Path) -> None:
    (root / "lost+found").mkdir()


def _nfs_silly_rename(root: Path, tmp: Path) -> None:
    (root / ".nfs000000000000abcd00000001").write_bytes(b"\0")


def _orphan_partial(root: Path, tmp: Path) -> None:
    (root / ".knowledge.partial" / "settings").mkdir(parents=True)


#: What used to be refused as "not a fresh data root" (#1214 O7): none of it is a refusal now.
BESIDE_CELLS = [
    pytest.param(_two_tenants, id="another-tenant-beside-it"),
    pytest.param(_other_tenant_with_runs, id="both-tenants-hold-runs"),
    pytest.param(_lost_and_found, id="lost+found"),
    pytest.param(_nfs_silly_rename, id="nfs-silly-rename"),
    pytest.param(_orphan_partial, id="orphan-knowledge-partial"),
]


@pytest.mark.parametrize("plant", BESIDE_CELLS)
def test_1214_the_one_tenant_guard_is_gone_a_tenant_is_accepted_beside_other_entries(
        tmp_path: Path, plant) -> None:
    """Another tenant's folder or filesystem debris in the data root refuses nothing; the owner no longer
    has a fresh-data-root rule (#1214 O7)."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    control = H.accept(_tenant, root)  # control: the placed tenant alone is accepted
    assert control.id == H.TID
    plant(root, tmp_path)
    before = H.tree_census(root)
    accepted = H.accept(_tenant, root)
    assert accepted.id == H.TID
    assert H.census_diff(before, H.tree_census(root)) == [], "acceptance wrote into the root"
    assert not hasattr(_tenant, "refuse_foreign_data_root"), "the one-tenant guard still exists"


def test_1214_two_tenants_are_each_accepted_under_one_data_root(tmp_path: Path) -> None:
    """Both of two tenants placed under one data root are accepted, each as itself (#1214 O7)."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    H.place_knowledge(root, H.OTHER)
    assert {H.accept(_tenant, root, tid).id for tid in (H.TID, H.OTHER)} == {H.TID, H.OTHER}



TENANT_ID_CELLS = [
    pytest.param(None, (), id="absent"),
    pytest.param(f"{H.OTHER}\n", (H.TID, H.OTHER), id="other-id"),
]


@pytest.mark.parametrize(("content", "also_named"), TENANT_ID_CELLS)
def test_1214_a_placed_knowledge_folder_whose_tenant_id_is_absent_or_names_another_tenant_is_refused(
        tmp_path: Path, content: str | None, also_named: tuple[str, ...]) -> None:
    """A clone of another tenant's repo (or no id file) is refused naming the id file; the right clone is accepted (Flow 4)."""
    root = tmp_path / "data"
    knowledge = H.cloned_tenant(tmp_path / "bad", root, tenant_id_file=content)
    before = H.tree_census(root)
    text = H.accept_refusal(_tenant, root)
    for name in (str(knowledge / H.TENANT_ID_FILE), *also_named):
        assert name in text, f"the refusal does not name {name!r}: {text!r}"
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused acceptance wrote something"
    assert H.git_status(knowledge) == "", "acceptance wrote into the clone"

    control = tmp_path / "control"
    H.cloned_tenant(tmp_path / "good", control)
    assert H.accept(_tenant, control).id == H.TID


def test_1214_accepting_a_finished_tenant_writes_nothing_and_leaves_grant_gaps_to_check(tmp_path: Path) -> None:
    """Acceptance is read-only and repeatable; a grant gap is `check`'s refusal, not acceptance's (Flow 4)."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    before = H.tree_census(root)
    assert H.accept(_tenant, root).id == H.TID
    assert H.census_diff(before, H.tree_census(root)) == [], "acceptance wrote something"

    _gap_table(H.settings_dir(root))
    gapped = H.tree_census(root)
    assert H.accept(_tenant, root).id == H.TID
    assert H.census_diff(gapped, H.tree_census(root)) == [], "the gapped acceptance wrote something"
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
def test_1214_a_tenant_accepted_before_is_refused_naming_the_knowledge_folder_that_no_longer_passes(
        tmp_path: Path, damage) -> None:
    """Every acceptance runs the folder rules afresh: damage after a first acceptance is refused, naming it (Flow 4)."""
    root = tmp_path / "data"
    H.place_knowledge(root)
    assert H.accept(_tenant, root).id == H.TID
    named = damage(root)
    before = H.tree_census(root)
    assert named in H.accept_refusal(_tenant, root)
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused acceptance wrote something"


def test_1214_a_placed_folder_that_fails_acceptance_is_refused_and_grant_gaps_are_left_to_check(
        tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    H.place_knowledge(missing)
    lead_zero = H.settings_dir(missing) / "lead-zero.yaml"
    lead_zero.unlink()
    before = H.tree_census(missing)
    assert str(lead_zero) in H.accept_refusal(_tenant, missing)
    assert H.census_diff(before, H.tree_census(missing)) == [], "the refused acceptance wrote something"

    torn = tmp_path / "torn"
    H.place_knowledge(torn)
    table = H.settings_dir(torn) / "verb-grants.yaml"
    table.write_text("dispositions:\n  cmdb: [unclosed\n", encoding="utf-8")
    before = H.tree_census(torn)
    assert str(table) in H.accept_refusal(_tenant, torn)
    assert H.census_diff(before, H.tree_census(torn)) == [], "the refused acceptance wrote something"

    gapped = tmp_path / "gapped"
    H.place_knowledge(gapped)
    _gap_table(H.settings_dir(gapped))
    assert H.accept(_tenant, gapped).id == H.TID
    H.assert_refused(H.check(tenant_py, gapped, H.TID), GAP_PAIR)


def _outside_file(tmp: Path) -> Path:
    target = tmp / "elsewhere" / "not-this-tenants.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("not this tenant's bytes\n", encoding="utf-8")
    return target


def _first_knowledge_symlink(root: Path, tmp: Path) -> Path:
    """The clone is elsewhere and symlinked in: the target is a complete, valid knowledge folder, so only
    the link itself can be the refusal."""
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
def test_1214_acceptance_of_a_never_accepted_folder_applies_every_folder_rule(tmp_path: Path, plant) -> None:
    """A freshly placed folder with one planted fault is refused naming it and nothing is written; a clean one is accepted (Flow 4)."""
    root = tmp_path / "data"
    named = plant(root, tmp_path)
    before = H.tree_census(root)
    text = H.accept_refusal(_tenant, root)
    # The case-history mapping's refusal names the file relative to settings/, never the host path.
    needle = "systems/case-history/mapping.yaml" if named.name == "mapping.yaml" else str(named)
    assert needle in text, f"the refusal does not name {needle!r}: {text!r}"
    assert H.census_diff(before, H.tree_census(root)) == [], "the refused acceptance wrote something"

    control = tmp_path / "control"
    H.place_knowledge(control)
    assert H.accept(_tenant, control).id == H.TID
