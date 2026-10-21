"""Acceptance answers a link loop or linked tenant folder with its own refusal, never a traceback."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

import shutil
from pathlib import Path

import pytest

from defender import _paths
from defender.tenancy import _tenant
from defender.cli import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H


def test_a_knowledge_folder_linked_to_itself_is_refused_by_name(tmp_path: Path) -> None:
    """`<T>/knowledge -> knowledge` (a one-link loop): refused naming the knowledge path.
    Control: the same row beside a real knowledge folder is accepted."""
    root = tmp_path / "data"
    H.adopted(root)
    knowledge = H.knowledge_dir(root)
    shutil.rmtree(knowledge)
    knowledge.symlink_to("knowledge")
    text = H.accept_refusal(_tenant, root)
    assert str(knowledge) in text, text

    knowledge.unlink()
    H.place_knowledge(root)
    assert H.accept(_tenant, root).knowledge == knowledge


def test_a_data_root_linked_to_itself_is_refused_by_name(tmp_path: Path) -> None:
    """A data root that is a self-loop: refused naming the root, before anything under it."""
    root = tmp_path / "data"
    root.symlink_to("data")
    text = H.accept_refusal(_tenant, root)
    assert str(root) in text, text


def test_check_folder_over_a_looped_folder_refuses_without_a_traceback(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    loop.symlink_to("loop")
    H.assert_refused(H.check(tenant_py, None, "--folder", str(loop)), "[tenant.py]", str(loop))
    refused = H.refusal(_tenant, _tenant.check_knowledge_folder, loop, tenant_id=None)
    assert str(loop) in str(refused), refused


def test_runs_linked_onto_knowledge_puts_settings_in_a_mounted_tree(tmp_path: Path) -> None:
    """`<T>/runs -> knowledge`: the settings half now lies inside the runs base a box mounts,
    so step 7 refuses it, naming the settings. Control: a real `runs/` is accepted."""
    root = tmp_path / "data"
    H.adopted(root)
    runs = H.tenant_folder(root) / "runs"
    shutil.rmtree(runs, ignore_errors=True)
    runs.symlink_to("knowledge")
    text = H.accept_refusal(_tenant, root)
    assert str(H.settings_dir(root)) in text, text

    runs.unlink()
    runs.mkdir()
    assert location_path(H.accept(_tenant, root).runs) == runs


def test_a_linked_folder_above_a_required_setting_is_named_as_a_link(tmp_path: Path) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    systems = H.settings_dir(root) / "systems"
    copy = tmp_path / "systems-copy"
    shutil.move(str(systems), copy)
    systems.symlink_to(copy, target_is_directory=True)
    text = H.accept_refusal(_tenant, root)
    assert "reached through a link" in text, text
    assert str(systems / "case-history" / "mapping.yaml") in text, text


def test_a_tenant_folder_linked_into_the_checkout_is_refused_before_acceptance(
        tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    (root / H.TID).symlink_to(_paths.PATHS.defender_dir, target_is_directory=True)
    refused = H.refusal(_tenant, _tenant._TenantPaths, fixture_data_root(root), H.TID)
    assert "inside the checkout's defender/ tree" in str(refused), refused

    (root / H.TID).unlink()
    (root / H.TID).mkdir()
    assert location_path(_tenant._TenantPaths(fixture_data_root(root), H.TID).tenant_root) == root / H.TID


def test_a_nul_in_a_mounted_tree_path_is_a_refusal(tmp_path: Path) -> None:
    """A caller-handed path with a NUL cannot be resolved (`ValueError`, not `OSError`): it is
    the refusal naming the path, never an escaping `ValueError`."""
    root = tmp_path / "data"
    H.adopted(root)
    text = H.accept_refusal(_tenant, root, box_mounted=(Path("/tmp/a\0b"),))
    assert "could not be resolved" in text, text


@pytest.mark.parametrize("target", ["knowledge/agent", "knowledge/settings/systems",
                                    "knowledge/archive", "knowledge/.git"])
def test_runs_linked_into_a_knowledge_half_is_refused(tmp_path: Path, target: str) -> None:
    root = tmp_path / "data"
    H.adopted(root)
    runs = H.tenant_folder(root) / "runs"
    shutil.rmtree(runs, ignore_errors=True)
    (H.tenant_folder(root) / target).mkdir(parents=True, exist_ok=True)
    runs.symlink_to(target)
    text = H.accept_refusal(_tenant, root)
    assert str(runs) in text, text
    assert "knowledge folder" in text, text
