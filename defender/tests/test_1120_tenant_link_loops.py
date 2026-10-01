"""#1120 piece 1 — acceptance answers a link loop, or a linked tenant folder, with its own
refusal, never a traceback (code review on PR #1157).

Python 3.11's `Path.resolve()` raises `RuntimeError` on a link loop, not `OSError`, so a check
that resolved a path below the data root and caught only `OSError` crashed on one. Acceptance
now walks below the root no-follow and resolves only what it is handed, through one translator.

  * A `knowledge` that is a link to itself, and a data root that is one, are `TenantRefused`
    naming the path.
  * `tenant.py check --folder` over a looped folder exits 1 with `[tenant.py] …`, and the
    census lint's call (`check_knowledge_folder`) refuses it rather than raising.
  * A link on the way to a required settings file is named as a link.
  * A NUL in a caller-handed path is a refusal, not a `ValueError`.
  * Before acceptance, a tenant folder that is a link into the running checkout's `defender/`
    is refused by the layout's O11a guard, which judges `<T>` by where it leads.
  * Step 7 refuses a mounted tree inside either knowledge half (a `runs/` linked into `agent/`).
  * Step 7 counts the tenant's own `runs/`: a `<T>/runs` linked onto `knowledge/` would put the
    host-only settings half inside the runs base, which a box mounts.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from defender import _paths, _tenant
from defender.scripts import tenant as tenant_py
from defender.tests.tenant_1120_piece1 import _spec1120 as H


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
    """`tenant.py check --folder <loop>` exits 1 naming the folder; the census lint's call,
    `check_knowledge_folder(<loop>)`, raises the refusal the lint reports (exit 2), never a
    `RuntimeError`."""
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
    assert H.accept(_tenant, root).runs == runs


def test_a_linked_folder_above_a_required_setting_is_named_as_a_link(tmp_path: Path) -> None:
    """`settings/systems` swapped for a link to a real copy: step 4 cannot reach
    `systems/case-history/mapping.yaml` without following it, and says the file is reached
    through a link rather than that it could not be read."""
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
    """`<root>/<T> -> <the checkout's defender/>`: the pre-acceptance layout (what
    `create_tenant`, `require_tenant` and `tenant_of_run_dir` build) refuses it as inside the
    checkout. Control: the same id under a real folder is built."""
    root = tmp_path / "data"
    root.mkdir()
    (root / H.TID).symlink_to(_paths.PATHS.defender_dir, target_is_directory=True)
    refused = H.refusal(_tenant, _tenant._TenantPaths, root, H.TID)
    assert "inside the checkout's defender/ tree" in str(refused), refused

    (root / H.TID).unlink()
    (root / H.TID).mkdir()
    assert _tenant._TenantPaths(root, H.TID).dir == root / H.TID


def test_a_nul_in_a_mounted_tree_path_is_a_refusal(tmp_path: Path) -> None:
    """A caller-handed path with a NUL cannot be resolved (`ValueError`, not `OSError`): it is
    the refusal naming the path, never an escaping `ValueError`."""
    root = tmp_path / "data"
    H.adopted(root)
    text = H.accept_refusal(_tenant, root, box_mounted=(Path("/tmp/a\0b"),))
    assert "could not be resolved" in text, text


@pytest.mark.parametrize("target", ["knowledge/agent", "knowledge/settings/systems"])
def test_runs_linked_into_a_knowledge_half_is_refused(tmp_path: Path, target: str) -> None:
    """`<T>/runs` linked INTO a half (code review max, finding 1): step 7 refuses it naming
    the runs base, since every run dir would be a read-write mount inside the tenant's
    knowledge. A tree beside the halves is still a near miss (pinned by the spec's s0 cell)."""
    root = tmp_path / "data"
    H.adopted(root)
    runs = H.tenant_folder(root) / "runs"
    shutil.rmtree(runs, ignore_errors=True)
    runs.symlink_to(target)
    text = H.accept_refusal(_tenant, root)
    assert str(runs) in text, text
    assert "knowledge folder" in text, text
