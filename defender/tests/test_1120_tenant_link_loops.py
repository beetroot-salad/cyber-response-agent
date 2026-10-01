"""#1120 piece 1 — acceptance answers a link loop, or a linked tenant folder, with its own
refusal, never a traceback (code review on PR #1157).

Python 3.11's `Path.resolve()` raises `RuntimeError` on a link loop, not `OSError`, so a check
that resolved a path below the data root and caught only `OSError` crashed on one. Acceptance
now walks below the root no-follow and resolves only what it is handed, through one translator.

  * A `knowledge` that is a link to itself, and a data root that is one, are `TenantRefused`
    naming the path.
  * `tenant.py check --folder` over a looped folder exits 1 with `[tenant.py] …`, and the
    census lint's call (`check_knowledge_folder`) refuses it rather than raising.
  * Step 7 counts the tenant's own `runs/`: a `<T>/runs` linked onto `knowledge/` would put the
    host-only settings half inside the tree a box mounts read-write.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from defender import _tenant
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
