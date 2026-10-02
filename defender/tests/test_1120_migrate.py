"""#1120 piece 1 — `tenant.py migrate`, the one-off that gives a tenant set up before #1120 the
knowledge folder acceptance now requires (human, PR #1157: "one-off migration").

A data root made before #1120 holds `<T>/{tenant.json, runs, sessions}` and no `knowledge/`:
its settings lived in the product checkout's `knowledge/tenants/<T>/`, and there is no tenant
repo to clone. Acceptance refuses it, naming migrate as well as the clone.

  * migrate builds `<root>/<T>/knowledge` as a new repo committing the checkout's HEAD copy plus
    `agent/.tenant-id` (an untracked file beside the copy is not carried), touches nothing else
    under the data root, and `setup <T>` then accepts it writing nothing — the row stays
    byte-identical. The data root sits inside the product checkout, beside `defender/`, as the
    dev container's does.
  * It refuses before any write: a bad id, an id the checkout carries no copy for, a target that
    exists, a target whose parent is missing, a target in the checkout's `defender/` tree, a git
    with no commit identity.
  * A failure after it creates the folder (a commit hook that refuses) removes the folder again.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from defender import _tenant
from defender._paths import PATHS
from defender.scripts import tenant as tenant_py
from defender.tests.tenant_1120_piece1 import _spec1120 as H
from defender.tests.tenant_1120_piece1 import test_1120_scaffold as S

_LAB = "knowledge/tenants/playground"
_TID = "playground"


def _migrate(tenant_id: str, target: Path, *, home: Path, script: Path | None = None,
             identity_env: bool = True) -> subprocess.CompletedProcess:
    """`tenant.py migrate <tenant_id> <target>` as a process, under `home`'s git config and
    with no data root at all (migrate needs none)."""
    extra = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "xdg")}
    if identity_env:
        extra.update(H.GIT_IDENTITY)
    return H.run_script(script or H.script_of(tenant_py), "migrate", tenant_id, str(target),
                        root=None, unset=S._AMBIENT_GIT, **extra)


def _old_shape_root(root: Path) -> Path:
    """`<root>/playground/{tenant.json, runs/r1/report.md, sessions/s1}`, no knowledge/."""
    H.plant_row(root, _TID)
    run = root / _TID / "runs" / "r1"
    run.mkdir(parents=True)
    (run / "report.md").write_text("an old run\n", encoding="utf-8")
    (root / _TID / "sessions").mkdir()
    (root / _TID / "sessions" / "s1").write_text("{}\n", encoding="utf-8")
    return root


def _committed(repo: Path) -> dict[str, bytes]:
    names = H.git(repo, "ls-tree", "-r", "-z", "--name-only", "HEAD").stdout.split("\0")
    return {n: H.git(repo, "cat-file", "blob", f"HEAD:{n}").stdout.encode("utf-8")
            for n in names if n}


def test_migrate_gives_an_old_shape_tenant_a_folder_setup_accepts(tmp_path: Path) -> None:
    """Over an old-shape root inside a tmp checkout (beside its `defender/`), acceptance refuses
    naming migrate; `migrate playground <root>/playground/knowledge` exits 0, telling the
    operator to run setup; the new repo commits exactly HEAD's lab files (an untracked
    `.DS_Store` beside them left out) plus `.tenant-id`, with HEAD's bytes; nothing else under
    the root changed. `setup playground` then exits 0 and writes nothing, and the tenant is
    accepted."""
    checkout = H.tmp_checkout(tmp_path / "checkout")
    (checkout / _LAB / ".DS_Store").write_bytes(b"\0\0finder")
    root = _old_shape_root(checkout / ".defender-data")
    knowledge = root / _TID / "knowledge"
    refused = H.accept_refusal(_tenant, root, _TID)
    assert f"tenant.py migrate {_TID} {knowledge}" in refused, refused

    before = H.tree_census(root)
    home = S._home(tmp_path / "cfg")
    script = checkout / H.script_of(tenant_py).relative_to(H.REPO_ROOT)
    said = H.assert_clean(_migrate(_TID, knowledge, home=home, script=script))
    assert f"tenant.py setup {_TID}" in said, said

    lab = {Path(n).relative_to(_LAB).as_posix(): data
           for n, data in _committed(checkout).items() if n.startswith(_LAB + "/")}
    assert lab, "precondition: the tmp checkout commits no lab copy"
    committed = _committed(knowledge)
    assert committed.pop(H.TENANT_ID_FILE.as_posix()) == f"{_TID}\n".encode()
    assert committed == lab
    after = H.tree_census(root)
    assert {rel: v for rel, v in after.items()
            if not rel.startswith(f"{_TID}/knowledge")} == before, (
        "migrate changed something under the data root besides the knowledge folder")

    H.assert_clean(H.run_script(script, "setup", _TID, root=root, cwd=checkout))
    assert H.census_diff(after, H.tree_census(root)) == [], "setup wrote over a migrated tenant"
    accepted = _tenant.accept_tenant(root, _tenant.TenantId(_TID),
                                     defender_dir=PATHS.defender_dir)
    assert accepted.knowledge == knowledge


@pytest.mark.parametrize("cell", ["bad-id", "no-copy", "target-exists", "no-parent",
                                  "linked-parent", "inside-defender", "no-identity"])
def test_migrate_refuses_before_writing(tmp_path: Path, cell: str) -> None:
    """Each refusal exits 1 naming what it refuses, and the data root (and the target) are as
    they were. Control: the same root with a clean target migrates (the happy-path test)."""
    root = _old_shape_root(tmp_path / "root")
    target = root / _TID / "knowledge"
    tenant_id, home, names = _TID, S._home(tmp_path / "cfg"), [str(target)]
    identity_env, script = True, None
    if cell == "bad-id":
        tenant_id, names = "A", ["A"]
    elif cell == "no-copy":
        H.plant_row(root, H.TID)
        tenant_id, target = H.TID, root / H.TID / "knowledge"
        names = [f"knowledge/tenants/{H.TID}", "clone"]
    elif cell == "target-exists":
        target.mkdir()
    elif cell == "no-parent":
        target = root / "absent" / "knowledge"
        names = [str(target.parent)]
    elif cell == "linked-parent":
        (root / "linked").symlink_to(root / _TID, target_is_directory=True)
        target = root / "linked" / "knowledge"
        names = [str(target.parent), "a link is refused"]
    elif cell == "inside-defender":
        # A tmp checkout's own copy, so a guard that regressed writes into tmp, never this tree.
        checkout = H.tmp_checkout(tmp_path / "checkout")
        script = checkout / H.script_of(tenant_py).relative_to(H.REPO_ROOT)
        target = checkout / "defender" / "scripts" / "spec1120-migrate-never-made"
        names = [str(target), "defender"]
    elif cell == "no-identity":
        home, identity_env = S._home(tmp_path / "cfg-anon", identity=False), False
        names = ["identity"]
    before = H.tree_census(root)
    target_existed = target.exists()
    H.assert_refused(_migrate(tenant_id, target, home=home, script=script,
                              identity_env=identity_env), *names)
    assert H.census_diff(before, H.tree_census(root)) == [], "a refused migrate wrote"
    assert target.exists() == target_existed


def test_a_migrate_that_fails_after_creating_the_folder_removes_it(tmp_path: Path) -> None:
    """A pre-commit hook (from the operator's global `core.hooksPath`) that refuses: migrate
    exits 1 saying it was undone, and the knowledge folder is gone — the root is as it was."""
    root = _old_shape_root(tmp_path / "root")
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    hook = hooks / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    home = S._home(tmp_path / "cfg", extra=f"[core]\n\thooksPath = {hooks}\n")
    target = root / _TID / "knowledge"
    before = H.tree_census(root)
    H.assert_refused(_migrate(_TID, target, home=home), "undone")
    assert not target.exists()
    assert H.census_diff(before, H.tree_census(root)) == []


def test_a_copy_that_commits_its_own_tenant_id_migrates_with_the_requested_one(
        tmp_path: Path) -> None:
    """A checkout whose copy also commits `agent/.tenant-id` (another tenant's id, say): migrate
    still exits 0, and the new repo's `.tenant-id` is the one it writes for the id asked for."""
    checkout = H.tmp_checkout(tmp_path / "checkout")
    (checkout / _LAB / H.TENANT_ID_FILE).write_text(f"{H.OTHER}\n", encoding="utf-8")
    H.git(checkout, "add", "--force", "--", f"{_LAB}/{H.TENANT_ID_FILE.as_posix()}")
    H.git(checkout, "commit", "-q", "-m", "a copy carrying an id")
    root = _old_shape_root(tmp_path / "root")
    knowledge = root / _TID / "knowledge"
    script = checkout / H.script_of(tenant_py).relative_to(H.REPO_ROOT)
    H.assert_clean(_migrate(_TID, knowledge, home=S._home(tmp_path / "cfg"), script=script))
    assert _committed(knowledge)[H.TENANT_ID_FILE.as_posix()] == f"{_TID}\n".encode()
