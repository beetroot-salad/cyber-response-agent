"""tenant.py migrate gives a pre-knowledge-folder tenant the folder acceptance requires."""
from __future__ import annotations

import shutil
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


def _committed(repo: Path, rev: str = "HEAD", under: str = "") -> dict[str, bytes]:
    """`{path: bytes}` of what `rev` commits (under `under`, relative to it)."""
    args = ["ls-tree", "-r", "-z", "--name-only", rev] + (["--", under] if under else [])
    names = [n for n in H.git(repo, *args).stdout.split("\0") if n]
    return {(Path(n).relative_to(under).as_posix() if under else n):
            H.git(repo, "cat-file", "blob", f"{rev}:{n}").stdout.encode("utf-8") for n in names}


def _checkout_with_a_retired_lab(dest: Path, shape: str = "merged",
                                 extra: dict[str, str] | None = None) -> tuple[Path, dict]:
    """A tmp checkout whose history commits a lab at `knowledge/tenants/playground` (the
    fixture's files, plus `extra`) and then deletes it, reaching HEAD by `shape`: "merged" (a
    branch deleting it, merged with a merge commit into a main that moved on), "squashed", or
    "linear". Returns the checkout and the lab's committed files."""
    checkout = H.tmp_checkout(dest)
    lab = checkout / _LAB
    if not lab.exists():
        shutil.copytree(H.FIXTURE, lab, symlinks=True)
    for rel, text in (extra or {}).items():
        (lab / rel).write_text(text, encoding="utf-8")
    H.git(checkout, "add", "--force", "--", _LAB)
    H.git(checkout, "commit", "-q", "--allow-empty", "-m", "the lab")
    files = _committed(checkout, under=_LAB)
    if shape == "linear":
        H.git(checkout, "rm", "-r", "-q", "--", _LAB)
        H.git(checkout, "commit", "-q", "-m", "retire the lab")
        return checkout, files
    H.git(checkout, "checkout", "-q", "-b", "retire")
    H.git(checkout, "rm", "-r", "-q", "--", _LAB)
    H.git(checkout, "commit", "-q", "-m", "retire the lab")
    H.git(checkout, "checkout", "-q", "main")
    (checkout / "NOTE").write_text("main moved on\n", encoding="utf-8")
    H.git(checkout, "add", "NOTE")
    H.git(checkout, "commit", "-q", "-m", "main moves on")
    if shape == "merged":
        H.git(checkout, "merge", "-q", "--no-ff", "-m", "merge retire", "retire")
    else:
        H.git(checkout, "merge", "-q", "--squash", "retire")
        H.git(checkout, "commit", "-q", "-m", "retire the lab (squashed)")
    assert not lab.exists(), "precondition: HEAD still has the lab"
    return checkout, files


def _script(checkout: Path) -> Path:
    return checkout / H.script_of(tenant_py).relative_to(H.REPO_ROOT)


@pytest.mark.parametrize("shape", ["merged", "squashed", "linear"])
def test_migrate_gives_an_old_shape_tenant_a_folder_setup_accepts(
        tmp_path: Path, shape: str) -> None:
    checkout, lab = _checkout_with_a_retired_lab(tmp_path / "checkout", shape)
    stale = checkout / _LAB / "settings"
    stale.mkdir(parents=True)
    (stale / "verb-grants.yaml").write_text("a stale copy on disk\n", encoding="utf-8")
    root = _old_shape_root(checkout / ".defender-data")
    knowledge = root / _TID / "knowledge"
    refused = H.accept_refusal(_tenant, root, _TID)
    assert f"tenant.py migrate {_TID} {knowledge}" in refused, refused

    before = H.tree_census(root)
    script = _script(checkout)
    said = H.assert_clean(_migrate(_TID, knowledge, home=S._home(tmp_path / "cfg"),
                                   script=script))
    assert f"tenant.py setup {_TID}" in said, said
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


def test_a_migrate_that_fails_after_creating_the_folder_removes_it(tmp_path: Path) -> None:
    """A pre-commit hook (from the operator's global `core.hooksPath`) that refuses: migrate
    exits 1 saying it was undone, and the knowledge folder is gone — the root is as it was."""
    checkout, _ = _checkout_with_a_retired_lab(tmp_path / "checkout")
    root = _old_shape_root(tmp_path / "root")
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    hook = hooks / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    hook.chmod(0o755)
    home = S._home(tmp_path / "cfg", extra=f"[core]\n\thooksPath = {hooks}\n")
    target = root / _TID / "knowledge"
    before = H.tree_census(root)
    H.assert_refused(_migrate(_TID, target, home=home, script=_script(checkout)), "undone")
    assert not target.exists()
    assert H.census_diff(before, H.tree_census(root)) == []
