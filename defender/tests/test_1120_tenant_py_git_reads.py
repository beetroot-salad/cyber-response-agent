"""#1120 piece 1 — `tenant.py`'s git reads act on the folder they are aimed at, never on a
repository the environment or an enclosing tree points them at (claims-adversary follow-ups
on PR #1157).

  * An exported `GIT_DIR` reaches no git call `tenant.py` makes (J-PO1: "both callers must
    ignore it") — the census's read of the running checkout included, not only check's
    committed-`.tenant-id` read.
  * A folder whose `.git` is not a repository of its own (an empty `.git` directory inside
    another repo's work tree) gets no answer from the ENCLOSING repo: check's committed read
    cannot say what the folder's own repo commits, so it fails closed (V16).
  * A clone whose git converts line endings on checkout (`core.autocrlf=true`, a Windows
    operator's default) holds `.tenant-id` as CRLF over an LF commit: that IS what HEAD
    commits, so check is clean — the working file is hashed as git would store it, not as raw
    bytes (code review on PR #1157).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from defender.scripts import tenant as tenant_py
from defender.tests.tenant_1120_piece1 import _spec1120 as H


def test_check_folder_ignores_an_exported_git_dir_for_every_git_read(tmp_path: Path) -> None:
    """`check --folder` over a clean clone exits 0 both with and without `GIT_DIR` exported
    to an unrelated repository: neither the committed-`.tenant-id` read nor the census's read
    of the running checkout follows it."""
    knowledge = H.cloned_tenant(tmp_path, tmp_path / "root")
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    H.git(unrelated, "init", "-q", "-b", "main")
    H.assert_clean(H.check(tenant_py, None, "--folder", str(knowledge)))
    H.assert_clean(H.check(tenant_py, None, "--folder", str(knowledge),
                           GIT_DIR=str(unrelated / ".git")))


def test_check_folder_fails_closed_when_its_git_is_not_its_own_repository(
        tmp_path: Path) -> None:
    """A repo that commits `sub/` (the fixture with its `.tenant-id`), and an empty `sub/.git`
    directory: git walks past the bogus `.git` to the enclosing repo, whose HEAD does commit
    the bytes. `check --folder sub` exits 1 naming "cannot verify .tenant-id is committed" —
    the enclosing repo's answer is not the folder's. The positive control: the same tree
    without the bogus `.git` is a plain folder, which is exempt and checks clean."""
    outer = tmp_path / "outer"
    sub = outer / "sub"
    shutil.copytree(H.FIXTURE, sub, symlinks=True)
    H.write_tenant_id_file(sub, H.TID, "id")
    H.git(outer, "init", "-q", "-b", "main")
    H.git(outer, "add", "-A")
    H.git(outer, "commit", "-q", "-m", "outer")
    H.assert_clean(H.check(tenant_py, None, "--folder", str(sub)))

    (sub / ".git").mkdir()
    H.assert_refused(H.check(tenant_py, None, "--folder", str(sub)), H.CANNOT_VERIFY_TENANT_ID)


def test_check_folder_accepts_a_crlf_checkout_of_an_lf_commit(tmp_path: Path) -> None:
    """The tenant repo commits `.tenant-id` with an LF; a clone made with
    `core.autocrlf=true` checks it out with a CRLF (asserted first, so the test cannot pass
    vacuously). `check --folder` exits 0. The negative control: the same clone with the id
    edited by hand is still a finding."""
    src = tmp_path / "src"
    shutil.copytree(H.FIXTURE, src, symlinks=True)
    H.write_tenant_id_file(src, H.TID, "id")
    repo = H.repo_of(src, tmp_path / "repo")
    knowledge = tmp_path / "root" / H.TID / "knowledge"
    knowledge.parent.mkdir(parents=True)
    H.git(knowledge.parent, "clone", "-q", "-c", "core.autocrlf=true", str(repo),
          str(knowledge))
    tenant_id_file = knowledge / H.TENANT_ID_FILE
    assert tenant_id_file.read_bytes() == f"{H.TID}\r\n".encode(), (
        "precondition: the clone did not check .tenant-id out with a CRLF")
    H.assert_clean(H.check(tenant_py, None, "--folder", str(knowledge)))

    tenant_id_file.write_bytes(f"{H.OTHER}\r\n".encode())
    H.assert_refused(H.check(tenant_py, None, "--folder", str(knowledge)), str(tenant_id_file))
