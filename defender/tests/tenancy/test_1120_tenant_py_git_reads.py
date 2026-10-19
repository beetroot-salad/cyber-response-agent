"""tenant.py git reads act on the folder aimed at, never a repository the environment or an enclosing tree points to."""
from __future__ import annotations

import os
import shutil
import threading
from pathlib import Path

import pytest

from defender.scripts import tenant as tenant_py
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H


def test_check_folder_ignores_an_exported_git_dir_for_every_git_read(tmp_path: Path) -> None:
    knowledge = H.cloned_tenant(tmp_path, tmp_path / "root")
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    H.git(unrelated, "init", "-q", "-b", "main")
    H.assert_clean(H.check(tenant_py, None, "--folder", str(knowledge)))
    H.assert_clean(H.check(tenant_py, None, "--folder", str(knowledge),
                           GIT_DIR=str(unrelated / ".git")))


def test_check_folder_fails_closed_when_its_git_is_not_its_own_repository(
        tmp_path: Path) -> None:
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


def test_a_configured_clean_filter_neither_runs_nor_masks_an_edited_id(tmp_path: Path) -> None:
    knowledge = H.cloned_tenant(tmp_path, tmp_path / "root")
    marker = tmp_path / "filter-ran"
    H.git(knowledge, "config", "filter.mask.clean", f"sh -c 'touch {marker}; printf \"{H.TID}\\n\"'")
    (knowledge / ".git" / "info").mkdir(exist_ok=True)
    (knowledge / ".git" / "info" / "attributes").write_text(
        f"{H.TENANT_ID_FILE.as_posix()} filter=mask\n", encoding="utf-8")
    tenant_id_file = knowledge / H.TENANT_ID_FILE
    tenant_id_file.write_text(f"{H.OTHER}\n", encoding="utf-8")
    H.assert_refused(H.check(tenant_py, None, "--folder", str(knowledge)), str(tenant_id_file))
    assert not marker.exists(), "check ran the clone's configured clean filter"


def test_a_replace_object_does_not_make_an_edited_id_look_committed(tmp_path: Path) -> None:
    knowledge = H.cloned_tenant(tmp_path, tmp_path / "root")
    rel = H.TENANT_ID_FILE.as_posix()
    committed = H.git(knowledge, "rev-parse", f"HEAD:{rel}").stdout.strip()
    tenant_id_file = knowledge / H.TENANT_ID_FILE
    tenant_id_file.write_text(f"{H.OTHER}\n", encoding="utf-8")
    forged = H.git(knowledge, "hash-object", "-w", "--", rel).stdout.strip()
    H.git(knowledge, "replace", committed, forged)
    H.assert_refused(H.check(tenant_py, None, "--folder", str(knowledge)), str(tenant_id_file))


_FIFO_BOUND = 1.5


def test_a_fifo_in_git_fails_closed_instead_of_hanging(tmp_path: Path) -> None:
    knowledge = H.cloned_tenant(tmp_path, tmp_path / "root")
    head = knowledge / ".git" / "HEAD"
    head.unlink()
    os.mkfifo(head)
    answered: list[str | None] = []
    worker = threading.Thread(
        target=lambda: answered.append(tenant_py._tenant_id_committed(knowledge,
                                                                      timeout=_FIFO_BOUND)),
        daemon=True)
    worker.start()
    worker.join(10 * _FIFO_BOUND)
    if worker.is_alive():  # unbounded: free the blocked git (open the FIFO's other end), fail
        os.close(os.open(head, os.O_RDWR | os.O_NONBLOCK))
        pytest.fail(f"no answer within {10 * _FIFO_BOUND}s: the git read is not bounded")
    finding = answered[0]
    assert finding is not None
    assert H.CANNOT_VERIFY_TENANT_ID in finding, finding
    assert f"did not answer within {_FIFO_BOUND}s" in finding, finding


def test_a_repo_with_no_commits_reports_the_id_as_not_committed(tmp_path: Path) -> None:
    """A tenant folder that is a fresh `git init` (no commit yet): check names `.tenant-id` as
    not committed — the operator's next step — rather than "cannot verify"."""
    folder = tmp_path / "fresh"
    shutil.copytree(H.FIXTURE, folder, symlinks=True)
    H.write_tenant_id_file(folder, H.TID, "id")
    H.git(folder, "init", "-q", "-b", "main")
    text = H.assert_refused(H.check(tenant_py, None, "--folder", str(folder)), "is not committed")
    assert H.CANNOT_VERIFY_TENANT_ID not in text, text
