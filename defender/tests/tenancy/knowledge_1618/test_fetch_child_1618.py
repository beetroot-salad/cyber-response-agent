"""#1618 flow 1 (K3, K5, K6, K7): the fetch child fills a caller-made empty folder from Forgejo and reports one line."""
from __future__ import annotations

import os
import stat
import threading

import pytest

from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_delivery._support import git, index_entry, push_to_remote
from defender.tests.tenancy.tenant_1108_p4._support import OTHER_TENANT_ID


def _dest(t):
    return K.owned_dest(K.tenant_root(t) / "run-knowledge")


def test_a2_the_child_fills_the_callers_empty_folder_with_main_s_halves_and_reports_ok(decoy, tmp_path):
    """The folder holds agent/ and settings/ at the remote's main (never the clone or exports); the line is `ok <commit>` (F1)."""
    t, dest = decoy, _dest(decoy)
    tip = t.origin_main()
    report = K.child_report(t, tmp_path, dest)
    assert (report.rc, report.word) == (0, "ok"), report
    assert report.commit == tip != t.commit
    assert sorted(os.listdir(dest)) == ["agent", "settings"]
    assert K.tree_bytes(dest / "agent") == K.half_at(t, tip, "agent")
    assert K.tree_bytes(dest / "settings") == K.half_at(t, tip, "settings")
    assert K.CLONE_ONLY_MARK.encode() not in b"".join(K.tree_bytes(dest).values())


def test_a3_a_folder_that_is_not_empty_is_refused_and_left_as_it_was(t, tmp_path):
    """A non-empty destination is refused, its content untouched, nothing added (F1)."""
    dest = _dest(t)
    (dest / "sentinel").write_text("mine\n")
    report = K.child_report(t, tmp_path, dest)
    assert report.word == "refused", report
    assert os.listdir(dest) == ["sentinel"]
    assert (dest / "sentinel").read_text() == "mine\n"
    assert K.child_report(t, tmp_path, _dest(t)).word == "ok", "control: an empty folder is filled"


def test_a3_a_destination_that_is_a_link_to_an_empty_folder_is_refused_and_nothing_is_written_through_it(t, tmp_path):
    """The child opens the destination without following links (F1)."""
    target = tmp_path / "elsewhere"
    target.mkdir()
    parent = K.tenant_root(t) / "run-knowledge"
    link = K.owned_dest(parent, "lnk")
    link.rmdir()
    link.symlink_to(target)
    report = K.child_report(t, tmp_path, link)
    assert report.word == "refused", report
    assert os.listdir(target) == []
    assert link.is_symlink()


_BAD = {
    "other-tenant": ("names tenant", None),
    "file-link": ("regular blobs", ("120000", "agent/lessons/link.md", b"/etc/passwd")),
    "settings-link": ("regular blobs", ("120000", "settings/link.yaml", b"../agent/.tenant-id")),
    "submodule": ("regular blobs", ("160000", "agent/lessons/sub", None)),
}


@pytest.mark.parametrize("case", sorted(_BAD))
def test_a11_content_the_validation_refuses_is_refused_with_todays_wording_and_nothing_is_left(t, tmp_path, case):
    """A merged commit naming another tenant, or holding a link or submodule, is refused as `lasting`, naming the commit (K6)."""
    wording, entry = _BAD[case]
    if entry is None:
        bad = K.advance_main(t, files={"agent/.tenant-id": f"{OTHER_TENANT_ID}\n"})
    else:
        mode, path, data = entry

        def edit(checkout):
            if data is None:
                index_entry(checkout, mode, path, blob=git(checkout, "rev-parse", "HEAD"))
            else:
                index_entry(checkout, mode, path, data=data)
        bad = push_to_remote(t.p3, t.scratch, edit, stage=False)
    dest = _dest(t)
    report = K.child_report(t, tmp_path, dest)
    assert (report.word, report.klass) == ("refused", "lasting"), report
    assert bad in report.reason, report.reason
    assert wording in report.reason, report.reason
    if entry is None:
        assert OTHER_TENANT_ID in report.reason
        assert t.tenant_id in report.reason
    assert K.tree_bytes(dest) == {}, "refused content was left in the folder"
    ok = K.child_report(t, tmp_path, _dest(t), commit=t.commit)
    assert ok.word == "ok", "control: the earlier good commit is fetchable by id"
    assert ok.commit == t.commit, "control: the earlier good commit is fetchable by id"


def test_a10_a_sibling_copy_of_a_commit_by_id_holds_that_commits_bytes(t, tmp_path):
    """A commit that is neither the seed nor main's tip is fetched by id into the helper-made folder (K5)."""
    old = K.advance_main(t, "K1618-SIBLING-PIN")
    K.advance_main(t, "K1618-LATER")
    dest = _dest(t)
    report = K.child_report(t, tmp_path, dest, commit=old)
    assert report.word == "ok", report
    assert report.commit == old, report
    assert K.tree_bytes(dest / "agent") == K.half_at(t, old, "agent")
    assert K.mark_text("K1618-SIBLING-PIN").encode() == (dest / "settings" / K.MARK_FILE.removeprefix("settings/")).read_bytes()


def test_k5_a_commit_forgejo_does_not_serve_is_refused_naming_it(t, tmp_path):
    """An unserved id is refused, naming the commit (K5)."""
    report = K.child_report(t, tmp_path, _dest(t), commit=K.ABSENT_COMMIT)
    assert report.word == "refused", report
    assert K.ABSENT_COMMIT in report.reason, report


@pytest.mark.parametrize("refuse", [False, True], ids=["ok", "refused"])
def test_a19_the_private_repository_is_a_0700_owned_folder_under_repo_scratch_never_under_the_tenant_and_gone_after(t, tmp_path, refuse):
    """While the child fetches, its repository sits in `<data root>/.repo-scratch/`, owned and 0700; afterwards nothing is left (K7)."""
    from defender.tenancy._owner import owner_alive

    if refuse:
        K.advance_main(t, files={"agent/.tenant-id": f"{OTHER_TENANT_ID}\n"})
    snap: dict = {}
    reached, release = threading.Event(), threading.Event()

    def hold(_service):
        scratch = K.tenant_root(t).parent / ".repo-scratch"
        snap["entries"] = K.repo_scratch(t)
        snap["modes"] = {n: stat.S_IMODE((scratch / n).stat().st_mode) for n in snap["entries"]}
        snap["alive"] = {n: owner_alive(scratch / n) for n in snap["entries"]}
        snap["uids"] = {(scratch / n).stat().st_uid for n in snap["entries"]}
        snap["under_tenant"] = A.repos_under(K.tenant_root(t))
        reached.set()
        release.wait(30)

    t.server.on_service = hold
    out: list = []
    worker = threading.Thread(target=lambda: out.append(K.child_report(t, tmp_path, _dest(t))))
    worker.start()
    assert reached.wait(60), "the child never fetched"
    release.set()
    worker.join(60)
    assert len(snap["entries"]) == 1, snap
    (name,) = snap["entries"]
    assert t.tenant_id in name, name
    assert A.NAMED_OWNER.search(name), name
    assert snap["modes"][name] == 0o700
    assert snap["uids"] == {os.getuid()}
    assert snap["alive"][name]
    assert snap["under_tenant"] == []
    assert out[0].word == ("refused" if refuse else "ok"), out[0]
    assert K.repo_scratch(t) == []
    assert A.repos_under(K.tenant_root(t)) == []
