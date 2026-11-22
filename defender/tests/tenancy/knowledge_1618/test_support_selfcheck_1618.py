"""Self-check of the #1618 shared machinery: the scene and the fakes behave as the contract assumes (base-green)."""
from __future__ import annotations

import contextlib
import subprocess
import threading
from pathlib import Path

import pytest

from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_delivery._support import git


def test_default_scene_has_no_local_knowledge_state(t):
    """Scene: upgrade step done, `main` at the seed, halves read from the bare remote."""
    assert K.local_state(t) == []
    assert not (K.tenant_root(t) / "exports").exists()
    assert t.origin_main() == t.commit
    assert K.half_at(t, t.commit, "agent")["lessons/fixture-owner-before-close.md"] == K.lesson_text(K.SEEDED_MARK).encode()
    assert K.repo_scratch(t) == []
    assert t.directory is not None


def test_decoy_scene_leaves_stale_copies_while_main_moves_on(decoy):
    """Scene: decoy holds clone/exports/current at the seed with a clone-only mark; the remote is ahead."""
    t = decoy
    assert K.local_state(t) == ["exports", "knowledge"]
    assert (K.tenant_root(t) / "exports" / "current").read_text().strip() == t.commit
    assert t.origin_main() != t.commit
    assert K.CLONE_ONLY_MARK in (Path(t.checkout) / K.LESSON).read_text()
    stale = K.tree_bytes(K.tenant_root(t) / "exports" / t.commit / "agent")
    assert stale["lessons/fixture-owner-before-close.md"] == K.lesson_text(K.SEEDED_MARK).encode()
    now = K.half_at(t, t.origin_main(), "settings")[K.MARK_FILE.removeprefix("settings/")]
    assert now == K.mark_text(K.MERGED_MARK).encode()


def test_advance_main_returns_the_commit_and_marks(t):
    """Helper: advance_main lands the chosen marks on the remote's `main`."""
    new = K.advance_main(t, K.MERGED_MARK)
    assert t.origin_main() == new != t.commit
    assert K.half_at(t, new, "agent")["lessons/fixture-owner-before-close.md"] == K.lesson_text(K.MERGED_MARK).encode()
    assert K.half_at(t, t.commit, "agent")["lessons/fixture-owner-before-close.md"] == K.lesson_text(K.SEEDED_MARK).encode()


def test_unadvertised_commit_is_fetchable_by_id_with_protocol_2(t, tmp_path):
    """Fidelity (a): a commit no ref advertises is served by id over v2; an absent id is not."""
    old = t.commit
    K.advance_main(t, K.MERGED_MARK)
    K.advance_main(t, "K1618-THIRD")
    assert K.fetch_by_id(t, tmp_path / "into", old) == "commit"
    with pytest.raises(subprocess.CalledProcessError):
        K.fetch_by_id(t, tmp_path / "into2", K.ABSENT_COMMIT)


def test_pull_ref_exists_on_open_and_survives_a_merge_that_deletes_the_branch(t, tmp_path):
    """Fidelity (b): opening a PR makes refs/pull/<n>/head; merge with branch deletion keeps it (C-F5)."""
    tip = K.push_branch(t, "batch-x", {"agent/lessons/new-1618.md": "n\n"})
    n = K.open_pr(t, "batch-x")
    assert K.remote_ref(t, f"refs/pull/{n}/head") == tip
    K.merge_pr(t, "batch-x", style="squash", delete_branch=True)
    assert K.remote_ref(t, "refs/heads/batch-x") is None
    assert K.remote_ref(t, f"refs/pull/{n}/head") == tip
    into = tmp_path / "pull"
    into.mkdir()
    git(into, "init", "--bare", "--template=")
    K.http_git(t, into, "fetch", "--depth", "1", t.origin, f"refs/pull/{n}/head", protocol=2)
    assert git(into, "cat-file", "-t", "FETCH_HEAD") == "commit"


def _clone_with_branch(t, tmp_path):
    work = tmp_path / "pusher"
    K.http_git(t, tmp_path, "clone", t.origin, str(work))
    git(work, "checkout", "-b", "batch-y")
    (work / "agent" / "lessons").mkdir(parents=True, exist_ok=True)
    (work / "agent" / "lessons" / "y.md").write_text("y\n")
    git(work, "add", "-A")
    git(work, "commit", "-m", "y")
    return work, git(work, "rev-parse", "HEAD")


def test_a_push_that_lands_with_its_reply_lost_fails_for_the_client_but_is_on_the_remote(t, tmp_path):
    """Fidelity (c): lose_reply applies the push and drops the connection; a plain refusal applies nothing."""
    work, tip = _clone_with_branch(t, tmp_path)
    t.server.fail_push("refuse")
    with pytest.raises(subprocess.CalledProcessError):
        K.http_git(t, work, "push", "origin", "batch-y:refs/heads/batch-y")
    assert K.remote_ref(t, "refs/heads/batch-y") is None
    t.server.fail_push("lose_reply")
    with pytest.raises(subprocess.CalledProcessError):
        K.http_git(t, work, "push", "origin", "batch-y:refs/heads/batch-y")
    assert K.remote_ref(t, "refs/heads/batch-y") == tip
    assert t.server.pushes == ["refused", "landed-reply-lost"]
    K.http_git(t, work, "push", "origin", "batch-y:refs/heads/batch-z")  # control: unfaulted pushes land
    assert K.remote_ref(t, "refs/heads/batch-z") == tip
    assert t.server.pushes[-1] == "landed"


def test_six_clients_fetch_at_once(t, tmp_path):
    """Fidelity (d): GitHTTP serves ~6 parallel fetches without serialising or failing."""
    K.advance_main(t, K.MERGED_MARK)
    failures: list[str] = []
    ready = threading.Barrier(6)

    def reader(i: int) -> None:
        into = tmp_path / f"r{i}"
        into.mkdir()
        try:
            git(into, "init", "--bare", "--template=")
            ready.wait(timeout=30)
            K.http_git(t, into, "fetch", "--depth", "1", t.origin, "+refs/heads/main:refs/heads/main", protocol=2)
            if git(into, "rev-parse", "main") != t.origin_main():
                failures.append(f"{i}: wrong tip")
        except Exception as e:  # noqa: BLE001
            failures.append(f"{i}: {e}")

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(6)]
    [x.start() for x in threads]
    [x.join(60) for x in threads]
    assert failures == []


def test_forge_down_is_a_real_refusal_for_git_and_api(t, tmp_path):
    """Helper: forge_down refuses git connections and forge API calls; before it, both work (control)."""
    K.http_git(t, tmp_path, "ls-remote", t.origin)
    K.forge_down(t)
    with pytest.raises(subprocess.CalledProcessError) as down:
        K.http_git(t, tmp_path, "ls-remote", t.origin)
    assert "refused" in down.value.stderr.lower() or "connect" in down.value.stderr.lower()
    with pytest.raises(Exception, match="unreachable"):
        K.open_pr(t, "main")


def test_owned_dest_is_owned_by_this_process(t):
    """Seam: owned_dest makes an empty folder whose name carries this process as owner (exists today)."""
    from defender.tenancy._owner import owner_alive

    dest = K.owned_dest(K.tenant_root(t) / "run-knowledge")
    assert dest.is_dir()
    assert not any(dest.iterdir())
    assert owner_alive(dest)


def test_seams_route_to_names_that_may_not_exist_yet(t, tmp_path):
    """Seam: the not-yet-existing production names fail only when called (ImportError/AttributeError), never at collection."""
    with contextlib.suppress(ImportError, AttributeError):
        K.sweep(t)


def test_delivery_store_fixtures_still_work_at_base(repo, store):
    """Fixtures: P3's `repo` and the Postgres `store` re-exported by conftest are usable (not skipped with the DSN set)."""
    assert store.batches(str(repo[0].id)) == []
