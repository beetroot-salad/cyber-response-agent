"""#1618 flows 1-2 (K1, K3-K5, K8): a run's start through `run.main` and the production launcher over the real fetch child."""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path

import pytest

from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

pytestmark = pytest.mark.e2e


def test_a1_an_unpinned_run_reads_and_stamps_the_commit_its_own_fetch_saw_never_a_later_one(decoy, tmp_path):
    """main moves after the child answered: copy, stamp and record are the fetched commit, not clone/exports/later (K3)."""
    t = decoy
    fetched = t.origin_main()
    later: list[str] = []
    pub = A.fetching(t, tmp_path, after=lambda _d, _l: later.append(K.advance_main(t, "K1618-LATER")))
    out = B.launch(t, tmp_path, publish=None, fetch=pub)
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert pub.lines == [f"ok {fetched}"], pub.lines
    seen = out.seen[0]
    assert seen.agent_files == K.half_at(t, fetched, "agent")
    assert A.settings_mark(seen) == K.mark_text(K.MERGED_MARK)
    assert B.stamped_commit(out.stamp_after) == {"commit": fetched}
    source = B.knowledge_source(out)
    assert (source.get("commit"), source.get("kind")) == (fetched, "fresh"), source
    assert later
    assert t.origin_main() == later[0] != fetched


def test_a4_the_copy_is_built_in_an_owned_temporary_and_ends_owned_by_the_run_process(decoy, tmp_path):
    """The child is handed an empty owned temporary under run-knowledge; the run copy then carries this process's owner and a token (F1)."""
    from defender.tenancy._owner import owned_temporary, owner_alive

    t = decoy
    start: dict = {}

    def observe(dest):
        start.update(parent=dest.parent, empty=os.listdir(dest) == [], alive=owner_alive(dest), name=dest.name,
                     run=A.UUID.search(dest.name))

    final: dict = {}

    def during(seen):
        copy = A.run_copies(t) / seen.run_dir.name
        final.update(owner=json.loads((copy / "owner").read_text()), token=(copy / "stage" / "token").is_file(),
                     listing=A.listing(A.run_copies(t)), name=seen.run_dir.name)

    pub = A.fetching(t, tmp_path, observe=observe)
    out = B.launch(t, tmp_path, publish=None, fetch=pub, during=during)
    assert out.reached, out.text()
    assert start["parent"] == A.run_copies(t)
    assert start["empty"]
    assert start["alive"]
    named = A.NAMED_OWNER.search(start["name"])
    assert named is not None, start["name"]
    assert int(named.group(1)) == os.getpid(), start["name"]
    assert owned_temporary  # the grammar the name follows exists today
    assert final["owner"]["pid"] == os.getpid()
    assert final["token"]
    assert final["listing"] == [final["name"]], final


def test_1618_k7_the_run_copy_holds_its_owner_record_at_the_instant_it_is_renamed_into_place(decoy, tmp_path, monkeypatch):
    """Two-phase ownership (flow 1): the filled temporary carries its owner in its name until it is renamed to the run id, so
    its `owner` record (this run process) is written BEFORE that rename, never after: at no instant is the run copy a folder
    with no owner a concurrent sweep would read as dead (K7, C-K13)."""
    t = decoy
    real_rename = os.rename
    renames: list[dict] = []

    def spy(src, dst, *args, **kwargs):
        dst_path = os.fspath(dst)
        if os.path.dirname(dst_path) == os.fspath(A.run_copies(t)) and A.UUID.fullmatch(os.path.basename(dst_path)):
            owner = os.path.join(os.fspath(src), "owner")
            renames.append({"dst": os.path.basename(dst_path),
                            "owner": json.loads(Path(owner).read_text(encoding="utf-8")) if os.path.isfile(owner) else None})
        return real_rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "rename", spy)
    out = B.launch(t, tmp_path, publish=None, fetch=A.fetching(t, tmp_path))
    monkeypatch.setattr(os, "rename", real_rename)
    assert out.reached, out.text()
    assert len(renames) == 1, f"premise: one rename made the run copy: {renames}"
    assert renames[0]["dst"] == out.seen[0].run_dir.name, renames
    assert renames[0]["owner"] is not None, "the run copy was renamed into place before its owner was recorded"
    assert renames[0]["owner"]["pid"] == os.getpid(), renames[0]


def test_a5_a_dead_owners_folder_at_the_run_id_is_never_replaced_the_rename_refuses(decoy, tmp_path):
    """The rename onto an existing target refuses and the run does not start; the planted folder is untouched (F1)."""
    t = decoy
    planted: list = []

    def after(dest, _line):
        run_id = A.UUID.search(dest.name).group(0)  # FORCED: the temporary's name carries the run id
        pid, start = A.dead_mark()
        planted.append(A.plant(A.run_copies(t) / run_id, pid=pid, start=start))

    out = B.launch(t, tmp_path, publish=None, fetch=A.fetching(t, tmp_path, after=after))
    assert planted, "premise: the temporary's name carries the run id"
    assert not out.reached, out.text()
    assert out.raised is None, out.text()
    assert out.refusal is not None, out.text()
    assert (planted[0] / "stage" / "agent" / "half.md").read_text() == "half\n"
    assert A.listing(A.run_copies(t)) == [planted[0].name], "a temporary was left"


def test_a6_a_child_killed_mid_fill_leaves_nothing_and_the_run_refuses(decoy, tmp_path):
    """The live caller discards the half-filled temporary and nothing is made at the run id; control: the real child starts (F1)."""
    t = decoy
    command = A.stand_in_command(tmp_path, A.KILLED_MID_FILL)
    pub = A.fetching(t, tmp_path, command=command)
    out = B.launch(t, tmp_path, publish=None, fetch=pub)
    assert not out.reached, out.text()
    assert out.raised is None, out.text()
    assert out.refusal is not None, out.text()
    assert A.listing(A.run_copies(t)) == []
    assert B.launch(decoy, tmp_path, publish=None, fetch=A.fetching(t, tmp_path)).reached, "control"


def test_a8_a_pinned_run_reads_its_unadvertised_commit_by_id(decoy, tmp_path):
    """A pin that is neither the seed nor main's tip is fetched by id and read (K5)."""
    t = decoy
    pinned = K.advance_main(t, "K1618-PINNED")
    K.advance_main(t, "K1618-AFTER-PIN")
    pub = A.fetching(t, tmp_path)
    out = B.launch(t, tmp_path, publish=None, fetch=pub, argv_extra=("--knowledge-commit", pinned))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert [c["commit"] for c in pub.calls] == [pinned]
    seen = out.seen[0]
    assert seen.agent_files == K.half_at(t, pinned, "agent")
    assert A.settings_mark(seen) == K.mark_text("K1618-PINNED")
    source = B.knowledge_source(out)
    assert (source.get("kind"), source.get("commit")) == ("pinned", pinned), source


def test_a9_a_pin_forgejo_does_not_serve_refuses_naming_the_commit(decoy, tmp_path):
    """No fallback to main for an unserved pin (K5)."""
    pub = A.fetching(decoy, tmp_path)
    out = B.launch(decoy, tmp_path, publish=None, fetch=pub, argv_extra=("--knowledge-commit", K.ABSENT_COMMIT))
    assert [c["commit"] for c in pub.calls] == [K.ABSENT_COMMIT], "premise: the child was asked for the pin, not main"
    assert pub.lines, "premise: the child reported"
    assert pub.lines[0].startswith("refused "), pub.lines
    assert not out.reached, out.text()
    assert out.raised is None, out.text()
    assert out.refusal is not None, out.text()
    assert K.ABSENT_COMMIT in out.refusal, out.text()
    assert "usage:" not in out.refusal, out.text()
    assert A.listing(A.run_copies(decoy)) == []


def test_a12_a_flock_held_on_the_old_lock_path_changes_nothing(decoy, tmp_path):
    """A process holding `<T>/knowledge.lock` does not make a start stale or refused (K1)."""
    t = decoy
    tip = t.origin_main()
    with open(K.tenant_root(t) / "knowledge.lock", "a+") as held:  # noqa: PTH123
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with open(K.tenant_root(t) / "knowledge.lock", "a+") as probe, pytest.raises(BlockingIOError):  # noqa: PTH123
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)  # control: the lock is really held
        out = B.launch(t, tmp_path, publish=None, fetch=A.fetching(t, tmp_path))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert B.knowledge_source(out).get("commit") == tip


def test_a14_after_the_upgrade_a_run_starts_and_makes_no_clone_exports_current_or_lock(t, tmp_path):
    """No `knowledge`, `exports` or `knowledge.lock` appears under `<T>`, and the run copy is gone after the run (K8)."""
    before = K.tenant_entries(t)
    out = B.launch(t, tmp_path, publish=None, fetch=A.fetching(t, tmp_path))
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert out.seen[0].agent_files == K.half_at(t, t.origin_main(), "agent")
    assert K.local_state(t) == []
    assert not (K.tenant_root(t) / "exports").exists()
    assert set(K.tenant_entries(t)) - set(before) <= {"run-knowledge", "runs"}, K.tenant_entries(t)
    assert A.listing(A.run_copies(t)) == []
