"""Tenant delivery: batches behavior through the public API."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path


import os


import signal


import pytest


from ._support import (
    DEFENDER,
    LANES,
    ForgeHTTP,
    advance_remote,
    agent_blobs,
    branch_tip,
    delivery,
    files_under,
    git,
    odd_entries,
    opened,
    target,
    fixture_identity,
    configured_origin,
)


from ._scenarios import (
    _changes,
    _branches,
    _write,
    _drafts,
    _temps,
    _worktrees,
    _build_elsewhere,
    _publish_big_lesson,
)

def test_start_batch_makes_a_git_free_draft_of_the_export_commit_and_no_checkout(repo, tmp_path):
    """Flow 3, O7b and C2: the batch starts from a fresh publish, so a human merge on the remote
    reaches the clone, the export and the draft."""
    tenant = repo[0]
    clone = tenant.knowledge
    expected = advance_remote(repo, tmp_path)
    batch = delivery(repo, ForgeHTTP()).start_batch("fresh", lanes=LANES)
    assert batch.export.commit == expected
    current = target().current_export(tenant)
    assert (current.commit, current.path) == (batch.export.commit, batch.export.path)
    assert git(clone, "rev-parse", "HEAD") == expected
    assert (tenant.agent / "lessons/merged.md").read_text(encoding="utf-8") == "human-reviewed merge\n"

    assert _worktrees(clone) == [os.path.realpath(clone)], "a batch worktree was made"
    assert not location_path(tenant.worktrees).exists() or not any(location_path(tenant.worktrees).iterdir())
    assert branch_tip(clone, batch.branch) is None, "the batch's branch exists before any commit"
    assert git(clone, "status", "--porcelain") == ""

    # Amendment A / U9: the draft is `<T>/drafts/<id>/{owner, stage/{agent/, <token>}}`; the
    # batch's `draft_root` is its `stage/` (the root the box mounts as `staged`), and the owner
    # record sits beside it, never inside what the box sees.
    folder = location_path(tenant.tenant_root) / "drafts" / "fresh"
    assert batch.draft_root == folder / "stage"
    assert _drafts(tenant) == ["fresh"], "a temporary entry was left beside the draft"
    assert sorted(p.name for p in folder.iterdir()) == ["owner", "stage"]
    assert (folder / "owner").is_file()
    assert (folder / "owner").stat().st_size > 0, "the owner record is empty"
    staged = {p.name for p in batch.draft_root.iterdir()}
    assert "agent" in staged, staged
    # Beside `agent/` the stage holds at most the box token (each box start plants its own).
    assert len(staged - {"agent"}) <= 1, staged
    assert all((batch.draft_root / n).is_file() for n in staged - {"agent"}), staged
    assert not list(folder.rglob(".git"))
    assert odd_entries(folder) == []
    assert files_under(batch.draft_root / "agent") == agent_blobs(clone, expected) \
        == files_under(batch.export.path / "agent")
    assert _changes(batch.change_set()) == {}


@pytest.mark.parametrize("state", ["dirty", "untracked", "diverged"])
def test_refresh_refuses_local_state_without_creating_batch(repo, tmp_path, state):
    """O7b: a clone with local edits or a diverged `main` refuses, naming the state; nothing
    is fast-forwarded or published, and no branch, draft or temporary entry is made."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    advance_remote(repo, tmp_path)
    p = tenant.agent / "lessons/seed.md"
    if state == "untracked":
        p = tenant.agent / "lessons/untracked.md"
    p.write_text("local\n", encoding="utf-8")
    if state == "diverged":
        git(tenant.knowledge, "add", ".")
        git(tenant.knowledge, "commit", "-m", "local divergence")
    before = git(tenant.knowledge, "rev-parse", "HEAD")
    with pytest.raises(target().DeliveryRefused, match="dirty|diverg|fast.forward|untracked"):
        d.start_batch("refused", lanes=LANES)
    assert git(tenant.knowledge, "rev-parse", "HEAD") == before
    assert _branches(tenant.knowledge) == ["refs/heads/main"]
    assert _drafts(tenant) == []
    with pytest.raises(target().DeliveryRefused):
        target().current_export(tenant)


def test_publishing_after_a_batch_starts_never_changes_its_draft_or_branch(repo, tmp_path):
    tenant = repo[0]
    batch = delivery(repo, ForgeHTTP()).start_batch("pinned", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/pinned.md", "claimed before the publish\n")
    sha = batch.commit(batch.change_set(), "claim")
    batch.reset()
    draft = files_under(batch.draft_root)
    export = files_under(batch.export.path)
    newer = advance_remote(repo, tmp_path)
    other = target().TenantDelivery.open(tenant, defender_dir=DEFENDER, client=ForgeHTTP(origin=configured_origin(tenant.knowledge)).client, identity=fixture_identity(str(tenant.id)), origin=configured_origin(tenant.knowledge))
    assert other.publish().commit == newer
    assert target().current_export(tenant).commit == newer
    assert files_under(batch.draft_root) == draft
    assert branch_tip(tenant.knowledge, batch.branch) == sha
    assert files_under(batch.export.path) == export
    assert _changes(batch.change_set()) == {}


@pytest.mark.parametrize("left", ["draft", "branch"])
def test_start_batch_refuses_an_id_whose_draft_or_branch_exists(repo, left):
    """Start batch refuses an id whose draft or branch exists."""
    tenant = repo[0]
    clone = tenant.knowledge
    d = delivery(repo, ForgeHTTP())
    batch = d.start_batch("taken", lanes=LANES)
    if left == "branch":
        _write(batch.draft_root / "agent/lessons/new.md", "committed\n")
        batch.commit(batch.change_set(), "claim")
        batch.discard()
    tip, drafts = branch_tip(clone, batch.branch), _drafts(tenant)
    draft = files_under(batch.draft_root) if left == "draft" else None
    for again in (d, delivery(repo, ForgeHTTP())):
        with pytest.raises(target().DeliveryRefused):
            again.start_batch("taken", lanes=LANES)
    assert branch_tip(clone, batch.branch) == tip
    assert _drafts(tenant) == drafts
    if draft is not None:
        assert files_under(batch.draft_root) == draft


def test_discard_removes_the_draft_and_deliver_picks_up_the_branch(repo):
    tenant = repo[0]
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("discarded", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "committed, then discarded\n")
    sha = batch.commit(batch.change_set(), "claim")
    batch.discard()
    assert not os.path.lexists(batch.draft_root)
    assert _drafts(tenant) == []
    assert branch_tip(tenant.knowledge, batch.branch) == sha
    opened(delivery(repo, http).deliver("discarded"))
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha


@pytest.mark.parametrize("by", ["publish", "start_batch"])
def test_stale_draft_temporaries_are_swept_and_drafts_are_kept(repo, by):
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    kept = d.start_batch("kept", lanes=LANES)
    drafts = location_path(tenant.tenant_root) / "drafts"
    _write(drafts / ".killed-1a2b3c/agent/lessons/seed.md", "a part-built draft\n")
    (drafts / ".empty-4d5e6f").mkdir()
    draft = files_under(kept.draft_root)
    if by == "publish":
        d.publish()
    else:
        d.start_batch("next", lanes=LANES)
    assert _temps(tenant) == [], "a stale temporary was left in drafts/"
    assert _drafts(tenant) == sorted(["kept", *(["next"] if by == "start_batch" else [])])
    assert files_under(kept.draft_root) == draft


def test_a_draft_build_that_fails_leaves_nothing_and_its_id_can_be_retried(repo, tmp_path):
    """R3: the draft is built under the lock in `<T>/drafts/.<id>-<rand>` and renamed into place."""
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    export = _publish_big_lesson(repo, tmp_path, d)
    code, out, err = _build_elsewhere(repo, tmp_path, "retried", "fail")
    assert code == 0, err
    assert out.get("armed"), f"the build never began under drafts/: {out} {err}"
    assert "failed" in out, f"the build was never cut off: {out}"
    assert _drafts(tenant) == [], "a failed build left its draft or its temporary"
    assert _branches(tenant.knowledge) == ["refs/heads/main"]
    batch = d.start_batch("retried", lanes=LANES)
    assert files_under(batch.draft_root / "agent") == files_under(export.path / "agent")


@pytest.mark.parametrize("by", ["publish", "start_batch"])
def test_a_killed_draft_build_leaves_only_a_temporary_the_next_publish_or_start_sweeps(
        repo, tmp_path, by):
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    _publish_big_lesson(repo, tmp_path, d)
    code, out, err = _build_elsewhere(repo, tmp_path, "killed", "kill")
    assert code == -signal.SIGXFSZ or "failed" in out, \
        f"the build was never cut off: {code} {out} {err}"
    assert _drafts(tenant) == _temps(tenant), "a killed build left a draft in place"
    if by == "publish":
        d.publish()
    else:
        d.start_batch("next", lanes=LANES)
    assert _temps(tenant) == [], "the killed build's temporary was never swept"
    assert _drafts(tenant) == ([] if by == "publish" else ["next"])


def test_a_crash_after_the_draft_exists_refuses_its_id_until_a_publish_sweeps_the_dead_owners_draft(
        repo, tmp_path):
    """Re-spelled for amendment A / U9 + O-SWEEP (was `..._leaves_its_id_refused_for_good`): a
    crashed build's draft names its (now dead) owner. While it stands, its id is refused; the
    next publish, under the tenant lock, sweeps it because its owner is dead. A draft this live
    process owns survives the same publish (positive control)."""
    tenant = repo[0]
    code, out, err = _build_elsewhere(repo, tmp_path, "crashed", "crash")
    assert code == -signal.SIGKILL, f"{code} {out} {err}"
    drafts = location_path(tenant.tenant_root) / "drafts"
    draft = files_under(drafts / "crashed")
    assert "stage/agent/lessons/seed.md" in draft, draft
    assert "owner" in draft, draft
    d = delivery(repo, ForgeHTTP())
    with pytest.raises(target().DeliveryRefused):
        d.start_batch("crashed", lanes=LANES)
    assert files_under(drafts / "crashed") == draft, "a refused start touched the standing draft"
    other = d.start_batch("other", lanes=LANES)
    assert other.draft_root == drafts / "other" / "stage"
    d.publish()
    assert _drafts(tenant) == ["other"], "the dead owner's draft was not swept (or the live one was)"
    assert files_under(other.draft_root / "agent")
