"""Tenant delivery: batches behavior through the public API."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path


import os


import signal


import pytest


from ._support import (
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
    push_and_open,
    push_to_remote,
    target,
)


from ._clone_free_1618 import delivery_without_clone

from ._scenarios import (
    _changes,
    _branches,
    _write,
    _drafts,
    _temps,
    _build_elsewhere,
    _publish_big_lesson,
)

def test_start_batch_makes_a_git_free_draft_of_the_fetched_main_and_no_checkout(repo, tmp_path):
    """The batch starts from `main` as its delivery's opening fetch saw it, so a human merge on the remote before the
    open reaches the draft (#1618 D4: no clone, export or `current`; `Batch.base_commit` is the base)."""
    tenant = repo[0]
    expected = advance_remote(repo, tmp_path)
    with delivery(repo, ForgeHTTP()) as d:
        batch = d.start_batch("fresh", lanes=LANES)
        assert batch.base_commit == expected
        assert not location_path(tenant.worktrees).exists() or not any(location_path(tenant.worktrees).iterdir())
        assert branch_tip(d.repository.path, batch.branch) is None, "the batch's branch exists before any commit"
        assert branch_tip(repo[1], batch.branch) is None, "the batch's branch was pushed before any commit"

        # The draft is `<T>/drafts/<id>/{owner, stage/{agent/, <token>}}`; the
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
        assert files_under(batch.draft_root / "agent") == agent_blobs(repo[1], expected)
        assert (batch.draft_root / "agent/lessons/merged.md").read_text(encoding="utf-8") == "human-reviewed merge\n"
        assert _changes(batch.change_set()) == {}
    assert sorted(p.name for p in location_path(tenant.tenant_root).iterdir()
                  if p.name in ("knowledge", "exports", "knowledge.lock")) == [], "a clone, export or lock was made"


# retired (#1618 design "Retired promises": `test_batches::refresh_refuses_local_state[*]`, a clone-state check): with
# no clone there is no dirty, untracked or diverged local `main` to refuse.


def test_a_later_delivery_after_main_advances_never_changes_a_started_batchs_draft_or_branch(repo, tmp_path):
    """A merge on `main` after a batch started, seen by a later delivery's own fetch, leaves the first batch's draft,
    branch and change set as they were (was: "publishing after a batch starts"; #1618 has no publish, a later tick's
    delivery is what sees the newer `main`)."""
    with delivery(repo, ForgeHTTP()) as d:
        batch = d.start_batch("pinned", lanes=LANES)
        _write(batch.draft_root / "agent/lessons/pinned.md", "claimed before the merge\n")
        sha = batch.commit(batch.change_set(), "claim")
        batch.reset()
        draft = files_under(batch.draft_root)
        newer = advance_remote(repo, tmp_path)
        with delivery(repo, ForgeHTTP()) as later:
            assert later.start_batch("later", lanes=LANES).base_commit == newer, "control: the later delivery saw the merge"
        assert files_under(batch.draft_root) == draft
        assert d.repository.branch_tip(batch.branch) == sha
        assert batch.base_commit != newer
        assert _changes(batch.change_set()) == {}


@pytest.mark.parametrize("left", ["draft", "branch"])
def test_start_batch_refuses_an_id_whose_draft_or_branch_exists(repo, left):
    """A batch id whose draft stands, or whose branch exists, is refused by the delivery that made it and by a later one.
    #1618: an unpushed branch lives only in its holder's private repository, so the `branch` arm's branch is pushed
    (a takeover's case: the branch is on the forge) before the later delivery opens; the holder's own delivery refuses
    from its local branch."""
    tenant = repo[0]
    with delivery(repo, ForgeHTTP()) as d:
        batch = d.start_batch("taken", lanes=LANES)
        if left == "branch":
            _write(batch.draft_root / "agent/lessons/new.md", "committed\n")
            sha = batch.commit(batch.change_set(), "claim")
            batch.discard()
            batch.repository.push(sha, batch.branch)
            assert branch_tip(repo[1], batch.branch) == sha, "premise: the taken branch is on the forge"
        tip, drafts = branch_tip(repo[1], batch.branch), _drafts(tenant)
        draft = files_under(batch.draft_root) if left == "draft" else None
        with delivery(repo, ForgeHTTP()) as later:
            for again in (d, later):
                with pytest.raises(target().DeliveryRefused):
                    again.start_batch("taken", lanes=LANES)
        assert branch_tip(repo[1], batch.branch) == tip
        assert _drafts(tenant) == drafts
        if draft is not None:
            assert files_under(batch.draft_root) == draft


def test_start_batch_accepts_a_fresh_id_beside_a_taken_one(repo):
    """Control for the refusal above: on the same deliveries a fresh id starts."""
    with delivery(repo, ForgeHTTP()) as d:
        d.start_batch("taken", lanes=LANES)
        assert d.start_batch("fresh-id", lanes=LANES).draft_root.is_dir()


def test_discard_removes_the_draft_and_the_branch_still_reaches_the_forge(repo):
    tenant = repo[0]
    with delivery(repo, ForgeHTTP()) as d:
        batch = d.start_batch("discarded", lanes=LANES)
        _write(batch.draft_root / "agent/lessons/new.md", "committed, then discarded\n")
        sha = batch.commit(batch.change_set(), "claim")
        batch.discard()
        assert not os.path.lexists(batch.draft_root)
        assert _drafts(tenant) == []
        assert d.repository.branch_tip(batch.branch) == sha
        opened(push_and_open(batch))
    # retired here: a fresh delivery picking the branch up by the on-disk record; that is a takeover over the store's
    # record (design D11, A2 D1): tenant_1108_p4/test_1278_tick.py::test_o1_a_pushed_branch_with_no_pr_is_taken_over_and_gets_its_one_pr
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha


# The `[publish]` arms below are retired (#1618: there is no publish; flow 8's host triggers are `fetch_copy`'s start, the
# helper's `batch.start` and a host drain's tick, whose delivery's `start_batch` sweeps); the `start_batch` arm stays.
def test_stale_draft_temporaries_are_swept_and_drafts_are_kept(repo):
    tenant = repo[0]
    with delivery(repo, ForgeHTTP()) as d:
        kept = d.start_batch("kept", lanes=LANES)
        drafts = location_path(tenant.tenant_root) / "drafts"
        _write(drafts / ".killed-1a2b3c/agent/lessons/seed.md", "a part-built draft\n")
        (drafts / ".empty-4d5e6f").mkdir()
        draft = files_under(kept.draft_root)
        d.start_batch("next", lanes=LANES)
        assert _temps(tenant) == [], "a stale temporary was left in drafts/"
        assert _drafts(tenant) == sorted(["kept", "next"])
        assert files_under(kept.draft_root) == draft


def test_a_draft_build_that_fails_leaves_nothing_and_its_id_can_be_retried(repo, tmp_path):
    """The draft is built in `<T>/drafts/.<id>-<rand>` and renamed into place."""
    tenant = repo[0]
    big = _publish_big_lesson(repo, tmp_path)
    code, out, err = _build_elsewhere(repo, tmp_path, "retried", "fail")
    assert code == 0, err
    assert out.get("armed"), f"the build never began under drafts/: {out} {err}"
    assert "failed" in out, f"the build was never cut off: {out}"
    assert _drafts(tenant) == [], "a failed build left its draft or its temporary"
    assert _branches(repo[1]) == ["refs/heads/main"]
    with delivery(repo, ForgeHTTP()) as d:
        batch = d.start_batch("retried", lanes=LANES)
        assert files_under(batch.draft_root / "agent") == agent_blobs(repo[1], big)


def test_a_killed_draft_build_leaves_only_a_temporary_the_next_start_sweeps(repo, tmp_path):
    tenant = repo[0]
    _publish_big_lesson(repo, tmp_path)
    code, out, err = _build_elsewhere(repo, tmp_path, "killed", "kill")
    assert code == -signal.SIGXFSZ or "failed" in out, \
        f"the build was never cut off: {code} {out} {err}"
    assert _drafts(tenant) == _temps(tenant), "a killed build left a draft in place"
    assert _temps(tenant), "premise: the killed build left its temporary"
    with delivery(repo, ForgeHTTP()) as d:
        d.start_batch("next", lanes=LANES)
    assert _temps(tenant) == [], "the killed build's temporary was never swept"
    assert _drafts(tenant) == ["next"]


def test_a_crash_after_the_draft_exists_refuses_its_id_until_a_later_start_sweeps_the_dead_owners_draft(
        repo, tmp_path):
    """A crashed build's draft names its (now dead) owner: while it stands its id is refused;
    the next batch start sweeps it (flow 8). A draft this live process owns survives
    the same sweep (positive control)."""
    tenant = repo[0]
    code, out, err = _build_elsewhere(repo, tmp_path, "crashed", "crash")
    assert code == -signal.SIGKILL, f"{code} {out} {err}"
    drafts = location_path(tenant.tenant_root) / "drafts"
    draft = files_under(drafts / "crashed")
    assert "stage/agent/lessons/seed.md" in draft, draft
    assert "owner" in draft, draft
    with delivery(repo, ForgeHTTP()) as d:
        with pytest.raises(target().DeliveryRefused):
            d.start_batch("crashed", lanes=LANES)
        assert files_under(drafts / "crashed") == draft, "a refused start touched the standing draft"
        other = d.start_batch("other", lanes=LANES)
        assert other.draft_root == drafts / "other" / "stage"
        assert _drafts(tenant) == ["other"], "the dead owner's draft was not swept by the next start"
        d.start_batch("third", lanes=LANES)
        assert _drafts(tenant) == ["other", "third"], "the dead owner's draft was not swept (or the live one was)"
        assert files_under(other.draft_root / "agent")


def test_1618_f6_a_later_fetch_in_the_same_repository_leaves_the_holders_unpushed_branch_alone(repo, tmp_path):
    """With no clone, a batch's commit on its unpushed branch survives a fetch made after a merge landed: not moved, not deleted. (F6 fetch rules)"""
    with delivery_without_clone(repo, ForgeHTTP()) as d:  # FORCED: a delivery is a context manager owning its private repository (the repository is read only inside it)
        batch = d.start_batch("holder", lanes=LANES)
        _write(batch.draft_root / "agent/lessons/unpushed.md", "work that is only here\n")
        sha = batch.commit(batch.change_set(), "unpushed work")
        assert d.repository.branch_tip(batch.branch) == sha
        assert branch_tip(repo[1], batch.branch) is None, "premise: nothing of the batch is on the remote"
        merged = advance_remote(repo, tmp_path)
        # A lapsed holder's branch is a real case: the same-named remote branch is pushed, then force-moved to a commit
        # that is not its descendant, between the opening fetch and the later fetch.
        first, second = _force_moved_remote_branch(repo, tmp_path, batch.branch)

        d.repository.fetch()  # FORCED: the repository's fetch entry (today's name); the design's later fetches name their refs, no wildcard and no prune

        assert branch_tip(repo[1], batch.branch) == second != first, "premise: the remote's batch branch was force-moved"
        assert d.repository.branch_tip(batch.branch) == sha, "the holder's unpushed branch was moved or pruned by a fetch"
        assert d.repository.holds_commit(merged), "control: the fetch did bring the merge"


def _force_moved_remote_branch(repo, tmp_path, branch):
    """Push `branch` to the remote at one commit, then force it to a sibling commit (same parent): `(first, second)`."""
    writer = tmp_path / "lapsed-holder"
    git(writer.parent, "clone", repo[1], writer)
    git(writer, "checkout", "-b", branch)
    tips = []
    for text in ("first push\n", "force-moved\n"):
        git(writer, "reset", "--hard", "origin/main")
        (writer / "agent" / "lessons" / "lapsed.md").write_text(text, encoding="utf-8")
        git(writer, "add", "-A")
        git(writer, "commit", "-m", "lapsed holder")
        git(writer, "push", "--force", "origin", f"HEAD:refs/heads/{branch}")
        tips.append(git(writer, "rev-parse", "HEAD"))
    return tuple(tips)


_OTHER_TENANT = "00000000-0000-4000-8000-0000000000ff"


@pytest.mark.parametrize("case", ["other-tenant", "settings-not-plain"])
def test_start_batch_refuses_a_main_the_run_copy_would_refuse_and_leaves_no_draft(repo, tmp_path, case):
    """A batch's draft is read through the same check as a run's copy (#1618 follow-up): a `main` whose
    `agent/.tenant-id` names another tenant, or whose `settings/` holds a path that is not plain, refuses the
    batch, naming why, and leaves no draft. Control: the earlier `main` drafts."""
    tenant = repo[0]
    with delivery(repo, ForgeHTTP()) as d:
        assert d.start_batch("before", lanes=LANES).id == "before", "control: a good main drafts"

    def bad(writer):
        if case == "other-tenant":
            (writer / "agent" / ".tenant-id").write_text(f"{_OTHER_TENANT}\n", encoding="utf-8")
        else:
            (writer / "settings" / " lead-space.yaml").write_text("x: 1\n", encoding="utf-8")
    push_to_remote(repo, tmp_path, bad)
    with delivery(repo, ForgeHTTP()) as d, pytest.raises(target().DeliveryRefused, match="names tenant|not a plain path"):
        d.start_batch("after", lanes=LANES)
    assert not (location_path(tenant.tenant_root) / "drafts" / "after").exists()
