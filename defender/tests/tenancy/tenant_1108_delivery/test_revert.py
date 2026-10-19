"""Tenant delivery: revert behavior through the public API."""
from __future__ import annotations


import pytest


from ._support import (
    FORK,
    LANES,
    MERGE_STYLES,
    ForgeHTTP,
    advance_remote,
    bounded,
    close_on_remote,
    delivery,
    forge_pulls,
    git,
    git_bytes,
    in_a_later_process,
    install_planting_hook,
    merge_on_remote,
    merged_agent_lesson,
    opened,
    plant_raw_commit,
    pr_row,
    push_object,
    push_to_remote,
    remote_refs,
    still_open,
    target,
)


from ._scenarios import (
    _name_status,
    _modes,
    _branches,
    _write,
    _revert_commit,
    _LEARNED,
    _reverted,
    _refused_revert,
    _on_main,
    _revert_and_merge,
    _FIRST,
    _SECOND,
    _agent_wrote,
    _AnswerLost,
)

@pytest.mark.parametrize("style", MERGE_STYLES)
def test_revert_peels_back_through_the_agents_changes_to_none_left(repo, tmp_path, style):
    """R1 (D-peel): each revert undoes the newest agent change whose result `main` still holds
    exactly and which has no merged revert."""
    _agent_wrote(repo, tmp_path, _FIRST, _SECOND, _FIRST)
    peeled = [_revert_and_merge(repo, tmp_path, _LEARNED, "learned", style) for _ in range(2)]
    main = git(repo[1], "rev-parse", "main")
    later = in_a_later_process(repo, "revert", _LEARNED, "learned")
    assert later.get("status") == "opened", later
    [create] = later["creates"]
    assert later["url"] == forge_pulls(repo[1])[-1]["html_url"]
    tip = git(repo[1], "rev-parse", f"refs/heads/{create['head']}")
    assert git(repo[1], "rev-parse", f"{tip}^") == main
    merge_on_remote(repo, tmp_path, create["head"], style, delete_branch=style != "merge")
    peeled.append(_on_main(repo, _LEARNED))
    assert peeled == [_SECOND, _FIRST, None]
    _refused_revert(repo, _LEARNED, "learned")


def test_a_revert_whose_pr_was_closed_refuses_the_next_and_skips_nothing(repo, tmp_path):
    """R1 with D-closed: a revert PR closed unmerged is a rejection."""
    _agent_wrote(repo, tmp_path, _FIRST, _SECOND, _FIRST)
    http = ForgeHTTP()
    opened(delivery(repo, http).revert(_LEARNED, "learned"), None)
    close_on_remote(repo, http.creates[-1]["head"])
    _refused_revert(repo, _LEARNED, "learned")
    branches = _branches(repo[1])
    later = in_a_later_process(repo, "revert", _LEARNED, "learned")
    assert "refused" in later, later
    assert later["creates"] == []
    assert _branches(repo[1]) == branches


def test_a_revert_whose_pr_is_open_answers_that_pr(repo, tmp_path):
    _agent_wrote(repo, tmp_path, _FIRST, _SECOND)
    url = opened(delivery(repo, ForgeHTTP()).revert(_LEARNED, "learned"), None)
    refs = remote_refs(repo[1])
    again = ForgeHTTP()
    still_open(delivery(repo, again).revert(_LEARNED, "learned"), url)
    assert not again.creates
    later = in_a_later_process(repo, "revert", _LEARNED, "learned")
    assert later.get("status") == "open", later
    assert later["url"] == url
    assert later["creates"] == []
    assert remote_refs(repo[1]) == refs


def test_each_lesson_of_one_batch_has_its_own_revert(repo, tmp_path):
    """R1 / C1: the record holds one row per lesson per batch, and a revert is recorded against
    its row."""
    writer = delivery(repo, ForgeHTTP())
    batch = writer.start_batch("two", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    (lane / "first.md").write_bytes(b"first\n")
    (lane / "second.md").write_bytes(b"second\n")
    batch.commit(batch.change_set(), "two lessons")
    opened(writer.finish(batch))
    merge_on_remote(repo, tmp_path, batch.branch)
    first = opened(delivery(repo, ForgeHTTP()).revert("agent/lessons/first.md", "first"), None)
    http = ForgeHTTP()
    main = git(repo[1], "rev-parse", "main")
    tip = _revert_commit(repo[1], http, main, delivery(repo, http).revert("agent/lessons/second.md", "second"))
    assert forge_pulls(repo[1])[-1]["html_url"] != first
    assert _name_status(repo[1], tip) == {"agent/lessons/second.md": "D"}


def test_a_closed_fork_pr_at_the_revert_commit_is_not_the_reverts(repo, tmp_path):
    """R1 / C1: every PR the revert's lookup considers is filtered by the base repository's id."""
    _agent_wrote(repo, tmp_path, _FIRST, _SECOND)
    http = ForgeHTTP()
    d = delivery(repo, http)
    before = set(_branches(repo[1]))
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused):
        d.revert(_LEARNED, "learned")
    remaining = sorted(set(_branches(repo[1])) - before)
    assert remaining, "the revert's push left no branch on the remote"
    sha = git(repo[1], "rev-parse", remaining[0])
    push_object(repo, sha, "refs/pull/5/head")
    http.add_pr(pr_row(5, "mallory-branch", repo=FORK, sha=sha, state="closed"))
    retry = ForgeHTTP()
    main = git(repo[1], "rev-parse", "main")
    tip = _revert_commit(repo[1], retry, main, delivery(repo, retry).revert(_LEARNED, "learned"))
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:{_LEARNED}") == _FIRST


def test_a_revert_whose_pr_was_created_but_unanswered_is_found_not_made_again(repo, tmp_path):
    """R1 / C1 (orchestrator ruling): the revert commit is recorded against its row as soon as it
    exists, before any push, and its PR is found by that commit."""
    _agent_wrote(repo, tmp_path, _FIRST, _SECOND)
    with pytest.raises(target().DeliveryRefused):
        delivery(repo, _AnswerLost()).revert(_LEARNED, "learned")
    [row] = [r for r in forge_pulls(repo[1]) if r["state"] == "open"]
    refs = remote_refs(repo[1])
    retry = ForgeHTTP()
    still_open(delivery(repo, retry).revert(_LEARNED, "learned"), row["html_url"])
    assert not retry.creates
    later = in_a_later_process(repo, "revert", _LEARNED, "learned")
    assert later.get("status") == "open", later
    assert later["url"] == row["html_url"]
    assert later["creates"] == []
    assert remote_refs(repo[1]) == refs


@pytest.mark.parametrize("failure", ["pr-request", "push"])
def test_a_revert_that_never_got_a_pr_is_made_again(repo, tmp_path, failure):
    _agent_wrote(repo, tmp_path, _FIRST, _SECOND)
    http = ForgeHTTP()
    d = delivery(repo, http)
    hook = repo[1] / "hooks" / "pre-receive"
    if failure == "push":
        hook.parent.mkdir(exist_ok=True)
        hook.write_text("#!/bin/sh\necho 'p3: the remote refused this push' >&2\nexit 1\n",
                        encoding="utf-8")
        hook.chmod(0o755)
    else:
        http.fail_create = True
    with pytest.raises(target().DeliveryRefused):
        d.revert(_LEARNED, "learned")
    hook.unlink(missing_ok=True)
    retry = ForgeHTTP()
    main = git(repo[1], "rev-parse", "main")
    tip = _revert_commit(repo[1], retry, main, delivery(repo, retry).revert(_LEARNED, "learned"))
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:{_LEARNED}") == _FIRST


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_a_lesson_created_then_changed_within_one_batch_reverts_to_absent(repo, tmp_path, style):
    """R9: the record holds one row per lesson per batch, its net change."""
    writer = delivery(repo, ForgeHTTP())
    batch = writer.start_batch("written-twice", lanes=LANES)
    for words in (_FIRST, _SECOND):
        (batch.draft_root / _LEARNED).write_bytes(words)
        batch.commit(batch.change_set(), "claim")
        batch.reset()
    opened(writer.finish(batch))
    merge_on_remote(repo, tmp_path, batch.branch, style)
    tip = _reverted(repo, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_revert_deletes_a_lesson_the_commit_maker_created(repo, tmp_path, style):
    """Revert deletes a lesson the commit maker created."""
    merged_agent_lesson(repo, tmp_path, "created", _LEARNED, b"the agent's lesson\n", style)
    advance_remote(repo, tmp_path)
    tip = _reverted(repo, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_revert_restores_what_a_lesson_held_before_the_commit_maker_changed_it(repo, tmp_path, style):
    merged_agent_lesson(repo, tmp_path, "changed", "agent/lessons/seed.md",
                        b"seed, as the agent rewrote it\n", style)
    tip = _reverted(repo, "agent/lessons/seed.md", "seed")
    assert _name_status(repo[1], tip) == {"agent/lessons/seed.md": "M"}
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:agent/lessons/seed.md") == b"seed\n"
    assert _modes(repo[1], tip, "agent/lessons/seed.md") == {"agent/lessons/seed.md": "100644"}


@pytest.mark.parametrize("history", [(b"first\n", b"second\n"), (b"first\n", b"second\n", b"first\n")],
                         ids=["changed-once", "back-to-the-first-bytes"])
def test_revert_undoes_only_the_latest_of_several_commit_maker_changes(repo, tmp_path, history):
    """Choice 5 (orchestrator ruling): the commit-maker created a lesson, then changed it in
    later batches, all merged."""
    for number, words in enumerate(history):
        merged_agent_lesson(repo, tmp_path, f"batch-{number}", _LEARNED, words)
    tip = _reverted(repo, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "M"}
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:{_LEARNED}") == history[-2]


def test_revert_undoes_one_lesson_of_a_claim_that_wrote_several(repo, tmp_path):
    """Flow 4 / O-C: a revert is a change set for the one lesson named, made by the commit-maker,
    never an undoing of the agent's whole commit."""
    writer = delivery(repo, ForgeHTTP())
    batch = writer.start_batch("several", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    (lane / "learned.md").write_bytes(b"one of the claim's lessons\n")
    (lane / "other.md").write_bytes(b"another of the claim's lessons\n")
    (lane / "seed.md").write_bytes(b"seed, as the same claim rewrote it\n")
    batch.commit(batch.change_set(), "learning several")
    writer.finish(batch)
    merge_on_remote(repo, tmp_path, batch.branch)
    tip = _reverted(repo, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


def test_revert_ignores_a_later_commit_maker_change_whose_pr_is_still_open(repo, tmp_path):
    """Choice 5 (orchestrator ruling): the change a revert undoes is the most recent commit-maker
    change to the lesson whose resulting bytes equal `main`'s."""
    merged_agent_lesson(repo, tmp_path, "created", _LEARNED, b"the agent's merged words\n")
    writer = delivery(repo, ForgeHTTP())
    batch = writer.start_batch("unmerged", lanes=LANES)
    (batch.draft_root / _LEARNED).write_bytes(b"the agent's unmerged words\n")
    batch.commit(batch.change_set(), "learning unmerged")
    assert writer.finish(batch).status == "opened"
    tip = _reverted(repo, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


def test_revert_proceeds_when_main_again_holds_exactly_the_agents_bytes(repo, tmp_path):
    """Choice 5 (orchestrator ruling): the test is content, not history."""
    agent_bytes = b"seed, as the agent rewrote it\n"
    merged_agent_lesson(repo, tmp_path, "changed", "agent/lessons/seed.md", agent_bytes)
    push_to_remote(repo, tmp_path, lambda c: _write(c / "agent/lessons/seed.md", "a human's edit\n"))
    push_to_remote(repo, tmp_path, lambda c: (c / "agent/lessons/seed.md").write_bytes(agent_bytes))
    tip = _reverted(repo, "agent/lessons/seed.md", "seed")
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:agent/lessons/seed.md") == b"seed\n"


def test_revert_recreates_a_lesson_the_commit_maker_deleted(repo, tmp_path):
    """Revert recreates a lesson the commit maker deleted."""
    merged_agent_lesson(repo, tmp_path, "deleted", "agent/lessons/seed.md", None)
    tip = _reverted(repo, "agent/lessons/seed.md", "seed")
    assert _name_status(repo[1], tip) == {"agent/lessons/seed.md": "A"}
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:agent/lessons/seed.md") == b"seed\n"
    assert _modes(repo[1], tip, "agent/lessons/seed.md") == {"agent/lessons/seed.md": "100644"}


@pytest.mark.parametrize(("path", "edit"), [
    (_LEARNED, b"a human's later edit\n"), ("agent/lessons/seed.md", b"a human's later edit\n"),
    ("agent/lessons/seed.md", b"the human's words\n"),
    ("agent/lessons/seed.md", b"the agent's words\nand a human's addition\n"),
], ids=["agent-created", "agent-changed", "same-length-edit", "appended-edit"])
def test_revert_refuses_a_lesson_changed_on_main_since_the_commit_maker_wrote_it(
        repo, tmp_path, path, edit):
    """Revert refuses a lesson changed on main since the commit maker wrote it."""
    agent_words = b"the agent's words\n"
    assert len(agent_words) == len(b"the human's words\n")
    assert b"the agent's words\nand a human's addition\n".startswith(agent_words)
    merged_agent_lesson(repo, tmp_path, "written", path, agent_words)
    push_to_remote(repo, tmp_path, lambda c: (c / path).write_bytes(edit))
    _refused_revert(repo, path, "written")


@pytest.mark.parametrize("path", ["agent/lessons/seed.md", "agent/lessons/merged.md"],
                         ids=["seeded", "human-merged"])
def test_revert_refuses_a_lesson_the_commit_maker_never_wrote(repo, tmp_path, path):
    advance_remote(repo, tmp_path)
    _refused_revert(repo, path, "human")


def test_a_later_process_reverts_by_the_commit_maker_record(repo, tmp_path):
    """A later process reverts by the commit maker record."""
    remote = repo[1]
    merged_agent_lesson(repo, tmp_path, "changed", "agent/lessons/seed.md", b"seed, as the agent rewrote it\n")
    main = git(remote, "rev-parse", "main")
    later = in_a_later_process(repo, "revert", "agent/lessons/seed.md", "seed")
    assert later.get("status") == "opened", later
    [create] = later["creates"]
    assert create["base"] == "main"
    assert later["url"] == forge_pulls(remote)[-1]["html_url"]
    tip = git(remote, "rev-parse", f"refs/heads/{create['head']}")
    assert git(remote, "rev-parse", f"{tip}^") == main
    assert git(remote, "rev-parse", "main") == main
    assert _name_status(remote, tip) == {"agent/lessons/seed.md": "M"}
    assert git_bytes(remote, "cat-file", "blob", f"{tip}:agent/lessons/seed.md") == b"seed\n"


def test_a_later_process_refuses_to_revert_a_lesson_changed_on_main(repo, tmp_path):
    """Choice 5 across processes: after a human edit on `main` of the commit-maker's merged
    lesson, a revert from a fresh process refuses with nothing pushed or requested."""
    remote = repo[1]
    merged_agent_lesson(repo, tmp_path, "written", _LEARNED, b"the agent's words\n")
    push_to_remote(repo, tmp_path, lambda c: _write(c / _LEARNED, "a human's later edit\n"))
    main, branches = git(remote, "rev-parse", "main"), _branches(remote)
    later = in_a_later_process(repo, "revert", _LEARNED, "written")
    assert "refused" in later, later
    assert later["creates"] == []
    assert _branches(remote) == branches
    assert git(remote, "rev-parse", "main") == main


def test_revert_refuses_a_commit_laid_on_its_branch_by_a_clone_hook(repo, tmp_path):
    """Revert refuses a commit laid on its branch by a clone hook."""
    tenant, remote, _ = repo
    merged_agent_lesson(repo, tmp_path, "learned", _LEARNED, b"the agent's lesson\n")
    http = ForgeHTTP()
    d = delivery(repo, http)
    branches = _branches(remote)
    marker = tmp_path / "planted"
    install_planting_hook(tenant.knowledge, git(remote, "rev-parse", "main"), marker,
                          "agent/lessons/raw.md", b"raw git, not the commit-maker\n")
    _, error, hung = bounded(lambda: d.revert(_LEARNED, "learned"))
    assert not hung
    if marker.exists():
        assert isinstance(error, target().DeliveryRefused), error
        assert _branches(remote) == branches
        assert not http.creates
    else:
        assert error is None, f"the revert refused though nothing was laid on its branch: {error}"
        assert len(http.creates) == 1


def test_a_retried_revert_never_sends_a_commit_laid_on_its_branch(repo, tmp_path):
    """O-C on the revert route, with no hook: a revert pushes its branch, then its PR request
    fails."""
    tenant, remote, _ = repo
    merged_agent_lesson(repo, tmp_path, "learned", _LEARNED, b"the agent's lesson\n")
    http = ForgeHTTP()
    d = delivery(repo, http)
    before = set(_branches(remote))
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused, match="503|forge|PR|pull"):
        d.revert(_LEARNED, "learned")
    remaining = sorted(set(_branches(remote)) - before)
    if not remaining:
        return  # the failed request left no branch to lay a commit on (choice 16)
    branch = remaining[0]
    made = git(remote, "rev-parse", branch)
    planted = plant_raw_commit(tenant.knowledge, branch, "agent/lessons/raw.md",
                               b"raw git, not the commit-maker\n", base=made)
    http.fail_create = False
    _, _error, hung = bounded(lambda: d.revert(_LEARNED, "learned"))
    assert not hung
    assert planted not in git(remote, "rev-list", "--all").split()


@pytest.mark.parametrize("path", ["agent/.tenant-id", "settings/lead-zero.yaml",
                                  "agent/lessons/absent.md", "agent/lessons/../.tenant-id",
                                  "agent/lessons/\ud800.md"],
                         ids=["tenant-id", "settings", "absent", "traversal", "lone-surrogate"])
def test_revert_refuses_a_path_that_is_not_a_lesson_on_main(repo, path):
    """Revert refuses a path that is not a lesson on main."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    with pytest.raises(target().DeliveryRefused):
        d.revert(path, "x")
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert not http.creates
