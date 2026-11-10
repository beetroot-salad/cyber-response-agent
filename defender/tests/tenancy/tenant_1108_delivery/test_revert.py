"""Tenant delivery: revert behavior through `revert_lesson` over the learning store (#1278).

The commit-maker's record lives in the learning store (design D5, Reverts); a revert is a batch of kind
revert that `revert_lesson` claims, commits with the commit-maker and opens a PR for. Each test drives it over
a real store (postgres), the lessons written by claimed author batches merged on the forge by a person.

Retired with the file-state design (the on-disk commit record and the delivery object's own `revert`):
- `test_a_later_process_reverts_by_the_commit_maker_record`, `test_a_later_process_refuses_to_revert_a_lesson_changed_on_main`:
  the record is the store's rows, read by whichever process asks (design D5, Reverts); every test here already reads it
  through a fresh delivery object, and `tenant_1108_p4/test_1278_revert.py::test_reverts_a_revert_opens_beside_an_open_author_batch_and_its_commit_is_in_the_record`
  runs the CLI over a record written by another run.
- `test_a_closed_fork_pr_at_the_revert_commit_is_not_the_reverts`: a revert no longer looks its PR up by commit; its
  PR is opened by the batch that owns the branch, and a retry is a takeover (design Crash recovery, A2 D1). The
  repository-id filter on a branch's PR lookup is pinned by
  `test_delivery.py::test_finish_answers_only_with_the_pr_for_its_own_head`.
- `test_a_retried_revert_never_sends_a_commit_laid_on_its_branch`: a retry is a takeover over the store's record; a branch
  tip beyond the record is not opened (`tenant_1108_p4/test_1278_tick.py::test_o5_a_forge_tip_beyond_the_record_is_not_opened_and_goes_to_a_person`).
"""
from __future__ import annotations

import sys

import pytest

from ._revert_store import end_revert, refused_revert, revert, revert_batches, wrote
from ._scenarios import (
    _FIRST,
    _LEARNED,
    _SECOND,
    _AnswerLost,
    _MAKES_COMMITS,
    _SENDS_COMMITS,
    _branches,
    _census,
    _modes,
    _name_status,
    _on_main,
    _revert_commit,
    _worktree_made,
    _write,
)
from ._support import (
    MERGE_STYLES,
    ForgeHTTP,
    advance_remote,
    bounded,
    forge_pulls,
    git,
    git_bytes,
    git_subcommand,
    install_planting_hook,
    opened,
    push_to_remote,
    remote_refs,
    still_open,
    target,
)

pytestmark = pytest.mark.postgres

SEED = "agent/lessons/seed.md"


def _wrote_each(repo, tmp_path, store, *words, path=_LEARNED):
    """The commit-maker wrote `path` once per entry of `words`, each in a batch of its own, each merged."""
    for number, content in enumerate(words):
        wrote(repo, tmp_path, store, f"batch-{number}", [{path: content}])


def _reverted(repo, store, lesson, name):
    """Revert `lesson`; returns the revert's one commit on the remote (directly on `main`, which does not move)."""
    http = ForgeHTTP()
    main = git(repo[1], "rev-parse", "main")
    return _revert_commit(repo[1], http, main, revert(repo, store, http, lesson, name))


def _revert_and_merge(repo, tmp_path, store, lesson, name, style):
    """Revert `lesson`, merge the revert's PR as a person would in `style` (branch deleted after a squash or a rebase)
    and end its batch merged. Returns what `main` then holds for the lesson."""
    _reverted(repo, store, lesson, name)
    end_revert(repo, tmp_path, store, "merged", style, delete_branch=style != "merge")
    return _on_main(repo, lesson)


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_revert_peels_back_through_the_agents_changes_to_none_left(repo, tmp_path, store, style):
    """Each revert undoes the newest agent change whose result `main` still holds exactly and
    which has no merged revert."""
    _wrote_each(repo, tmp_path, store, _FIRST, _SECOND, _FIRST)
    peeled = [_revert_and_merge(repo, tmp_path, store, _LEARNED, "learned", style) for _ in range(3)]
    assert peeled == [_SECOND, _FIRST, None]
    refused_revert(repo, store, _LEARNED, "learned")


def test_a_revert_whose_pr_was_closed_refuses_the_next_and_skips_nothing(repo, tmp_path, store):
    """A revert PR closed unmerged is a rejection."""
    _wrote_each(repo, tmp_path, store, _FIRST, _SECOND, _FIRST)
    opened(revert(repo, store, ForgeHTTP(), _LEARNED, "learned"), None)
    end_revert(repo, tmp_path, store, "closed")
    refused_revert(repo, store, _LEARNED, "learned")


def test_a_revert_whose_pr_is_open_answers_that_pr(repo, tmp_path, store):
    _wrote_each(repo, tmp_path, store, _FIRST, _SECOND)
    url = opened(revert(repo, store, ForgeHTTP(), _LEARNED, "learned"), None)
    refs = remote_refs(repo[1])
    again = ForgeHTTP()
    still_open(revert(repo, store, again, _LEARNED, "learned"), url)
    assert not again.creates
    assert remote_refs(repo[1]) == refs
    assert len(revert_batches(repo, store)) == 1


def test_each_lesson_of_one_batch_has_its_own_revert(repo, tmp_path, store):
    """The record holds one row per lesson per batch, and a revert is recorded against its
    row."""
    wrote(repo, tmp_path, store, "two", [{"agent/lessons/first.md": b"first\n", "agent/lessons/second.md": b"second\n"}])
    first = opened(revert(repo, store, ForgeHTTP(), "agent/lessons/first.md", "first"), None)
    http = ForgeHTTP()
    main = git(repo[1], "rev-parse", "main")
    tip = _revert_commit(repo[1], http, main, revert(repo, store, http, "agent/lessons/second.md", "second"))
    assert forge_pulls(repo[1])[-1]["html_url"] != first
    assert _name_status(repo[1], tip) == {"agent/lessons/second.md": "D"}


def test_a_revert_whose_pr_was_created_but_unanswered_is_not_made_again(repo, tmp_path, store):
    """The forge made the PR and lost the answer: the revert batch stays working with its commit recorded, and a
    second revert makes no second branch, commit or PR (a takeover, not a retry, finishes it; Crash recovery)."""
    _wrote_each(repo, tmp_path, store, _FIRST, _SECOND)
    with pytest.raises(target().DeliveryRefused):
        revert(repo, store, _AnswerLost(), _LEARNED, "learned")
    [row] = [r for r in forge_pulls(repo[1]) if r["state"] == "open"]
    [working] = revert_batches(repo, store)
    assert working.phase == "working"
    refs = remote_refs(repo[1])
    retry = ForgeHTTP()
    with pytest.raises(target().DeliveryRefused, match="not made again"):
        revert(repo, store, retry, _LEARNED, "learned")
    assert not retry.creates
    assert remote_refs(repo[1]) == refs
    assert [r["html_url"] for r in forge_pulls(repo[1]) if r["state"] == "open"] == [row["html_url"]]
    assert [b.id for b in revert_batches(repo, store)] == [working.id]


@pytest.mark.parametrize("failure", ["pr-request", "push"])
def test_a_revert_that_never_got_a_pr_stays_one_working_batch_for_a_takeover(repo, tmp_path, store, failure):
    """A revert refused after its commit (the push or the PR request) leaves its batch working with the commit
    recorded: a second revert makes nothing new, so exactly one revert awaits the takeover that finishes it
    (`test_1278_revert.py::test_reverts_a_revert_that_crashed_after_its_push_is_taken_over_and_gets_one_pr`)."""
    _wrote_each(repo, tmp_path, store, _FIRST, _SECOND)
    http = ForgeHTTP()
    hook = repo[1] / "hooks" / "pre-receive"
    if failure == "push":
        hook.parent.mkdir(exist_ok=True)
        hook.write_text("#!/bin/sh\necho 'p3: the remote refused this push' >&2\nexit 1\n", encoding="utf-8")
        hook.chmod(0o755)
    else:
        http.fail_create = True
    with pytest.raises(target().DeliveryRefused):
        revert(repo, store, http, _LEARNED, "learned")
    hook.unlink(missing_ok=True)
    [working] = revert_batches(repo, store)
    assert working.phase == "working"
    assert [r for r in store.commit_record(str(repo[0].id)) if r.reverts], "the revert commit was not recorded"
    branches, retry = _branches(repo[1]), ForgeHTTP()
    with pytest.raises(target().DeliveryRefused, match="not made again"):
        revert(repo, store, retry, _LEARNED, "learned")
    assert not retry.creates
    assert _branches(repo[1]) == branches
    assert [b.id for b in revert_batches(repo, store)] == [working.id]


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_a_lesson_created_then_changed_within_one_batch_reverts_to_absent(repo, tmp_path, store, style):
    """The record holds one row per lesson per batch: its net change."""
    wrote(repo, tmp_path, store, "written-twice", [{_LEARNED: _FIRST}, {_LEARNED: _SECOND}], style=style)
    tip = _reverted(repo, store, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_revert_deletes_a_lesson_the_commit_maker_created(repo, tmp_path, store, style):
    wrote(repo, tmp_path, store, "created", [{_LEARNED: b"the agent's lesson\n"}], style=style)
    advance_remote(repo, tmp_path)
    tip = _reverted(repo, store, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


@pytest.mark.parametrize("style", MERGE_STYLES)
def test_revert_restores_what_a_lesson_held_before_the_commit_maker_changed_it(repo, tmp_path, store, style):
    wrote(repo, tmp_path, store, "changed", [{SEED: b"seed, as the agent rewrote it\n"}], style=style)
    tip = _reverted(repo, store, SEED, "seed")
    assert _name_status(repo[1], tip) == {SEED: "M"}
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:{SEED}") == b"seed\n"
    assert _modes(repo[1], tip, SEED) == {SEED: "100644"}


@pytest.mark.parametrize("history", [(b"first\n", b"second\n"), (b"first\n", b"second\n", b"first\n")],
                         ids=["changed-once", "back-to-the-first-bytes"])
def test_revert_undoes_only_the_latest_of_several_commit_maker_changes(repo, tmp_path, store, history):
    """The commit-maker created a lesson, then changed it in later batches, all merged."""
    _wrote_each(repo, tmp_path, store, *history)
    tip = _reverted(repo, store, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "M"}
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:{_LEARNED}") == history[-2]


def test_revert_undoes_one_lesson_of_a_claim_that_wrote_several(repo, tmp_path, store):
    """A revert is a change set for the one lesson named, made by the commit-maker, never an
    undoing of the agent's whole commit."""
    wrote(repo, tmp_path, store, "several", [{
        "agent/lessons/learned.md": b"one of the claim's lessons\n",
        "agent/lessons/other.md": b"another of the claim's lessons\n",
        SEED: b"seed, as the same claim rewrote it\n"}])
    tip = _reverted(repo, store, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


def test_revert_ignores_a_later_commit_maker_change_whose_pr_is_still_open(repo, tmp_path, store):
    """The change a revert undoes is the most recent commit-maker change to the lesson whose
    resulting bytes equal `main`'s."""
    wrote(repo, tmp_path, store, "created", [{_LEARNED: b"the agent's merged words\n"}])
    wrote(repo, tmp_path, store, "unmerged", [{_LEARNED: b"the agent's unmerged words\n"}], merge=False)
    tip = _reverted(repo, store, _LEARNED, "learned")
    assert _name_status(repo[1], tip) == {_LEARNED: "D"}


def test_revert_proceeds_when_main_again_holds_exactly_the_agents_bytes(repo, tmp_path, store):
    """Main's content decides, not its history."""
    agent_bytes = b"seed, as the agent rewrote it\n"
    wrote(repo, tmp_path, store, "changed", [{SEED: agent_bytes}])
    push_to_remote(repo, tmp_path, lambda c: _write(c / SEED, "a human's edit\n"))
    push_to_remote(repo, tmp_path, lambda c: (c / SEED).write_bytes(agent_bytes))
    tip = _reverted(repo, store, SEED, "seed")
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:{SEED}") == b"seed\n"


def test_revert_recreates_a_lesson_the_commit_maker_deleted(repo, tmp_path, store):
    wrote(repo, tmp_path, store, "deleted", [{SEED: None}])
    tip = _reverted(repo, store, SEED, "seed")
    assert _name_status(repo[1], tip) == {SEED: "A"}
    assert git_bytes(repo[1], "cat-file", "blob", f"{tip}:{SEED}") == b"seed\n"
    assert _modes(repo[1], tip, SEED) == {SEED: "100644"}


@pytest.mark.parametrize(("path", "edit"), [
    (_LEARNED, b"a human's later edit\n"), (SEED, b"a human's later edit\n"),
    (SEED, b"the human's words\n"),
    (SEED, b"the agent's words\nand a human's addition\n"),
], ids=["agent-created", "agent-changed", "same-length-edit", "appended-edit"])
def test_revert_refuses_a_lesson_changed_on_main_since_the_commit_maker_wrote_it(
        repo, tmp_path, store, path, edit):
    agent_words = b"the agent's words\n"
    assert len(agent_words) == len(b"the human's words\n")
    assert b"the agent's words\nand a human's addition\n".startswith(agent_words)
    wrote(repo, tmp_path, store, "written", [{path: agent_words}])
    push_to_remote(repo, tmp_path, lambda c: (c / path).write_bytes(edit))
    refused_revert(repo, store, path, "written")


@pytest.mark.parametrize("path", [SEED, "agent/lessons/merged.md"], ids=["seeded", "human-merged"])
def test_revert_refuses_a_lesson_the_commit_maker_never_wrote(repo, tmp_path, store, path):
    advance_remote(repo, tmp_path)
    refused_revert(repo, store, path, "human")


def test_revert_refuses_a_commit_laid_on_its_branch_by_a_clone_hook(repo, tmp_path, store):
    tenant, remote, _ = repo
    wrote(repo, tmp_path, store, "learned", [{_LEARNED: b"the agent's lesson\n"}])
    http = ForgeHTTP()
    branches = _branches(remote)
    marker = tmp_path / "planted"
    install_planting_hook(tenant.knowledge, git(remote, "rev-parse", "main"), marker,
                          "agent/lessons/raw.md", b"raw git, not the commit-maker\n")
    _, error, hung = bounded(lambda: revert(repo, store, http, _LEARNED, "learned"))
    assert not hung
    if marker.exists():
        assert isinstance(error, target().DeliveryRefused), error
        assert _branches(remote) == branches
        assert not http.creates
    else:
        assert error is None, f"the revert refused though nothing was laid on its branch: {error}"
        assert len(http.creates) == 1


@pytest.mark.parametrize("path", ["agent/.tenant-id", "settings/lead-zero.yaml",
                                  "agent/lessons/absent.md", "agent/lessons/../.tenant-id",
                                  "agent/lessons/\ud800.md"],
                         ids=["tenant-id", "settings", "absent", "traversal", "lone-surrogate"])
def test_revert_refuses_a_path_that_is_not_a_lesson_on_main(repo, store, path):
    refused_revert(repo, store, path, "x")
    assert _branches(repo[1]) == ["refs/heads/main"]


def test_only_the_commit_maker_makes_the_revert_commit_and_only_the_push_routes_it(repo, tmp_path, store):
    """The git census of delivery, over a revert: its one commit is the commit-maker's, the push sends it, and no
    worktree is made."""
    wrote(repo, tmp_path, store, "census", [{_LEARNED: b"one claim\n"}])
    events, active = [], [False]

    def audit(event, args):
        if active[0] and event == "subprocess.Popen":
            sub, argv = git_subcommand(args[1])
            if sub is not None:
                events.append(("revert", sub, argv))
    sys.addaudithook(audit)
    active[0] = True
    try:
        revert(repo, store, ForgeHTTP(), _LEARNED, "census")
    finally:
        active[0] = False
    assert _census(events, _MAKES_COMMITS) == {"revert"}, events
    assert _census(events, _SENDS_COMMITS) == {"revert"}, events
    assert not [e for e in events if _worktree_made(e[1], e[2])], "a git worktree was made"
