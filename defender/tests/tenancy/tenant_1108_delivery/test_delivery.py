"""Tenant delivery: delivery behavior through the public API."""
from __future__ import annotations


import sys


import httpx

import pytest


from ._support import (
    DEFENDER,
    FORK,
    LANES,
    MERGE_STYLES,
    ForgeHTTP,
    bounded,
    delivery,
    forge_pulls,
    git,
    git_subcommand,
    in_a_later_process,
    merge_on_remote,
    opened,
    plant_raw_commit,
    pr_row,
    remote_refs,
    set_pull_state,
    still_open,
    target,
    fixture_identity,
    configured_origin,
)


from ._scenarios import (
    _branches,
    _write,
    _lay_pr,
    _TRANSPORT_FAULTS,
    _NOT_OUR_PR,
    _OUR_PR,
    _MAKES_COMMITS,
    _SENDS_COMMITS,
    _census,
    _worktree_made,
    _checkouts,
)

def test_finish_pushes_the_commit_maker_branch_and_opens_its_pr_without_product_write(repo):
    http = ForgeHTTP()
    d = delivery(repo, http)
    tenant, remote, _ = repo
    product_head = git(DEFENDER, "rev-parse", "HEAD")
    batch = d.start_batch("one", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "review me\n")
    sha = batch.commit(batch.change_set(), "learning")
    for rogue in ("refs/heads/lessons/rogue", "refs/heads/rogue", "refs/tags/rogue"):
        plant_raw_commit(tenant.knowledge, rogue, "agent/lessons/rogue.md", b"never sent\n",
                         base=batch.export.commit)
    assert opened(d.finish(batch)) == "http://forge.invalid:3000/tenants/blue/pulls/7"
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert [line.split()[0] for line in remote_refs(remote)] == \
        sorted([f"refs/heads/{batch.branch}", "refs/heads/main"]), "finish sent more than its branch"
    assert git(remote, "rev-parse", "main") == batch.export.commit
    assert [(c["base"], c["head"]) for c in http.creates] == [("main", batch.branch)]
    api = "/api/v1/repos/tenants/blue"
    assert all(r.url.path == api or r.url.path.startswith(api + "/") for r in http.requests)
    assert http.foreign == []
    assert git(DEFENDER, "rev-parse", "HEAD") == product_head


@pytest.mark.parametrize("how", ["on-top", "amend", "only-raw", "forbidden-path"])
def test_finish_refuses_a_branch_holding_a_commit_the_commit_maker_did_not_make(repo, how):
    """Finish refuses a branch holding a commit the commit maker did not make."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("foreign", lanes=LANES)
    if how != "only-raw":
        _write(batch.draft_root / "agent/lessons/made.md", "made by the commit-maker\n")
        batch.commit(batch.change_set(), "commit-maker claim")
    path = "settings/rogue.yaml" if how == "forbidden-path" else "agent/lessons/raw.md"
    plant_raw_commit(repo[0].knowledge, f"refs/heads/{batch.branch}", path,
                     b"raw git, not the commit-maker\n", amend=how == "amend",
                     base=batch.export.commit)
    with pytest.raises(target().DeliveryRefused):
        d.finish(batch)
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert not http.creates


def test_a_foreign_commit_beneath_a_later_commit_maker_commit_is_refused(repo):
    """O-C: provenance covers every commit the branch would send, not only its tip."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("sandwich", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    _write(lane / "first.md", "first claim\n")
    batch.commit(batch.change_set(), "claim one")
    batch.reset()
    planted = plant_raw_commit(repo[0].knowledge, f"refs/heads/{batch.branch}",
                               "agent/lessons/raw.md", b"raw git, not the commit-maker\n",
                               base=batch.export.commit)
    _write(lane / "second.md", "second claim\n")

    def claim_two_then_finish():
        batch.commit(batch.change_set(), "claim two")
        return d.finish(batch)
    with pytest.raises(target().DeliveryRefused):
        claim_two_then_finish()
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert planted not in git(repo[1], "rev-list", "--all").split()
    assert not http.creates


@pytest.mark.parametrize("planted", [None, "on-top", "amended"])
def test_retained_branch_delivery_pushes_only_commit_maker_commits(repo, planted):
    """O-C on the retained route: finish pushed the branch but PR creation failed; a later drain
    (a new delivery object) delivers the retained branch, opening the PR."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("retained", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "retained\n")
    sha = batch.commit(batch.change_set(), "retained")
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused, match="503|forge|PR|pull"):
        d.finish(batch)
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    http.fail_create = False
    posts = len(http.creates)
    if planted is not None:
        plant_raw_commit(repo[0].knowledge, f"refs/heads/{batch.branch}", "agent/lessons/raw.md",
                         b"raw git, not the commit-maker\n", amend=planted == "amended")
    later = target().TenantDelivery.open(repo[0], defender_dir=DEFENDER, client=http.client, identity=fixture_identity(str(repo[0].id)), origin=configured_origin(repo[0].knowledge))
    if planted is None:
        opened(later.deliver("retained"))
        assert len(http.creates) == posts + 1
    else:
        with pytest.raises(target().DeliveryRefused):
            later.deliver("retained")
        assert len(http.creates) == posts
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha


@pytest.mark.parametrize("planted", [None, "on-top"])
def test_a_later_process_delivers_a_retained_branch_by_the_commit_maker_record(repo, planted):
    """A later process delivers a retained branch by the commit maker record."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("retained", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "retained\n")
    sha = batch.commit(batch.change_set(), "retained")
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused, match="503|forge|PR|pull"):
        d.finish(batch)
    if planted:
        plant_raw_commit(repo[0].knowledge, f"refs/heads/{batch.branch}", "agent/lessons/raw.md",
                         b"raw git, not the commit-maker\n", base=batch.export.commit)
    later = in_a_later_process(repo, "deliver", "retained")
    if planted is None:
        assert later.get("status") == "opened", later
        assert later["url"].endswith("/pulls/7"), later
        assert [(c["base"], c["head"]) for c in later["creates"]] == [("main", batch.branch)]
    else:
        assert "refused" in later, later
        assert later["creates"] == []
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha


@pytest.mark.parametrize("where", sorted(_TRANSPORT_FAULTS))
def test_a_forge_transport_fault_is_a_refusal_and_a_later_deliver_opens_the_pr(repo, where):
    """Refusal contract (deck #678): the forge unreachable mid-request (a connection error, not
    an HTTP status) is a `DeliveryRefused`, never an `httpx` exception escaping delivery."""
    http = ForgeHTTP()
    matches = _TRANSPORT_FAULTS[where]

    def fault(request):
        return httpx.ConnectError("forge unreachable", request=request) if matches(request) else None
    if where == "protection-read":
        http.fault = fault
        with pytest.raises(target().DeliveryRefused):
            delivery(repo, http)
        return
    d = delivery(repo, http)
    batch = d.start_batch("unreachable", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "delivered through a fault\n")
    sha = batch.commit(batch.change_set(), "claim")
    _lay_pr(repo, http, pr_row(5, batch.branch, repo=FORK, sha=sha))
    http.fault = fault
    with pytest.raises(target().DeliveryRefused):
        d.finish(batch)
    assert any(matches(r) for r in http.requests), "the faulted request was never made"
    if where == "pr-lookup":
        assert _branches(repo[1]) == ["refs/heads/main"], "finish pushed before its lookup"
        assert not http.creates
    else:
        assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    http.fault = None
    opened(delivery(repo, http).deliver("unreachable"))
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert [row["number"] for row in forge_pulls(repo[1]) if row["head"].get("repo_id") == 11] == [7]


@pytest.mark.parametrize("other", sorted(_NOT_OUR_PR))
def test_finish_and_deliver_answer_only_with_the_pr_for_their_own_head(repo, other):
    """Finish and deliver answer only with the pr for their own head."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("forked", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "ours\n")
    sha = batch.commit(batch.change_set(), "ours")
    _lay_pr(repo, http, _NOT_OUR_PR[other](batch.branch, sha, batch.export.commit))
    url = opened(d.finish(batch))
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert [c["head"] for c in http.creates] == [batch.branch]
    still_open(d.deliver("forked"), url)
    assert len(http.creates) == 1


@pytest.mark.parametrize("row", sorted(_OUR_PR))
def test_the_batchs_pr_is_known_by_its_head_commit_and_repository_id(repo, row):
    """The batchs pr is known by its head commit and repository id."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("known", lanes=LANES)
    shas = []
    for number in (1, 2):
        _write(batch.draft_root / f"agent/lessons/claim-{number}.md", "claimed\n")
        shas.append(batch.commit(batch.change_set(), f"claim {number}"))
        batch.reset()
    make, status = _OUR_PR[row]
    _lay_pr(repo, http, make(batch.branch, shas))
    for result in (d.finish(batch), d.deliver("known")):
        assert result.status == status, result
        if status == "open":
            assert result.url.endswith("/pulls/5"), result.url
    assert _branches(repo[1]) == ["refs/heads/main"], "a batch the forge already had a PR for was pushed"
    assert not http.creates


def test_finishing_twice_answers_the_one_open_pr(repo):
    """Finishing twice answers the one open pr."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("twice", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "finished twice\n")
    batch.commit(batch.change_set(), "claim")
    url = opened(d.finish(batch))
    refs = remote_refs(repo[1])
    still_open(d.finish(batch), url)
    still_open(d.deliver("twice"), url)
    assert len(http.creates) == 1
    assert remote_refs(repo[1]) == refs


def test_a_batch_with_no_commit_has_nothing_to_deliver(repo):
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("idle", lanes=LANES)
    assert d.finish(batch).status == "nothing to deliver"
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert not http.creates


@pytest.mark.parametrize("delete_branch", [False, True], ids=["branch-kept", "branch-deleted"])
@pytest.mark.parametrize("style", MERGE_STYLES)
def test_a_merged_batch_answers_merged_and_is_never_delivered_again(repo, tmp_path, style, delete_branch):
    """A merged batch answers merged and is never delivered again."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("merged", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "merged by a human\n")
    batch.commit(batch.change_set(), "claim")
    opened(d.finish(batch))
    merge_on_remote(repo, tmp_path, batch.branch, style, delete_branch=delete_branch)
    refs = remote_refs(repo[1])
    assert d.finish(batch).status == "merged"
    assert d.deliver("merged").status == "merged"
    later = in_a_later_process(repo, "deliver", "merged")
    assert later.get("status") == "merged", later
    assert later["creates"] == []
    assert len(http.creates) == 1
    assert remote_refs(repo[1]) == refs


@pytest.mark.parametrize("delete_branch", [False, True], ids=["branch-kept", "branch-deleted"])
def test_a_closed_batch_answers_closed_and_is_never_delivered_again(repo, delete_branch):
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("closed", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "rejected by a human\n")
    batch.commit(batch.change_set(), "claim")
    opened(d.finish(batch))
    set_pull_state(repo[1], batch.branch, merged=False, delete_branch=delete_branch)
    refs = remote_refs(repo[1])
    assert d.finish(batch).status == "closed"
    assert d.deliver("closed").status == "closed"
    later = in_a_later_process(repo, "deliver", "closed")
    assert later.get("status") == "closed", later
    assert later["creates"] == []
    assert len(http.creates) == 1
    assert remote_refs(repo[1]) == refs


def test_a_reused_batch_id_is_not_mistaken_for_its_old_pr(repo, tmp_path):
    """A reused batch id is not mistaken for its old pr."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    clone = repo[0].knowledge
    old = d.start_batch("reused", lanes=LANES)
    _write(old.draft_root / "agent/lessons/old.md", "the first use of the id\n")
    old.commit(old.change_set(), "claim")
    old_url = opened(d.finish(old))
    merge_on_remote(repo, tmp_path, old.branch)
    old.discard()
    git(clone, "update-ref", "-d", f"refs/heads/{old.branch}")
    new = d.start_batch("reused", lanes=LANES)
    _write(new.draft_root / "agent/lessons/new.md", "the second use of the id\n")
    new.commit(new.change_set(), "claim")
    result, error, hung = bounded(lambda: d.finish(new))
    assert not hung
    if not isinstance(error, target().DeliveryRefused):
        assert error is None, error
        assert result.status == "opened", result
        assert result.url != old_url, "the new batch was answered with its old PR"


def test_only_the_commit_maker_makes_commits_and_only_the_push_routes_push(repo, tmp_path):
    """Only the commit maker makes commits and only the push routes push."""
    http = ForgeHTTP()
    events, phase, active = [], ["control"], [True]

    def audit(event, args):
        if active[0] and event == "subprocess.Popen":
            sub, argv = git_subcommand(args[1])
            if sub is not None:
                events.append((phase[0], sub, argv))

    def under(name, call):
        phase[0] = name
        return call()
    sys.addaudithook(audit)
    try:
        git(repo[0].knowledge, "rev-parse", "HEAD")
        assert [(p, sub) for p, sub, _ in events] == [("control", "rev-parse")], events
        events.clear()
        d = under("open", lambda: delivery(repo, http))
        under("publish", d.publish)
        batch = under("start_batch", lambda: d.start_batch("census", lanes=LANES))
        under("box_request", batch.box_request)
        _write(batch.draft_root / "agent/lessons/census.md", "one claim\n")
        change_set = under("change_set", batch.change_set)
        under("commit", lambda: batch.commit(change_set, "claim"))
        under("reset", batch.reset)
        http.fail_create = True
        with pytest.raises(target().DeliveryRefused):
            under("finish", lambda: d.finish(batch))
        http.fail_create = False
        under("deliver", lambda: d.deliver("census"))
        active[0] = False
        merge_on_remote(repo, tmp_path, batch.branch)
        active[0] = True
        under("revert", lambda: d.revert("agent/lessons/census.md", "census"))
    finally:
        active[0] = False
    assert _census(events, _MAKES_COMMITS) == {"commit", "revert"}, events
    sent = _census(events, _SENDS_COMMITS)
    assert {"finish", "revert"} <= sent <= {"finish", "deliver", "revert"}, events
    assert not [e for e in events if _worktree_made(e[1], e[2])], "a git worktree was made"
    assert _checkouts(events) <= {"publish", "start_batch", "revert"}, events
