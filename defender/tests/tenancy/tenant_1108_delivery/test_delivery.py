"""Tenant delivery: delivery behavior through the public API."""
from __future__ import annotations





import pytest


from ._support import (
    deliver,
    DEFENDER,
    LANES,
    ForgeHTTP,
    delivery,
    git,
    opened,
    plant_raw_commit,
    remote_refs,
    still_open,
    target,
)


from ._scenarios import (
    _branches,
    _write,
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
        plant_raw_commit(d.repository.path, rogue, "agent/lessons/rogue.md", b"never sent\n",
                         base=batch.base_commit)
    assert opened(deliver(d, batch)) == "http://forge.invalid:3000/tenants/blue/pulls/7"
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert [line.split()[0] for line in remote_refs(remote)] == \
        sorted([f"refs/heads/{batch.branch}", "refs/heads/main"]), "finish sent more than its branch"
    assert git(remote, "rev-parse", "main") == batch.base_commit
    assert [(c["base"], c["head"]) for c in http.creates] == [("main", batch.branch)]
    api = "/api/v1/repos/tenants/blue"
    assert all(r.url.path == api or r.url.path.startswith(api + "/") for r in http.requests)
    assert http.foreign == []
    assert git(DEFENDER, "rev-parse", "HEAD") == product_head


def test_a_foreign_commit_beneath_a_later_commit_maker_commit_is_refused(repo):
    """Provenance covers every commit the branch would send, not only its tip."""
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("sandwich", lanes=LANES)
    lane = batch.draft_root / "agent/lessons"
    _write(lane / "first.md", "first claim\n")
    batch.commit(batch.change_set(), "claim one")
    batch.reset()
    planted = plant_raw_commit(d.repository.path, f"refs/heads/{batch.branch}",
                               "agent/lessons/raw.md", b"raw git, not the commit-maker\n",
                               base=batch.base_commit)
    _write(lane / "second.md", "second claim\n")

    def claim_two_then_finish():
        batch.commit(batch.change_set(), "claim two")
        return deliver(d, batch)
    with pytest.raises(target().DeliveryRefused):
        claim_two_then_finish()
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert planted not in git(repo[1], "rev-list", "--all").split()
    assert not http.creates


def test_finishing_twice_answers_the_one_open_pr(repo):
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("twice", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "finished twice\n")
    batch.commit(batch.change_set(), "claim")
    url = opened(deliver(d, batch))
    refs = remote_refs(repo[1])
    still_open(deliver(d, batch), url)
    assert len(http.creates) == 1
    assert remote_refs(repo[1]) == refs


def test_a_batch_with_no_commit_has_nothing_to_deliver(repo):
    http = ForgeHTTP()
    d = delivery(repo, http)
    batch = d.start_batch("idle", lanes=LANES)
    assert deliver(d, batch).status == "nothing to deliver"
    assert _branches(repo[1]) == ["refs/heads/main"]
    assert not http.creates

# Retired (#1618 design r5 census, "test-only code: `TenantDelivery.finish`, `_deliver`, `CommitMaker.made`"): the cases
# below pinned `finish`'s own answers (refusing a branch with a commit the commit-maker did not make before any push, a
# found PR answered without a push, `merged`/`closed` answered and never delivered again, a second finish after a failed
# PR request, a reused batch id, the per-call git census with flow-1 `publish`). Production delivers a batch only at
# the drain tick's end (`store_tick`: push, then `find_pr` / `open_pr_on`) and checks a takeover's tip against the
# store's record (`tip_commits_recorded`); those promises are the tick's cases (`tenant_1108_p4/test_1278_tick*.py`,
# `test_1278_tick_faults_one_pr.py`). Retired: test_finish_refuses_a_branch_holding_a_commit_the_commit_maker_did_not_make, test_a_second_finish_after_a_failed_pr_request_sends_only_commit_maker_commits, test_a_forge_transport_fault_is_a_refusal_and_a_second_finish_opens_the_pr, test_finish_answers_only_with_the_pr_for_its_own_head, test_the_batchs_pr_is_known_by_its_head_commit_and_repository_id, test_a_pr_created_but_unanswered_is_found_by_the_next_finish_not_made_again, test_a_merged_batch_answers_merged_and_is_never_delivered_again, test_a_closed_batch_answers_closed_and_is_never_delivered_again, test_a_reused_batch_id_is_not_mistaken_for_its_old_pr, test_only_the_commit_maker_makes_commits_and_only_the_push_routes_push.
