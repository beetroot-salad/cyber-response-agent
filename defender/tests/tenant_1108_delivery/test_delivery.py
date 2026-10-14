"""O7/O7b/O8/O9: real tenant git and HTTP delivery through the dormant entry seam."""
from __future__ import annotations

import json
import shutil
import os
import sys

import pytest

from ._support import DEFENDER, TOKEN, ForgeHTTP, advance_remote, delivery, git, target  # noqa: F401


def test_tenant_batch_commits_pushes_and_opens_tenant_main_without_product_write(repo):
    http = ForgeHTTP()
    d = delivery(repo, http)
    tenant, remote, _ = repo
    product_head = git(DEFENDER, "rev-parse", "HEAD")
    wt = d.start_batch("one")
    assert wt.is_relative_to(tenant.worktrees)
    assert d.branch.quarantine_dir.is_relative_to(tenant.worktrees)
    path = "agent/lessons/new.md"
    (wt / path).write_text("review me\n")
    d.commit(wt, [path], "learning")
    assert git(wt, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD") == path
    assert d.finish_batch("one", wt) == "http://forge.invalid:3000/tenants/blue/pulls/7"
    branch = d.branch.branch_name("one")
    assert git(remote, "rev-parse", f"refs/heads/{branch}") == git(wt, "rev-parse", "HEAD")
    assert git(remote, "rev-parse", "main") == git(tenant.knowledge, "rev-parse", "main")
    assert http.creates[0]["base"] == "main"
    assert http.creates[0]["head"] == branch
    assert all(r.url.path.startswith("/api/v1/repos/tenants/blue/") for r in http.requests)
    assert git(DEFENDER, "rev-parse", "HEAD") == product_head


@pytest.mark.parametrize("path", ["agent/.tenant-id", "settings/lead-zero.yaml", "product.py", "agent/../settings/escape.md"])
def test_commit_gate_refuses_forbidden_paths_before_staging_or_commit(repo, path):
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("gate")
    before = git(wt, "rev-parse", "HEAD")
    forbidden = wt / path
    forbidden.parent.mkdir(parents=True, exist_ok=True)
    forbidden.write_text("forbidden edit\n")
    with pytest.raises(target().DeliveryRefused, match="path|tenant-id|agent"):
        d.commit(wt, [path], "forbidden")
    assert git(wt, "rev-parse", "HEAD") == before
    assert git(wt, "diff", "--cached", "--name-only") == ""


@pytest.mark.parametrize("path", ["agent/.tenant-id", "settings/rogue.yaml", "product.py"])
def test_finish_refuses_out_of_policy_commit_that_bypassed_gate(repo, path):
    http = ForgeHTTP()
    d = delivery(repo, http)
    wt = d.start_batch("bypass")
    (wt / path).write_text("forbidden bypass edit\n")
    git(wt, "add", ".")
    git(wt, "commit", "-m", "bypass")
    with pytest.raises(target().DeliveryRefused, match="tenant-id|path"):
        d.finish_batch("bypass", wt)
    assert not http.creates
    assert git(repo[1], "for-each-ref", "--format=%(refname)", f"refs/heads/{d.branch.branch_name('bypass')}") == ""


def test_next_batch_fast_forwards_clone_before_creating_worktree(repo, tmp_path):
    expected = advance_remote(repo, tmp_path)
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("fresh")
    assert git(repo[0].knowledge, "rev-parse", "HEAD") == expected
    assert git(wt, "rev-parse", "HEAD") == expected
    assert (repo[0].agent / "lessons/merged.md").read_text() == "human-reviewed merge\n"


@pytest.mark.parametrize("state", ["dirty", "untracked", "diverged"])
def test_refresh_refuses_local_state_without_creating_batch(repo, tmp_path, state):
    tenant = repo[0]
    d = delivery(repo, ForgeHTTP())
    advance_remote(repo, tmp_path)
    p = tenant.agent / "lessons/seed.md"
    if state == "untracked":
        p = tenant.agent / "lessons/untracked.md"
    p.write_text("local\n")
    if state == "diverged":
        git(tenant.knowledge, "add", ".")
        git(tenant.knowledge, "commit", "-m", "local divergence")
    before = git(tenant.knowledge, "rev-parse", "HEAD")
    with pytest.raises(target().DeliveryRefused, match="dirty|diverg|fast.forward|untracked"):
        d.start_batch("refused")
    assert git(tenant.knowledge, "rev-parse", "HEAD") == before
    assert not list(tenant.worktrees.glob("*"))


@pytest.mark.parametrize(("fault", "reason"), [("unversioned", "version|git"), ("local-origin", "network|origin"), ("credentials", "credential"), ("main", "main")])
def test_delivery_refuses_unusable_tenant_with_named_reason(repo, fault, reason):
    tenant, _, credentials = repo
    if fault == "unversioned":
        shutil.rmtree(tenant.knowledge / ".git")
    elif fault == "local-origin":
        git(tenant.knowledge, "remote", "set-url", "origin", "/tmp/local.git")
    elif fault == "credentials":
        credentials.unlink()
    else:
        git(tenant.knowledge, "branch", "-m", "other")
        git(tenant.knowledge, "update-ref", "-d", "refs/remotes/origin/main")
    with pytest.raises(target().DeliveryRefused, match=reason):
        delivery(repo, ForgeHTTP())


@pytest.mark.parametrize("entry", ["https://bot:secret@forge.invalid:3000", "http://bot:secret@other.invalid:3000", "http://bot:secret@forge.invalid:3001"])
def test_credentials_require_scheme_host_and_port_agreement_before_http(repo, entry):
    repo[2].write_text(entry + "\n")
    http = ForgeHTTP()
    with pytest.raises(target().DeliveryRefused, match="credential|origin"):
        delivery(repo, http)
    assert http.requests == []


@pytest.mark.parametrize("protection", [{"protected": False, "user_can_push": False}, {"protected": True, "user_can_push": True}, {"protected": True}, {"user_can_push": False}, {"protected": "true", "user_can_push": False}, {"protected": True, "user_can_push": 0}])
def test_main_requires_known_protected_and_bot_cannot_push(repo, protection):
    http = ForgeHTTP()
    http.protection = protection
    with pytest.raises(target().DeliveryRefused, match="protect|push|main"):
        delivery(repo, http)
    assert not http.creates


def test_credentials_loaded_once_and_token_not_in_representation(repo):
    reads = []
    active = [True]
    credential_path = str(repo[2])
    def audit(event, args):
        if not active[0] or event != "open" or not isinstance(args[0], (str, bytes, os.PathLike)):
            return
        if os.fsdecode(args[0]) != credential_path:
            return
        mode, flags = args[1:3]
        if (mode is not None and ("r" in mode or "+" in mode)) or (
            mode is None and flags & os.O_ACCMODE != os.O_WRONLY
        ):
            reads.append(args)
    sys.addaudithook(audit)
    try:
        # Positive control proves this instrumentation detects the actual reader primitive.
        repo[2].read_bytes()
        assert len(reads) == 1
        reads.clear()
        http = ForgeHTTP()
        d = delivery(repo, http)
        repo[2].write_text("http://bot:changed@forge.invalid:3000\n")
        wt = d.start_batch("once")
        (wt / "agent/lessons/new.md").write_text("new")
        d.commit(wt, ["agent/lessons/new.md"], "new")
        d.finish_batch("once", wt)
        assert len(http.requests) >= 2
        assert all(TOKEN in r.headers.get("Authorization", "") for r in http.requests)
        assert TOKEN not in repr(d)
        assert TOKEN not in json.dumps(d.box_request(wt, "once", writable_dirs=("lessons",)).env)
        assert len(reads) == 1, "the credential file has one process-local read for the drain"
    finally:
        active[0] = False



def test_mixed_allowed_and_forbidden_commit_is_atomic_and_does_not_include_staged_settings(repo):
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("mixed")
    before = git(wt, "rev-parse", "HEAD")
    (wt / "agent/lessons/new.md").write_text("allowed\n")
    (wt / "settings/rogue.yaml").write_text("forbidden\n")
    git(wt, "add", "settings/rogue.yaml")
    d.commit(wt, ["agent/lessons/new.md"], "bounded staging")
    assert git(wt, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD") == "agent/lessons/new.md"
    assert git(wt, "diff", "--cached", "--name-only") == "settings/rogue.yaml"
    before = git(wt, "rev-parse", "HEAD")
    (wt / "agent/lessons/new.md").write_text("second allowed edit\n")
    with pytest.raises(target().DeliveryRefused, match="path|agent"):
        d.commit(wt, ["agent/lessons/new.md", "settings/rogue.yaml"], "mixed request")
    assert git(wt, "rev-parse", "HEAD") == before
    assert git(wt, "diff", "--cached", "--name-only") == "settings/rogue.yaml"



def test_failed_pr_creation_can_deliver_retained_branch_without_reauthoring(repo):
    http = ForgeHTTP()
    d = delivery(repo, http)
    wt = d.start_batch("retry")
    (wt / "agent/lessons/new.md").write_text("retained\n")
    d.commit(wt, ["agent/lessons/new.md"], "retained")
    expected = git(wt, "rev-parse", "HEAD")
    http.fail_create = True
    with pytest.raises(target().DeliveryRefused, match="503|forge|PR|pull"):
        d.finish_batch("retry", wt)
    d.branch.cleanup(wt)
    http.fail_create = False
    assert d.deliver("retry").endswith("/pulls/7")
    assert git(repo[1], "rev-parse", d.branch.branch_name("retry")) == expected


def test_git_operations_explicitly_reset_helpers_and_use_only_tenant_file(repo, tmp_path, monkeypatch):
    trace = tmp_path / "git-trace.jsonl"
    monkeypatch.setenv("GIT_TRACE2_EVENT", str(trace))
    git(repo[0].knowledge, "config", "credential.helper", "!false unexpected-clone-helper")
    d = delivery(repo, ForgeHTTP())
    wt = d.start_batch("helpers")
    (wt / "agent/lessons/new.md").write_text("new\n")
    d.commit(wt, ["agent/lessons/new.md"], "new")
    d.finish_batch("helpers", wt)
    starts = [json.loads(line)["argv"] for line in trace.read_text().splitlines()
              if json.loads(line).get("event") == "start"]
    network = [argv for argv in starts if "fetch" in argv or "push" in argv]
    assert len(network) >= 2
    for argv in network:
        helpers = [arg.removeprefix("credential.helper=") for arg in argv
                   if arg.startswith("credential.helper=")]
        assert helpers == ["", f"store --file={repo[2]}"]
        assert TOKEN not in " ".join(argv)
