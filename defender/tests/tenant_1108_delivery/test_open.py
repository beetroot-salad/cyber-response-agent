"""Tenant delivery: open behavior through the public API."""
from __future__ import annotations


import json

import os

import shutil





import sys



import pytest


from ._support import (
    LANES,
    TOKEN,
    ForgeHTTP,
    delivery,
    files_under,
    forge_pulls,
    git,
    merge_on_remote,
    opened,
    target,
)


from ._scenarios import (
    _name_status,
    _branches,
    _write,
    _UNUSABLE_REPOSITORY,
    _forge,
)

@pytest.mark.parametrize("reply", sorted(_UNUSABLE_REPOSITORY))
def test_a_repository_read_without_an_integer_id_is_refused(repo, reply):
    """C1 / refusal contract (deck #677; orchestrator ruling): the repository id `open()` reads
    is what every PR row's head is compared with."""
    http = ForgeHTTP()
    http.repository = _UNUSABLE_REPOSITORY[reply]
    with pytest.raises((target().DeliveryRefused, _forge().ForgeError)):
        delivery(repo, http)


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


@pytest.mark.parametrize("entry", ["https://bot:secret@forge.invalid:3000", "http://bot:secret@other.invalid:3000", "http://bot:secret@forge.invalid:3001",
                                   "http://bot:secret@forge.invalid%3a3001", "http://bot:secret@other.invalid%3a3000"])
def test_credentials_require_scheme_host_and_port_agreement_before_http(repo, entry):
    """O8/O-G: a credential entry for another scheme, host or port refuses before any HTTP
    request, in git's credential-store spelling too (`host%3aport`, C5)."""
    repo[2].write_text(entry + "\n", encoding="utf-8")
    http = ForgeHTTP()
    with pytest.raises(target().DeliveryRefused, match="credential|origin"):
        delivery(repo, http)
    assert http.requests == []


@pytest.mark.parametrize(("origin", "entry"), [
    ("http://FORGE.Invalid:3000/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid:3000"),
    ("http://forge.invalid/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid:80"),
    ("http://forge.invalid:80/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid"),
    ("http://forge.invalid:3000/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid%3a3000"),
    ("http://forge.invalid:3000/tenants/blue.git", f"http://bot:{TOKEN}@forge.invalid%3A3000"),
], ids=["host-case", "default-port-in-entry", "default-port-in-origin", "store-spelling",
        "store-spelling-upper"])
def test_credentials_agree_with_an_equivalent_spelling_of_the_origin(repo, origin, entry):
    """O-G with O8: agreement compares the one parsed address (host case folded, default port
    explicit), so equivalent spellings agree and the token authenticates the API at that
    address."""
    tenant, remote, credentials = repo
    git(tenant.knowledge, "remote", "set-url", "origin", origin)
    git(tenant.knowledge, "config", f"url.{remote}.insteadOf", origin)
    credentials.write_text(entry + "\n", encoding="utf-8")
    http = ForgeHTTP()
    delivery(repo, http)
    assert http.requests
    assert http.foreign == []
    assert all(TOKEN in r.headers.get("Authorization", "") for r in http.requests)


@pytest.mark.parametrize("protection", [{"protected": False, "user_can_push": False}, {"protected": True, "user_can_push": True}, {"protected": True}, {"user_can_push": False}, {"protected": "true", "user_can_push": False}, {"protected": True, "user_can_push": 0},
                                        None, [], "main", 1, True])
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
        repo[2].write_text("http://bot:changed@forge.invalid:3000\n", encoding="utf-8")
        batch = d.start_batch("once", lanes=LANES)
        _write(batch.draft_root / "agent/lessons/new.md", "new")
        batch.commit(batch.change_set(), "new")
        d.finish(batch)
        assert len(http.requests) >= 2
        assert all(TOKEN in r.headers.get("Authorization", "") for r in http.requests)
        assert TOKEN not in repr(d)
        assert TOKEN not in repr(batch)
        assert TOKEN not in json.dumps(batch.box_request().env)
        assert len(reads) == 1, "the credential file has one process-local read for the drain"
    finally:
        active[0] = False


@pytest.mark.parametrize("ambient", ["git-dir", "work-tree", "both"])
def test_delivery_git_context_cannot_be_redirected_by_ambient_repository(repo, tmp_path, monkeypatch, ambient):
    """O7 under amendment 2: inherited `GIT_DIR`/`GIT_WORK_TREE` cannot redirect publish, the
    batch, the commit-maker, finish, retained delivery or, once a human has merged the PR,
    the revert of its lesson into another repository."""
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    git(foreign, "init", "-b", "main")
    (foreign / "foreign-only.md").write_text("another repository\n", encoding="utf-8")
    git(foreign, "add", ".")
    git(foreign, "commit", "-m", "foreign seed")
    foreign_head = git(foreign, "rev-parse", "HEAD")
    expected = git(repo[0].knowledge, "rev-parse", "HEAD")
    http = ForgeHTTP()

    def redirect(env):
        if ambient in {"git-dir", "both"}:
            env.setenv("GIT_DIR", str(foreign / ".git"))
        if ambient in {"work-tree", "both"}:
            env.setenv("GIT_WORK_TREE", str(foreign))
    with monkeypatch.context() as env:
        redirect(env)
        d = delivery(repo, http)
        batch = d.start_batch("ambient", lanes=LANES)
        assert (batch.draft_root / "agent/lessons/seed.md").read_text(encoding="utf-8") == "seed\n"
        assert "foreign-only.md" not in files_under(batch.draft_root)
        _write(batch.draft_root / "agent/lessons/ambient.md", "tenant authored\n")
        sha = batch.commit(batch.change_set(), "tenant ambient context")
        http.fail_create = True
        with pytest.raises(target().DeliveryRefused, match="503|forge|PR|pull"):
            d.finish(batch)
        http.fail_create = False
        opened(d.deliver("ambient"))
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert git(repo[0].knowledge, "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert git(repo[1], "rev-parse", "main") == expected
    merged = merge_on_remote(repo, tmp_path, batch.branch)
    with monkeypatch.context() as env:
        redirect(env)
        reverted = d.revert("agent/lessons/ambient.md", "ambient")
    assert opened(reverted, None) == forge_pulls(repo[1])[-1]["html_url"]
    revert_head = http.creates[-1]["head"]
    tip = git(repo[1], "rev-parse", f"refs/heads/{revert_head}")
    assert git(repo[1], "rev-parse", f"{tip}^") == merged == git(repo[1], "rev-parse", "main")
    assert _name_status(repo[1], tip) == {"agent/lessons/ambient.md": "D"}
    assert git(repo[0].knowledge, "show", f"{sha}:agent/lessons/ambient.md") == "tenant authored"
    assert _name_status(repo[0].knowledge, sha) == {"agent/lessons/ambient.md": "A"}
    assert git(foreign, "rev-parse", "HEAD") == foreign_head
    assert not (foreign / "agent").exists()
    assert _branches(foreign) == ["refs/heads/main"]


