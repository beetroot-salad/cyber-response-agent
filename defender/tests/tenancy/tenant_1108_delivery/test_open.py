"""Tenant delivery: open behavior through the public API."""
from __future__ import annotations


import json


import shutil


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


@pytest.mark.parametrize(("fault", "reason"), [("unversioned", "version|git"), ("local-origin", "network|origin"), ("main", "main")])
def test_delivery_refuses_unusable_tenant_with_named_reason(repo, fault, reason):
    tenant, _, credentials = repo
    options = {}
    if fault == "unversioned":
        shutil.rmtree(tenant.knowledge / ".git")
    elif fault == "local-origin":
        options["origin"] = "/tmp/local.git"
    else:
        git(tenant.knowledge, "branch", "-m", "other")
        git(tenant.knowledge, "update-ref", "-d", "refs/remotes/origin/main")
    with pytest.raises(target().DeliveryRefused, match=reason):
        delivery(repo, ForgeHTTP(), **options)


@pytest.mark.parametrize("protection", [{"protected": False, "user_can_push": False}, {"protected": True, "user_can_push": True}, {"protected": True}, {"user_can_push": False}, {"protected": "true", "user_can_push": False}, {"protected": True, "user_can_push": 0},
                                        None, [], "main", 1, True])
def test_main_requires_known_protected_and_bot_cannot_push(repo, protection):
    http = ForgeHTTP()
    http.protection = protection
    with pytest.raises(target().DeliveryRefused, match="protect|push|main"):
        delivery(repo, http)
    assert not http.creates


def test_identity_is_cached_and_never_exposed_to_a_box(repo):
    from ._identity import VaultHTTP
    vault = VaultHTTP()
    d = delivery(repo, ForgeHTTP(), identity=vault.identity())
    batch = d.start_batch("once", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "new")
    batch.commit(batch.change_set(), "new")
    d.finish(batch)
    assert len(vault.calls) == 1
    assert TOKEN not in repr(d)
    assert TOKEN not in repr(batch)
    assert TOKEN not in json.dumps(batch.box_request().env)


def test_tenant_identity_must_match_before_forge_http(repo):
    from ._identity import identity
    http = ForgeHTTP()
    with pytest.raises(target().DeliveryRefused, match="tenant"):
        delivery(repo, http, identity=identity("other"))
    assert http.requests == []


@pytest.mark.parametrize("ambient", ["git-dir", "work-tree", "both"])
def test_delivery_git_context_cannot_be_redirected_by_ambient_repository(repo, tmp_path, monkeypatch, ambient):
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


def test_no_legacy_credential_file_is_needed(repo):
    repo[2].unlink()
    result = delivery(repo, ForgeHTTP()).publish()
    assert result.commit == git(repo[1], "rev-parse", "main")
