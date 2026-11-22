"""Tenant delivery: open behavior through the public API."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid


import json



import pytest

from defender.learning.author.version_control.forgejo import ForgeError

from ._revert_store import claimed_batch, reviewed, revert_with
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
    push_and_open,
    target,
)


from ._clone_free_1618 import delivery_without_clone

from ._scenarios import (
    _name_status,
    _branches,
    _write,
    _UNUSABLE_REPOSITORY,
)

@pytest.mark.parametrize("reply", sorted(_UNUSABLE_REPOSITORY))
def test_a_repository_read_without_an_integer_id_is_refused(repo, reply):
    """The repository id `open()` reads is what every PR row's head is compared with, so a
    reply without an integer id is refused."""
    http = ForgeHTTP()
    http.repository = _UNUSABLE_REPOSITORY[reply]
    with pytest.raises((target().DeliveryRefused, ForgeError)):
        delivery(repo, http)


# retired (#1618 design "Retired promises": `test_open::refuses_unusable_tenant`, a clone-state check): the
# `unversioned` and `main` arms judged the host clone, which r5 deletes. The `local-origin` arm guards the recorded
# origin's shape, which survives, and stays below.
def test_delivery_refuses_a_local_origin_naming_it(repo):
    """An origin that is not a network forge URL refuses the open, naming it (the arm of the retired clone-state case
    that does not judge the clone)."""
    with pytest.raises(target().DeliveryRefused, match="network|origin"):
        delivery(repo, ForgeHTTP(), origin="/tmp/local.git")


@pytest.mark.parametrize("protection", [{"protected": False, "user_can_push": False}, {"protected": True, "user_can_push": True}, {"protected": True}, {"user_can_push": False}, {"protected": "true", "user_can_push": False}, {"protected": True, "user_can_push": 0},
                                        None, [], "main", 1, True,
                                        # #1163 N13: the bot may not merge either, and merge
                                        # rights must be known.
                                        {"protected": True, "user_can_push": False, "user_can_merge": True},
                                        {"protected": True, "user_can_push": False},
                                        {"protected": True, "user_can_push": False, "user_can_merge": 0}])
def test_main_requires_known_protected_and_bot_cannot_push(repo, protection):
    http = ForgeHTTP()
    http.protection = protection
    with pytest.raises(target().DeliveryRefused, match="protect|push|merge|main"):
        delivery(repo, http)
    assert not http.creates


def test_identity_is_cached_and_never_exposed_to_a_box(repo):
    from ._identity import VaultHTTP
    vault = VaultHTTP()
    d = delivery(repo, ForgeHTTP(), identity=vault.identity())
    batch = d.start_batch("once", lanes=LANES)
    _write(batch.draft_root / "agent/lessons/new.md", "new")
    sha = batch.commit(batch.change_set(), "new")
    opened(push_and_open(batch))  # #1618: `finish` is deleted; the push and the PR are the tick's (`push_and_open`)
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha, "control: the push used the identity"
    assert len(vault.calls) == 1
    assert TOKEN not in repr(d)
    assert TOKEN not in repr(batch)
    assert TOKEN not in json.dumps(batch.box_request().env)


def test_tenant_identity_must_match_before_forge_http(repo):
    from ._identity import identity
    http = ForgeHTTP()
    with pytest.raises(target().DeliveryRefused, match="tenant"):
        delivery(repo, http, identity=identity(fixture_uuid("tenant:other")))
    assert http.requests == []


@pytest.mark.parametrize("ambient", ["git-dir", "work-tree", "both"])
@pytest.mark.postgres
def test_delivery_git_context_cannot_be_redirected_by_ambient_repository(repo, store, tmp_path, monkeypatch, ambient):
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    git(foreign, "init", "-b", "main")
    (foreign / "foreign-only.md").write_text("another repository\n", encoding="utf-8")
    git(foreign, "add", ".")
    git(foreign, "commit", "-m", "foreign seed")
    foreign_head = git(foreign, "rev-parse", "HEAD")
    expected = repo.seed
    http = ForgeHTTP()

    def redirect(env):
        if ambient in {"git-dir", "both"}:
            env.setenv("GIT_DIR", str(foreign / ".git"))
        if ambient in {"work-tree", "both"}:
            env.setenv("GIT_WORK_TREE", str(foreign))
    with monkeypatch.context() as env:
        redirect(env)
        d = delivery(repo, http)
        batch, held = claimed_batch(repo, store, d, "ambient")
        assert (batch.draft_root / "agent/lessons/seed.md").read_text(encoding="utf-8") == "seed\n"
        assert "foreign-only.md" not in files_under(batch.draft_root)
        _write(batch.draft_root / "agent/lessons/ambient.md", "tenant authored\n")
        sha = batch.commit(batch.change_set(), "tenant ambient context")
        assert d.repository.branch_tip(batch.branch) == sha, "the commit landed outside the delivery's repository"
        # #1618: `finish` (and its retry after a refused PR create) is deleted, test-only; the push and PR are the tick's.
        again = push_and_open(batch)
        opened(again)
        reviewed(store, held, again)
    assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == sha
    assert git(repo[1], "rev-parse", "main") == expected
    merged = merge_on_remote(repo, tmp_path, batch.branch)
    d.close()
    with monkeypatch.context() as env:
        redirect(env)
        # #1618 (flow 7): the revert is its own operation, over its own private repository fetched after the merge.
        with delivery(repo, http) as later:
            reverted = revert_with(later, store, "agent/lessons/ambient.md", "ambient")
    assert opened(reverted, None) == forge_pulls(repo[1])[-1]["html_url"]
    revert_head = http.creates[-1]["head"]
    tip = git(repo[1], "rev-parse", f"refs/heads/{revert_head}")
    assert git(repo[1], "rev-parse", f"{tip}^") == merged == git(repo[1], "rev-parse", "main")
    assert _name_status(repo[1], tip) == {"agent/lessons/ambient.md": "D"}
    assert git(repo[1], "show", f"{sha}:agent/lessons/ambient.md") == "tenant authored"
    assert _name_status(repo[1], sha) == {"agent/lessons/ambient.md": "A"}
    assert git(foreign, "rev-parse", "HEAD") == foreign_head
    assert not (foreign / "agent").exists()
    assert _branches(foreign) == ["refs/heads/main"]


def test_no_legacy_credential_file_is_needed(repo):
    """With the legacy credential file gone, a delivery opens and fetches `main` (#1618: no publish; its opening fetch
    is what read the remote)."""
    repo[2].unlink()
    with delivery(repo, ForgeHTTP()) as d:
        assert d.start_batch("no-legacy", lanes=LANES).base_commit == git(repo[1], "rev-parse", "main")


def test_1618_d9_delivery_checks_main_protection_and_a_knowledge_copy_does_not(repo, tmp_path, data_root):
    """An unprotected `main` refuses a delivery's open (the protection rule is read), while a knowledge copy of that forge is made and asks for no protection. (D9)"""
    from defender.tests.tenancy.knowledge_1618 import _support as K

    unprotected = ForgeHTTP()
    unprotected.protection = {"protected": False, "user_can_push": False}
    with pytest.raises(target().DeliveryRefused, match="protect|push|merge|main"):
        delivery_without_clone(repo, unprotected)
    asked = [r.url.path for r in unprotected.requests]
    assert any(p.endswith("/branches/main") for p in asked), "control: the delivery's open reads main's protection"

    with K.scene(tmp_path, data_root) as t:
        t.forge.protection = {"protected": False, "user_can_push": False}
        dest = K.owned_dest(tmp_path / "copy")
        commit = K.fetch_copy(t, dest)
        assert commit == t.origin_main()
        assert K.half_at(t, commit, "agent") == K.tree_bytes(dest / "agent")
        assert [r.url.path for r in t.forge.requests if r.url.path.endswith("/branches/main")] == [], \
            "the knowledge copy asked the forge about main's protection"
