"""Remote publication has one explicit destination and no operator git policy."""

from __future__ import annotations

import pytest

from ._revert_store import claimed_batch, reviewed, revert_with
from ._support import (
    deliver,
    BARE_NO_UPKEEP,
    LANES,
    ForgeHTTP,
    build_tenant,
    delivery,
    git,
    git_config_home,
    merge_on_remote,
    opened,
    remote_refs,
    target,
)


def _refs(repo):
    return dict(line.split(" ", 1) for line in remote_refs(repo))


@pytest.mark.parametrize("route", ["finish", "refinish", pytest.param("revert", marks=pytest.mark.postgres)])
def test_publication_never_follows_operator_tags(
    http_repo, tmp_path, monkeypatch, route, request
):
    tenant, remote, _, _ = http_repo
    http = ForgeHTTP()
    d = delivery(http_repo, http)
    if route == "revert":
        store = request.getfixturevalue("http_store")
        batch, held = claimed_batch(http_repo, store, d, "tagged")
    else:
        batch = d.start_batch("tagged", lanes=LANES)
    (batch.draft_root / "agent/lessons/tagged.md").write_text("review me\n")
    commit = batch.commit(batch.change_set(), "tagged lesson")
    if route == "refinish":
        http.fail_create = True
        # #1618 census (`finish` deleted): the tick's PR open surfaces a forge fault as `ForgeError`, which the tick
        # counts among its delivery faults (`store_tick._delivery_faults`) as it did `finish`'s `DeliveryRefused`.
        from defender.learning.author.version_control.forgejo import ForgeError

        with pytest.raises(ForgeError, match="503"):
            deliver(d, batch)
        http.fail_create = False
    elif route == "revert":
        finished = deliver(d, batch)
        opened(finished)
        reviewed(store, held, finished)
        merge_on_remote(http_repo, tmp_path, batch.branch)
        # The batch ended merged, as the author tick records a merged review (`_revert_store.wrote` does the same).
        store.end_review(str(tenant.id), str(held.batch_id), expect_phase="in_review", outcome="merged",
                         published=[], held=[])

    control = tmp_path / "control.git"
    git(tmp_path, "clone", "--bare", *BARE_NO_UPKEEP, remote, control)
    private = d.repository.path  # #1618 K8: the delivery's private repository, where publication starts
    git(
        private,
        "tag",
        "-a",
        "operator-tag",
        "-m",
        "not for publication",
        commit,
    )
    git(private, "config", "push.followTags", "true")
    git_config_home(tmp_path).global_config.write_text("[push]\nfollowTags = true\n")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "push.followTags")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")

    # Positive control: this annotated tag is reachable and ordinary operator git follows it.
    git(private, "push", control, f"{commit}:refs/heads/control")
    assert "refs/tags/operator-tag" in _refs(control)
    before = _refs(remote)
    if route in ("finish", "refinish"):
        opened(deliver(d, batch))
    else:
        opened(revert_with(d, store, "agent/lessons/tagged.md", "tagged"), None)
    branch = "refs/heads/" + http.creates[-1]["head"]
    after = _refs(remote)
    assert set(after) == set(before) | {branch}
    assert {ref: oid for ref, oid in after.items() if ref != branch} == {
        ref: oid for ref, oid in before.items() if ref != branch
    }


def test_transfer_ignores_clone_includes_system_user_and_environment_config(
    http_repo, rewritten, tmp_path, monkeypatch
):
    tenant, remote, _, server = http_repo
    origin = f"{server.url}/tenants/blue.git"
    d = delivery(http_repo, ForgeHTTP(), origin=origin)
    other = rewritten.url
    included = tmp_path / "included.gitconfig"
    included.write_text(f'''[url "{other}/"]
    insteadOf = {server.url}/
    pushInsteadOf = {server.url}/
[remote "origin"]
    url = {other}/tenants/blue.git
    pushurl = {other}/tenants/blue.git
    mirror = true
[push]
    followTags = true
    gpgSign = true
[http]
    proxy = {other}
''')
    private = d.repository.path  # #1618 K8: the delivery's private repository (no host clone)
    # (#1618 census: the host clone and `transport._context`'s temporary repository are deleted; the private repository
    # is the product's own 0700 state (K7), so no clone include is planted there. The system, user and environment
    # config below still name the rewritten host.)
    git(private, "config", "remote.origin.pushurl", f"{other}/tenants/blue.git")
    config = git_config_home(tmp_path)
    config.global_config.write_text(config.global_config.read_text() + f"[include]\npath = {included}\n")
    config.system_config.write_text(f"[include]\npath = {included}\n")
    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", f"url.{other}/.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", f"{server.url}/")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'push.followTags=true'")
    monkeypatch.setenv("ALL_PROXY", other)
    monkeypatch.setenv("http_proxy", other)
    monkeypatch.setenv("NO_PROXY", "")
    assert (
        git(private, "remote", "get-url", "--push", "origin")
        == f"{other}/tenants/blue.git"
    )
    batch = d.start_batch("isolated", lanes=LANES)
    (batch.draft_root / "agent/lessons/isolated.md").write_text(
        "explicit destination\n"
    )
    commit = batch.commit(batch.change_set(), "isolated lesson")
    opened(deliver(d, batch))
    assert git(remote, "rev-parse", f"refs/heads/{batch.branch}") == commit
    assert server.authorized("git-upload-pack")
    assert server.authorized("git-receive-pack")
    assert rewritten.authorizations == []


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_transport_shares_objects_without_requiring_clone_remotes(
    tmp_path, object_format
):
    with build_tenant(tmp_path, object_format=object_format) as repo:
        d = delivery(repo, ForgeHTTP())
        # #1618 K8: the remotes are the delivery's private repository's (no host clone); `publish` (flow 1) is gone.
        private = d.repository.path
        if "origin" in git(private, "remote").split():
            git(private, "remote", "remove", "origin")
        batch = d.start_batch("objects", lanes=LANES)
        (batch.draft_root / "agent/lessons/objects.md").write_text("objects only\n")
        commit = batch.commit(batch.change_set(), "objects")
        opened(deliver(d, batch))
        assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == commit
