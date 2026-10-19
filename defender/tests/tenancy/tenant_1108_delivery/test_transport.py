"""Remote publication has one explicit destination and no operator git policy."""

from __future__ import annotations

import pytest

from ._support import (
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


@pytest.mark.parametrize("route", ["finish", "deliver", "revert"])
def test_publication_never_follows_operator_tags(
    http_repo, tmp_path, monkeypatch, route
):
    tenant, remote, _, _ = http_repo
    http = ForgeHTTP()
    d = delivery(http_repo, http)
    batch = d.start_batch("tagged", lanes=LANES)
    (batch.draft_root / "agent/lessons/tagged.md").write_text("review me\n")
    commit = batch.commit(batch.change_set(), "tagged lesson")
    if route == "deliver":
        http.fail_create = True
        with pytest.raises(target().DeliveryRefused, match="503"):
            d.finish(batch)
        http.fail_create = False
    elif route == "revert":
        opened(d.finish(batch))
        merge_on_remote(http_repo, tmp_path, batch.branch)

    control = tmp_path / "control.git"
    git(tmp_path, "clone", "--bare", *BARE_NO_UPKEEP, remote, control)
    git(
        tenant.knowledge,
        "tag",
        "-a",
        "operator-tag",
        "-m",
        "not for publication",
        commit,
    )
    git(tenant.knowledge, "config", "push.followTags", "true")
    git_config_home(tmp_path).global_config.write_text("[push]\nfollowTags = true\n")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "push.followTags")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")

    # Positive control: this annotated tag is reachable and ordinary operator git follows it.
    git(tenant.knowledge, "push", control, f"{commit}:refs/heads/control")
    assert "refs/tags/operator-tag" in _refs(control)
    before = _refs(remote)
    if route == "finish":
        opened(d.finish(batch))
    elif route == "deliver":
        opened(d.deliver(batch.id))
    else:
        opened(d.revert("agent/lessons/tagged.md", "tagged"), None)
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
    git(tenant.knowledge, "config", "include.path", included)
    config = git_config_home(tmp_path)
    config.global_config.write_text(f"[include]\npath = {included}\n")
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
        git(tenant.knowledge, "remote", "get-url", "--push", "origin")
        == f"{other}/tenants/blue.git"
    )
    batch = d.start_batch("isolated", lanes=LANES)
    (batch.draft_root / "agent/lessons/isolated.md").write_text(
        "explicit destination\n"
    )
    commit = batch.commit(batch.change_set(), "isolated lesson")
    opened(d.finish(batch))
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
        git(repo[0].knowledge, "remote", "remove", "origin")
        # Recreate the local tracking ref removed by `remote remove`; it is local state,
        # independently of the explicit network destination accepted by the factory.
        git(repo[0].knowledge, "update-ref", "refs/remotes/origin/main", "main")
        d.publish()
        batch = d.start_batch("objects", lanes=LANES)
        (batch.draft_root / "agent/lessons/objects.md").write_text("objects only\n")
        commit = batch.commit(batch.change_set(), "objects")
        opened(d.finish(batch))
        assert git(repo[1], "rev-parse", f"refs/heads/{batch.branch}") == commit
