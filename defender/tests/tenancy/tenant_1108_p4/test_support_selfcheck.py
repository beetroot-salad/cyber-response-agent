"""Self-check of `_support`: the shared machinery seeds the tenant's served remote with the committed fixture tenant, and
the product's real fetch reads it back. It pins the machinery, nothing about P4 behaviour.

#1618 K8 / D2: there is no publish, clone, `exports/` or `current` (knowledge lives only in Forgejo), so the self-checks
that read an export folder and `current` now read what the product's own fetch (`fetch_copy`, through
`_fetch_standin_1618.fetch_line` over the served remote) copies at a commit, and the remote's `main`."""
from __future__ import annotations

import contextlib
from pathlib import Path

import pytest

from defender.tests.support.learning.core._store1278 import TickChild, migrated_database, world  # noqa: F401 — fixtures
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.tenancy import _tenants1106 as tenants

from ._support import (
    FIXTURE_TENANT_ID,
    OTHER_LESSON,
    agent_blobs,
    bind_forge,
    files_under,
    fixture_agent_files,
    publish_once,
    second_tenant,
    unbind_forge,
)


def _with_id(files, tenant_id):
    return {**files, ".tenant-id": f"{tenant_id}\n".encode()}


def _fetched_agent(t, commit: str | None, into: Path) -> dict:
    """The `agent/` the product's real fetch (`fetch_copy`, in process, over `t.remote` served by smart HTTP) copies at
    `commit` (`None`: `main`) into the empty `into`, by path, with its bytes. Asserted `ok` at the commit asked for."""
    from defender.tests.support.tenancy._fetch_standin_1618 import fetch_line

    into.mkdir(parents=True)
    line = fetch_line(t.tenant_id, into, data_root=t.data_root, commit=commit, remote=t.remote)
    assert line == f"ok {commit if commit is not None else t.origin_main()}", line
    return files_under(into / "agent")


def _no_host_knowledge(tenant) -> None:
    """#1618 K8: the tenant folder holds no clone, `exports/` or `knowledge.lock` once seeded."""
    folder = Path(location_path(tenant.tenant_root))
    left = [name for name in ("knowledge", "exports", "knowledge.lock") if (folder / name).exists()]
    assert left == [], f"the seeded tenant's folder still holds {left}"


def test_o11_helper_seeds_the_committed_fixture_agent_that_a_real_fetch_copies_at_the_seed_commit(p4_tenant, tmp_path):
    """The remote's `main` is the seed commit, whose `agent/` is the committed fixture's agent content (plus the placed
    `.tenant-id`); the product's fetch of `main` copies exactly that, and the tenant folder holds no knowledge (K8)."""
    t = p4_tenant
    assert t.tenant_id == FIXTURE_TENANT_ID
    expected = _with_id(fixture_agent_files(), FIXTURE_TENANT_ID)
    assert "lessons/fixture-owner-before-close.md" in expected  # the fixture is not empty
    assert t.origin_main() == t.commit
    assert agent_blobs(t.remote, t.commit) == expected
    assert _fetched_agent(t, None, tmp_path / "main") == expected
    _no_host_knowledge(t.tenant)


def test_o11_a_merge_moves_main_and_a_fetch_of_each_commit_holds_that_commits_lessons(p4_tenant, tmp_path):
    """The advance helper lands a merge on origin's `main`: a fetch of `main` then holds the merged lesson, and a fetch of
    the seed commit by id does not (K5: a pinned read fetches its commit by id). #1618 K8: no `current` or export moves."""
    t = p4_tenant
    merged = t.merge({"agent/lessons/merged-later.md": "merged after the first publish\n"})
    assert merged != t.commit
    assert t.origin_main() == merged
    assert _fetched_agent(t, None, tmp_path / "main")["lessons/merged-later.md"] == b"merged after the first publish\n"
    assert "lessons/merged-later.md" not in _fetched_agent(t, t.commit, tmp_path / "seed")
    _no_host_knowledge(t.tenant)


def test_second_tenant_is_seeded_apart_under_the_same_data_root(p4_tenant, tmp_path):
    """The second tenant has its own remote whose fetched `agent/` holds its own lesson and id; the first tenant's `main`
    does not move and its fetched `agent/` does not hold it."""
    first = p4_tenant
    path, data = OTHER_LESSON
    rel = path.removeprefix("agent/")
    with second_tenant(first) as other:
        assert other.tenant_id != first.tenant_id
        assert other.data_root == first.data_root
        assert other.remote != first.remote
        theirs = _fetched_agent(other, other.commit, tmp_path / "other")
        assert theirs == _with_id({**fixture_agent_files(), rel: data}, other.tenant_id)
    assert first.origin_main() == first.commit
    assert rel not in _fetched_agent(first, first.commit, tmp_path / "first")


def test_forge_binding_is_recorded_in_the_directory_and_writes_nothing_to_the_folder(p4_tenant):
    """`bind_forge` records the origin and a live generation on `t.directory` (O6: no row on disk, the folder is
    untouched); `unbind_forge` leaves the tenant active with no forge wiring."""
    t = p4_tenant
    before = files_under(Path(location_path(t.tenant.tenant_root)))
    other = "http://forge.test/other.git"
    bound = bind_forge(t, origin=other)
    assert bound["origin"] == other
    assert len(bound["generations"]) == 1
    assert files_under(Path(location_path(t.tenant.tenant_root))) == before
    assert not (Path(location_path(t.tenant.tenant_root)) / "tenant.json").exists()
    assert t.directory.state(t.tenant_id) == "active"
    assert t.directory.forge_wiring(t.tenant_id).origin == other
    assert t.directory_with(origin=t.origin).forge_wiring(t.tenant_id).origin == t.origin  # keywords win
    unbind_forge(t)
    assert t.directory.state(t.tenant_id) == "active"
    assert t.directory.forge_wiring(t.tenant_id) is None


def test_publish_placed_seeds_a_hand_planted_tenant_and_pushes_its_next_placement(tmp_path, data_root):
    """`publish_once` over a tenant a suite planted itself (`_tenants1106.place_tenant`, its own agent marker file): a
    fetch of the seed holds exactly the planted agent half, and the placed folder is taken (K8: `<T>` holds no
    knowledge); placing it again with an edit and a second call push the edit as a new commit on `main`."""
    import shutil

    tenant_id = fixture_uuid("tenant:p4-hand-planted")
    knowledge = tenants.place_tenant(data_root, tenant_id)
    planted = files_under(knowledge / "agent")
    kept = tmp_path / "placed-copy"
    shutil.copytree(knowledge, kept, symlinks=True)
    first = publish_once(tmp_path / "forge", root=data_root, tenant_id=tenant_id)
    assert _fetched_agent(first, first.commit, tmp_path / "first") == planted
    _no_host_knowledge(first.tenant)
    shutil.copytree(kept, knowledge, symlinks=True)  # the operator places the folder again, edited
    (knowledge / "agent" / "lessons").mkdir()
    (knowledge / "agent" / "lessons" / "edit.md").write_text("edited\n", encoding="utf-8")
    second = publish_once(tmp_path / "forge", root=data_root, tenant_id=tenant_id)
    assert second.commit != first.commit
    assert second.origin_main() == second.commit
    assert _fetched_agent(second, second.commit, tmp_path / "second") == {**planted, "lessons/edit.md": b"edited\n"}


@pytest.mark.parametrize(("sentence", "part", "key"), [
    pytest.param("missing required config keys in {loc}: CMDB_TIMEOUT_SEC", "settings", "CMDB_TIMEOUT_SEC",
                 id="locator-then-colon"),
    pytest.param("{loc}: CMDB_COLOUR is not a setting of cmdb (it reads CMDB_TIMEOUT_SEC; its base is its access.yaml's)",
                 "settings", "CMDB_COLOUR", id="file-first-format-and-possessive"),
    pytest.param("{loc} carries key(s) ['colour'] that nothing reads.", "access", "colour", id="full-stop-after"),
])
def test_1366_the_handoff_locator_helper_keeps_the_punctuation_around_the_file(sentence, part, key):
    """Test machinery (`_handoff1366`): the store's line and the handoff's line compare equal once each side's locator is
    replaced, whatever punctuation follows the file name (`:`, a full stop, `'s`) and whatever folder prefix precedes it.
    The helper must not eat the sentence along with the file name."""
    from defender.tests.support.tenancy import _handoff1366 as H

    store = H.store_sentence(sentence.format(loc=f"system cmdb {part}"), "cmdb", part)
    handoff = H.handoff_lines("  x " + sentence.format(loc=f"/tmp/h/cmdb/{H.FILES[part]}"), key, "cmdb", part)

    assert any(store in line for line in handoff), (store, handoff)



@pytest.mark.postgres
def test_the_port_self_check_counts_the_requests_the_helper_received_whichever_process_asked(world, tmp_path):  # noqa: F811 — the imported fixture
    """`TickImpl.unreached` (the self-check `conftest.tick_impl` runs at the end of each `[port]` case) is the helper's own
    count of the requests its socket received (counted at dispatch, a refused one included): a tick in a forked
    child counts, a helper nobody asked does not, and a case that started no helper reached nothing. It pins the harness, nothing about the port."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import TickImpl

    adapter = TickImpl("adapter", world, tmp_path, world.monkeypatch)
    assert adapter.unreached() is None, "the adapter has no port to reach"
    port = TickImpl("port", world, tmp_path, world.monkeypatch)
    assert "started no helper" in port.unreached()

    port.prestart()
    helper, owned = port.take()
    assert not owned, "the prestarted helper is left to `close`"

    def ask_from_the_child() -> int:
        with contextlib.suppress(Exception):  # the helper refuses what it does not serve; it counted the request
            helper.ask("selfcheck.no-such-request")
        return 0

    assert TickChild(ask_from_the_child, tmp_path / "child.json").wait() == {"rc": 0}
    port.release(helper)
    assert port.received == [["selfcheck.no-such-request"]]
    assert port.unreached() is None

    port._start()  # noqa: SLF001 — a second helper nobody asks
    port.close()
    assert port.received[1] == []
    assert "1 of 2 helper(s)" in port.unreached()


def test_adopt_scene_refuses_a_data_root_the_short_root_provider_did_not_make_before_any_helper_starts(tmp_path, monkeypatch):
    """The helper's job socket is `<data root>/.job-sockets/<claim>/job.sock` (root + 55 bytes, refused at 108): whether a root
    fits must not depend on the machine or the case's position on its worker. `adopt_scene` refuses a root of pytest's default
    shape at once, naming the root, the socket path's length and the remedy, whatever its length here."""
    import time
    from types import SimpleNamespace

    from defender.tests.support.jobs._relay1487 import adopt_scene
    from defender.tests.support.jobs._short_root import NotAShortRoot

    long_root = tmp_path / "data-root100"  # pytest's own shape: `/tmp/pytest-of-<user>/pytest-N/popen-gwN/test-x0/...`
    started = time.monotonic()
    with pytest.raises(NotAShortRoot) as refused:
        adopt_scene(SimpleNamespace(data_root=long_root, tenant_id="t"), "postgresql://unused", monkeypatch)
    assert time.monotonic() - started < 5, "the refusal must be at once, not a helper's start timeout"
    text = str(refused.value)
    for named in (str(long_root), str(len(str(long_root)) + 55), "short_root()"):
        assert named in text, (named, text)
    assert not long_root.exists(), "nothing was made under the refused root"
    # A short root that merely happens to be short is refused too: the check is the provider, not a length measured here.
    shorty = SimpleNamespace(data_root=Path("/tmp/x"), tenant_id="t")
    with pytest.raises(NotAShortRoot):
        adopt_scene(shorty, "postgresql://unused", monkeypatch)


@pytest.mark.postgres
def test_adopt_scene_over_the_cases_own_data_root_starts_a_helper(world, tmp_path):  # noqa: F811 — the imported fixture
    """Control for the refusal above: this case requests nothing but `world`, and its data root is the folder's short one, so
    a helper starts over it (its socket path is root + 55 bytes, far under the limit)."""
    from defender.tests.support.jobs._relay1487 import PostStepHelper, adopt_scene
    from defender.tests.support.jobs._short_root import socket_path_length

    assert socket_path_length(world.t.data_root) < 80, world.t.data_root
    helper = PostStepHelper(adopt_scene(world.t, world.dsn, world.monkeypatch), tmp_path)
    try:
        assert Path(helper.socket).exists()
    finally:
        helper.close()
