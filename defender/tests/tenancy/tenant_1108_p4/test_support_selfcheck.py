"""Self-check of `_support`: the shared machinery produces a real export of the committed fixture
tenant through P3. It pins the machinery, nothing about P4 behaviour."""
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
    current_commit,
    export_dir,
    files_under,
    fixture_agent_files,
    publish_once,
    second_tenant,
    unbind_forge,
)


def _with_id(files, tenant_id):
    return {**files, ".tenant-id": f"{tenant_id}\n".encode()}


def test_o11_helper_exports_the_committed_fixture_agent_at_the_published_commit(p4_tenant):
    """The export's `agent/` is the committed fixture's agent content (plus the placed
    `.tenant-id`) at the commit origin's `main` holds, and `current` names that commit."""
    t = p4_tenant
    assert t.tenant_id == FIXTURE_TENANT_ID
    expected = _with_id(fixture_agent_files(), FIXTURE_TENANT_ID)
    assert "lessons/fixture-owner-before-close.md" in expected  # the fixture is not empty
    exported = files_under(export_dir(t.tenant, t.commit) / "agent")
    assert exported == expected
    assert agent_blobs(t.remote, t.commit) == expected
    assert t.origin_main() == t.commit
    assert current_commit(t.tenant) == t.commit
    # Published through P3's network path, not a local export: the origin served an
    # authenticated fetch and the forge was asked about `main`'s protection.
    assert t.server.authorized("git-upload-pack")
    assert any(r.url.path.endswith("/branches/main") for r in t.forge.requests)


def test_o11_merge_then_publish_moves_current_to_the_merged_commit(p4_tenant):
    """The advance helper lands a merge on origin that only a real publish brings in: before
    publishing `current` still names the first export; after, it names the merge, whose export
    holds the merged lesson, and the first export is unchanged."""
    t = p4_tenant
    merged = t.merge({"agent/lessons/merged-later.md": "merged after the first publish\n"})
    assert merged != t.commit
    assert t.origin_main() == merged
    assert current_commit(t.tenant) == t.commit
    export = t.publish()
    assert export.commit == merged
    assert len(t.vault.calls) == 2  # each publish asked the issuer afresh
    assert current_commit(t.tenant) == merged
    assert files_under(export_dir(t.tenant, merged) / "agent")["lessons/merged-later.md"] == \
        b"merged after the first publish\n"
    assert "lessons/merged-later.md" not in files_under(export_dir(t.tenant, t.commit) / "agent")


def test_second_tenant_is_published_apart_under_the_same_data_root(p4_tenant):
    """The second tenant has its own export holding its own lesson; the first tenant's export
    and `current` do not change and do not hold it."""
    first = p4_tenant
    path, data = OTHER_LESSON
    rel = path.removeprefix("agent/")
    with second_tenant(first) as other:
        assert other.tenant_id != first.tenant_id
        assert other.data_root == first.data_root
        theirs = files_under(export_dir(other.tenant, other.commit) / "agent")
        assert theirs == _with_id({**fixture_agent_files(), rel: data}, other.tenant_id)
        assert current_commit(other.tenant) == other.commit
    assert current_commit(first.tenant) == first.commit
    assert rel not in files_under(export_dir(first.tenant, first.commit) / "agent")


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


def test_publish_placed_exports_a_hand_planted_tenant_and_republishes_its_edits(tmp_path, data_root):
    """`publish_once` over a tenant a suite planted itself (`_tenants1106.place_tenant`, its own
    agent marker file): the export holds exactly the planted agent half; an edit to the folder
    and a second call export the edit as a new commit and move `current` to it."""
    tenant_id = fixture_uuid("tenant:p4-hand-planted")
    knowledge = tenants.place_tenant(data_root, tenant_id)
    planted = files_under(knowledge / "agent")
    first = publish_once(tmp_path / "forge", root=data_root, tenant_id=tenant_id)
    assert files_under(export_dir(first.tenant, first.commit) / "agent") == planted
    assert current_commit(first.tenant) == first.commit
    (knowledge / "agent" / "lessons").mkdir()
    (knowledge / "agent" / "lessons" / "edit.md").write_text("edited\n", encoding="utf-8")
    second = publish_once(tmp_path / "forge", root=data_root, tenant_id=tenant_id)
    assert second.commit != first.commit
    assert current_commit(second.tenant) == second.commit
    assert files_under(export_dir(second.tenant, second.commit) / "agent") == {
        **planted, "lessons/edit.md": b"edited\n"}


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
def test_the_port_self_check_counts_the_requests_the_helper_answered_whichever_process_asked(world, tmp_path):  # noqa: F811 — the imported fixture
    """`TickImpl.unreached` (the self-check `conftest.tick_impl` runs at the end of each `[port]` case) is the helper's own
    count of the requests its socket was asked: a tick in a forked child counts, a helper nobody asked does not, and a case
    that started no helper reached nothing. It pins the harness, nothing about the port."""
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
    assert port.answered == [["selfcheck.no-such-request"]]
    assert port.unreached() is None

    port._start()  # noqa: SLF001 — a second helper nobody asks
    port.close()
    assert port.answered[1] == []
    assert "1 of 2 helper(s)" in port.unreached()
