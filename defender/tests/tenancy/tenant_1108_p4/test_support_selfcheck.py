"""S0 self-check: the shared machinery produces a REAL export of the committed fixture tenant
(O11's "one helper that git-inits the fixture tenant and publishes for real"). Validates the
machinery against P3 as merged; it promises nothing about P4 behaviour."""
from __future__ import annotations

import json
from pathlib import Path

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.tenancy import _tenants1106 as tenants

from ._support import (
    FIXTURE_TENANT_ID,
    ISSUER_AUDIENCE,
    OTHER_LESSON,
    agent_blobs,
    bind_forge,
    default_issuer_config,
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
    """O11: the export's `agent/` is the committed fixture's agent content (plus the placed
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


def test_forge_binding_round_trips_through_the_tenant_row(p4_tenant):
    """`bind_forge` writes `forge: {origin, audience, issuer_role, issuer_config}` into `<T>/tenant.json`,
    keeping the row's own fields, and the tenant is still accepted by the real reader (which
    today ignores the field); `unbind_forge` removes it again."""
    t = p4_tenant
    row_path = Path(location_path(t.tenant.row_path))
    before = json.loads(row_path.read_text(encoding="utf-8"))
    assert "forge" not in before
    binding = bind_forge(t)
    assert binding == {"origin": t.origin, "audience": ISSUER_AUDIENCE,
                       "issuer_role": f"tenant-{t.tenant_id}",
                       "issuer_config": str(default_issuer_config(t))}
    assert json.loads(row_path.read_text(encoding="utf-8")) == {**before, "forge": binding}
    assert str(tenants.accept(t.data_root, t.tenant_id).id) == t.tenant_id
    unbind_forge(t)
    assert json.loads(row_path.read_text(encoding="utf-8")) == before


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
