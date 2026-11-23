"""Branch launcher and tenant settings: box-mounted tenants-root refusal; a sibling resolves its own record."""
from __future__ import annotations

from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv
from defender.tests.support.shared._locations_1210 import fixture_data_root

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from pathlib import Path
from typing import Any

import pytest

from defender.integrations import elastic_adapter
from defender.tests.integrations.credential_proxy_1163 import _harness as credential_harness
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

#: A tenant id nothing else on this box spells, so "the message names the tenant" is a finding
#: about the message and never about a default.
TID = fixture_uuid("tenant:acme-t1107")


def _resolve(root: Path) -> Any:
    """The real acceptance frame over a planted root, the run's tenant built from records (#1366)."""

    return R.resolve_tenant(
        fixture_data_root(Path(root)), TID, defender_dir=S.DEFENDER, dispatches_lead_zero=False)


# Retired by #1618 K8: `test_s7_mf13_launcher_refuses_box_mounted_tenants_root` pinned the launcher refusing a tenant whose
# settings half lay inside the box-mounted episodes folder. A tenant holds no settings path (K8: every reader reads its own
# fetched copy), so acceptance judges `<T>` alone; a box-mounted tree holding `<T>` is still refused
# (`tenant_1120_piece1/test_accept_tenant.py`'s mounted-tree cells, `test_tenant_piece_entry_points.py[mounted-tree]`).


def test_s7_mf17_sibling_resolves_its_own_record(tmp_path, data_root, monkeypatch):
    shim = S.DockerShim(tmp_path / "docker")
    monkeypatch.setenv("PATH", shim.path_value())
    for name in S.BRANCH_CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    _base, src = H.tenant_source(data_root, TID)
    root = data_root
    folder = S.plant(root, TID, marker="mf17")
    manifest = H.family_for(src)
    # At launch the Elastic part was whole ...
    assert "ELASTIC_EVENTS_INDEX" in _resolve(root).systems["elastic"], \
        "the tenant's Elastic part was not whole at launch"
    # ... and is edited bad before the sibling starts.
    S.drop_key(folder, "elastic", "ELASTIC_EVENTS_INDEX")

    # A run reads its own copy of an export, never the clone's working tree: the sibling's own
    # (unpinned) launch publishes the edited folder (`S.drive_run`'s in-process publish) and
    # resolves its record from that export.
    rec = S.RunRecorder(tmp_path / "sibling-run")
    rc, refused = S.drive_run(
        H.sibling_argv(manifest, "b", "--tenant", TID), rec,
        visualize=rec.visualize)

    assert refused is None, f"the sibling was refused: {H.refusal_text(refused)!r}"
    assert rc == 0, f"the sibling exited {rc} ({rec.order})"
    assert len(rec.lifecycle_calls) == 1, f"lifecycle ran {len(rec.lifecycle_calls)} times"
    record, world = rec.lifecycle_calls[0]["tenant"], rec.lifecycle_calls[0]["world"]
    assert world.label == "b", f"the sibling ran another world: {world!r}"
    assert "ELASTIC_EVENTS_INDEX" not in record.systems["elastic"], \
        f"the sibling's own record does not see the edit: {record.systems['elastic']!r}"
    # Its Elastic calls fault.
    run_dir = tmp_path / "sibling-run"
    reached: list[str] = []

    async def proxy_app(scope: Any, receive: Any, send: Any) -> None:  # records what reaches the proxy; answers nothing
        if scope["type"] == "http":
            reached.append(scope["path"])
        raise RuntimeError("the faulted call must not reach the proxy")

    with (credential_harness.serve_asgi(proxy_app) as proxy_url, pytest.raises(S.config_fault())):
        elastic_adapter.query(S.verb_context(record, run_dir, shim.env(), proxy_url=proxy_url,
                                             request_token="tok"), native_query="*")
    assert reached == [], f"a faulted Elastic call reached the proxy: {reached}"  # elastic never uses docker (O3)


# #1366 H9: a sibling's own start reads the tenant's current records, not the source run's settings folders


def _sibling_of_records(tmp_path, data_root, monkeypatch, change):
    """A sibling `run.main --episode` over a tenant whose source run's knowledge still plants every system folder; `change(spec)`
    gives the records it is current with. Returns the sibling's recorder and the planted spec."""

    monkeypatch.setenv("PATH", S.DockerShim(tmp_path / "docker").path_value())
    for name in S.BRANCH_CONFIG_VARS:
        monkeypatch.delenv(name, raising=False)
    _base, src = H.tenant_source(data_root, TID)
    folder = S.plant(data_root, TID, marker="h9")
    planted = R.records_from_settings(S.settings_of(folder))
    assert {"cmdb", "elastic"} <= set(planted.systems), "premise: the source run's knowledge plants both systems"
    argv = H.sibling_argv(H.family_for(src), "b", "--tenant", TID)
    rec = S.RunRecorder(tmp_path / "sibling-run")
    directory = directory_for_argv(argv, records=change(planted))
    rc, refused = S.drive_run(argv, rec, visualize=rec.visualize, directory=directory)
    assert refused is None, f"the sibling was refused: {H.refusal_text(refused)!r}"
    assert rc == 0, f"the sibling exited {rc} ({rec.order})"
    assert len(rec.lifecycle_calls) == 1, f"lifecycle ran {len(rec.lifecycle_calls)} times"
    return rec, planted


@pytest.mark.parametrize("current", ["records-keep-cmdb", "cmdb-no-longer-recorded"])
def test_1366_h9_a_sibling_serves_the_systems_of_the_current_records_not_those_its_source_run_planted(
        tmp_path, data_root, monkeypatch, current):
    """The source run's knowledge plants and grants cmdb; the sibling's roster holds cmdb only while the tenant's current records
    name it (the grant is then ignored), elastic being the control. (#1366 H9, O6)"""

    rec, _ = _sibling_of_records(tmp_path, data_root, monkeypatch,
                                 lambda spec: spec if current == "records-keep-cmdb" else R.without(spec, "cmdb"))

    roster = set(rec.lifecycle_calls[0]["systems"].roster.systems)
    assert "elastic" in roster, sorted(roster)
    assert ("cmdb" in roster) is (current == "records-keep-cmdb"), sorted(roster)


def test_1366_h9_a_record_changed_after_the_source_run_is_the_one_the_sibling_runs_with(tmp_path, data_root, monkeypatch):
    """Elastic's events index differs between what the source run's knowledge plants and the current record: the sibling's
    tenant carries the record's. (#1366 H9, O6)"""

    now = "h9-now-events-*"

    def moved_on(spec):
        elastic = spec.systems["elastic"]
        assert elastic.settings["ELASTIC_EVENTS_INDEX"] != now, "premise: the planted index is another"
        return R.edited(spec, "elastic", version=2, settings={**elastic.settings, "ELASTIC_EVENTS_INDEX": now})

    rec, planted = _sibling_of_records(tmp_path, data_root, monkeypatch, moved_on)

    assert rec.lifecycle_calls[0]["tenant"].systems["elastic"]["ELASTIC_EVENTS_INDEX"] == now
