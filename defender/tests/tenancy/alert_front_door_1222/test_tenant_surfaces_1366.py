"""#1366 O1 (read side): every tenant surface shows exactly the tenant's systems, the ones with a current enabled record.

Entry: `run.main` through `S.run_alert` over the production driver registry (`verbs=None`: built from the run's roster),
twin-backed directories. Tenant A has no cmdb record, tenant B has all of them; cmdb is granted by both (the planted
table grants cmdb and elastic to gather) and is the discriminator because it is the verb-bearing lab adapter that no
other record names. Surfaces: the opening message's systems of record, gather's system index (the skill-description
hook), `list_verbs`, `query`, and the operator workspace map.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared.contracts._data_root_1078 import tenant_directory
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

LEAD = "l-001"
HOST = {"host": "web-1"}


def _scene(tmp_path: Path, name: str, *, with_cmdb: bool, leads: list[Any] | None = None) -> tuple[S.Drive, Any]:
    """One run of a tenant (its own, named by `name`) whose records lack cmdb (or not). Returns the drive and the directory."""
    planted = S.plant_tenant(fixture_uuid(f"tenant:{name}"))
    spec = R.records_from_settings(planted.settings)
    spec = spec if with_cmdb else R.without(spec, "cmdb")
    directory = tenant_directory(planted.root, planted.tenant_id, alert_mapping=S.current_mapping(planted), records=spec)
    leads = leads or [S.text("Summary: nothing asked.")]
    drive = S.run_alert(tmp_path / name, tenant=planted, verbs=None, directory=directory,
                        main=[S.gather(LEAD, "elastic", goal="what else fired on web-1"), S.text(S.DONE)],
                        leads={LEAD: leads})
    assert (drive.raised, drive.refusal, drive.rc) == (None, None, 0), (drive.raised, drive.refusal)
    assert drive.router.dispatched(LEAD), f"premise: the lead never ran (MAIN requests: {drive.main.requests})"
    return drive, directory


def _systems_of_record(opening: str) -> set[str]:
    start = opening.index("## Systems of record")
    rest = opening[start + len("## Systems of record"):]
    ends = [i for i in (rest.find("\n## "), rest.find("\n### ")) if i >= 0]
    block = rest[: min(ends)] if ends else rest
    return {line.split("`")[1] for line in block.splitlines() if line.startswith("- `")}


def _skill_listing(opening: str) -> set[str]:
    """The systems MAIN's opening message lists under `System skills` (one bullet each)."""
    return {line[2:].split()[0] for line in opening.splitlines() if line.startswith("- ") and "dispatched via the query tool" in line}


def test_1366_o1_the_opening_message_and_gathers_system_index_show_the_systems_of_the_tenants_records(tmp_path):
    """Tenant A (no cmdb record) is shown elastic and not cmdb in MAIN's system skills and in the lead's systems of record
    (the skill-description hook's index); tenant B, with the record, is shown both. (#1366 O1 model listing, hook, status)"""
    a, _ = _scene(tmp_path, "a", with_cmdb=False)
    b, _ = _scene(tmp_path, "b", with_cmdb=True)

    assert "elastic" in _skill_listing(a.opening_message)
    assert "cmdb" not in _skill_listing(a.opening_message)
    assert {"cmdb", "elastic"} <= _skill_listing(b.opening_message), _skill_listing(b.opening_message)
    index = {name: _systems_of_record(d.router.first_prompt(LEAD)) for name, d in (("a", a), ("b", b))}
    assert "elastic" in index["a"], index["a"]
    assert "cmdb" not in index["a"], index["a"]
    assert {"cmdb", "elastic"} <= index["b"], index["b"]


def test_1366_o1_list_verbs_and_query_answer_for_the_tenants_systems_only(tmp_path):
    """The lead of tenant A asks `list_verbs`/`query` about cmdb (no record): neither publishes a cmdb verb, and the query
    never reaches the adapter (base: it reached the transport and failed there for want of a proxy); `list_verbs elastic`
    still lists elastic's verbs. Tenant B's `list_verbs cmdb` lists cmdb's. (#1366 O1 list_verbs, query, driver roster)"""
    ask = [S.list_verbs("cmdb"), S.query("cmdb", "get-host", HOST), S.list_verbs("elastic"), S.text("Summary: done.")]
    a, _ = _scene(tmp_path, "a", with_cmdb=False, leads=ask)
    b, _ = _scene(tmp_path, "b", with_cmdb=True, leads=[S.list_verbs("cmdb"), S.text("Summary: done.")])

    returned_a = a.router.seen(LEAD)[-1].tool_returns
    returned_b = b.router.seen(LEAD)[-1].tool_returns
    assert len(returned_a) == 3, (returned_a, returned_b)
    assert len(returned_b) == 1, (returned_a, returned_b)
    # The returns arrive in the order the host delivers them (a query reply is stamped and may come last), so each is
    # told by what it answers: the elastic listing by its verb rows, the query by the `system.verb` it echoes, and the
    # cmdb listing is the one left.
    elastic_list = [r for r in returned_a if 'verb="alerts"' in r]
    query_reply = [r for r in returned_a if "cmdb.get-host" in r]
    cmdb_list = [r for r in returned_a if r not in elastic_list and r not in query_reply]
    assert (len(elastic_list), len(query_reply), len(cmdb_list)) == (1, 1, 1), returned_a
    assert 'verb="get-host"' in returned_b[0], "control: tenant B's cmdb lists its verbs"
    assert 'verb="alerts"' in elastic_list[0], "control: tenant A's elastic still lists its verbs"
    assert "cmdb" in cmdb_list[0], cmdb_list[0]
    assert 'verb="get-host"' not in cmdb_list[0], cmdb_list[0]
    assert "cmdb" in query_reply[0], query_reply[0]
    assert "credential proxy" not in query_reply[0], query_reply[0]


def test_1366_o1_the_workspace_map_command_lists_the_tenants_systems_not_the_checkouts(tmp_path, capsys):
    """The operator's map of tenant A's run lists elastic and not cmdb; tenant B's lists both. (#1366 O1 workspace map)"""
    from defender.cli import workspace_map

    maps = {}
    for name, with_cmdb in (("a", False), ("b", True)):
        drive, directory = _scene(tmp_path, name, with_cmdb=with_cmdb)
        capsys.readouterr()
        rc = workspace_map.main(["workspace_map.py", "--tenant", drive.tenant.tenant_id, drive.run_dir.name],
                                directory=directory)
        maps[name] = (rc, capsys.readouterr().out)

    listed = {name: [line for line in text.splitlines() if re.match(r"- [a-z-]+ ", line)] for name, (_, text) in maps.items()}
    assert maps["a"][0] == maps["b"][0] == 0
    assert any(line.startswith("- elastic ") for line in listed["a"]), listed["a"]
    assert not any(line.startswith("- cmdb ") for line in listed["a"]), listed["a"]
    assert any(line.startswith("- cmdb ") for line in listed["b"]), listed["b"]
