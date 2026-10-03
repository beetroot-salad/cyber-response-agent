"""#1120 piece 1 — O1/D2 end to end: a run reads its tenant's settings from the DATA ROOT,
whatever checkout runs the code, and the replay harness runs as the fixture tenant (H2).

Two lanes, each driven through the REAL runtime on the replay harness
(`defender/tests/e2e/_replay_harness.py`), with the models faked at the harness's own
`make_model` seam and every registry either the production one or the harness's `FakeVerbs`:

  * O1 — `run.main` resolves the run's tenant from `DEFENDER_DATA_ROOT` (never from the
    checkout's `knowledge/`), and the gather lead the run then drives is granted exactly that
    tenant's table. The data-root tenant carries the retired lab's OWN id (`playground`) and a
    table that differs from the committed fixture's (the lab's frozen copy) by one gather
    verb, so a lane that read a checkout copy is caught by value, not only by path.
  * H2 (the replay harness's R5 survival) — a replay that names no tenant runs as the fixture
    tenant (`knowledge/tenant-fixture/`) set up under the test's own data root, never as the
    checkout's lab resolved through the removed `tenant_dir`.

Every fault is a real input on disk; the only fakes are the harness's model and verb seams,
which RECORD what they are handed. No `monkeypatch.setattr`. See `_spec1120.py` for the coined
names.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender import run as run_py  # noqa: E402
from defender.tests import _dispositions995 as D995  # noqa: E402
from defender.tests.e2e import _replay_harness as R  # noqa: E402
from defender.tests.tenant_1120_piece1 import _spec1120 as H  # noqa: E402

pytestmark = pytest.mark.e2e

#: The retired lab's own id: the data-root tenant carries it, so reading a checkout copy would
#: be caught by the table's value.
LAB_ID = "playground"

#: The one gather pair the data-root table withholds and the checkout's fixture grants.
WITHHELD = ("change-mgmt", "list-changes")

LEAD = "l-001"
DONE = R.Turn(text="Summary: measured the lead.")


def _withhold_in_data_root_table(settings: Path) -> None:
    """Rewrite the placed tenant's `list-changes` row as withheld (roles: [] with a reason) —
    one gather verb fewer than the fixture grants, and still total over the census."""
    H.edit_table(settings, drop=("    list-changes:",))
    table = settings / "verb-grants.yaml"
    text = table.read_text(encoding="utf-8")
    anchor = "    get-change: {roles: [gather]}\n"
    assert anchor in text, "the fixture's change-mgmt block changed shape"
    table.write_text(text.replace(anchor, anchor + (
        "    list-changes:\n      roles: []\n"
        "      reason: \"withheld by #1120's O1 spec: this tenant differs from the lab\"\n"),
        1), encoding="utf-8")


def _gather_pairs(grant) -> set[tuple[str, str]]:
    return {(s, v) for s, v, *_ in grant.entries}


def _dispatch(system: str) -> R.Turn:
    return R.Turn(tool_calls=[("gather", {
        "lead_id": LEAD, "system": system, "goal": f"measure the {system} lead",
        "what_to_summarize": ["what the system says"]})])


def _lead_prompts(gather: R.ReplayFn) -> list[str]:
    """Every prompt the gather fake saw for THIS test's lead (not a harness lead-0)."""
    seen = [s for s in gather.seen if f"lead_id: {LEAD}" in s or f"lead_id: '{LEAD}'" in s]
    assert seen, f"no gather prompt for {LEAD}: {[s[:200] for s in gather.seen]}"
    return seen


def _systems_of_record(prompt: str) -> set[str]:
    start = prompt.index("## Systems of record")
    rest = prompt[start + len("## Systems of record"):]
    ends = [i for i in (rest.find("\n## "), rest.find("\n### ")) if i >= 0]
    block = rest[: min(ends)] if ends else rest
    return {line.split("`")[1] for line in block.splitlines() if line.startswith("- `")}


def _under(path: Path, parent: Path) -> bool:
    return Path(path).resolve().is_relative_to(Path(parent).resolve())


def test_1120_a_run_from_a_checkout_with_different_lab_settings_reads_the_data_root_copy(
        data_root: Path, tmp_path: Path) -> None:
    """This drives run.main over an alert with --tenant playground from this checkout, whose
    committed fixture (knowledge/tenant-fixture/settings, the retired lab's frozen copy) grants
    gather change-mgmt list-changes. A tmp data root holds the same id, whose
    knowledge/settings/verb-grants.yaml differs from the fixture's by that one gather verb
    (withheld, with a reason). The RunTenant
    run.main hands its lifecycle reads the data-root copy: its tenant's settings is
    <root>/playground/knowledge/settings, its table path lies there, and its gather grant is
    exactly the fixture's census minus the withheld pair. No path the run resolved for its
    tenant (settings, agent, knowledge, the table) lies under the checkout's knowledge/ tree.
    The gather lead the run then drives, through the real driver on that tenant and those
    grants, is granted exactly the data-root table: list_verbs for change-mgmt publishes
    active-changes but not list-changes, and a query for list-changes is refused as not
    granted — the fixture's grant would have admitted it."""
    checkout_table = (H.FIXTURE / "settings" / "verb-grants.yaml").read_text(encoding="utf-8")
    assert "    list-changes: {roles: [gather]}" in checkout_table, (
        "precondition: the checkout's fixture no longer grants change-mgmt list-changes, so "
        "this scenario no longer tells a checkout copy's table from the data root's")
    H.adopted(data_root, LAB_ID)
    settings = H.settings_dir(data_root, LAB_ID)
    _withhold_in_data_root_table(settings)

    rec = H.RunRecorder(tmp_path / "run-main")
    rc, exc = H.drive_run(
        run_py, [str(H.plant_alert(tmp_path / "in")), "--tenant", LAB_ID], rec)
    assert exc is None, f"run.main refused the data-root tenant: {H.exit_text(exc)}"
    assert rc == 0, f"run.main exited {rc}"
    assert len(rec.lifecycle_calls) == 1, f"the lifecycle ran {len(rec.lifecycle_calls)} times"
    run_tenant = rec.lifecycle_calls[0]["tenant"]

    assert Path(run_tenant.settings) == settings, (
        f"the run read its tenant's settings from {run_tenant.settings}, not the data root's "
        f"copy {settings} — a checkout copy decided the run")
    assert Path(run_tenant.tenant.settings) == settings
    assert Path(run_tenant.grants.path) == settings / "verb-grants.yaml"
    expected = set(D995.GATHER_CENSUS) - {WITHHELD}
    assert WITHHELD in D995.GATHER_CENSUS, "the census no longer holds the withheld pair"
    assert _gather_pairs(run_tenant.grants.gather) == expected, (
        "the run's gather grant is not the data-root table's")
    checkout_knowledge = H.KNOWLEDGE_ROOT
    for label, path in (("settings", run_tenant.tenant.settings),
                        ("agent", run_tenant.tenant.agent),
                        ("knowledge", run_tenant.tenant.knowledge),
                        ("table", run_tenant.grants.path)):
        assert _under(path, data_root), f"the run's tenant {label} {path} is not under the root"
        assert not _under(path, checkout_knowledge), (
            f"the run's tenant {label} {path} lies under the checkout's {checkout_knowledge}")

    run_dir = R.materialize(tmp_path / "replay", R.GOLDEN_AB3)
    main = R.ReplayFn([_dispatch("change-mgmt"), R.Turn(text="Investigation complete.")])
    gather = R.ReplayFn([
        R.Turn(tool_calls=[("list_verbs", {"system": "change-mgmt"})]),
        R.Turn(tool_calls=[("query", {"system": "change-mgmt", "verb": "list-changes",
                                      "params": {}})]),
        DONE,
    ])
    R.drive(run_dir, run_id="o1-1120-data-root", main=main, gather=gather,
            tenant=run_tenant.tenant)
    after = "\n".join(_lead_prompts(gather))
    assert 'query(system="change-mgmt", verb="active-changes"' in after, (
        "positive control: list_verbs did not publish a verb the data-root table grants")
    assert 'verb="list-changes"' not in after, (
        "list_verbs published change-mgmt list-changes, which the data-root table withholds")
    assert "change-mgmt.list-changes is not granted" in after, (
        "a query for the withheld verb was not refused as ungranted — the run's gather policy "
        "is not the data-root table")


def test_1120_a_replay_without_a_named_tenant_runs_as_the_fixture_tenant_under_the_data_root(
        data_root: Path, tmp_path: Path) -> None:
    """A replay driven through the harness with no tenant named completes, and the tenant it
    ran as is the fixture tenant (knowledge/tenant-fixture) set up under the test's own
    DEFENDER_DATA_ROOT — never the checkout's lab resolved through the removed tenant_dir
    (H2; the replay harness is the tenant_dir's surviving dependent). Afterwards the data
    root holds exactly one tenant folder, with its row naming it and a knowledge/settings
    tree byte-equal to the fixture's, and an agent/.tenant-id naming it. The query verb the
    gather lead calls is handed that folder's settings path, which lies under the data root
    and not under the checkout's knowledge/ tree, and the gather dispatch advertises exactly
    the systems the fixture's gather grant reaches (its census)."""
    rec = R.VerbRecorder()

    def get_host(ctx, *, host: str = "web-1") -> dict:
        rec.record("get-host", ctx, {"host": host})
        return {"host": host}

    run_dir = R.materialize(tmp_path / "replay", R.GOLDEN_AB3)
    main = R.ReplayFn([_dispatch("cmdb"), R.Turn(text="Investigation complete.")])
    gather = R.ReplayFn([
        R.Turn(tool_calls=[("query", {"system": "cmdb", "verb": "get-host",
                                      "params": {"host": "web-1"}})]),
        DONE,
    ])
    R.drive(run_dir, run_id="h2-1120-fixture", main=main, gather=gather,
            verbs=R.FakeVerbs({"cmdb": {"get-host": get_host}}))
    assert main.calls == 2, f"the replay did not complete: {main.calls} main turns"

    handed = Path(rec.only().ctx.tenant.settings)
    assert not _under(handed, H.KNOWLEDGE_ROOT), (
        f"the replay ran as a tenant whose settings live in the checkout ({handed}) — the "
        "harness still resolves the lab, not the fixture under the data root")
    assert _under(handed, data_root), f"the verb was handed {handed}, not a data-root folder"

    folders = sorted(p for p in data_root.iterdir() if p.is_dir())
    assert len(folders) == 1, f"expected one tenant folder under the data root: {folders}"
    folder = folders[0]
    tenant_id = folder.name
    assert handed.resolve() == (folder / "knowledge" / "settings").resolve()
    row = (folder / H.ROW_NAME).read_text(encoding="utf-8")
    assert f'"tenant_id": "{tenant_id}"' in row, f"the row does not name {tenant_id!r}: {row}"
    id_file = (folder / "knowledge" / H.TENANT_ID_FILE).read_text(encoding="utf-8")
    assert id_file.rstrip("\r\n") == tenant_id, f"agent/.tenant-id reads {id_file!r}"

    fixture_settings = H.FIXTURE / "settings"
    placed = folder / "knowledge" / "settings"
    names = sorted(p.relative_to(fixture_settings).as_posix()
                   for p in fixture_settings.rglob("*") if p.is_file())
    copied = sorted(p.relative_to(placed).as_posix() for p in placed.rglob("*") if p.is_file())
    assert copied == names, f"the tenant's settings are not the fixture's: {copied} != {names}"
    for rel in names:
        assert (placed / rel).read_bytes() == (fixture_settings / rel).read_bytes(), (
            f"settings/{rel} differs from the fixture's")

    census_systems = {s for s, _ in D995.GATHER_CENSUS}
    advertised = _systems_of_record(_lead_prompts(gather)[0])
    assert advertised == census_systems, (
        f"the gather dispatch advertises {sorted(advertised)}, not the fixture grant's "
        f"{sorted(census_systems)}")
