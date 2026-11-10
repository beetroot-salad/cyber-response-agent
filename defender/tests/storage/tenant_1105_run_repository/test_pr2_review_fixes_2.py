"""Review-finding regressions: tick without data root, tenant acceptance, quarantined curation rows, cross-tenant grading, prompt view numbering."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

import os
import re
from pathlib import Path
from typing import Any

import pytest

from defender.tenancy import _tenant
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P
from defender.tests.storage.tenant_1105_run_repository import test_pr2_review_fixes as R1
from defender.records._tenant_id import TenantId, TenantRefused
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


@pytest.fixture
def published(tmp_path, data_root):
    """As `test_pr2_review_fixes.published`: the fixture tenant published for real, its
    forge bound, for the tenant-selected lead-author ticks."""
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        yield t


class _EnqueueingBox(R1._Box):
    """The box seam, which also files a curation request in the store as the box starts: a row landing
    mid-tick, after the tick looked at its queue."""

    def __init__(self, dsn: str, tenant_id: str, row: dict) -> None:
        super().__init__()
        self.dsn, self.tenant_id, self.row = dsn, tenant_id, row

    def start(self, request: Any, **kw: Any) -> Any:
        P.file_request(self.dsn, self.tenant_id, self.row["case_id"], self.row)
        return super().start(request, **kw)


@pytest.mark.postgres
@pytest.mark.parametrize("root_set", [True, False], ids=["root-set", "root-unset"])
def test_1_a_row_landing_mid_tick_waits_for_the_next_tick(published, tmp_path, monkeypatch, root_set, migrated_database):
    """Through the REAL tenant-selected tick over the published tenant's drain paths. The late request is filed in the
    store after the tick's claim (#1278: the claim is the store's, so it is not in the batch and stays `waiting`)."""
    from defender.tests.support.runtime.engine._declared869 import pitfall_row

    t = published
    H.make_run(H.runs_folder(t.tenant), R1.RID_R1)
    root = os.environ[P.DATA_ROOT_ENV]
    paths = R1._tenant_paths(t, tmp_path)
    P.store_tick_scene(migrated_database, monkeypatch, t.tenant_id)
    P.file_pitfall(migrated_database, t.tenant_id, pitfall_row("r:0", "elastic"))  # wakes the tick with no curation row
    if not root_set:
        monkeypatch.delenv(P.DATA_ROOT_ENV)
    row = {"case_id": "late", "tenant_id": t.tenant_id, "run_id": R1.RID_R1}
    box = _EnqueueingBox(migrated_database, t.tenant_id, row)
    lane = P.Lane()
    pitfalls: list[str] = []

    rc = R1._tick(t, paths, lane=lane, pitfalls=pitfalls, box=box)
    assert rc == 0
    assert box.started, "the tick never started its box"
    assert pitfalls == ["pitfalls"], "the pitfalls step did not run"
    assert lane.handed == [], "a row that landed mid-tick was served"
    late = P.store_items(migrated_database, t.tenant_id, "curation_request")["late"]
    assert (late.status, late.attempts) == ("waiting", 0), f"the late row was claimed into the tick's batch: {late}"

    monkeypatch.setenv(P.DATA_ROOT_ENV, root)
    assert R1._tick(t, paths, lane=lane, pitfalls=[], box=R1._Box()) == 0
    assert lane.run_dirs == [Path(location_path(t.tenant.runs)) / R1.RID_R1], (
        "control: the next tick did not serve it")


def test_2_requested_tenant_is_the_one_acceptance_of_a_raw_or_stored_tenant_id(d9_tenant):
    from defender._paths import process_defender_dir

    root = _tenant.resolve_data_root()
    direct = _tenant.accept_tenant(fixture_data_root(root), d9_tenant, defender_dir=process_defender_dir())
    for raw in (d9_tenant, TenantId(d9_tenant)):
        got = _tenant.requested_tenant(fixture_data_root(root), raw)
        assert isinstance(got, _tenant.Tenant)
        assert (got.id, Path(location_path(got.runs)), Path(location_path(got.data_root))) == (
            direct.id, Path(location_path(direct.runs)), Path(location_path(direct.data_root))), raw
    for bad in (None, "../x", "no-such-tenant"):
        assert isinstance(H.raised(_tenant.requested_tenant, root, bad),
                          TenantRefused), bad


# retired: the `lead_author` row (the by-hand `lead_author.main` entry is deleted, design A3).
@pytest.mark.parametrize("cli", ["visualize_run", "workspace_map"])
def test_2_each_run_id_command_prints_the_data_roots_refusal(tmp_path, d9_tenant, monkeypatch,
                                                              cli):
    from defender.tenancy._command_line_run import open_command_line_run
    from defender.records import Run
    from defender.tests.support.learning.core._state1135 import curation_run_dir

    run_dir = curation_run_dir("r-real", tenant_id=d9_tenant)
    run_id = run_dir.name  # the uuid4 its label names (`fixture_uuid`)
    # r10.1 C1: the opener takes the tenant its command's host acceptance admitted; it never accepts one itself.
    from defender._paths import process_defender_dir

    tenant = _tenant.accept_tenant(fixture_data_root(_tenant.resolve_data_root()), d9_tenant,
                                   defender_dir=process_defender_dir())
    run = open_command_line_run(tenant, run_id)
    assert isinstance(run, Run), run
    assert str(tenant.id) == d9_tenant
    assert Path(run.run_dir) == run_dir

    argv, main, status = {
        "visualize_run": (P.new_run_page_argv(d9_tenant, run_id), P.run_page_main(), 1),
        "workspace_map": (["workspace_map.py", "--tenant", d9_tenant, run_id],
                          R1._workspace_map_main(), 2),
    }[cli]
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    # With no data root there is nothing to accept: the refusal is the command's own acceptance (the opener is only
    # reached with an accepted tenant, C1), asserted through each command below.
    with R1._no_logging():
        got = P.drive_cli(main, argv)
    assert got.rc == status, f"{cli}: {got.rc} {got.err!r}"
    assert P.DATA_ROOT_ENV in got.err, f"{cli}: {got.err!r}"
    assert got.out == ""


@pytest.mark.postgres
def test_4_a_dead_curation_request_shows_its_address(published, tmp_path, monkeypatch, migrated_database):
    """The request is retired by the REAL tenant-selected tick over the published tenant's drain paths, and the queue
    page lists it dead with the run id it names and the reason, with no run folder. #1278 update: the queue page's
    dead-letter list (design O2) carries the item's id (the run id the request is keyed by) and reason; the old
    quarantine row's separate `tenant_id`/`run_id` fields are gone, the page being per tenant."""
    from defender.learning.frontend import serialize_queues
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    t = published
    H.runs_folder(t.tenant)
    paths = R1._tenant_paths(t, tmp_path)
    P.store_tick_scene(migrated_database, monkeypatch, t.tenant_id)
    gone_run = fixture_uuid("nope")  # a well-formed run id naming no run
    P.file_request(migrated_database, t.tenant_id, "gone", {"case_id": "gone", "tenant_id": t.tenant_id, "run_id": gone_run})
    assert R1._tick(t, paths, lane=P.Lane(), pitfalls=[], box=R1._Box()) == 0

    from defender.learning.store import blocking

    with blocking(migrated_database) as store:
        view = serialize_queues.build_view(paths, store)
    channel = next(c for c in view["channels"] if c["name"] == "curation_requests")
    rows = [r for r in channel["deadletter"] if r["id"] == gone_run]
    assert len(rows) == 1, channel
    assert rows[0]["reason"] == "artifact-missing", rows[0]
    assert "run_dir" not in str(channel), channel


def test_6_grading_another_tenants_episode_is_refused(tmp_path):
    from defender.learning.judge import JudgeRefused, grade_episode
    from defender.records import RunRefused
    from defender.tests.support.learning.judge import _judge_921 as J
    from defender.tests.support.learning.judge._memory_store import MemoryStore
    from defender.tests.storage.ids_1187 import _spec1187 as S

    est, src = P.launch_source(tmp_path)
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert got.raised is None, f"the launch did not run: {got!r}"
    assert got.rc == 0, f"the launch did not run: {got!r}"
    episodes = S.episodes_dir(location_path(P.data_root)(), P.LAUNCH_TENANT)
    made = sorted(p.name for p in episodes.iterdir()) if episodes.is_dir() else []
    assert len(made) == 1, f"the launch made {made} under <T>/episodes"
    episode_id = made[0]
    ep = episodes / episode_id
    (ep / "judge.yaml").unlink(missing_ok=True)
    other = P.second_tenant(location_path(P.data_root)(), H.U_ID)
    refused_store = MemoryStore()

    judge = J.scripted_judge()
    err = H.raised(grade_episode, other.runs_repository(), episode_id, judge=judge,
                   store=refused_store)
    assert isinstance(err, (JudgeRefused, RunRefused, TenantRefused,
                            FileNotFoundError)), f"another tenant graded the episode: {err!r}"
    assert not (ep / "judge.yaml").exists(), "a grade was written for another tenant"
    assert not refused_store.items, "the refused grade queued findings"
    assert not os.path.lexists(S.episodes_dir(location_path(P.data_root)(), H.U_ID) / episode_id)

    own = _tenant.accept_tenant(fixture_data_root(location_path(P.data_root)()), P.LAUNCH_TENANT,
                                defender_dir=H.DEFENDER).runs_repository()
    assert not (ep / "runs" / "_tenant.json").exists(), "the launch wrote a container record"
    moved = tmp_path / "container-away"
    (ep / "runs").rename(moved)
    handle = own.episode_files(episode_id)
    handle.close()
    moved.rename(ep / "runs")

    graded = grade_episode(own, episode_id, judge=J.scripted_judge(), store=MemoryStore())
    assert graded is not None
    assert (ep / "judge.yaml").is_file(), "control: the own tenant did not grade"


@pytest.mark.postgres
def test_7_the_judge_prompts_views_are_numbered_without_a_gap(tmp_path, monkeypatch, migrated_database):
    from defender.learning.judge import layout as judge_layout

    numbers = [int(m.group(1)) for title in judge_layout.FOCUS_VIEW_TITLES.values()
               if (m := re.match(r"VIEW (\d+):", title))]
    assert numbers == list(range(1, len(numbers) + 1)), numbers
    lessons = judge_layout.FOCUS_VIEW_TITLES["lessons"]
    assert lessons.startswith(f"VIEW {len(numbers)}:"), lessons

    P.reach_launch_store(migrated_database, monkeypatch)  # the judge pass inserts into the learning store (#1278)
    est, src = P.launch_source(tmp_path)
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert got.judge.prompts, "the judge was never asked"
    # The per-world prompts carry the views; the family-level call carries none.
    viewed = [sorted({int(n) for n in re.findall(r"VIEW (\d+):", prompt)})
              for prompt in got.judge.prompts]
    viewed = [seen for seen in viewed if seen]
    assert viewed, "control: no prompt carries a view"
    assert any(lessons in prompt for prompt in got.judge.prompts), "control: no lessons view"
    for seen in viewed:
        assert seen == list(range(1, max(seen) + 1)), f"a gap in the prompt's views: {seen}"
