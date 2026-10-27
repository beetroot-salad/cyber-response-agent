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
from defender.tests.storage.tenant_1105_run_repository import test_1105_pr2_review_fixes as R1
from defender.records._tenant_id import TenantId, TenantRefused


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _queue_dir(paths: Any) -> Path:
    return Path(location_path(paths.state_root)) / "author-queue"


def _queued_top(paths: Any, case_id: str) -> bool:
    return (_queue_dir(paths) / f"{case_id}.json").is_file()


def _inflight(paths: Any, case_id: str) -> bool:
    return (_queue_dir(paths) / "inflight" / f"{case_id}.json").is_file()


def _pitfall_at_threshold(paths: Any, monkeypatch: Any) -> None:
    """One pitfall row with the threshold at 1, so the tick wakes with no curation row."""
    from defender.learning.core import persist
    from defender.tests.support.learning.core._state1135 import state_for_paths

    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls([{"pitfall_id": "r:0", "system": "elastic"}],
                            state=state_for_paths(paths))


@pytest.fixture
def published(tmp_path, data_root):
    """`test_1105_pr2_review_fixes.published`: the fixture tenant published for real, its forge
    bound — #1108 P4's lead-author drain is tenant-selected, so its ticks run over it."""
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        yield t


# #1105 PR 2 finding 1's first case — a tick with rows and no configured data root is the
# stage's configuration refusal — is retired by #1108 P4 (OD12 class i): every drain is
# tenant-selected and rehydrates its rows under the SELECTED tenant's own root, so the scratch
# path it pinned cannot arise. Covered by
# `test_1105_pr2_review_fixes.py::test_c_a_tenant_tick_serves_its_rows_from_its_own_root_without_the_env`.


class _EnqueueingBox(R1._Box):
    """The box seam, which also enqueues a curation row as the box starts: a row landing
    mid-tick, after the tick looked at its queue."""

    def __init__(self, paths: Any, row: dict) -> None:
        super().__init__()
        self.paths, self.row = paths, row

    def start(self, request: Any, **kw: Any) -> Any:
        P.queue_row(self.paths, self.row["case_id"], self.row)
        return super().start(request, **kw)


@pytest.mark.parametrize("root_set", [True, False], ids=["root-set", "root-unset"])
def test_1_a_row_landing_mid_tick_waits_for_the_next_tick(published, tmp_path, monkeypatch,
                                                         root_set):
    """#1108 P4: over the published tenant's drain paths, the REAL tenant-selected tick."""
    t = published
    H.make_run(H.runs_folder(t.tenant), R1.RID_R1)
    root = os.environ[P.DATA_ROOT_ENV]
    paths = R1._tenant_paths(t, tmp_path)
    _pitfall_at_threshold(paths, monkeypatch)
    if not root_set:
        monkeypatch.delenv(P.DATA_ROOT_ENV)
    row = {"case_id": "late", "tenant_id": t.tenant_id, "run_id": R1.RID_R1}
    box = _EnqueueingBox(paths, row)
    lane = P.Lane()
    pitfalls: list[str] = []

    rc = R1._tick(t, paths, lane=lane, pitfalls=pitfalls, box=box)
    assert rc == 0
    assert box.started, "the tick never started its box"
    assert pitfalls == ["pitfalls"], "the pitfalls step did not run"
    assert lane.handed == [], "a row that landed mid-tick was served"
    assert _queued_top(paths, "late"), "the late row left the queue's top-level slot"
    assert not _inflight(paths, "late"), "the late row was claimed"

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


@pytest.mark.parametrize("cli", ["lead_author", "visualize_run", "workspace_map"])
def test_2_each_run_id_command_prints_the_data_roots_refusal(tmp_path, d9_tenant, monkeypatch,
                                                              cli):
    from defender.tenancy._command_line_run import open_command_line_run
    from defender.records import Run
    from defender.tests.support.learning.core._state1135 import curation_run_dir

    run_dir = curation_run_dir("r-real", tenant_id=d9_tenant)
    run_id = run_dir.name  # #1187: the run's id is the uuid4 its label names (`fixture_uuid`)
    opened = open_command_line_run(d9_tenant, run_id)
    assert not isinstance(opened, str), opened
    tenant, run = opened
    assert isinstance(run, Run), opened
    assert str(tenant.id) == d9_tenant
    assert Path(run.run_dir) == run_dir

    argv, main, status = {
        "lead_author": (["--tenant", d9_tenant, run_id], R1._lead_author_main(), 2),
        "visualize_run": (P.new_run_page_argv(d9_tenant, run_id), P.run_page_main(), 1),
        "workspace_map": (["workspace_map.py", "--tenant", d9_tenant, run_id],
                          R1._workspace_map_main(), 2),
    }[cli]
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    refused = open_command_line_run(d9_tenant, run_id)
    assert isinstance(refused, str), refused
    assert P.DATA_ROOT_ENV in refused, refused
    with R1._no_logging():
        got = P.drive_cli(main, argv)
    assert got.rc == status, f"{cli}: {got.rc} {got.err!r}"
    assert P.DATA_ROOT_ENV in got.err, f"{cli}: {got.err!r}"
    assert got.out == ""


def test_4_a_quarantined_curation_row_shows_its_address(published, tmp_path):
    """#1108 P4: the row is quarantined by the REAL tenant-selected tick over the published
    tenant's drain paths."""
    from defender.learning.frontend import serialize_queues
    from defender.tests.support.shared._fixture_uuid import fixture_uuid
    from defender.tests.support.learning.core._state1135 import state_for_paths

    t = published
    H.runs_folder(t.tenant)
    paths = R1._tenant_paths(t, tmp_path)
    gone_run = fixture_uuid("nope")  # #1187: a well-formed run id (a uuid4) naming no run
    P.queue_row(paths, "gone", {"case_id": "gone", "tenant_id": t.tenant_id, "run_id": gone_run})
    assert R1._tick(t, paths, lane=P.Lane(), pitfalls=[], box=R1._Box()) == 0
    assert P.dead_letter(paths, "gone") is not None, "control: the row was not quarantined"

    view = serialize_queues.build_view(paths, state_for_paths(paths))
    rows = [r for r in view["quarantine"]["markers"]["rows"] if r["identity"] == "gone"]
    assert len(rows) == 1, view["quarantine"]["markers"]
    row = rows[0]
    assert row["failed"] == "artifact-missing"
    assert (row.get("tenant_id"), row.get("run_id")) == (t.tenant_id, gone_run), row
    assert "run_dir" not in row, row


def test_6_grading_another_tenants_episode_is_refused(tmp_path):
    from defender.learning.judge import JudgeRefused, grade_episode
    from defender.records import RunRefused
    from defender.tests.support.learning.judge import _judge_921 as J
    from defender.tests.support.learning.core._state1135 import env_state
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
    state_dir = tmp_path / "learning-state"
    before = P.tree(state_dir)

    judge = J.scripted_judge()
    err = H.raised(grade_episode, other.runs_repository(), episode_id, judge=judge,
                   state=env_state())
    assert isinstance(err, (JudgeRefused, RunRefused, TenantRefused,
                            FileNotFoundError)), f"another tenant graded the episode: {err!r}"
    assert not (ep / "judge.yaml").exists(), "a grade was written for another tenant"
    assert P.tree(state_dir) == before, "the refused grade touched the learning state"
    assert not os.path.lexists(S.episodes_dir(location_path(P.data_root)(), H.U_ID) / episode_id)

    own = _tenant.accept_tenant(fixture_data_root(location_path(P.data_root)()), P.LAUNCH_TENANT,
                                defender_dir=H.DEFENDER).runs_repository()
    assert not (ep / "runs" / "_tenant.json").exists(), "the launch wrote a container record"
    moved = tmp_path / "container-away"
    (ep / "runs").rename(moved)
    handle = own.episode_files(episode_id)
    handle.close()
    moved.rename(ep / "runs")

    graded = grade_episode(own, episode_id, judge=J.scripted_judge(), state=env_state())
    assert graded is not None
    assert (ep / "judge.yaml").is_file(), "control: the own tenant did not grade"


def test_7_the_judge_prompts_views_are_numbered_without_a_gap(tmp_path):
    from defender.learning.judge import layout as judge_layout

    numbers = [int(m.group(1)) for title in judge_layout.FOCUS_VIEW_TITLES.values()
               if (m := re.match(r"VIEW (\d+):", title))]
    assert numbers == list(range(1, len(numbers) + 1)), numbers
    lessons = judge_layout.FOCUS_VIEW_TITLES["lessons"]
    assert lessons.startswith(f"VIEW {len(numbers)}:"), lessons

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
