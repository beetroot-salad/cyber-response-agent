"""Review-finding regressions: tick without data root, tenant acceptance, quarantined curation rows, cross-tenant grading, prompt view numbering."""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

import pytest

from defender import _tenant
from defender.tests.tenant_1105_run_repository import _spec1105 as H
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P
from defender.tests.tenant_1105_run_repository import test_1105_pr2_review_fixes as R1

EP = R1.EP


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    P.roots(tmp_path, monkeypatch)


def _queue_dir(paths: Any) -> Path:
    return Path(paths.state_root) / "author-queue"


def _queued_top(paths: Any, case_id: str) -> bool:
    return (_queue_dir(paths) / f"{case_id}.json").is_file()


def _inflight(paths: Any, case_id: str) -> bool:
    return (_queue_dir(paths) / "inflight" / f"{case_id}.json").is_file()


def _pitfall_at_threshold(paths: Any, monkeypatch: Any) -> None:
    """One pitfall row with the threshold at 1, so the tick wakes with no curation row."""
    from defender.learning.core import persist
    from defender.tests._state1135 import state_for_paths

    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    persist.append_pitfalls([{"pitfall_id": "r:0", "system": "elastic"}],
                            state=state_for_paths(paths))


# ==========================================================================================
# 1 — the drain's data root: resolved once, before the batch, refused as configuration.
# ==========================================================================================

def test_1_a_tick_with_rows_and_no_data_root_is_the_stages_configuration_refusal(
        tmp_path, monkeypatch, caplog):
    """`loop.py --lead-author-drain`'s stage runner (`_run_stage`) over a tick with a curation
    row queued and `DEFENDER_DATA_ROOT` unset: exit 2 with the stage's one-line CRITICAL
    refusal naming the variable, no traceback, no box started, the row still queued (not
    claimed). The tick's own refusal is a `FatalConfigError` raised from the data root's
    `TenantRefused`. Positive control: with the root restored the same stage exits 0 and serves
    the row. RED before the fix: the `TenantRefused` is no systemic fault, so it escapes
    `_run_stage` as a traceback."""
    from defender.learning.core.cli import _run_stage
    from defender.learning.core.config import FatalConfigError

    t = R1._good(tmp_path, "r1")
    root = os.environ[P.DATA_ROOT_ENV]
    paths = P.loop_paths(tmp_path)
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": H.T_ID, "run_id": "r1"})
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    box = R1._Box()
    lane = P.Lane()

    err = H.raised(R1._tick, paths, lane=lane, pitfalls=[], box=box)
    assert isinstance(err, FatalConfigError), f"the tick's refusal: {err!r}"
    assert isinstance(err.__cause__, _tenant.TenantRefused), err.__cause__

    caplog.clear()
    with caplog.at_level(logging.CRITICAL):
        got = H.raised(lambda: _run_stage(
            lambda: R1._tick(paths, lane=lane, pitfalls=[], box=box)))
        assert got is None, f"the stage let the refusal out: {got!r}"
        rc = _run_stage(lambda: R1._tick(paths, lane=lane, pitfalls=[], box=box))
    assert rc == 2
    critical = [r for r in caplog.records if r.levelno >= logging.CRITICAL]
    assert critical, "the refusal was not logged"
    assert P.DATA_ROOT_ENV in critical[0].getMessage(), critical[0].getMessage()
    assert "\n" not in critical[0].getMessage()
    assert all(r.exc_info is None for r in caplog.records), "a traceback was logged"
    assert box.started == [], "a box was started for a tick that could not serve its rows"
    assert _queued_top(paths, "case-t")
    assert not _inflight(paths, "case-t")
    assert lane.handed == []

    monkeypatch.setenv(P.DATA_ROOT_ENV, root)
    assert _run_stage(lambda: R1._tick(paths, lane=lane, pitfalls=[], box=box)) == 0
    assert lane.run_dirs == [Path(t.runs) / "r1"], "control: the row was not served"


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
def test_1_a_row_landing_mid_tick_waits_for_the_next_tick(tmp_path, monkeypatch, root_set):
    """No curation row is queued when the tick starts (pitfalls woke it). A row enqueued while
    the tick runs (here, as its box starts) is not claimed: after the tick it is still in the
    queue's top-level slot, not in `inflight/`, and the lead author was never handed it — with
    the data root set or unset (unset, the tick also exits 0: it never needed the root). The
    pitfalls step still ran. Positive control: the next tick, the row queued at its start,
    serves it. RED before the fix: the claim loop resolved the root lazily and claimed the row
    (root set: served; root unset: the tick raised `TenantRefused`)."""
    t = R1._good(tmp_path, "r1")
    root = os.environ[P.DATA_ROOT_ENV]
    paths = P.loop_paths(tmp_path)
    _pitfall_at_threshold(paths, monkeypatch)
    if not root_set:
        monkeypatch.delenv(P.DATA_ROOT_ENV)
    row = {"case_id": "late", "tenant_id": H.T_ID, "run_id": "r1"}
    box = _EnqueueingBox(paths, row)
    lane = P.Lane()
    pitfalls: list[str] = []

    rc = R1._tick(paths, lane=lane, pitfalls=pitfalls, box=box)
    assert rc == 0
    assert box.started, "the tick never started its box"
    assert pitfalls == ["pitfalls"], "the pitfalls step did not run"
    assert lane.handed == [], "a row that landed mid-tick was served"
    assert _queued_top(paths, "late"), "the late row left the queue's top-level slot"
    assert not _inflight(paths, "late"), "the late row was claimed"

    monkeypatch.setenv(P.DATA_ROOT_ENV, root)
    assert R1._tick(paths, lane=lane, pitfalls=[], box=R1._Box()) == 0
    assert lane.run_dirs == [Path(t.runs) / "r1"], "control: the next tick did not serve it"


# ==========================================================================================
# 2 — one acceptance step for a request's tenant; one opener for `--tenant T <run_id>`.
# ==========================================================================================

def test_2_requested_tenant_is_the_one_acceptance_of_a_raw_or_stored_tenant_id(d9_tenant):
    """`_tenant.requested_tenant(data_root, raw)`: a command line's raw `--tenant` text or a
    stored `TenantId` accepted under `data_root` by one rule — the id grammar, then
    `accept_tenant` with the process's `defender/` and no box mount. An absent id (`None`) and
    an id off the grammar refuse (`TenantRefused`), as does an unknown tenant. Positive
    control: the answer is the `Tenant` `accept_tenant` hands out for the same request. RED
    before the fix: no such function."""
    from defender._paths import process_defender_dir

    root = _tenant.resolve_data_root()
    direct = _tenant.accept_tenant(root, d9_tenant, defender_dir=process_defender_dir())
    for raw in (d9_tenant, _tenant.TenantId(d9_tenant)):
        got = _tenant.requested_tenant(root, raw)
        assert isinstance(got, _tenant.Tenant)
        assert (got.id, Path(got.runs), Path(got.data_root)) == (
            direct.id, Path(direct.runs), Path(direct.data_root)), raw
    for bad in (None, "../x", "no-such-tenant"):
        assert isinstance(H.raised(_tenant.requested_tenant, root, bad),
                          _tenant.TenantRefused), bad



@pytest.mark.parametrize("cli", ["lead_author", "visualize_run", "workspace_map"])
def test_2_each_run_id_command_prints_the_data_roots_refusal(tmp_path, d9_tenant, monkeypatch,
                                                              cli):
    """With `DEFENDER_DATA_ROOT` unset, each `--tenant T <run_id>` command line prints the data
    root's refusal (naming the variable) on stderr and exits with its own refusal status,
    nothing on stdout. Positive control for the shared opener: with the root set it opens the
    run. Green before the fix for the CLIs (the behaviour moved, unchanged); RED for the opener
    (no such function)."""
    from defender._command_line_run import open_command_line_run
    from defender.run_repository import Run
    from defender.tests._state1135 import curation_run_dir

    run_dir = curation_run_dir("r-real", tenant_id=d9_tenant)
    opened = open_command_line_run(d9_tenant, "r-real")
    assert isinstance(opened, Run), opened
    assert Path(opened.run_dir) == run_dir

    argv, main, status = {
        "lead_author": (["--tenant", d9_tenant, "r-real"], R1._lead_author_main(), 2),
        "visualize_run": (P.new_run_page_argv(d9_tenant, "r-real"), P.run_page_main(), 1),
        "workspace_map": (["workspace_map.py", "--tenant", d9_tenant, "r-real"],
                          R1._workspace_map_main(), 2),
    }[cli]
    monkeypatch.delenv(P.DATA_ROOT_ENV)
    refused = open_command_line_run(d9_tenant, "r-real")
    assert isinstance(refused, str), refused
    assert P.DATA_ROOT_ENV in refused, refused
    with R1._no_logging():
        got = P.drive_cli(main, argv)
    assert got.rc == status, f"{cli}: {got.rc} {got.err!r}"
    assert P.DATA_ROOT_ENV in got.err, f"{cli}: {got.err!r}"
    assert got.out == ""


# ==========================================================================================
# 3 — one hold of an episode's container for all its arms.
# ==========================================================================================


# ==========================================================================================
# 4 — the failed-requests view shows the row's address.
# ==========================================================================================

def test_4_a_quarantined_curation_row_shows_its_address(tmp_path):
    """A curation row the drain quarantined (`artifact-missing`: its run is gone), in the
    `{case_id, tenant_id, run_id}` shape every row now has, is shown on the queue page's
    failed-requests list with its `tenant_id` and `run_id` — rev 5.1 J13's address — and no
    `run_dir`. Positive control: the row is there, with its failure. RED before the fix: the
    view reads `run_dir`, which no row carries (always null), and drops the address."""
    from defender.learning.frontend import serialize_queues
    from defender.tests._state1135 import state_for_paths

    R1._good(tmp_path)
    paths = P.loop_paths(tmp_path)
    P.queue_row(paths, "gone", {"case_id": "gone", "tenant_id": H.T_ID, "run_id": "nope"})
    assert R1._tick(paths, lane=P.Lane(), pitfalls=[], box=R1._Box()) == 0
    assert P.dead_letter(paths, "gone") is not None, "control: the row was not quarantined"

    view = serialize_queues.build_view(paths, state_for_paths(paths))
    rows = [r for r in view["quarantine"]["markers"]["rows"] if r["identity"] == "gone"]
    assert len(rows) == 1, view["quarantine"]["markers"]
    row = rows[0]
    assert row["failed"] == "artifact-missing"
    assert (row.get("tenant_id"), row.get("run_id")) == (H.T_ID, "nope"), row
    assert "run_dir" not in row, row


# ==========================================================================================
# 6 — the judge's door judges the container's tenant record.
# ==========================================================================================

def test_6_grading_another_tenants_episode_is_refused(tmp_path):
    """The judge (`grade_episode`) handed tenant U's repository and tenant T's episode (its
    container's `_tenant.json` names T) refuses (`JudgeRefused`, naming the record) before
    anything is graded: the judge is never asked, no `judge.yaml` is written, the learning
    state is untouched. So does T's own repository once the record is removed (a present
    container with no record). An ABSENT container is not the door's to refuse: the episode
    opens. Positive control: T's own repository grades the episode. RED before the fix:
    `episode_files` reads nothing in `runs/`, so U grades T's episode."""
    from defender.learning.judge import JudgeRefused, grade_episode
    from defender.tests import _judge_921 as J
    from defender.tests._state1135 import env_state

    est, src = P.launch_source(tmp_path)
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert got.raised is None, f"the launch did not run: {got!r}"
    assert got.rc == 0, f"the launch did not run: {got!r}"
    ep = R1._episodes() / P.EPISODE_ID
    (ep / "judge.yaml").unlink(missing_ok=True)
    other = P.second_tenant(P.data_root(), H.U_ID)
    state_dir = tmp_path / "learning-state"
    before = P.tree(state_dir)

    judge = J.scripted_judge()
    err = H.raised(grade_episode, other.runs_repository(), P.EPISODE_ID, judge=judge,
                   state=env_state())
    assert isinstance(err, JudgeRefused), f"another tenant graded the episode: {err!r}"
    assert "_tenant.json" in str(err), err
    assert not (ep / "judge.yaml").exists(), "a grade was written for another tenant"
    assert P.tree(state_dir) == before, "the refused grade touched the learning state"

    own = _tenant.accept_tenant(P.data_root(), P.LAUNCH_TENANT,
                                defender_dir=H.DEFENDER).runs_repository()
    record = ep / "runs" / "_tenant.json"
    kept = record.read_bytes()
    record.unlink()
    err = H.raised(grade_episode, own, P.EPISODE_ID, judge=J.scripted_judge(),
                   state=env_state())
    assert isinstance(err, JudgeRefused), f"a recordless container was graded: {err!r}"
    record.write_bytes(kept)

    moved = tmp_path / "container-away"
    (ep / "runs").rename(moved)
    handle = own.episode_files(P.EPISODE_ID)
    handle.close()
    moved.rename(ep / "runs")

    graded = P.grade(ep, P.LAUNCH_TENANT)
    assert graded is not None
    assert (ep / "judge.yaml").is_file(), "control: the own tenant did not grade"


# ==========================================================================================
# 7 — the judge prompt's views are numbered without a gap.
# ==========================================================================================

def test_7_the_judge_prompts_views_are_numbered_without_a_gap(tmp_path):
    """With the same-alert siblings view gone (J3), the judge's views are numbered 1..n with
    no gap: in the section titles, and in every prompt a launch hands the judge (each number
    there a title's). Positive control: the prompts carry VIEW 1 and the lessons view. RED
    before the fix: the lessons view is VIEW 5 after VIEW 3. (#1234: the titles are the
    focus section's host view labels, `layout.FOCUS_VIEW_TITLES`, spelled `VIEW <n>: ...`.)"""
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
