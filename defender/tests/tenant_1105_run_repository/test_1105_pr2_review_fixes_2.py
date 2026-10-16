"""#1105 PR 2 — the code review's second round (PR #1236), owner-approved, each finding driven
through its real entry point with a positive control.

* 1 — the lead-author drain resolves the data root ONCE, after its locks and before its batch,
  and only when a curation row is queued then. A refusal is the stage's ordinary configuration
  refusal (`FatalConfigError`, a logged one-line exit 2 from `_run_stage`), not a traceback.
  With no row queued at the tick's start the tick claims no curation row at all: a row that
  lands mid-tick waits, queued, for the next tick.
* 2 — one tenant-acceptance step for a request's tenant (`_tenant.requested_tenant`), shared
  by every command line and by the drain's rehydration; the three `--tenant T <run_id>`
  command lines resolve the root and open the run through one shared opener.
* 3 — the launcher's VERIFY and the episode page hold an episode's container once for all its
  arms, its `_tenant.json` judged once, however many arms there are. (#1187 R1: no record is
  judged; VERIFY's per-arm handout stays pinned below, the page's count test is retired — the
  page's arms by roster id are pinned by
  `ids_1187/test_1187_roster_consumers.py::test_page_links_each_arm_by_its_roster_id_never_a_composed_name`.)
* 4 — the failed-requests view shows a quarantined row's address (`tenant_id`, `run_id`).
* 6 — the judge's door judges the episode container's `_tenant.json`, as `runs.episode` does.
  (#1187 R1, O8: no record; another tenant's episode is not under the asking tenant at all.)
* 7 — the judge prompt's views are numbered without a gap.
"""
from __future__ import annotations

import ast
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

from defender import _tenant
from defender.tests.tenant_1105_run_repository import _spec1105 as H
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P
from defender.tests.tenant_1105_run_repository import test_1105_pr2_review_fixes as R1


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

    t = R1._good(tmp_path, R1.RID_R1)
    root = os.environ[P.DATA_ROOT_ENV]
    paths = P.loop_paths(tmp_path)
    P.queue_row(paths, "case-t", {"case_id": "case-t", "tenant_id": H.T_ID, "run_id": R1.RID_R1})
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
    assert lane.run_dirs == [Path(t.runs) / R1.RID_R1], "control: the row was not served"


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
    t = R1._good(tmp_path, R1.RID_R1)
    root = os.environ[P.DATA_ROOT_ENV]
    paths = P.loop_paths(tmp_path)
    _pitfall_at_threshold(paths, monkeypatch)
    if not root_set:
        monkeypatch.delenv(P.DATA_ROOT_ENV)
    row = {"case_id": "late", "tenant_id": H.T_ID, "run_id": R1.RID_R1}
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
    assert lane.run_dirs == [Path(t.runs) / R1.RID_R1], "control: the next tick did not serve it"


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


def _calls_named(path: Path, name: str) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            spelled = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if spelled == name:
                out.append(node.lineno)
    return out


_ACCEPTING_SITES = ("learning/ops/trace_lesson.py", "scripts/visualize/visualize_episode.py",
                    "run_repository/_lookup.py", "learning/core/drains.py")
_RUN_ID_CLIS = ("learning/leads/lead_author/__init__.py", "scripts/visualize/visualize_run.py",
                "scripts/workspace_map.py")


def test_2_no_request_site_hand_writes_the_tenant_acceptance():
    """The tracer, the episode page, the shared run opener and the drain's rehydration accept a
    request's tenant through `requested_tenant` and none calls `accept_tenant` itself; the
    three `--tenant T <run_id>` command lines open their run through the one shared opener
    (`open_command_line_run`), which resolves the data root, so none of them calls
    `resolve_data_root` itself. Positive control: the census finds `accept_tenant` in
    `run.py`, which accepts with its box mounts. RED before the fix: each site spells
    `accept_tenant(resolve_data_root(), requested_tenant_id(raw), defender_dir=…)` and each CLI
    resolves the root around the opener."""
    assert _calls_named(H.DEFENDER / "run.py", "accept_tenant"), "control: the census is blind"
    for rel in _ACCEPTING_SITES:
        path = H.DEFENDER / rel
        assert _calls_named(path, "accept_tenant") == [], f"{rel} hand-writes the acceptance"
        assert _calls_named(path, "requested_tenant"), f"{rel} does not use requested_tenant"
    for rel in _RUN_ID_CLIS:
        path = H.DEFENDER / rel
        assert _calls_named(path, "resolve_data_root") == [], f"{rel} resolves the root itself"
        assert _calls_named(path, "open_command_line_run"), f"{rel} skips the shared opener"


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

def test_3_verify_judges_the_container_once_for_every_arm(tmp_path):
    """VERIFY's `_finished_arms` hands each arm back by its own entry: a real folder is a
    `Run`, nothing at the id is `RunAbsent`, a link at the id a refused entry (`RunRefused`,
    never followed) — one arm's entry never spoils another's.

    #1187 declared changes 6 and 15 (R1, R2): the container's `_tenant.json` is judged by
    nobody, so the "judged once" count (and its per-arm control) is retired; the arms are the
    ones the episode's roster names, each at its roster id under `<T>/episodes/<uuid>/runs/`:
    `a` and `b` real, `c`'s id with nothing at it, `l`'s id a link to `a`'s folder. (Name kept.)"""
    from defender.learning.branch import cli
    from defender.run_repository import Run, RunAbsent, RunRefused

    t = R1._uuid_tenant()
    ep, episode_id, roster = R1._post_runs_episode(H.T_ID, ("a", "b", "c", "l"))
    runs_dir = ep / "runs"
    shutil.rmtree(runs_dir / roster["c"])
    shutil.rmtree(runs_dir / roster["l"])
    os.symlink(runs_dir / roster["a"], runs_dir / roster["l"])
    with t.runs_repository().episode(episode_id) as view:
        arms = cli._finished_arms(view, ("a", "b", "c", "l"))
    for label in ("a", "b"):
        assert isinstance(arms[label], Run), arms[label]
        assert Path(arms[label].run_dir) == runs_dir / roster[label]
    assert isinstance(arms["c"], RunAbsent), arms["c"]
    assert isinstance(arms["l"], RunRefused), arms["l"]
    assert not isinstance(arms["l"], RunAbsent), arms["l"]


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
    """The judge (`grade_episode`) handed tenant U's repository and tenant T's episode id
    refuses before anything is graded: no `judge.yaml` is written and the learning state is
    untouched. An ABSENT container is not the door's to refuse: the episode opens. Positive
    control: T's own repository grades the episode. RED before the fix: `episode_files` reads
    nothing in `runs/`, so U grades T's episode.

    #1187 declared changes 3, 5, 6 and 8 (R1, O8): no container record is judged. T's episode
    is the one fresh `<T>/episodes/<uuid>/` the launch made; U's repository looks under
    `<U>/episodes` only, finds nothing, and refuses (the door's absent refusal, or the judge's).
    The "recordless container refuses" half flips: a container holding no `_tenant.json` is
    every episode's, and T grades it. (Name kept.)"""
    from defender.learning.judge import JudgeRefused, grade_episode
    from defender.run_repository import RunRefused
    from defender.tests import _judge_921 as J
    from defender.tests._state1135 import env_state
    from defender.tests.ids_1187 import _spec1187 as S

    est, src = P.launch_source(tmp_path)
    got = P.drive_launch(est, P.launch_argv(P.LAUNCH_TENANT, src))
    assert got.raised is None, f"the launch did not run: {got!r}"
    assert got.rc == 0, f"the launch did not run: {got!r}"
    episodes = S.episodes_dir(P.data_root(), P.LAUNCH_TENANT)
    made = sorted(p.name for p in episodes.iterdir()) if episodes.is_dir() else []
    assert len(made) == 1, f"the launch made {made} under <T>/episodes"
    episode_id = made[0]
    ep = episodes / episode_id
    (ep / "judge.yaml").unlink(missing_ok=True)
    other = P.second_tenant(P.data_root(), H.U_ID)
    state_dir = tmp_path / "learning-state"
    before = P.tree(state_dir)

    judge = J.scripted_judge()
    err = H.raised(grade_episode, other.runs_repository(), episode_id, judge=judge,
                   state=env_state())
    assert isinstance(err, (JudgeRefused, RunRefused, _tenant.TenantRefused,
                            FileNotFoundError)), f"another tenant graded the episode: {err!r}"
    assert not (ep / "judge.yaml").exists(), "a grade was written for another tenant"
    assert P.tree(state_dir) == before, "the refused grade touched the learning state"
    assert not os.path.lexists(S.episodes_dir(P.data_root(), H.U_ID) / episode_id)

    own = _tenant.accept_tenant(P.data_root(), P.LAUNCH_TENANT,
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
