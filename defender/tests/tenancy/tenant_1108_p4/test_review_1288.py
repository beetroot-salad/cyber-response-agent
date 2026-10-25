"""#1108 P4, PR #1288 review: the fixes that dissolve a finding by construction, each pinned at the
seam that now carries it.

- a run copy is owned from the instant its folder exists (its building name carries its owner),
  so a publish's sweep, which takes no notice of the building process, never removes it;
- the publish child holds ONE deadline over its network phase and reports, and records, running
  out of it itself;
- the launcher records the outcomes only it sees (a child that crashed or printed nothing).

Second round:
- every outcome the child reports is recorded from the report line itself (lock busy too);
- a deadline that is not positive is already out, never "no deadline";
- the run's agent folder and its stage are judged before the box-or-host choice, so the
  unsandboxed opt-out never swallows a stage refusal;
- the reducer pitfalls page the curator writes is the page a gather dispatch names, and the
  tenant template ships it;
- removing a batch's draft never raises; a missing alert is refused before any publish; two
  launches into one held-out index cannot interleave their pin read and append.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge


def _status(t) -> dict | None:
    from defender.tenancy._publish_status import read_status

    return read_status(t.tenant)


# --- a run copy is owned while it is built --------------------------------------------------------

def test_a_folder_built_under_an_owned_name_is_alive_before_its_owner_file_exists(tmp_path):
    from defender.tenancy._owner import OWNER_FILE, owned_temporary, owner_alive

    building = tmp_path / owned_temporary(".building-r1")
    building.mkdir()
    assert not (building / OWNER_FILE).exists()
    assert owner_alive(building), "a folder mid-build, its owner this live process, counted dead"


def test_a_folder_whose_name_carries_a_dead_owner_is_dead(tmp_path):
    from defender.tenancy._owner import owned_temporary, owner_alive

    gone = subprocess.Popen([sys.executable, "-c", "pass"])  # noqa: S603 — a process that exits
    gone.wait()
    pid, start = owned_temporary("").split("-")[1:3]
    dead = tmp_path / f".building-r1.owner-{gone.pid}-{start}-0123abcd"
    dead.mkdir()
    assert not owner_alive(dead), "a building folder whose owner has exited counted alive"
    assert owner_alive(tmp_path / f".building-r1.owner-{pid}-{start}-0123abcd"), "control"


def test_a_publish_sweep_keeps_a_run_copy_being_built_and_removes_a_dead_builders(p4_tenant):
    """The finding's race, replayed in order: a run copy's building folder exists with no owner
    file yet (the builder is between making it and writing its record) when a publish sweeps."""
    from defender.learning.author.version_control.exports import sweep_dead_owners
    from defender.tenancy._owner import owned_temporary

    copies = Path(p4_tenant.tenant.run_knowledge)
    copies.mkdir(parents=True, exist_ok=True)
    live = copies / owned_temporary(".building-r-live")
    live.mkdir()
    orphan = copies / ".building-r-orphan-0123abcd"
    orphan.mkdir()
    sweep_dead_owners(p4_tenant.tenant)
    assert live.is_dir(), "the sweep removed a run copy while its owner was building it"
    assert not orphan.exists(), "control: an unowned building folder is swept"


# --- the publish child's one deadline ---------------------------------------------------------------

@pytest.fixture
def child_tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        yield t


def test_the_child_reports_and_records_running_out_of_its_network_budget(child_tenant, tmp_path):
    """A forge call answers slowly: well within its own 30s bound, but past the child's whole
    budget. The child ends itself at the budget with `stale:transient` and records it, so
    `tenant.py check` names the outage."""
    t = child_tenant
    config = B.write_issuer_config(tmp_path / "operator")
    t.merge(B.MERGE_FILES)

    def slow(_request):
        time.sleep(3.0)

    t.forge.fault = slow
    began = time.monotonic()
    line = B.run_child(t, config, budget=1.0)
    took = time.monotonic() - began
    assert line.startswith("stale:transient "), line
    assert "budget" in line, line
    assert took < 2.5, f"the child took {took:.1f}s over a 1s budget"
    status = _status(t)
    assert status is not None
    assert status.get("kind") == "transient", status
    assert status.get("by") == "launch-time publish", status


def test_the_launcher_hands_the_child_a_budget_inside_its_own(tmp_path):
    from defender.runtime import publish_launch
    from defender.tests.tenancy.tenant_1108_p4.test_publish_child import _RecordingSpawn

    spawn = _RecordingSpawn()
    publish_launch.launch_publish("some-tenant", data_root=tmp_path, budget=60.0, spawn=spawn)
    (argv, _env), = spawn.calls
    budget = float(argv[argv.index("--budget") + 1])
    assert 0 < budget < 60.0, argv


# --- the launcher records what only it sees -----------------------------------------------------------

@pytest.mark.parametrize("child", [
    "import sys; sys.exit(3)",
    "print('not a report')",
])
def test_the_launcher_records_a_child_that_reports_nothing_valid(p4_tenant, child):
    from defender.runtime import publish_launch

    line = publish_launch.launch_publish(
        p4_tenant.tenant_id, data_root=p4_tenant.data_root, budget=30.0,
        command=[sys.executable, "-c", child, "--"])
    assert line.startswith("stale:operator publish child failed:"), line
    status = _status(p4_tenant)
    assert status is not None, "the failed child left no publish status for `check`"
    assert status.get("kind") == "operator", status
    assert status.get("by") == "launch-time publish", status
    assert "publish child failed" in status.get("refused", ""), status


def test_control_a_child_that_reports_validly_is_not_recorded_by_the_launcher(p4_tenant):
    from defender.runtime import publish_launch

    line = publish_launch.launch_publish(
        p4_tenant.tenant_id, data_root=p4_tenant.data_root, budget=30.0,
        command=[sys.executable, "-c", "print('stale:transient the forge is down')", "--"])
    assert line == "stale:transient the forge is down"
    status = _status(p4_tenant)
    assert status is None or "publish child failed" not in status.get("refused", ""), status


# --- second round: one recorder for every reported outcome -------------------------------------

def _lock(t):
    from defender.learning.author.version_control import tenant_lock

    return tenant_lock(t.tenant)


def test_a_lock_busy_publish_records_its_outcome_and_clears_an_earlier_refusal(
        child_tenant, tmp_path):
    """A refusal is recorded; then every launch overlaps a drain holding the lock while
    `current` already names `origin/main`. Each reports `fresh`, and `check` must say so
    rather than keep showing the old refusal."""
    from defender.tenancy._publish_status import OPERATOR, record_refusal

    t = child_tenant
    config = B.write_issuer_config(tmp_path / "operator")
    record_refusal(t.tenant, kind=OPERATOR, reason="the issuer is sealed", by="launch-time publish")
    with _lock(t):
        line = B.run_child(t, config)
    assert line.startswith("fresh "), line
    status = _status(t)
    assert status is not None
    assert status.get("published") == t.commit, status
    assert "refused" not in status, status


def test_a_lock_busy_stale_publish_is_recorded_transient(child_tenant, tmp_path):
    t = child_tenant
    config = B.write_issuer_config(tmp_path / "operator")
    t.merge(B.MERGE_FILES)
    with _lock(t):
        line = B.run_child(t, config)
    assert line.startswith("stale:transient "), line
    status = _status(t)
    assert status is not None
    assert status.get("kind") == "transient", status
    assert "lock is busy" in status.get("refused", ""), status


def test_a_zero_budget_is_already_out_not_unbounded(child_tenant, tmp_path):
    """`setitimer(0)` disarms a timer: a budget of 0 must end the network phase at once."""
    t = child_tenant
    config = B.write_issuer_config(tmp_path / "operator")

    def slow(_request):
        time.sleep(3.0)

    t.forge.fault = slow
    began = time.monotonic()
    line = B.run_child(t, config, budget=0.0)
    assert time.monotonic() - began < 2.0, "a zero budget let the network phase run"
    assert line.startswith("stale:transient "), line
    assert "budget" in line, line


@pytest.mark.parametrize("budget", [0.0, -1.0])
def test_the_launcher_refuses_a_budget_that_is_not_positive(tmp_path, budget):
    from defender.runtime import publish_launch
    from defender.tests.tenancy.tenant_1108_p4.test_publish_child import _RecordingSpawn

    spawn = _RecordingSpawn()
    with pytest.raises(ValueError, match="positive"):
        publish_launch.launch_publish("some-tenant", data_root=tmp_path, budget=budget,
                                      spawn=spawn)
    assert spawn.calls == [], "a child was started with no time to run in"


def test_the_launcher_and_run_start_build_one_failed_child_line():
    from defender.runtime import run_knowledge

    line = run_knowledge.failed_line("it printed no report line")
    report = run_knowledge.read_publish_report(line)
    assert report.kind == run_knowledge.STALE, report
    assert report.stale_kind == "operator", report
    assert report.reason == run_knowledge.child_failed("it printed no report line").reason


# --- second round: the stage is judged on both paths -------------------------------------------

def _stage(tmp_path: Path) -> tuple[Path, Path]:
    stage = tmp_path / "copy" / "stage"
    (stage / "agent").mkdir(parents=True)
    token = stage / "token"
    token.write_text("t0ken", encoding="utf-8")
    return stage, token


def _no_docker(*_a, **_k):
    raise AssertionError("docker was reached before the stage was judged")


@pytest.mark.parametrize("fault", ["another-agent", "extra-entry"])
def test_a_stage_fault_is_refused_even_with_the_unsandboxed_opt_out(tmp_path, monkeypatch, fault):
    """With `DEFENDER_ALLOW_UNSANDBOXED=1` a box fault degrades to the host. A stage that is not
    this run's must still refuse, on the host path too, and write the did-not-run marker."""
    from defender.box import BoxFault, BoxSpec
    from defender.box import _lifecycle

    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    stage, token = _stage(tmp_path)
    agent = stage / "agent"
    if fault == "another-agent":
        agent = tmp_path / "elsewhere" / "agent"
        agent.mkdir(parents=True)
    else:
        (stage / "settings").mkdir()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    verdicts: list[dict] = []
    with pytest.raises(BoxFault):
        _lifecycle._start_run_box(run_dir, tmp_path, BoxSpec(), _no_docker, agent, token,
                                  verdicts.append)
    assert verdicts, "the refusal wrote no did-not-run marker"


# --- second round: the reducer pitfalls page is one name, shipped and named ---------------------

def test_the_template_ships_the_reducer_pitfalls_page_the_curator_edits():
    from defender.knowledge._knowledge import AGENT_REL, REDUCER_PITFALLS
    from defender.learning.leads.pitfalls_curator import PITFALLS_SECTION, REDUCER_REL
    from defender.tenancy._tenants import template_dir
    from defender._git import REPO_ROOT

    assert f"{AGENT_REL}/{REDUCER_PITFALLS}" == REDUCER_REL
    page = template_dir(REPO_ROOT) / REDUCER_REL
    assert page.is_file(), "a fresh tenant has no reducer pitfalls page: the curator would mint it"
    assert PITFALLS_SECTION in page.read_text(encoding="utf-8").splitlines()


def test_a_gather_dispatch_names_the_run_copys_reducer_pitfalls_page():
    from defender.runtime import tools as tools_mod
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.driver import MAIN_DEF
    from defender.runtime.tools_gather import GatherRequest, _gather_prompt
    from defender.tests.support.tenancy import _tenants1106 as T1106

    defender_dir = Path(__file__).resolve().parents[3]
    run_dir = Path("/tmp/x")
    deps = tools_mod.AgentDeps(
        run_dir=run_dir, defender_dir=defender_dir, run_id="r",
        policy=compile_policy_for(MAIN_DEF, run_dir=run_dir, defender_dir=defender_dir),
        cwd_anchor=run_dir, tenant=T1106.fixture_run_tenant())
    page = deps.knowledge.reducer_pitfalls
    assert page.is_file(), "the fixture tenant carries the page"
    prompt = _gather_prompt(deps, GatherRequest("l-1", "elastic", "g", ("x",)), catalog=None)
    assert f"reducer_pitfalls: {deps.view.to_model(page)}" in prompt, prompt
    skill = (defender_dir / "skills" / "gather" / "SKILL.md").read_text(encoding="utf-8")
    assert "reducer_pitfalls" in skill, "the gather skill never tells the agent to read it"


# --- second round: cleanup, alert, held-out index ----------------------------------------------

def test_a_draft_that_cannot_be_removed_is_logged_not_raised(tmp_path, caplog):
    from types import SimpleNamespace

    from defender.learning.author.version_control.batch import Batch

    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x", encoding="utf-8")
    batch = SimpleNamespace(id="b1", draft_root=blocker / "draft" / "root")
    Batch.discard(batch)  # type: ignore[arg-type]
    assert any("could not be removed" in r.getMessage() for r in caplog.records), caplog.text


def test_a_missing_alert_is_refused_before_the_launch_time_publish(p4_tenant, tmp_path):
    def publish(*_a, **_k):
        raise AssertionError("the publish ran for a run with no alert")

    out = B.launch(p4_tenant, tmp_path, publish=publish, alert_dir=tmp_path / "nowhere")
    assert out.publish_calls == [], out.text()
    assert out.refusal is not None, out.text()
    assert "alert not found" in out.refusal, out.text()


def test_an_exclusively_held_index_folder_excludes_another_process(tmp_path):
    from defender import _io

    probe = ("import fcntl, os, sys\n"
             "fd = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)\n"
             "try:\n    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\nexcept OSError:\n"
             "    sys.exit(7)\n")
    with _io.hold(tmp_path) as held:
        with held.exclusive():
            busy = subprocess.run([sys.executable, "-c", probe, str(tmp_path)], check=False)  # noqa: S603
        free = subprocess.run([sys.executable, "-c", probe, str(tmp_path)], check=False)  # noqa: S603
    assert busy.returncode == 7, "another process took the folder while it was held"
    assert free.returncode == 0, "control: the folder is free once released"
