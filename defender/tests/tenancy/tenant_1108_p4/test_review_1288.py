"""#1108 P4 fixes from PR #1288's review, each pinned at the seam that now carries it.

A run copy is owned from the instant its folder exists (its building name carries its owner), so
a sweep never removes it mid-build. The fetch child holds one deadline over its network phase. The stage is judged
before the box-or-host choice. A run's knowledge commit comes from its host-held record, and a family's from the
episode's knowledge pin.

#1618 (the publish child is the fetch child, flow 1): retired here, each with its successor or reason:
- every "records its outcome" case ("the child records running out of its budget", "the launcher records a child that
  reports nothing valid" and its control, "a lock-busy publish records its outcome and clears an earlier refusal", "a
  lock-busy stale publish is recorded transient"): D7, the publish status and its writers are gone; K1, no lock. The
  deadline itself is `test_r6_launcher.py::test_1618_the_child_holds_its_own_deadline_and_reports_running_out_of_it`;
  the failed child's line is `::test_1618_a_child_whose_line_is_not_the_fetch_vocabulary_is_a_failed_child_*`;
- "what the child left running dies with it":
  `test_r6_publish_stop.py::test_1618_a_child_that_reported_and_exited_takes_its_process_group_with_it`.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from defender.tests.support.tenancy._host1214 import TEST_TENANT
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

OID = "0123456789abcdef0123456789abcdef01234567"


class _RecordingSpawn:
    """`launch_publish`'s spawn seam (`subprocess.Popen`'s signature): records the argv it would start its child with,
    then starts a harmless process that prints no report line. (Local: the publish child's file is retired.)"""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kw):
        self.calls.append(list(map(str, argv)))
        return subprocess.Popen([sys.executable, "-c", "pass"],  # noqa: S603 — a test double
                                stdout=kw.get("stdout"), stderr=kw.get("stderr"), stdin=kw.get("stdin"))


def _dest(tmp_path: Path) -> Path:
    dest = tmp_path / "fetch-dest"
    dest.mkdir(exist_ok=True)
    return dest


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


def test_a_sweep_keeps_a_run_copy_being_built_and_removes_a_dead_builders(p4_tenant):
    """The race, replayed in order: a run copy's building folder exists with no owner file yet
    (the builder is between making it and writing its record) when a fetch sweeps (#1618 flow 8: the sweep is
    `tenancy._owner.sweep_dead_owners`, run at every fetch's start)."""
    from defender.tenancy._owner import owned_temporary, sweep_dead_owners

    copies = Path(p4_tenant.tenant.run_knowledge)
    copies.mkdir(parents=True, exist_ok=True)
    live = copies / owned_temporary(".building-r-live")
    live.mkdir()
    orphan = copies / ".building-r-orphan-0123abcd"
    orphan.mkdir()
    sweep_dead_owners(Path(p4_tenant.data_root), p4_tenant.tenant_id)
    assert live.is_dir(), "the sweep removed a run copy while its owner was building it"
    assert not orphan.exists(), "control: an unowned building folder is swept"


# --- the fetch child's one deadline -----------------------------------------------------------------

def test_the_launcher_hands_the_child_a_budget_inside_its_own(tmp_path):
    from defender.investigation import publish_launch

    spawn = _RecordingSpawn()
    publish_launch.launch_publish("some-tenant", data_root=tmp_path, dest=_dest(tmp_path), budget=60.0, spawn=spawn)
    argv, = spawn.calls
    budget = float(argv[argv.index("--budget") + 1])
    assert 0 < budget < 60.0, argv


def test_a_zero_budget_is_already_out_not_unbounded(p4_tenant, tmp_path):
    """`setitimer(0)` disarms a timer: a budget of 0 must end the network phase at once, refused transient naming the
    budget, the folder left empty. Control: no budget fetches. (#1618: the fetch child's deadline, was the publish's.)"""
    from defender.learning.author import version_control as vc
    from defender.learning.author.version_control.fetch import fetch_copy

    t = p4_tenant
    dest = _dest(tmp_path)
    began = time.monotonic()
    with pytest.raises(vc.DeliveryRefused, match="budget") as refused:
        fetch_copy(t.tenant_id, dest, data_root=Path(t.data_root), directory=t.directory,
                   identity=t.vault.identity(), budget=0.0)
    assert time.monotonic() - began < 2.0, "a zero budget let the network phase run"
    assert "within its 0s budget" in str(refused.value), refused.value
    assert list(dest.iterdir()) == [], "a zero budget fetch wrote into the folder"
    control = tmp_path / "control"
    control.mkdir()
    assert fetch_copy(t.tenant_id, control, data_root=Path(t.data_root), directory=t.directory,
                      identity=t.vault.identity()) == t.commit, "control"


@pytest.mark.parametrize("budget", [0.0, -1.0])
def test_the_launcher_refuses_a_budget_that_is_not_positive(tmp_path, budget):
    """No child starts with no time to run in; the launcher's own fault is the failed child's line, lasting. (#1618:
    "and records it" retires with the publish status, D7.)"""
    from defender.investigation import publish_launch

    spawn = _RecordingSpawn()
    line = publish_launch.launch_publish("r6-tenant", data_root=tmp_path, dest=_dest(tmp_path), budget=budget,
                                         spawn=spawn)
    assert spawn.calls == [], "a child was started with no time to run in"
    assert line.startswith("refused lasting fetch child failed:"), line
    assert "positive" in line, line


def test_the_launcher_and_run_start_build_one_failed_child_line():
    from defender.tenancy import run_knowledge

    line = run_knowledge.failed_line("it printed no report line")
    report = run_knowledge.read_publish_report(line)
    assert report.kind == run_knowledge.REFUSED, report
    assert not report.transient, report
    assert report.reason == run_knowledge.child_failed("it printed no report line").reason


# --- the stage is judged on both paths ---------------------------------------------------------

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
                                  verdicts.append, tenant_id=TEST_TENANT, data_root=tmp_path)
    assert verdicts, "the refusal wrote no did-not-run marker"


# --- the reducer pitfalls page is one name, shipped and named -----------------------------------

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
    from defender.investigation import tools as tools_mod
    from defender.investigation.agent_definition import compile_policy_for
    from defender.investigation.driver import MAIN_DEF
    from defender.investigation.tools_gather import GatherRequest, _gather_prompt
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


# --- cleanup, alert, held-out index ------------------------------------------------------------

def test_a_draft_that_cannot_be_removed_is_logged_not_raised(tmp_path, caplog):
    from types import SimpleNamespace

    from defender.learning.author.version_control.batch import Batch

    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x", encoding="utf-8")
    batch = SimpleNamespace(id="b1", draft_root=blocker / "draft" / "root")
    Batch.discard(batch)  # type: ignore[arg-type]
    assert any("could not be removed" in r.getMessage() for r in caplog.records), caplog.text


def test_a_missing_alert_is_refused_before_the_fetch(p4_tenant, tmp_path):
    def must_not_fetch(*_a, **_k):
        raise AssertionError("the fetch ran for a run with no alert")

    fetch = B.Recorded(must_not_fetch)
    out = B.launch(p4_tenant, tmp_path, fetch=fetch, alert_dir=tmp_path / "nowhere")
    assert fetch.calls == [], out.text()
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


# --- the child's word wins ----------------------------------------------------------------------------

def test_a_child_that_finishes_after_the_stop_is_reported_as_it_said(tmp_path):
    """The launcher's wait runs out and it asks the child to stop; the child ignores the request, finishes within the
    grace and reports `ok`. That report is the outcome. (#1618: "and the launcher records nothing over it" retires with
    the publish status, D7.)"""
    from defender.investigation import publish_launch

    child = ("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
             f"time.sleep(1.5); print('ok {OID}')")
    line = publish_launch.launch_publish(
        "r6-tenant", data_root=tmp_path, dest=_dest(tmp_path), budget=0.5,
        command=[sys.executable, "-c", child, "--"])
    assert line == f"ok {OID}", line


# --- a run box is always a run copy's ----------------------------------------------------------

def test_a_run_box_over_a_bare_agent_folder_is_refused(tmp_path):
    from defender.box import BoxSpec
    from defender.box import _lifecycle

    agent = tmp_path / "agent"
    agent.mkdir()
    with pytest.raises(TypeError, match="run copy"):
        _lifecycle._start_run_box(tmp_path / "run", tmp_path, BoxSpec(), _no_docker, agent,
                                  None, None, tenant_id=TEST_TENANT, data_root=tmp_path)


# --- knowledge commits from host-held records --------------------------------------------------

_A = "a" * 40
_B = "b" * 40


def _run_with_record(tmp_path: Path, *, record: str, stamp: str):
    import json

    from defender.records import Run

    import dataclasses

    from defender._git import REPO_ROOT
    from defender.records import _provenance

    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)
    # A real stamp, in the shape every reader accepts, naming `stamp` as its knowledge.
    real = dataclasses.replace(_provenance.capture_tree(REPO_ROOT),
                               knowledge=_provenance.KnowledgeRevision.at(stamp))
    (run_dir / "provenance.json").write_text(real.as_json(
        knowledge_source={"kind": "fresh", "commit": stamp, "stale_kind": None}),
        encoding="utf-8")
    assert _provenance.read_provenance(run_dir / "provenance.json") is not None, "control: a readable stamp"
    (run_dir.parent / "r1.knowledge-source.json").write_text(json.dumps(
        {"kind": "fresh", "commit": record, "stale_kind": None, "reason": None}), encoding="utf-8")
    return Run(run_dir, runs_base=None)


def test_a_runs_knowledge_commit_is_its_host_records_not_its_stamps(tmp_path):
    run = _run_with_record(tmp_path, record=_A, stamp=_B)
    status = run.knowledge_status()
    assert status is not None
    assert status.commit == _A, "the run's knowledge commit was taken from its box-writable stamp"


def test_the_branch_pin_is_the_source_runs_recorded_commit(tmp_path):
    """(#1618: the pin is `_source_pin`'s commit, fetched by id later; there is no export to resolve it to.)"""
    from defender.learning.branch.cli import _source_pin

    source = _run_with_record(tmp_path, record=_A, stamp=_B)
    assert _source_pin(source) == _A, "the family was pinned to the commit a box wrote"


class _Episode:
    def __init__(self, folder: Path) -> None:
        self._folder = folder

    def view(self):
        from defender import _io

        return _io.bind(self._folder).__enter__()


def _pinned_episode(tmp_path: Path, commit: str | None) -> _Episode:
    from defender.records._knowledge_pin import pin_text

    folder = tmp_path / "episode"
    folder.mkdir(parents=True)
    if commit is not None:
        (folder / "knowledge_pin.json").write_text(pin_text(commit), encoding="utf-8")
    return _Episode(folder)


def test_a_sibling_reads_its_familys_pin_without_the_flag(tmp_path):
    from argparse import Namespace

    from defender.run import _family_pin

    assert _family_pin(Namespace(episode="e"), None, _pinned_episode(tmp_path, _A)) == _A


def test_a_sibling_whose_flag_names_another_commit_is_refused(tmp_path):
    from argparse import Namespace

    from defender.run import _family_pin

    with pytest.raises(SystemExit, match="not the family"):
        _family_pin(Namespace(episode="e"), _B, _pinned_episode(tmp_path, _A))


def test_a_sibling_of_an_episode_launched_before_pins_keeps_its_flag(tmp_path):
    from argparse import Namespace

    from defender.run import _family_pin

    assert _family_pin(Namespace(episode="e"), _B, _pinned_episode(tmp_path, None)) == _B
    assert _family_pin(Namespace(episode="e"), None, _pinned_episode(tmp_path / "x", None)) is None


def test_the_judge_reads_lesson_bodies_at_the_familys_pin_not_a_siblings_stamp(tmp_path):
    import json

    from defender.records._episode_paths import LAYOUT
    from defender.learning.judge import _pass_knowledge
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    world = fixture_uuid("world:judge-pin")
    episode = _pinned_episode(tmp_path, _A)
    world_dir = episode._folder / LAYOUT.world(world).dir
    world_dir.mkdir(parents=True)
    (world_dir / "provenance.json").write_text(json.dumps({"knowledge": {"commit": _B}}),
                                               encoding="utf-8")
    assert _pass_knowledge(episode.view(), [world]) == {"commit": _A}, (
        "the judge read lesson bodies at the commit a sibling's box wrote")


# --- a batch reads its base once per head ------------------------------------------------------

def test_a_batch_reads_its_bases_files_once_per_head():
    from types import SimpleNamespace

    from defender.learning.author.version_control.batch import Batch

    class _Repo:
        def __init__(self) -> None:
            self.reads = 0

        def entries(self, commit, _paths, *, recursive):
            self.reads += 1
            return [("100644", "blob", f"oid-{commit}", "agent/a.md")]

        def blobs(self, oids):
            return {oid: oid.encode() for oid in oids}

    repo = _Repo()
    line = SimpleNamespace(head="c1")
    batch = SimpleNamespace(repository=repo, _line=line, _blobs_at=None)
    first = Batch._head_blobs(batch)  # type: ignore[arg-type]
    Batch._head_blobs(batch)  # type: ignore[arg-type]
    assert repo.reads == 1, "the same head was read from git twice"
    first["a.md"] = b"changed"
    assert Batch._head_blobs(batch)["a.md"] == b"oid-c1", "a caller's edit reached the cache"  # type: ignore[arg-type]
    line.head = "c2"
    assert Batch._head_blobs(batch)["a.md"] == b"oid-c2"  # type: ignore[arg-type]
    assert repo.reads == 2
