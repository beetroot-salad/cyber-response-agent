"""#1546 (design r8) `JobTenant`: the frozen `RecordTenant` the container entries build from the launch facts over a job
root (`<root>/<T>/...`) and inputs, in place of `accept_tenant` (which refuses a root with no `knowledge/`). Members are the
census's set; the entries (investigation, readiness, learning job) run over a job root with no clone in it.
Pinned: `defender.tenancy.JobTenant(id=, data_root=, inputs=)`."""
from __future__ import annotations

import random
from pathlib import Path

import pytest

from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures
from defender.tests.support.jobs import _helper_evidence1546 as H
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture

evidence_store = H.evidence_store
process_state = J.process_state
scene = J.scene

ID = "7a1c5e93-4b2d-4f86-9e07-3c8d1b6a2f54"


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    root, inputs = tmp_path / "root", tmp_path / "inputs"
    (root / ID / "runs").mkdir(parents=True)
    (root / ID / "episodes").mkdir()
    inputs.mkdir()
    return root, inputs


def test_premise_accept_tenant_refuses_a_job_root_because_it_holds_no_knowledge_folder(tmp_path):
    """G8, green at the base: a root laid out as a job's is refused by `accept_tenant`, which is why the entries need `JobTenant`."""
    from defender.records.formats import TenantRefused
    from defender.tenancy import accept_tenant, data_root_from_path

    root, _ = _layout(tmp_path)
    with pytest.raises(TenantRefused):
        accept_tenant(data_root_from_path(root), ID, defender_dir=Path(__file__).resolve().parents[2], clone_tree=False)


def test_a_job_tenant_has_the_censuss_members_over_the_root_and_the_inputs_and_no_other(tmp_path):
    """`id`, `data_root`, `tenant_root`, `runs`, `episodes`, `runs_repository()`, `run_knowledge`, `export_folder(pin)`,
    `root_names()` answer from root and inputs; `runs_legacy`/`episodes_legacy` raise; there is no `knowledge`, clone half,
    lock or scratch. (design: JobTenant)"""
    from defender.records import RunsRepository
    from defender.records._held import RecordTenant
    from defender.tenancy import JobTenant

    root, inputs = _layout(tmp_path)
    t = JobTenant(id=ID, data_root=root, inputs=inputs)
    assert isinstance(t, RecordTenant)
    assert str(t.id) == ID
    assert Path(str(t.data_root)) == root
    assert Path(str(t.tenant_root)) == root / ID
    assert Path(str(t.runs)) == root / ID / "runs"
    assert Path(str(t.episodes)) == root / ID / "episodes"
    assert Path(t.run_knowledge).is_relative_to(inputs)
    assert Path(t.export_folder("a" * 40)).is_relative_to(inputs)
    assert isinstance(t.runs_repository(), RunsRepository)
    assert "<data root>" in set(t.root_names().values())
    for legacy in ("runs_legacy", "episodes_legacy"):
        with pytest.raises(Exception):  # noqa: B017, PT011 — any refusal: the design says only that they raise
            getattr(t, legacy)
    for absent in ("knowledge", "settings", "agent", "knowledge_lock", "scratch", "drafts", "worktrees"):
        assert not hasattr(t, absent), f"JobTenant has `{absent}`"
    with pytest.raises(Exception):  # noqa: B017, PT011
        t.id = "x"  # frozen


def _bad_ids(seed: int, n: int = 25) -> list[str]:
    rng = random.Random(seed)
    junk = ["", ".", "..", "a/b", "../x", ID + "/", "/" + ID, " " + ID, ID.upper().replace("-", "_"), "not-a-uuid", "\x00",
            ID[:-1], ID + "0"]
    return junk + ["".join(rng.choice("0123456789abcdef-/. ") for _ in range(rng.randrange(1, 40))) for _ in range(n)]


@pytest.mark.parametrize("bad", [b for b in _bad_ids(1546) if b != ID])
def test_a_job_tenant_is_refused_for_an_id_that_is_no_tenant_id(tmp_path, bad):
    """Whole class: any text that is not a tenant id is refused by the constructor (the id grammar runs there); the
    well-formed id is the control. (design: JobTenant)"""
    from defender.records.formats import TenantRefused
    from defender.tenancy import JobTenant

    root, inputs = _layout(tmp_path)
    assert JobTenant(id=ID, data_root=root, inputs=inputs)
    with pytest.raises((TenantRefused, ValueError, TypeError)):
        JobTenant(id=bad, data_root=root, inputs=inputs)


def test_a_job_tenant_is_refused_for_a_relative_root_or_one_inside_the_code_tree(tmp_path):
    """Placement runs in the constructor: a relative data root, and a root inside the checkout's `defender/` tree, are refused. (design)"""
    import defender
    from defender.records.formats import TenantRefused
    from defender.tenancy import JobTenant

    _, inputs = _layout(tmp_path)
    inside = Path(defender.__file__).resolve().parent / "job-root-1546"
    for root in (Path("relative/root"), inside):
        with pytest.raises((TenantRefused, ValueError)):
            JobTenant(id=ID, data_root=root, inputs=inputs)


# --- the entries run over a job root ------------------------------------------------------------------------------------------------

@pytest.mark.postgres
@pytest.mark.openbao
@pytest.mark.garage
def test_the_investigation_entry_runs_over_its_job_root_and_stages_its_outcome(scene, evidence_store):
    """`run.job_main` in the container (data root = the job root, no clone in it) takes the job tenant, runs its lifecycle once
    and stages an outcome with `setup = done`: it did not call `accept_tenant` (which refuses that root). (design: entries use JobTenant)"""
    from defender import run as run_py
    from defender.investigation.challenge_gate import ReviewState

    planted = H.plant(scene, "investigation")
    calls: list[int] = []

    def lifecycle(**kw):
        calls.append(1)
        facts = kw["job_facts"]
        facts.box, facts.scrub_verified = "started", True
        facts.review_state["state"] = ReviewState(closed=True)
        return {"output": "x", "requests": 0, "truncated_by": None, "closed_before_cut": False, "exit_reason": None}

    seen: dict = {}

    def job(c) -> int:
        try:
            return int(run_py.job_main(["--job", planted.owner, "--tenant", scene.tenant], environ=c.env,
                                       lifecycle=lifecycle, preflight=lambda *a, **k: 0, visualize=lambda *a, **k: None))
        except SystemExit as e:
            seen["exit"] = e
            return 1

    H.drive(scene, planted, job, **evidence_store.seams)
    assert calls == [1], seen
    assert H.facts(scene.dsn, scene.claim)["outcome"]["setup"] == "done"


@pytest.mark.postgres
@pytest.mark.openbao
def test_the_readiness_entry_runs_over_its_job_root_and_stages_its_result(scene):
    """`run.readiness_main` over a job root with no clone stages a `result` whose outcome is `ready`. (design: entries use JobTenant)"""
    from defender.tests.support.jobs._readiness1471 import Readied, entry_of
    from defender.tests.support.jobs._job_helper import HelperRan, ContainerStandIn

    planted = H.plant(scene, "readiness")
    done = Readied(scene, planted.owner, HelperRan(), ContainerStandIn(), "")
    H.drive(scene, planted, entry_of(scene, planted.owner, done))
    assert done.container_raised is None, done.container_raised
    assert H.facts(scene.dsn, scene.claim)["result"]["outcome"] == "ready"


@pytest.mark.postgres
@pytest.mark.openbao
@pytest.mark.garage
def test_the_learning_job_entry_gets_past_its_tenant_step_without_reading_the_clones_settings(scene, evidence_store):
    """With the host clone's working-tree settings damaged (a link in them), the learning entry over its job root still
    reaches its launch steps (`_open_launch_source` runs in the container): it reads the pinned export's settings from the
    inputs, never the clone's. (design: the learning job passes the export roots)"""
    from defender.learning.branch import cli, job_entry
    from defender.tests.support.jobs._container_entry1170 import ThreadCalls

    stray = next(p for p in (scene.t.clone / "settings").rglob("*") if p.is_file())
    stray.unlink()
    stray.symlink_to("/etc/passwd")
    planted = H.plant(scene, "learning")

    def job(c) -> int:
        try:
            return int(job_entry.main(["--job", planted.owner, "--tenant", scene.tenant, "--source", planted.source],
                                      environ=c.env, preflight=lambda *a, **k: 0))
        except SystemExit:
            return 1

    with ThreadCalls({"source_opened": cli._open_launch_source}) as calls:
        H.drive(scene, planted, job, **evidence_store.seams)
    assert calls.container("source_opened") >= 1, "the entry never reached its launch steps"
