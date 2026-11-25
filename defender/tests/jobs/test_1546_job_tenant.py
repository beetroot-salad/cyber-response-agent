"""#1546 (design r8, r10 (b)) `JobTenant`: the frozen `RecordTenant` the container entries build from the launch facts over a
job root (`<root>/<T>/...`) and inputs, in place of `accept_tenant`. r10: its one reason is location (the run copies a
container reads live in the read-only inputs, `<inputs>/run-knowledge`, not under its writable root, where `accept_tenant`
over the root would place them). Members are r10's census set; the entries (investigation, readiness, learning job) run
over a job root, knowledge from the forge. Pinned: `defender.tenancy.JobTenant(id=, data_root=, inputs=)`."""
from __future__ import annotations

import contextlib
import os
import random
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures
from defender.tests.support.jobs import _helper_evidence1546 as H
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture

evidence_store = H.evidence_store
process_state = J.process_state
scene = H.fresh_scene

ID = "7a1c5e93-4b2d-4f86-9e07-3c8d1b6a2f54"


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    root, inputs = tmp_path / "root", tmp_path / "inputs"
    (root / ID / "runs").mkdir(parents=True)
    (root / ID / "episodes").mkdir()
    inputs.mkdir()
    return root, inputs


# r10 (f) bucket 1 retired `test_premise_accept_tenant_refuses_a_job_root_because_it_holds_no_knowledge_folder`: G8 is refuted
# on main (`accept_tenant` runs folder rules only and accepts a job-root layout; `clone_tree=` is gone). `JobTenant`'s reason
# is now location (`run_knowledge` in the inputs), pinned by the members test below; that no container entry calls
# `accept_tenant` is `tooling/test_no_container_accept_tenant_1546.py`.


def test_a_job_tenant_has_the_censuss_members_over_the_root_and_the_inputs_and_no_other(tmp_path):
    """`id`, `data_root`, `tenant_root`, `runs`, `episodes`, `runs_repository()`, `run_knowledge` (= `<inputs>/run-knowledge`),
    `root_names()` answer from root and inputs; `runs_legacy`/`episodes_legacy` raise; absent: `export_folder` (r10), what
    main's `Tenant` also lacks (`knowledge`, `agent`, `settings`, `exports`, `knowledge_lock`) and what main's `Tenant` has and
    a job root does not (`scratch`, `drafts`, `worktrees`, `sessions`, `data_root_path`, `learning_paths`). (design: JobTenant;
    r10 (b) "r10 members", the whole set)"""
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
    assert Path(str(t.run_knowledge)) == inputs / "run-knowledge"
    assert isinstance(t.runs_repository(), RunsRepository)
    assert "<data root>" in set(t.root_names().values())
    for legacy in ("runs_legacy", "episodes_legacy"):
        with pytest.raises(Exception):  # noqa: B017, PT011 — any refusal: the design says only that they raise
            getattr(t, legacy)
    for absent in ("export_folder", "knowledge", "agent", "settings", "exports", "knowledge_lock",
                   "scratch", "drafts", "worktrees", "sessions", "data_root_path", "learning_paths"):
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
    from defender.records.formats import TenantRefused
    from defender.tenancy import JobTenant

    _, inputs = _layout(tmp_path)
    inside = Path(__file__).resolve().parents[2] / "job-root-1546"  # the checkout's `defender/` (a namespace package: no __file__)
    for root in (Path("relative/root"), inside):
        with pytest.raises((TenantRefused, ValueError)):
            JobTenant(id=ID, data_root=root, inputs=inputs)


def _placements(tmp_path: Path) -> dict[str, tuple[Path, Path]]:
    """Every (root, inputs) placement the constructor refuses, by name: each folder relative, each inside the checkout's
    `defender/` tree (an existing folder there, so only placement can refuse it), each holding the other (as given and
    through a link), and the two the same folder."""
    root, inputs = _layout(tmp_path)
    code = Path(__file__).resolve().parents[2]  # the checkout's `defender/` (a namespace package: no __file__)
    in_code = code / "tests"
    assert in_code.is_dir(), "premise: a folder that exists inside the code tree"
    linked = tmp_path / "link-into-root"
    linked.symlink_to(root / ID / "runs", target_is_directory=True)
    return {
        "relative-root": (Path("relative/root"), inputs),
        "relative-inputs": (root, Path("relative/inputs")),
        "root-in-code-tree": (in_code, inputs),
        "inputs-in-code-tree": (root, in_code),
        "inputs-inside-root": (root, root / ID / "inputs"),
        "root-inside-inputs": (inputs / "root", inputs),
        "inputs-linked-into-root": (root, linked),
        "the-same-folder": (root, root),
    }


PLACEMENTS = ["relative-root", "relative-inputs", "root-in-code-tree", "inputs-in-code-tree", "inputs-inside-root",
              "root-inside-inputs", "inputs-linked-into-root", "the-same-folder"]


@pytest.mark.parametrize("placement", PLACEMENTS)
def test_a_job_tenant_is_refused_for_every_placement_of_root_or_inputs_the_design_forbids(tmp_path, monkeypatch, placement):
    """Whole class, root and inputs each the offender: a relative path, a folder inside the checkout's `defender/` tree,
    and a root and inputs where one holds the other (either way, as given or through a link, or the same folder) are
    refused by the constructor; two separate absolute folders outside the tree are the control. The working directory is
    outside the code tree, so a relative path is refused for being relative, not for where it happens to resolve.
    (design: JobTenant "a relative or unresolvable path, a folder inside the running checkout's `defender/` tree, or a root
    and inputs where one holds the other")"""
    from defender.records.formats import TenantRefused
    from defender.tenancy import JobTenant

    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    placements = _placements(tmp_path)
    assert set(placements) == set(PLACEMENTS)
    assert JobTenant(id=ID, data_root=tmp_path / "root", inputs=tmp_path / "inputs")  # the control
    root, inputs = placements[placement]
    with pytest.raises((TenantRefused, ValueError)):
        JobTenant(id=ID, data_root=root, inputs=inputs)


def test_a_job_tenants_root_names_name_each_of_its_three_folders_in_every_spelling(tmp_path):
    """`root_names()` names the job's root `<data root>`, its tenant folder `<tenant folder>` and its inputs `<job inputs>`,
    each as given and as resolved (root and inputs reached through links here), and `name_roots` with it rewrites an
    absolute path under each folder, in either spelling, to its name: no text shown to a model or an operator locates a
    job's folders. (design: JobTenant `root_names()`, a census member; #1256 spellings)"""
    from defender._paths import name_roots
    from defender.tenancy import JobTenant

    real_root, real_inputs = _layout(tmp_path / "real")
    root, inputs = tmp_path / "root-link", tmp_path / "inputs-link"
    root.symlink_to(real_root, target_is_directory=True)
    inputs.symlink_to(real_inputs, target_is_directory=True)
    names = JobTenant(id=ID, data_root=root, inputs=inputs).root_names()
    assert set(names.values()) == {"<data root>", "<tenant folder>", "<job inputs>"}, names
    for spelling, named in ((root, "<data root>"), (real_root, "<data root>"), (root / ID, "<tenant folder>"),
                            (real_root / ID, "<tenant folder>"), (inputs, "<job inputs>"),
                            (real_inputs, "<job inputs>")):
        assert names.get(str(spelling)) == named, (spelling, names)
    for under, named in ((root / "other" / "x.json", "<data root>/other/x.json"),
                         (real_root / ID / "runs" / "r.json", "<tenant folder>/runs/r.json"),
                         (root / ID / "episodes", "<tenant folder>/episodes"),
                         (real_inputs / "run-knowledge" / "a", "<job inputs>/run-knowledge/a"),
                         (inputs / "run-knowledge", "<job inputs>/run-knowledge")):
        assert name_roots(f"see {under} now", names) == f"see {named} now", under


# --- the entries run over a job root ------------------------------------------------------------------------------------------------

@pytest.mark.postgres
@pytest.mark.openbao
@pytest.mark.garage
def test_the_investigation_entry_runs_over_its_job_root_and_stages_its_outcome(scene, evidence_store):
    """`run.job_main` in the container (data root = the job root) takes the job tenant, runs its lifecycle once over the run
    copy the helper fetched into the inputs (the claim's pin, a commit the fetch stand-in serves) and stages an outcome with
    `setup = done`. (design: entries use JobTenant; r10 (b))"""
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
    """`run.readiness_main` over a job root, its run copy fetched into the inputs by the helper, stages a `result` whose
    outcome is `ready`. (design: entries use JobTenant; r10 (b), (c))"""
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
def test_the_helper_hands_a_learning_job_its_inputs_folder_and_its_pin_in_the_launch_facts(scene, evidence_store):
    """The facts a learning container builds its `JobTenant` from: `inputs_dir` names, through the container's binds, the
    claim's `.job-inputs/<claim>/` folder (the claim's alone), and `knowledge_commit` is the claim's pin. (design: JobTenant
    "from the launch facts"; The job's folders: Inputs; The pin)"""
    from defender.tests.support.evidence._facts1546 import LAUNCH_INPUTS
    from defender.tests.support.jobs._job_helper import host_path

    planted = H.plant(scene, "learning")
    seen: dict = {}

    def job(c) -> int:
        launch = c.request("launch")
        seen["launch"] = launch
        seen["inputs"] = host_path(c.mounts, launch[LAUNCH_INPUTS]) if launch.get(LAUNCH_INPUTS) else None
        seen["is_dir"] = bool(seen["inputs"]) and seen["inputs"].is_dir()
        return 0

    H.drive(scene, planted, job, check=False, **evidence_store.seams)
    assert "launch" in seen, "the job container never ran"
    assert seen["inputs"] == H.job_inputs(scene), (seen["launch"].get(LAUNCH_INPUTS), seen["inputs"])
    assert seen["is_dir"], "the inputs folder the launch names did not exist while the job ran"
    assert seen["launch"]["knowledge_commit"] == scene.t.commit, seen["launch"]


@pytest.mark.postgres
@pytest.mark.openbao
@pytest.mark.garage
@contextlib.contextmanager
def _in_container_environment(env: dict) -> Iterator[None]:
    """The process environment as the job container's (`c.env`) for an entry run on this thread: inside the box the two are
    one, so a read of `os.environ` (the data root) must see the container's job root, not the test's host data root."""
    saved = {k: os.environ.get(k) for k in env}
    try:
        for key, value in env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _damaging_main_copy(scene, damage: dict) -> object:
    """The real fetch seam; a fetch of `main` (no `commit=`) into the claim's `shared/` folder, which is the `copy.make()` copy
    the helper hands the learning container, has its `settings/verb-grants.yaml` replaced by a link once the child has filled
    it, and the damaged file recorded in `damage`. Any other fetch (the grant read, the pin's copy) is left as fetched."""
    from defender.tests.tenancy.knowledge_1618 import _support as K

    seam = K.fetch_seam(scene.t)
    shared = scene.root / H.SCRATCH / scene.claim / "shared"

    def fetch(tenant_id, dest, **kw) -> str:
        line = seam(tenant_id, dest, **kw)
        grants = Path(dest) / "settings" / "verb-grants.yaml"
        if kw.get("commit") is None and Path(dest).is_relative_to(shared) and grants.is_file():
            grants.unlink()
            grants.symlink_to("/etc/passwd")
            damage.setdefault("files", []).append(grants)
        return line

    fetch.calls = seam.calls  # type: ignore[attr-defined]
    return fetch


@pytest.mark.parametrize(("damaged", "reaches"), [("main-copy", False), ("none", True)])
def test_the_learning_job_entrys_settings_read_comes_from_the_copy_the_helper_handed_it(scene, evidence_store, damaged,
                                                                                         reaches, tmp_path):
    """The learning container's tenant check reads `main`'s settings from the `copy.make()` copy the helper handed it, in the
    claim's `shared/` folder: a link the fetch put in that copy's `settings/verb-grants.yaml` stops the entry at that read (a
    `launch_refused` naming the tenant's refusal), after it built its `JobTenant` and before the first step past the
    settings read (the source's declared disposition, `cli._declared_or_refused`). The `none` arm (no damage) is the
    control that the scene gets past the settings read at all, so the damaged arm's stop is the damage's. (owner D4 acknowledgement, r10 (c): "the container's
    settings read comes from the copy the helper handed it", never the host tenant folder, which holds no settings now; the
    `clone` arm went with the clone, r10 (f) bucket 2; was `..._gets_past_its_tenant_step_without_reading_the_clones_settings`)"""
    from defender.learning.branch import cli, job_entry
    from defender.tests.support.jobs._container_entry1170 import ThreadCalls

    planted = H.plant(scene, "learning")
    # The source's accepted bundle (a real source run, packed): without it the entry stops at its pull, before any settings read.
    evidence_store.plant_source_bundle(scene, planted.source, tmp_path)
    damage: dict = {}
    seams = dict(evidence_store.seams)
    if damaged == "main-copy":
        seams["fetch"] = _damaging_main_copy(scene, damage)

    def entry(c) -> int:
        try:
            with _in_container_environment(c.env):
                return int(job_entry.main(["--job", planted.owner, "--tenant", scene.tenant, "--source", planted.source],
                                          environ=c.env, preflight=lambda *a, **k: 0))
        except SystemExit:
            return 1

    def job(c) -> int:
        return entry(c)

    from defender.tenancy import JobTenant

    with ThreadCalls({"past_settings": cli._declared_or_refused, "tenant_step": JobTenant.__init__}) as calls:
        H.drive(scene, planted, job, **seams)
    if damaged == "main-copy":
        assert damage.get("files"), "premise: the helper fetched no `copy.make()` copy into `shared/` to damage"
    # Both arms reach their tenant step (the container builds its `JobTenant`), so the damaged arm's stop comes after it, at
    # the settings read, not at an earlier step.
    assert calls.container("tenant_step") >= 1, (damaged, "the entry stopped before it built its job tenant")
    outcome = H.facts(scene.dsn, scene.claim).get("outcome")
    assert (calls.container("past_settings") >= 1) is reaches, (damaged, damage.get("files"), outcome)
    if not reaches:
        assert (outcome or {}).get("reason") == "launch_refused", outcome
        assert "tenant" in ((outcome or {}).get("message") or ""), f"the stop is not the tenant check's: {outcome}"
