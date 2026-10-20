"""D1/O3: the entry points take a tenant through `accept_tenant`, once."""
from __future__ import annotations

from defender.runtime import session_store
from defender.runtime import run_tenant as run_tenant_mod
from defender.tests.support.learning.core import _state1135
from defender.tests.learning.oracle.live_contracts import _spec1224 as S1224

import inspect
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender.tenancy import _tenant
from defender.episodes._episode_handle import Episode
from defender import run as run_py
from defender.learning.branch import cli as branch_cli
from defender.cli import policy_cli
from defender.cli import tenant as tenant_py
from defender.skills.connect import validate_scaffold
from defender.tests.support.invlang.validation import _dispositions995 as D995
from defender.tests.support.shared.contracts import _spec1077 as S1077
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as P
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

#: The launcher's episodes knob (J44; the refusal stays until D12).
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"


def _owner(root: Path, tenant_id: str = H.TID, **kw: Any) -> str:
    """`accept_tenant`'s own refusal on this tree — the text every entry must pass through."""
    return H.accept_refusal(_tenant, root, tenant_id, **kw)


def _never_created_root() -> Path:
    """A data root inside the RUNNING checkout's box-mounted `defender/` tree that does not
    exist and must never be created: every path given it refuses before reading or writing."""
    return H.DEFENDER / f".spec1120-never-created-{uuid.uuid4().hex}" / "data"


def _assert_never_created(root: Path) -> None:
    assert not root.parent.exists(), (
        f"a refused entry created {root.parent} inside the checkout's defender/ tree")


def _owner_in_checkout(checkout: Path, root: Path, tenant_id: str = H.TID) -> str:
    """`accept_tenant`'s refusal as the tmp CHECKOUT's own code raises it (its O11a is keyed to
    its own `defender/`), obtained in a child interpreter that imports the copy."""
    code = (
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from defender.tenancy import _tenant\n"
        "assert Path(_tenant.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve()), "
        "_tenant.__file__\n"
        "try:\n"
        "    _tenant.accept_tenant(Path(sys.argv[2]), sys.argv[3],\n"
        "                          defender_dir=Path(sys.argv[1]) / 'defender', box_mounted=())\n"
        "except _tenant.TenantRefused as refused:\n"
        "    print(refused, end='')\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit('ACCEPTED')\n")
    proc = subprocess.run(  # noqa: S603 — fixed argv, the test's own interpreter
        [sys.executable, "-c", code, str(checkout), str(root), tenant_id],
        env=H.tenant_env(root), cwd=str(checkout), capture_output=True, text=True,
        timeout=120, check=False)
    assert proc.returncode == 0, (
        f"the checkout copy's accept_tenant did not refuse {root}:\n{proc.stdout}\n{proc.stderr}")
    assert proc.stdout, "the checkout copy's accept_tenant refused with no message"
    return proc.stdout


def _copy_script(checkout: Path, module: Any) -> Path:
    """The tmp checkout's own copy of an entry point's file."""
    return checkout / H.script_of(module).resolve().relative_to(H.REPO_ROOT)


def _knowledge_link(base: Path, root: Path, tenant_id: str = H.TID, *, row: bool = True) -> None:
    """`<root>/<id>/knowledge` a SYMLINK to a complete knowledge folder elsewhere (N13)."""
    real = H.place_knowledge(base / "elsewhere", tenant_id)
    if row:
        H.plant_row(root, tenant_id)
    H.tenant_folder(root, tenant_id).mkdir(parents=True, exist_ok=True)
    H.knowledge_dir(root, tenant_id).symlink_to(real, target_is_directory=True)


def _source_under(root: Path, *, runs_tenant: str = H.TID) -> Path:
    """A finished, branchable source run at `<root>/<runs_tenant>/runs/<id>`. #1187 R1
    (review-4 F42): no runs-base record — every caller named the run's own tenant, and the
    run's tenant is where it sits."""
    base = H.tenant_folder(root, runs_tenant) / "runs"
    base.mkdir(parents=True, exist_ok=True)
    return P.source_run(base)


def _launch(source: Path, spawn: Any, *, tenant_id: str | None = None,
            **seams: Any) -> BaseException | int:
    """The REAL launcher over one source, the role preflight neutralised (a refusal is never the host's
    credentials)."""
    seams.setdefault("preflight", T.no_preflight)
    requested = source.parent.parent.name if tenant_id is None else tenant_id
    try:
        return branch_cli.main(
            ["--tenant", requested, source.name, str(T.BRANCH_MESSAGE_ID),
             *T.retired_continuation_argv()],
            spawn=spawn, **seams)
    except SystemExit as refused:
        return refused


def test_1120_run_tenant_is_the_accepted_tenant_plus_its_grants_and_dispatch(
        data_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    H.adopted(data_root)
    rec = H.RunRecorder(tmp_path / "run")
    rc, exc = H.drive_run(run_py, [str(H.plant_alert(tmp_path / "in")), "--tenant", H.TID], rec)
    assert exc is None, f"run.main refused a finished tenant: {H.exit_text(exc)}"
    assert rc == 0
    assert len(rec.lifecycle_calls) == 1, f"the lifecycle ran {len(rec.lifecycle_calls)} times"
    run_tenant = rec.lifecycle_calls[0]["tenant"]

    expected = H.accept(_tenant, data_root, H.TID)
    assert run_tenant.tenant == expected, (
        f"RunTenant.tenant is not the Tenant accept_tenant returns: {run_tenant.tenant!r} "
        f"!= {expected!r}")
    assert type(run_tenant.tenant) is type(expected)
    assert run_tenant.settings == H.settings_dir(data_root) == run_tenant.tenant.settings
    assert run_tenant.tenant_id == H.TID
    assert Path(run_tenant.grants.path) == H.settings_dir(data_root) / "verb-grants.yaml"
    assert {(s, v) for s, v, *_ in run_tenant.grants.gather.entries} == set(D995.GATHER_CENSUS)
    assert run_tenant.correlation is not None, "a fresh run carries its lead-zero dispatch"
    assert run_tenant.correlation.template_id == H.FIXTURE_CORRELATION_TEMPLATE

    # The sibling: the same accepted Tenant, and no turn-0 dispatch.
    src = _source_under(data_root)
    # #1187 (Layout A): the episode is `<root>/<T>/episodes/<uuid>`, as RUNS leaves it. (The
    # retired variable, set below to that same folder, is read by nothing after #1187, O9.)
    manifest = P.family_for(src)
    monkeypatch.setenv(EPISODES_BASE_ENV, str(manifest.parent.parent))
    with Episode.open(manifest.parent) as episode:
        T.episode_view(episode, tenant=expected)  # the container, as its launcher makes it
    sib = H.RunRecorder(tmp_path / "sib")
    rc, exc = H.drive_run(
        run_py, ["--tenant", H.TID, "--episode", manifest.parent.name, "--world", "b"], sib)
    assert exc is None, f"run.main refused the sibling: {H.exit_text(exc)}"
    assert rc == 0
    sibling_tenant = sib.lifecycle_calls[0]["tenant"]
    assert sibling_tenant.tenant == expected
    assert sibling_tenant.correlation is None, "a --resume sibling dispatches no turn-0 lead"


#: The cells each entry point takes (F8 closed by correction 3; M7). `tenant.py setup` has no
ALL_CELLS = ("bad-id", "no-row", "knowledge-link", "mounted-tree")
CELLS_OF = {
    "run.main": ALL_CELLS,
    "branch.cli.main": ALL_CELLS,
    "tenant.setup": ("bad-id", "knowledge-link", "mounted-tree"),
    "tenant.check": ALL_CELLS,
    "tenant.scaffold": ("bad-id",),
    "policy_cli.main": ALL_CELLS,
    "validate_scaffold.main": ALL_CELLS,
}
PROCESS_ENTRIES = {"tenant.setup", "tenant.check", "tenant.scaffold", "validate_scaffold.main"}


@dataclass
class _Cell:
    """One refusal cell, built on disk: the data root, the id the entry is asked for, the
    extra environment, and the owner's own refusal text on exactly this tree."""

    root: Path
    tenant_id: str
    expected: str
    env: dict[str, str] = field(default_factory=dict)
    checkout: Path | None = None
    defender_dir: Path | None = None
    never_created: bool = False
    source: Path | None = None


def _build_cell(entry: str, cell: str, base: Path, monkeypatch) -> _Cell:  # noqa: C901, PLR0911 — one arm per cell
    base.mkdir(parents=True)
    root = base / "data"
    launcher = entry == "branch.cli.main"
    if cell == "bad-id":
        H.adopted(root)
        if launcher:
            # #1105 PR 2: the launcher's id comes from the request (`--tenant`), refused by
            # the one grammar, TenantId, before the source is read.
            src = _source_under(root)
            return _Cell(root, "A", str(H.refusal(_tenant, _tenant.TenantId, "A")), source=src)
        return _Cell(root, "A", _owner(root, "A"))
    if cell == "no-row":
        H.place_knowledge(root)
        cell_ = _Cell(root, H.TID, _owner(root))
        if launcher:
            cell_.source = _source_under(root)
        return cell_
    if cell == "knowledge-link":
        _knowledge_link(base, root)
        cell_ = _Cell(root, H.TID, _owner(root))
        if launcher:
            cell_.source = _source_under(root)
        return cell_
    assert cell == "mounted-tree", cell
    if entry == "policy_cli.main":
        # F9: at entry-point level through policy_cli's own --defender-dir — a tree that
        # contains the data root, so the settings half sits inside what a box mounts.
        tree = base / "tree"
        root = tree / "data"
        H.adopted(root)
        return _Cell(root, H.TID, _owner(root, defender_dir=tree), defender_dir=tree)
    if entry in PROCESS_ENTRIES:
        checkout = H.tmp_checkout(base / "checkout")
        root = checkout / "defender" / "tenant-data"
        H.adopted(root)
        return _Cell(root, H.TID, _owner_in_checkout(checkout, root), checkout=checkout)
    root = _never_created_root()
    cell_ = _Cell(root, H.TID, _owner(root), never_created=True)
    if launcher:
        cell_.source = root / H.TID / "runs" / T.SOURCE_RUN_ID
    return cell_


def _drive(entry: str, cell: _Cell, base: Path, monkeypatch, capsys) -> tuple[bool, str, bool]:  # noqa: C901, PLR0911, PLR0912 — one arm per entry point
    """Drive `entry` over `cell`: `(refused, what it said, did it spend/start anything)`."""
    monkeypatch.setenv(H.DATA_ROOT_ENV, str(cell.root))
    for key, value in cell.env.items():
        monkeypatch.setenv(key, value)
    capsys.readouterr()
    if entry == "run.main":
        rec = H.RunRecorder(base / "run")
        rc, exc = H.drive_run(run_py, [str(H.plant_alert(base / "in")), "--tenant", cell.tenant_id],
                              rec)
        said = H.exit_text(exc) if exc is not None else ""
        return exc is not None or rc != 0, said + capsys.readouterr().err, rec.spent
    if entry == "branch.cli.main":
        spawn = T.FakeSpawn()
        got = _launch(cell.source, spawn, tenant_id=cell.tenant_id)
        text = H.exit_text(got) if isinstance(got, BaseException) else ""
        return isinstance(got, BaseException) or got != 0, text, bool(spawn.launches)
    if entry == "policy_cli.main":
        argv = ["show", "gather", "--run-dir", str(base / "rd"), "--tenant", cell.tenant_id]
        if cell.defender_dir is not None:
            argv += ["--defender-dir", str(cell.defender_dir)]
        try:
            rc = policy_cli.main(argv)
        except SystemExit as refused:
            return True, H.exit_text(refused) + capsys.readouterr().err, False
        cap = capsys.readouterr()
        return rc != 0, cap.err + cap.out, True
    # The process entries.
    module, args = {
        "tenant.setup": (tenant_py, ["setup", cell.tenant_id]),
        "tenant.check": (tenant_py, ["check", cell.tenant_id]),
        "tenant.scaffold": (tenant_py, ["scaffold", cell.tenant_id, str(base / "scaffold-target")]),
        "validate_scaffold.main": (validate_scaffold, ["cmdb", "--tenant", cell.tenant_id]),
    }[entry]
    if entry == "tenant.scaffold":
        (base / "scaffold-target").mkdir()
    script = (_copy_script(cell.checkout, module) if cell.checkout is not None
              else H.script_of(module))
    proc = H.run_script(script, *args, root=cell.root, cwd=cell.checkout,
                        unset=("DEFENDER_DIR",), **cell.env)
    text = H.output(proc)
    if entry == "validate_scaffold.main":
        # M7 (human): advisory — the refusal is its WARN, and that tenant's config check is
        # skipped; its exit status follows the other checks and is not the observable.
        skipped = "config.env carries no inline secrets" not in text and "config.env:" not in text
        return skipped and "Traceback" not in text, text, not skipped
    return proc.returncode != 0 and "Traceback" not in text, text, False


def _cell_problems(where: str, entry: str, cell_name: str, cell: _Cell, base: Path,  # noqa: PLR0913 — one cell's whole observation
                   before: dict, *, refused: bool, text: str, spent: bool) -> list[str]:
    """What one driven cell got wrong: not refused, not verbatim, spent, or wrote."""
    problems = []
    if not refused:
        problems.append(f"{where}: NOT refused (said {text[-300:]!r})")
    if entry == "branch.cli.main" and cell_name == "mounted-tree":
        if str(cell.root) not in text or S1077.TENANT_RECORD_NAME in text:
            problems.append(f"{where}: not refused naming the data root before the record "
                            f"was read: {text[-400:]!r}")
    elif cell.expected not in text:
        problems.append(f"{where}: accept_tenant's refusal not passed through verbatim — "
                        f"expected {cell.expected!r} in {text[-400:]!r}")
    if spent:
        problems.append(f"{where}: spent or started something before refusing")
    if cell.never_created:
        if cell.root.parent.exists():
            problems.append(f"{where}: created {cell.root.parent} in the checkout")
    elif diff := H.census_diff(before, H.tree_census(cell.root)):
        problems.append(f"{where}: wrote into the data root {diff}")
    if entry == "tenant.scaffold" and any((base / "scaffold-target").iterdir()):
        problems.append(f"{where}: wrote into the scaffold target")
    return problems


# rejected: a second acceptance path (request_tenant's row-only check, resolve_tenant's
# folder+grants check — C7, K7).
@pytest.mark.parametrize("entry", list(CELLS_OF))
def test_1120_every_tenant_taking_entry_point_refuses_what_accept_tenant_refuses(
        entry: str, tmp_path: Path, monkeypatch, capsys) -> None:
    problems: list[str] = []
    for cell_name in CELLS_OF[entry]:
        base = tmp_path / cell_name
        cell = _build_cell(entry, cell_name, base, monkeypatch)
        before = H.tree_census(cell.root)
        refused, text, spent = _drive(entry, cell, base, monkeypatch, capsys)
        monkeypatch.delenv(H.LEARNING_STATE_ENV, raising=False)
        problems += _cell_problems(f"{entry} × {cell_name}", entry, cell_name, cell, base,
                                   before, refused=refused, text=text, spent=spent)
    assert not problems, "\n".join(problems)


# rejected: a tenants-root or data-root argument across the process boundary.
def test_1120_a_child_gets_the_tenant_id_inherits_the_data_root_and_re_accepts(
        data_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    H.adopted(data_root)
    episode = T.episode(tmp_path, root=tmp_path / "episodes")
    argv = branch_cli.sibling_argv(episode.name, "a", tenant_id=_tenant.TenantId(H.TID))
    at = argv.index("--tenant")
    assert argv[at + 1] == H.TID, argv
    assert str(data_root) not in " ".join(argv), argv
    assert "--tenants-root" not in argv, argv

    assert "tenants_root" not in inspect.signature(branch_cli.start_family).parameters
    spawn = T.FakeSpawn()
    # #1133 (merged into this branch, PR #1157): start_family takes the held Episode.
    with Episode.open(episode) as held:
        branch_cli.start_family(held, [T.world_id(episode, "a")], spawn=spawn, tenant_id=_tenant.TenantId(H.TID))
    assert len(spawn.launches) == 1, spawn.launches
    child_argv, child_env = spawn.launches[0]["argv"], spawn.launches[0]["env"]
    assert child_env.get(H.DATA_ROOT_ENV) == str(data_root), (
        "the sibling's environment does not carry the parent's DEFENDER_DATA_ROOT unchanged")
    assert "--tenants-root" not in child_argv
    assert str(data_root) not in " ".join(child_argv)

    # The child re-accepts: its tenant lost a required settings file since the launch.
    src = _source_under(data_root)
    # #1187 (Layout A): the episode is `<root>/<T>/episodes/<uuid>`, as RUNS leaves it. (The
    # retired variable, set below to that same folder, is read by nothing after #1187, O9.)
    manifest = P.family_for(src)
    (H.settings_dir(data_root) / "verb-grants.yaml").unlink()
    expected = _owner(data_root)
    assert "verb-grants.yaml" in expected, expected
    monkeypatch.setenv(EPISODES_BASE_ENV, str(manifest.parent.parent))
    rec = H.RunRecorder(tmp_path / "sib")
    rc, exc = H.drive_run(
        run_py, ["--tenant", H.TID, "--episode", manifest.parent.name, "--world", "b"], rec)
    assert exc is not None, f"the child accepted a tenant accept_tenant refuses (rc {rc})"
    assert expected in H.exit_text(exc), H.exit_text(exc)
    assert not rec.spent


def test_1120_every_pre_acceptance_path_refuses_a_relative_or_defender_tree_data_root_before_reading(
        tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)  # a relative root, if anything followed it, lands in tmp
    tid = _tenant.TenantId(H.TID)
    relative = Path("relative-spec1120") / "data"
    inside = _never_created_root()
    for root in (relative, inside):
        owners = {
            "create_tenant": lambda r=root: _tenant.create_tenant(r, tid),
            "require_tenant": lambda r=root: _tenant.require_tenant(r, tid),
            "accept_tenant": lambda r=root: H.accept(_tenant, r, H.TID),
        }
        for name, call in owners.items():
            text = str(H.refusal(_tenant, call))
            assert str(root) in text, f"{name} refused {root} without naming it: {text!r}"
            assert H.ROW_NAME not in text, f"{name} read the row before the guard: {text!r}"
            assert S1077.TENANT_RECORD_NAME not in text, (
                f"{name} read the runs-base record before the guard: {text!r}")
    assert not relative.exists()
    _assert_never_created(inside)

    # The launcher, with the root in the environment.
    for root in (relative, inside):
        monkeypatch.setenv(H.DATA_ROOT_ENV, str(root))
        source = (root if root.is_absolute() else tmp_path / root) / H.TID / "runs" / "r1"
        got = _launch(source, T.FakeSpawn())
        text = H.exit_text(got) if isinstance(got, BaseException) else f"exit {got}"
        assert isinstance(got, BaseException), f"the launcher accepted {root}: {text}"
        assert str(root) in text, f"the launcher's refusal does not name {root}: {text!r}"
        assert S1077.TENANT_RECORD_NAME not in text, (
            f"the launcher did not refuse {root} before reading the source's record: {text!r}")
    _assert_never_created(inside)

    proc = H.run_script(H.script_of(tenant_py), "setup", H.TID, root=relative, cwd=tmp_path)
    H.assert_refused(proc, str(relative))
    assert not (tmp_path / relative).exists()
    checkout = H.tmp_checkout(tmp_path / "checkout")
    placed_root = checkout / "defender" / "tenant-data"
    H.place_knowledge(placed_root)
    before = H.tree_census(placed_root)
    proc = H.run_script(_copy_script(checkout, tenant_py), "setup", H.TID, root=placed_root,
                        cwd=checkout)
    H.assert_refused(proc, str(placed_root))
    assert H.census_diff(before, H.tree_census(placed_root)) == []

    # Positive control: another checkout's defender/ is not the running one.
    other = tmp_path / "other-checkout"
    (other / ".git").mkdir(parents=True)
    other_root = other / "defender" / "data"
    H.adopted(other_root)
    assert H.accept(_tenant, other_root, H.TID).dir == other_root / H.TID


# ======================================================================================
# D1 — runs_base_for takes the accepted Tenant.
# ======================================================================================

def test_1120_runs_base_for_a_tenant_is_its_runs_folder(
        data_root: Path, monkeypatch) -> None:
    """runs_base_for, given a Tenant from accept_tenant, is exactly <root>/acme/runs (composed
    here by hand) — the Tenant's own runs folder — and it resolves no data root: the call
    runs with DEFENDER_DATA_ROOT unset. Carries pass-A d2_runs_base_for over Tenant
    (x1078_d2_runs_base_for's uncarried equality)."""
    H.adopted(data_root)
    tenant = H.accept(_tenant, data_root, H.TID)
    monkeypatch.delenv(H.DATA_ROOT_ENV)
    got = _tenant.runs_base_for(tenant)
    assert Path(got) == data_root / H.TID / "runs" == tenant.runs


def test_1120_tenant_sessions_is_the_session_stores_folder_for_a_fresh_run(
        data_root: Path, tmp_path: Path) -> None:
    """For a fresh run, Tenant.sessions is the session store's folder: run.py materializes
    the run (the real builder) under the accepted tenant's runs, and the session store the
    driver opens beside that runs base lives in <root>/acme/sessions (composed here by hand),
    which is what accept_tenant's Tenant.sessions names. SessionPaths' derivation is left
    alone (N10)."""
    H.adopted(data_root)
    rec = H.RunRecorder(tmp_path / "unused")
    seams = rec.seams()
    seams.pop("materialize")
    rc = run_py.main([str(H.plant_alert(tmp_path / "in")), "--tenant", H.TID], **seams)
    assert rc == 0
    assert len(rec.lifecycle_calls) == 1
    run_dir = Path(rec.lifecycle_calls[0]["run_dir"])
    from defender.run_repository import SessionPaths

    # #1105 fork S(b): the layout owner's `SessionPaths` names the store, not a runs base.
    store = session_store.store_path_for("spec1120-case", sessions=SessionPaths(run_dir.parent))
    expected = data_root / H.TID / "sessions"
    assert store.parent == expected
    assert H.accept(_tenant, data_root, H.TID).sessions == expected


# ======================================================================================
# R7 — every unmoved reader of RunTenant takes the accepted Tenant through it.
# ======================================================================================

def test_1120_every_run_tenant_reader_takes_the_accepted_tenant(
        data_root: Path, tmp_path: Path, monkeypatch) -> None:
    """The readers of RunTenant that piece 1 does not move — the branch launcher, the driver
    (run_investigation) and its opening prompt (driver._prompts) — read what they need through
    RunTenant, whose tenant member is now the accepted Tenant (M5's owner table): its settings
    is the Tenant's settings under the data root, its tenant_id the Tenant's id, its table
    pointer names that id. Each is handed the RunTenant run.py itself resolved and must agree
    with the Tenant: the launcher, over a source run under the accepted tenant, runs a whole
    episode and starts every sibling with that Tenant's id and the parent's data root; the
    RunTenant's table pointer
    names the tenant's id (the opening prompt no longer resolves a lead-zero fetch from the
    Tenant's settings, #1222); run_investigation's reads are the same RunTenant members (driven end to
    end only by the replay suite)."""
    H.adopted(data_root)
    tenant = H.accept(_tenant, data_root, H.TID)
    rec = H.RunRecorder(tmp_path / "run")
    rc, exc = H.drive_run(run_py, [str(H.plant_alert(tmp_path / "in")), "--tenant", H.TID], rec)
    assert exc is None, H.exit_text(exc)
    assert rc == 0
    run_tenant = rec.lifecycle_calls[0]["tenant"]
    assert run_tenant.tenant == tenant

    # driver._prompts — the opening prompt no longer reads the tenant's settings for a lead-zero
    # fetch (the ancestor fetch is gone, #1222); its table pointer still names the tenant's id.
    assert run_tenant_mod.table_pointer(tenant.id) == run_tenant.table_pointer

    # branch.cli.main — one whole episode through the real launcher (every seam it is not
    # about faked): it resolves the source run's tenant once and reads it through RunTenant for
    # pre-flight's reader and its siblings, each of which is started with the accepted id. The
    # episode runs over `_spec1224`'s estate tenant (its gather grant admits the source's
    # calls, so pre-flight accepts the family), placed under a data root of its own.
    branch_root = tmp_path / "branch-data-root"
    branch_root.mkdir()
    monkeypatch.setenv(H.DATA_ROOT_ENV, str(branch_root))
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")
    monkeypatch.setenv(EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    est = S1224.estate(tmp_path)
    branch_tenant = est.place()
    response = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon",
                          "host": "web-1", "ts": "2026-07-28T15:00:00Z"}]}
    calls = [S1224.Call("idp", "query", S1224.query_params("user:alice"), response),
             S1224.Call("edr", "query", S1224.query_params("host:db-1"), response)]
    run = S1224.launch(tmp_path, est, calls=calls,
                       oracle=S1224.oracle(then=S1224.submit(response, S1224.EMPTY_CLAIM)),
                       verifier=S1224.passing_verifier())
    assert run.message == "", f"the launcher refused a source whose tenant accept_tenant " \
                              f"accepts: {run.message}"
    assert run.spawn.launches, "the launcher started no sibling"
    for launch in run.spawn.launches:
        argv = launch["argv"]
        assert argv[argv.index("--tenant") + 1] == branch_tenant.id, argv
        assert launch["env"].get(H.DATA_ROOT_ENV) == str(branch_root), launch["env"]


@pytest.mark.parametrize("entry", list(CELLS_OF))
@pytest.mark.parametrize("legacy", ["acme", "playground"])
def test_legacy_names_are_refused_at_every_tenant_taking_entrypoint(
        entry, legacy, tmp_path, monkeypatch, capsys):
    base = tmp_path / "legacy"
    cell = _build_cell(entry, "bad-id", base, monkeypatch)
    cell.tenant_id = legacy
    cell.expected = str(H.refusal(_tenant, _tenant.TenantId, legacy))
    before = H.tree_census(cell.root)
    refused, text, spent = _drive(entry, cell, base, monkeypatch, capsys)
    monkeypatch.delenv(H.LEARNING_STATE_ENV, raising=False)
    problems = _cell_problems(f"{entry} × {legacy}", entry, "bad-id", cell, base, before,
                              refused=refused, text=text, spent=spent)
    assert problems == [], "\n".join(problems)
