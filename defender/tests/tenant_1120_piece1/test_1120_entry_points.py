"""#1120 piece 1 — D1/O3: the entry points take a tenant through `accept_tenant`, once.

Every process entry point that takes a tenant resolves the data root once
(`resolve_data_root`), builds its `Tenant` through `accept_tenant`, and hands that value down;
nothing below re-resolves the root or a tenant path. `RunTenant` is the accepted `Tenant` plus
its grants and lead-zero dispatch. A child process gets `--tenant <id>`, inherits
`DEFENDER_DATA_ROOT` and re-accepts. The removed surface (`default_tenants_root`,
`entry_tenant*`, `TenantDir`, `tenant_dir`, the public `TenantPaths`, `request_tenant`,
`--tenants-root`) is gone.

Entry points are driven through their own injection seams (`run.main`'s recorded preflight,
materialize and lifecycle seams, the launcher's spawn and preflight seams,
`generate_case.investigate`'s runner seam), in-process where they take an argv, and as processes
where they read `sys.argv`. "Refused with accept_tenant's message verbatim" is observed as: the
entry's refusal text CONTAINS the message `accept_tenant` itself raises on the same tree —
obtained by calling the owner directly, so which check fired is an observation, not a guess at
wording. Every tree is real, on disk, under the test's own tmp paths; the one tree that must sit
inside "the running checkout's defender/" is either a path there that is never created (an
in-process refusal before any read) or a tmp COPY of the checkout whose own scripts run it
(`_spec1120.tmp_checkout`). See `_spec1120.py` for the coined names.
"""
from __future__ import annotations

import inspect
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender import _tenant, _tenants
from defender import run as run_py
from defender.evals import held_out
from defender.evals.oracle_golden import generate_case
from defender.learning.branch import cli as branch_cli
from defender.learning.branch import seams as branch_seams
from defender.runtime import lead_zero
from defender.runtime import run_tenant as run_tenant_mod
from defender.runtime import session_store
from defender.runtime.driver import _prompts as driver_prompts
from defender.scripts import policy_cli
from defender.scripts import tenant as tenant_py
from defender.scripts.adapters import ticket_adapter
from defender.skills.connect import validate_scaffold
from defender.tests import _dispositions995 as D995
from defender.tests import _judge_921 as J
from defender.tests import _spec1077 as S1077
from defender.tests import _triplet_947 as T
from defender.tests.tenant_1078_pass_a import _spec1078 as P
from defender.tests.tenant_1120_piece1 import _spec1120 as H

#: The launcher's episodes knob (J44; the refusal stays until D12).
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"

#: held_out's report header — printed only once it has read and scored a runs base.
HELD_OUT_REPORT = "# Held-out eval"


# ======================================================================================
# Same-file helpers.
# ======================================================================================

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
        "from defender import _tenant\n"
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


def _source_under(root: Path, record_tenant: str, *, runs_tenant: str = H.TID) -> Path:
    """A finished, branchable source run at `<root>/<runs_tenant>/runs/<id>` whose runs-base
    record names `record_tenant` (written raw — an off-grammar id is a real corrupt record)."""
    base = H.tenant_folder(root, runs_tenant) / "runs"
    base.mkdir(parents=True, exist_ok=True)
    S1077.plant_tenant_record(base, tenant_id=record_tenant)
    return P.source_run(base)


class _RunnerRecorder:
    """`generate_case.investigate`'s runner seam: records the child command, runs nothing, and
    answers a failed child so `investigate` stops there."""

    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, argv: list[str], **kw: Any) -> subprocess.CompletedProcess:
        self.calls.append((list(argv), dict(kw)))
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="recorded, not run")


class _UntouchedVerbs:
    """A verb registry lead zero may hold but must never reach: any use is a loud failure."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"lead zero reached the verb registry ({name}) — no fetch expected")


def _launch(source: Path, spawn: Any, **seams: Any) -> BaseException | int:
    """The REAL launcher over one source, the role preflight neutralised (a refusal is never the
    host's credentials). Returns the exit status, or the refusal it raised."""
    seams.setdefault("preflight", T.no_preflight)
    try:
        return branch_cli.main(
            [str(source), str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", P.CONTINUATION],
            spawn=spawn, **seams)
    except SystemExit as refused:
        return refused


# ======================================================================================
# D1 — RunTenant is the accepted Tenant plus its grants and dispatch.
# ======================================================================================

def test_1120_run_tenant_is_the_accepted_tenant_plus_its_grants_and_dispatch(
        data_root: Path, tmp_path: Path) -> None:
    """The RunTenant that run.py hands the lifecycle has three parts: its tenant member, a
    Tenant equal to what accept_tenant returns for the request; its grants, the RunGrants
    loaded from that tenant's settings/verb-grants.yaml under the data root (for the fixture,
    a gather grant equal to GATHER_CENSUS); and its correlation member, a CorrelationDispatch
    naming the fixture's elastic.correlate-alerts-by-entity for a fresh run and None for a
    --resume sibling (which dispatches no turn-0 lead). Its settings equal its tenant's
    settings, and its tenant_id is a delegating property equal to the tenant's id (F17)."""
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

    # The --resume sibling: the same accepted Tenant, and no turn-0 dispatch.
    src = _source_under(data_root, H.TID)
    manifest = P.family_for(src, tmp_path / "episodes" / T.EPISODE_ID)
    sib = H.RunRecorder(tmp_path / "sib")
    rc, exc = H.drive_run(run_py, P.resume_argv(manifest, "b", "--tenant", H.TID), sib)
    assert exc is None, f"run.main refused the sibling: {H.exit_text(exc)}"
    assert rc == 0
    sibling_tenant = sib.lifecycle_calls[0]["tenant"]
    assert sibling_tenant.tenant == expected
    assert sibling_tenant.correlation is None, "a --resume sibling dispatches no turn-0 lead"


# ======================================================================================
# O3 — one acceptance frame: every tenant-taking entry refuses what accept_tenant refuses.
# ======================================================================================

#: The cells each entry point takes (F8 closed by correction 3; M7). `tenant.py setup` has no
#: "no row" cell (writing the row is its success path); `tenant.py scaffold` takes the bad-id
#: cell only and never resolves the data root (N10).
ALL_CELLS = ("bad-id", "no-row", "knowledge-link", "mounted-tree", "learning-state-overlap")
CELLS_OF = {
    "run.main": ALL_CELLS,
    "branch.cli.main": ALL_CELLS,
    "held_out.main": ALL_CELLS,
    "generate_case.main": ALL_CELLS,
    "tenant.setup": ("bad-id", "knowledge-link", "mounted-tree", "learning-state-overlap"),
    "tenant.check": ALL_CELLS,
    "ticket_adapter.main": ALL_CELLS,
    "tenant.scaffold": ("bad-id",),
    "policy_cli.main": ALL_CELLS,
    "validate_scaffold.main": ALL_CELLS,
}
PROCESS_ENTRIES = {"tenant.setup", "tenant.check", "tenant.scaffold", "ticket_adapter.main",
                   "validate_scaffold.main"}


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
            # The launcher takes no --tenant: its id comes from the source's runs-base
            # record, so the bad id is an off-grammar id planted there.
            src = _source_under(root, "A")
            return _Cell(root, "A", str(H.refusal(_tenant, _tenant.TenantId, "A")), source=src)
        return _Cell(root, "A", _owner(root, "A"))
    if cell == "no-row":
        H.place_knowledge(root)
        cell_ = _Cell(root, H.TID, _owner(root))
        if launcher:
            cell_.source = _source_under(root, H.TID)
        return cell_
    if cell == "knowledge-link":
        _knowledge_link(base, root)
        cell_ = _Cell(root, H.TID, _owner(root))
        if launcher:
            cell_.source = _source_under(root, H.TID)
        return cell_
    if cell == "learning-state-overlap":
        H.adopted(root)
        env = {H.LEARNING_STATE_ENV: str(root)}
        monkeypatch.setenv(H.DATA_ROOT_ENV, str(root))
        monkeypatch.setenv(H.LEARNING_STATE_ENV, str(root))
        expected = str(H.refusal(_tenant, _tenant.resolve_data_root))
        monkeypatch.delenv(H.LEARNING_STATE_ENV)
        cell_ = _Cell(root, H.TID, expected, env=env)
        if launcher:
            cell_.source = _source_under(root, H.TID)
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
        got = _launch(cell.source, spawn)
        text = H.exit_text(got) if isinstance(got, BaseException) else ""
        return isinstance(got, BaseException) or got != 0, text, bool(spawn.launches)
    if entry == "held_out.main":
        rc = held_out.main(["--tenant", cell.tenant_id])
        cap = capsys.readouterr()
        return rc != 0, cap.err + cap.out, HELD_OUT_REPORT in cap.out
    if entry == "generate_case.main":
        rc = generate_case.main(["--scenario", "s", "--tenant", cell.tenant_id, "--case-id", "c1",
                                 "--split", "dev", "--activity-family", "f"])
        cap = capsys.readouterr()
        # generate_case refuses every call (its assembler retired, #922): refused-for-the-tenant
        # is observed by the tenant refusal in its output, not by the status alone.
        return rc != 0 and cell.expected in cap.err, cap.err + cap.out, False
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
        "ticket_adapter.main": (ticket_adapter, ["--tenant", cell.tenant_id, "health-check"]),
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
    """Each entry point that takes a tenant after piece 1 — run.py, the branch launcher,
    held_out, generate_case, tenant.py setup and check, ticket_adapter, policy_cli,
    validate_scaffold — and tenant.py scaffold for its bad-id cell, is driven over each cell:
    a bad id ('A'); a data root with no row for the id; a knowledge folder that is a symlink;
    settings inside a mounted tree (through policy_cli's own defender-dir option, and for the
    others a data root inside the running checkout's defender/ tree, which is O11a); and a
    DEFENDER_LEARNING_STATE_DIR overlapping the data root, a cell on every row that resolves
    the data root (M7). Each is refused with accept_tenant's message passed through verbatim
    (the overlap cell with resolve_data_root's), exits non-zero, and spends nothing: no
    preflight, no run dir, no child, nothing written. Two entries take their cells
    differently. tenant.py setup has no no-row cell, because writing the row is its success
    path, and its knowledge-link cell is any setup over a symlinked knowledge folder. The
    branch launcher takes no tenant option: its id comes from the source run's runs-base
    record, so its bad-id cell is an off-grammar id planted in the source's record (refused
    by the one grammar, TenantId) and its no-row cell is a record naming a tenant with no row;
    its mounted cell has no id before that record, so it is the pre-acceptance guard's refusal
    naming the data root, before the record is read. M7 (human, keep as they are):
    validate_scaffold is advisory — it prints accept_tenant's refusal verbatim as its WARN,
    skips that tenant's config check and reads nothing of it; policy_cli takes a tenant for
    gather only."""
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


def test_1120_held_out_and_generate_case_refuse_a_tenant_with_a_row_but_no_knowledge(
        data_root: Path, tmp_path: Path, monkeypatch, capsys) -> None:
    """A tenant whose row exists but whose knowledge folder does not is refused by held_out
    with a tenant option and by generate_case with a tenant option, before any runs base is
    read or any child is spawned: exactly as run.py refuses it, all three passing
    accept_tenant's refusal (naming <root>/acme/knowledge) through verbatim. Today both
    accept it (K7). The positive control: the same tenant with its knowledge placed is
    accepted by generate_case's investigation step, which then hands its child the tenant."""
    H.plant_row(data_root)
    runs = H.tenant_folder(data_root) / "runs" / "r1"
    runs.mkdir(parents=True)
    expected = _owner(data_root)
    assert str(H.knowledge_dir(data_root)) in expected, expected

    rc = held_out.main(["--tenant", H.TID])
    cap = capsys.readouterr()
    assert rc != 0
    assert expected in cap.err, f"held_out did not refuse verbatim: {cap.err!r}"
    assert HELD_OUT_REPORT not in cap.out, f"held_out scored the runs base: {cap.out!r}"

    runner = _RunnerRecorder()
    with pytest.raises(_tenant.TenantRefused) as refused:
        generate_case.investigate(H.plant_alert(tmp_path / "in"), "r2", tenant_id=H.TID,
                                  run=runner)
    assert expected in str(refused.value)
    assert runner.calls == [], "generate_case spawned its child before refusing the tenant"
    rc = generate_case.main(["--scenario", "s", "--tenant", H.TID, "--case-id", "c1",
                             "--split", "dev", "--activity-family", "f"])
    assert rc != 0
    assert expected in capsys.readouterr().err, "generate_case did not refuse verbatim"

    rec = H.RunRecorder(tmp_path / "run")
    rc_run, exc = H.drive_run(run_py, [str(H.plant_alert(tmp_path / "in2")), "--tenant", H.TID],
                              rec)
    assert exc is not None, f"run.main accepted a tenant with no knowledge (rc {rc_run})"
    assert expected in H.exit_text(exc), H.exit_text(exc)
    assert not rec.spent

    # Positive control: knowledge placed, the same investigation step reaches its child.
    H.place_knowledge(data_root)
    with pytest.raises(RuntimeError):
        generate_case.investigate(H.plant_alert(tmp_path / "in3"), "r3", tenant_id=H.TID,
                                  run=runner)
    assert len(runner.calls) == 1, "an accepted tenant never reached generate_case's child"


# ======================================================================================
# D1 — the removed surface.
# ======================================================================================

REMOVED_FROM_TENANTS = ("default_tenants_root", "entry_tenant", "entry_tenant_args",
                        "TenantDir", "tenant_dir")
REMOVED_FROM_TENANT = ("TenantPaths", "request_tenant")


def test_1120_the_tenants_root_surface_is_gone_and_template_dir_stays(
        tmp_path: Path, capsys) -> None:
    """Importing default_tenants_root, entry_tenant, entry_tenant_args, TenantDir or
    tenant_dir from defender._tenants, or the public TenantPaths or request_tenant from
    defender._tenant, fails. run.py and the branch launcher reject --tenants-root as an
    unknown argument; add_tenant_arguments, if it survives, adds no --tenants-root; and
    sibling_argv neither takes a tenants root nor puts --tenants-root on a child's command
    line. The positive controls: template_dir of the repo root is
    <repo>/knowledge/tenant-template, and --tenant still parses on run.py and the launcher."""
    still_there = [f"defender._tenants.{n}" for n in REMOVED_FROM_TENANTS if hasattr(_tenants, n)]
    still_there += [f"defender._tenant.{n}" for n in REMOVED_FROM_TENANT if hasattr(_tenant, n)]
    assert not still_there, f"removed names still importable: {still_there}"

    alert = H.plant_alert(tmp_path / "in")
    with pytest.raises(SystemExit) as run_exit:
        run_py.parse_args([str(alert), "--tenant", H.TID, "--tenants-root", str(tmp_path)])
    assert run_exit.value.code == 2
    assert "--tenants-root" in capsys.readouterr().err
    with pytest.raises(SystemExit) as launch_exit:
        branch_cli.parse_branch_args([str(tmp_path), "1", "--continuation-prompt", "x",
                                      "--tenants-root", str(tmp_path)])
    assert launch_exit.value.code == 2
    assert "--tenants-root" in capsys.readouterr().err

    adder = getattr(_tenants, "add_tenant_arguments", None)
    if adder is not None:
        import argparse
        parser = argparse.ArgumentParser()
        adder(parser, reads="x")
        assert "--tenants-root" not in parser._option_string_actions  # noqa: SLF001

    assert "tenants_root" not in inspect.signature(branch_cli.sibling_argv).parameters
    argv = branch_cli.sibling_argv(tmp_path / "ep", "a", tenant_id=_tenant.TenantId(H.TID))
    assert "--tenants-root" not in argv, argv

    # Positive controls.
    assert _tenants.template_dir(H.REPO_ROOT) == H.REPO_ROOT / "knowledge" / "tenant-template"
    assert run_py.parse_args([str(alert), "--tenant", H.TID]).tenant == H.TID
    assert branch_cli.parse_branch_args(
        [str(tmp_path), "1", "--continuation-prompt", "x"]).source_run_dir is not None


# ======================================================================================
# D1 — process boundaries: a child gets the id, inherits the root, and re-accepts.
# ======================================================================================

# rejected: a tenants-root or data-root argument across the process boundary.
def test_1120_a_child_gets_the_tenant_id_inherits_the_data_root_and_re_accepts(
        data_root: Path, tmp_path: Path) -> None:
    """The branch launcher's sibling_argv for tenant acme contains --tenant acme and no root
    argument, and the launcher starts its siblings (start_family, which takes no tenants root)
    with an environment carrying the parent's DEFENDER_DATA_ROOT unchanged. generate_case's
    child command carries --tenant acme, no root argument, and inherits the environment. A
    child run.py --resume … --tenant acme whose tenant has since lost
    knowledge/settings/verb-grants.yaml refuses at its own acceptance, with accept_tenant's
    refusal naming that file, before it spends anything."""
    H.adopted(data_root)
    episode = tmp_path / "episodes" / "ep-1"
    episode.mkdir(parents=True)
    argv = branch_cli.sibling_argv(episode, "a", tenant_id=_tenant.TenantId(H.TID))
    at = argv.index("--tenant")
    assert argv[at + 1] == H.TID, argv
    assert str(data_root) not in " ".join(argv), argv
    assert "--tenants-root" not in argv, argv

    assert "tenants_root" not in inspect.signature(branch_cli.start_family).parameters
    spawn = T.FakeSpawn()
    branch_cli.start_family(episode, ["a"], spawn=spawn, tenant_id=_tenant.TenantId(H.TID))
    assert len(spawn.launches) == 1, spawn.launches
    child_argv, child_env = spawn.launches[0]["argv"], spawn.launches[0]["env"]
    assert child_env.get(H.DATA_ROOT_ENV) == str(data_root), (
        "the sibling's environment does not carry the parent's DEFENDER_DATA_ROOT unchanged")
    assert "--tenants-root" not in child_argv
    assert str(data_root) not in " ".join(child_argv)

    runner = _RunnerRecorder()
    with pytest.raises(RuntimeError):
        generate_case.investigate(H.plant_alert(tmp_path / "in"), "r1", tenant_id=H.TID,
                                  run=runner)
    (cmd, kw), = runner.calls
    at = cmd.index("--tenant")
    assert cmd[at + 1] == H.TID, cmd
    assert "--tenants-root" not in cmd
    assert str(data_root) not in " ".join(map(str, cmd)), cmd
    assert kw.get("env") is None or kw["env"].get(H.DATA_ROOT_ENV) == str(data_root), kw

    # The child re-accepts: its tenant lost a required settings file since the launch.
    src = _source_under(data_root, H.TID)
    manifest = P.family_for(src, tmp_path / "episodes" / T.EPISODE_ID)
    (H.settings_dir(data_root) / "verb-grants.yaml").unlink()
    expected = _owner(data_root)
    assert "verb-grants.yaml" in expected, expected
    rec = H.RunRecorder(tmp_path / "sib")
    rc, exc = H.drive_run(run_py, P.resume_argv(manifest, "b", "--tenant", H.TID), rec)
    assert exc is not None, f"the child accepted a tenant accept_tenant refuses (rc {rc})"
    assert expected in H.exit_text(exc), H.exit_text(exc)
    assert not rec.spent


# ======================================================================================
# M4 — the pre-acceptance guards (J03 + O11a) on every path.
# ======================================================================================

def test_1120_every_pre_acceptance_path_refuses_a_relative_or_defender_tree_data_root_before_reading(
        tmp_path: Path, monkeypatch, capsys) -> None:
    """A relative DEFENDER_DATA_ROOT, and one inside the running checkout's defender/ tree,
    are refused with TenantRefused naming it before anything under the root is read or
    written, on every pre-acceptance path: create_tenant, require_tenant, tenant_of_run_dir
    (which takes the data root), accept_tenant, held_out with a tenant option, the branch
    launcher (before it reads the source's runs-base record) and tenant.py setup (over an
    operator-placed knowledge folder inside a checkout's defender/, which it leaves
    byte-identical, writing no row). M4 (human): the checks live in the constructor of a
    private layout class, so every path meets the same refusal. O11a is keyed to the RUNNING
    checkout: a data root inside ANOTHER checkout's defender/ is not refused by it — a
    finished tenant there is accepted (the positive control, with an absolute tmp root)."""
    monkeypatch.chdir(tmp_path)  # a relative root, if anything followed it, lands in tmp
    tid = _tenant.TenantId(H.TID)
    relative = Path("relative-spec1120") / "data"
    inside = _never_created_root()
    for root in (relative, inside):
        owners = {
            "create_tenant": lambda r=root: _tenant.create_tenant(r, tid),
            "require_tenant": lambda r=root: _tenant.require_tenant(r, tid),
            "tenant_of_run_dir": lambda r=root: _tenant.tenant_of_run_dir(
                r, r / H.TID / "runs" / "r1"),
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

    # The entries: held_out and the launcher, with the root in the environment.
    for root in (relative, inside):
        monkeypatch.setenv(H.DATA_ROOT_ENV, str(root))
        capsys.readouterr()
        rc = held_out.main(["--tenant", H.TID])
        err = capsys.readouterr().err
        assert rc != 0
        assert str(root) in err, f"held_out over {root}: {err!r}"
        source = (root if root.is_absolute() else tmp_path / root) / H.TID / "runs" / "r1"
        got = _launch(source, T.FakeSpawn())
        text = H.exit_text(got) if isinstance(got, BaseException) else f"exit {got}"
        assert isinstance(got, BaseException), f"the launcher accepted {root}: {text}"
        assert str(root) in text, f"the launcher's refusal does not name {root}: {text!r}"
        assert S1077.TENANT_RECORD_NAME not in text, (
            f"the launcher did not refuse {root} before reading the source's record: {text!r}")
    _assert_never_created(inside)

    # tenant.py setup, as a process: relative, and inside a checkout copy's defender/ with a
    # placed knowledge folder (the guard refuses AFTER the operator's placement, and never
    # removes it — 71's accepted known limit).
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
# J44 — the launcher's episodes-base refusal survives until D12.
# ======================================================================================

# rejected: deleting J44's refusal in piece 1 — D12 removes it (scope constraint).
def test_1120_the_launcher_still_refuses_an_episodes_base_inside_the_data_root(
        data_root: Path, tmp_path: Path, monkeypatch) -> None:
    """Given a Tenant (from accept_tenant), the branch launcher's episodes_root still refuses
    DEFENDER_EPISODES_BASE in each of these cases: equal to the tenant's episodes folder,
    inside the data root, inside the checkout, or containing the data root. It raises
    LauncherRefused naming the base, and it takes the data root from the Tenant. J44 is
    unchanged until D12. The positive control: a base outside both is accepted and returned
    resolved."""
    H.adopted(data_root)
    tenant = H.accept(_tenant, data_root, H.TID)
    bases = {
        "tenant-episodes": H.tenant_folder(data_root) / "episodes",
        "inside-data-root-other": data_root / "elsewhere-episodes",
        "inside-checkout": H.REPO_ROOT / f".spec1120-episodes-{uuid.uuid4().hex}",
        "containing-data-root": data_root.parent,
    }
    for cell, base in bases.items():
        monkeypatch.setenv(EPISODES_BASE_ENV, str(base))
        with pytest.raises(branch_cli.LauncherRefused) as refused:
            branch_cli.episodes_root(tenant=tenant)
        assert str(base) in H.exit_text(refused.value), f"{cell}: {refused.value}"
    outside = tmp_path / "episodes-outside"
    monkeypatch.setenv(EPISODES_BASE_ENV, str(outside))
    assert branch_cli.episodes_root(tenant=tenant) == outside.resolve()


# ======================================================================================
# D1 — tenant_of_run_dir takes the data root (resolved once, at the entry).
# ======================================================================================

def test_1120_tenant_of_run_dir_takes_the_data_root_and_still_refuses_a_run_outside_its_tenant(
        data_root: Path, tmp_path: Path, monkeypatch) -> None:
    """tenant_of_run_dir(root, run_dir) returns acme for a run dir at <root>/acme/runs/r1
    whose runs-base record names acme. It raises TenantRefused for a run dir under a runs
    base elsewhere whose record names acme, and for one whose record names a tenant with no
    row. It calls no resolve_data_root: every call here runs with DEFENDER_DATA_ROOT unset."""
    H.adopted(data_root)
    base = H.tenant_folder(data_root) / "runs"
    base.mkdir(parents=True)
    S1077.plant_tenant_record(base, tenant_id=H.TID)
    (base / "r1").mkdir()
    elsewhere = tmp_path / "elsewhere" / "runs"
    elsewhere.mkdir(parents=True)
    S1077.plant_tenant_record(elsewhere, tenant_id=H.TID)
    (elsewhere / "r1").mkdir()
    ghost = data_root / "ghost" / "runs"
    ghost.mkdir(parents=True)
    S1077.plant_tenant_record(ghost, tenant_id="ghost")
    (ghost / "r1").mkdir()

    monkeypatch.delenv(H.DATA_ROOT_ENV)
    assert _tenant.tenant_of_run_dir(data_root, base / "r1") == H.TID
    H.refusal(_tenant, _tenant.tenant_of_run_dir, data_root, elsewhere / "r1")
    text = str(H.refusal(_tenant, _tenant.tenant_of_run_dir, data_root, ghost / "r1"))
    assert "ghost" in text, text


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
    store = session_store.store_path_for("spec1120-case", runs_base=run_dir.parent)
    expected = data_root / H.TID / "sessions"
    assert store.parent == expected
    assert H.accept(_tenant, data_root, H.TID).sessions == expected


# ======================================================================================
# R7 — every unmoved reader of RunTenant takes the accepted Tenant through it.
# ======================================================================================

def test_1120_every_run_tenant_reader_takes_the_accepted_tenant(
        data_root: Path, tmp_path: Path, monkeypatch) -> None:
    """The readers of RunTenant that piece 1 does not move — the branch launcher, the review's
    adapter seam (branch.seams), the driver (run_investigation) and its opening prompt
    (driver._prompts) — read what they need through RunTenant, whose tenant member is now the
    accepted Tenant (M5's owner table): its settings is the Tenant's settings under the data
    root, its tenant_id the Tenant's id, its table pointer names that id. Each is handed the
    RunTenant run.py itself resolved and must agree with the Tenant: the launcher, over a source
    run under the accepted tenant, runs a whole episode and starts every sibling with that
    Tenant's id and the parent's data root; the adapter seam's
    verb context reads the Tenant's settings; the opening prompt resolves lead zero from the
    Tenant's settings — over the fixture's alert it resolves to an empty lead zero, issuing
    no fetch, where a settings folder it could not read fails — and its table pointer names
    the tenant's id; run_investigation's reads are the same RunTenant members (driven end to
    end only by the replay suite)."""
    H.adopted(data_root)
    tenant = H.accept(_tenant, data_root, H.TID)
    rec = H.RunRecorder(tmp_path / "run")
    rc, exc = H.drive_run(run_py, [str(H.plant_alert(tmp_path / "in")), "--tenant", H.TID], rec)
    assert exc is None, H.exit_text(exc)
    assert rc == 0
    run_tenant = rec.lifecycle_calls[0]["tenant"]
    assert run_tenant.tenant == tenant

    # branch.seams — the review's read side reads the Tenant's settings through RunTenant.
    episode = tmp_path / "episode"
    episode.mkdir()
    adapters = branch_seams.adapter_seam(episode, run_tenant, runs_base=tenant.runs)
    assert Path(adapters.ctx.settings_dir) == H.settings_dir(data_root) == tenant.settings

    # driver._prompts — lead zero resolves from the Tenant's settings; no fault degrades it.
    run_dir = tmp_path / "prompt-run"
    run_dir.mkdir()
    alert = H.plant_alert(tmp_path / "in-prompt")
    prompt, _block, status = driver_prompts._user_prompt(  # noqa: SLF001 — the reader itself
        run_dir, alert, H.DEFENDER, systems=["elastic"], verbs=_UntouchedVerbs(),
        run_id="r-prompt", tenant=run_tenant)
    assert status == lead_zero.STATUS_EMPTY, (
        f"lead zero did not resolve from the Tenant's settings (status {status!r}):\n"
        f"{prompt[:3000]}")
    assert "a run-level fault interrupted resolution" not in prompt
    assert run_tenant_mod.table_pointer(tenant.id) == run_tenant.table_pointer

    # branch.cli.main — one whole episode through the real launcher (every seam it is not
    # about faked): it resolves the source run's tenant once and reads it through RunTenant for
    # its door, read side and siblings, each of which is started with the accepted id.
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))
    monkeypatch.setenv(EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    src = _source_under(data_root, H.TID)
    episode_dir = (tmp_path / "episodes-root").resolve() / T.EPISODE_ID
    spawn = J.FakeSibling(episode_dir)
    result = _launch(
        src, spawn, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        door=T.FakeDoor(), questioner=T.FakeAgent(T.family_doc(), T.world_doc("b"),
                                                  T.world_doc("c")),
        adapters=T.FakeAdapters(), invoke=T.FakeAgent(*["same"] * 24),
        live_tree=T.source_capture())
    assert not isinstance(result, BaseException), (
        f"the launcher refused a source whose tenant accept_tenant accepts: "
        f"{H.exit_text(result)}")
    assert spawn.launches, "the launcher started no sibling"
    for launch in spawn.launches:
        argv = launch["argv"]
        assert argv[argv.index("--tenant") + 1] == tenant.id, argv
        assert launch["env"].get(H.DATA_ROOT_ENV) == str(data_root), launch["env"]
