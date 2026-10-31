"""#1214 Flow 4 / P3: every host entry point proceeds only while the tenant is `active`, read through
`TenantDirectory`; with no directory and no `DEFENDER_DATABASE_DSN` it refuses (fails closed).

Entry points: run start (`run.main`), drain start (`learning.core.cli.main`), each lead-drain claim
(`drains.lead_author_drain`), the connect command (`cli.tenant.main`). Each takes `directory=` (pinned, r9; the last
two are GAP-C-1 additions of the same shape). Each negative has an active positive control on the same channel.
"""
from __future__ import annotations

import ast
import asyncio
import contextlib
import io
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.tenancy._active1214 import (
    CREATED,
    DSN_ENV,
    active_directory,
    database_env,
    insert_active_tenant,
)
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

TENANT = "7f3c1a52-9d4e-4b8a-a1c6-2e5d8b9f0c13"
OTHER = "0b9e6d2a-41c8-4f57-8e3b-6a7d1c5f9e24"
NOT_A_REFUSAL_OF_STATE = ("not active", "offboarding", "creating", "offboarded", "no database")
#: Refusals that are not about state; an admission control must show none of them either (FRR-1).
OTHER_REFUSALS = ("unknown", "no row", "no such", "not a tenant", "does not exist", "not found", "no forge wiring",
                  "invalid choice", "defender_database_dsn")
DEFENDER = Path(__file__).resolve().parents[3]


class _Calls:
    """The run start's stand-ins, recording that they were reached (a refusal must come before any of them)."""

    def __init__(self) -> None:
        self.reached: list[str] = []

    def hook(self, name: str, result: Any) -> Any:
        def call(*_a: Any, **_k: Any) -> Any:
            self.reached.append(name)
            return result
        return call


def _run_start(tenant: str, tmp_path: Path, directory: Any = ..., calls: _Calls | None = None) -> str:
    """`run.main` up to its first refusal or fault; its text ("" if the run finished). `directory=...` passes none."""
    from defender import run as run_py

    calls = calls or _Calls()
    alert = tmp_path / "alert.json"
    alert.write_text('{"rule": {"id": "r-1214"}, "alert_timestamp": "2026-10-28T00:00:00Z"}', encoding="utf-8")
    given = {} if directory is ... else {"directory": directory}
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            run_py.main([str(alert), "--tenant", tenant, "--no-learn"], **given,
                        preflight=calls.hook("preflight", 0), visualize=calls.hook("visualize", None),
                        enqueue=calls.hook("enqueue", False), publish=calls.hook("publish", ""),
                        lifecycle=calls.hook("lifecycle", {"output": "", "requests": 0, "truncated_by": None}))
    except SystemExit as refused:
        return f"{refused.code}\n{err.getvalue()}"
    except Exception as failed:  # noqa: BLE001 — past acceptance, the next real refusal
        return f"{type(failed).__name__}: {failed}\n{err.getvalue()}"
    return ""


def _drain_start(tenant: str, directory: Any = ...) -> str:
    from defender.learning.core import cli

    given = {} if directory is ... else {"directory": directory}
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            cli.main(["loop.py", "--author-drain", "--tenant", tenant], **given)
    except SystemExit as refused:
        return f"{refused.code}\n{err.getvalue()}"
    except Exception as failed:  # noqa: BLE001 — past acceptance, the next real refusal
        return f"{type(failed).__name__}: {failed}\n{err.getvalue()}"
    return err.getvalue()


def _connect(command: list[str], directory: Any = ...) -> str:
    from defender.cli import tenant as connect

    given = {} if directory is ... else {"directory": directory}
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = connect.main(command, **given)
    except SystemExit as refused:
        return f"{refused.code}\n{out.getvalue()}{err.getvalue()}"
    except Exception as failed:  # noqa: BLE001 — past acceptance, the next real refusal
        return f"{type(failed).__name__}: {failed}\n{out.getvalue()}{err.getvalue()}"
    return f"{code}\n{out.getvalue()}{err.getvalue()}"


def _has(text: str, *words: str) -> None:
    for word in words:
        assert word in text, f"{word!r} not in: {text}"


def _admits(text: str) -> bool:
    """True when the entry point got past the tenant-state check (its text names no state refusal). Strict: callers
    that claim admission also assert the run's stand-ins were reached, or that the folder is placed (`_tenant_placed`)."""
    return not any(word in text.lower() for word in (*NOT_A_REFUSAL_OF_STATE, *OTHER_REFUSALS))


def place_complete(data_root: Path, tenant: str) -> Path:
    """`tenant` as a set-up host folder: the knowledge folder plus an empty real `<tenant>/learning/` (what prepare makes)."""
    from defender.tests.support.tenancy._tenants1106 import place_tenant

    place_tenant(data_root, tenant)
    (data_root / tenant / "learning").mkdir(exist_ok=True)
    return data_root / tenant


@pytest.fixture(autouse=True)
def _tenant_placed(data_root) -> Path:
    """FR-1: `TENANT`'s folder is complete for every case, so a control's admission is not refused for a missing
    folder (Flow 4); a case that needs another folder places it itself."""
    return place_complete(data_root, TENANT)


# --- run start -------------------------------------------------------------------------------------

@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
def test_run_start_refuses_a_tenant_that_is_not_active_naming_its_state_before_any_work(tmp_path, data_root, state):
    """Run start refuses any non-`active` state, naming it, before preflight or publish run (Flow 4, P3)."""
    admitted = _Calls()
    assert _admits(_run_start(TENANT, tmp_path, active_directory(data_root, TENANT), admitted))  # control: active passes
    assert admitted.reached, "control: an active tenant reaches the run's first stand-in"
    calls = _Calls()
    refused = _run_start(TENANT, tmp_path, active_directory(data_root, TENANT, state=state), calls)
    _has(refused, "[run.py]", TENANT, state)
    assert calls.reached == []


def test_run_start_refuses_a_tenant_with_no_row(tmp_path, data_root):
    """An id the directory does not hold is refused as unknown by the directory alone, though its folder is placed
    and complete (Flow 4, P3)."""
    place_complete(data_root, OTHER)  # the folder exists and is well-formed: only the directory can refuse
    admitted = _Calls()
    text = _run_start(OTHER, tmp_path, active_directory(data_root, OTHER), admitted)
    assert _admits(text), f"control: the placed folder passes with a row: {text}"
    assert admitted.reached
    calls = _Calls()
    refused = _run_start(OTHER, tmp_path, active_directory(data_root, TENANT), calls)
    _has(refused, "[run.py]", OTHER)
    assert calls.reached == []


def test_run_start_refuses_an_active_tenant_with_no_forge_wiring(tmp_path, data_root):
    """Fail closed on bad wiring: an active tenant whose `forge_wiring` is absent has no origin, so run start refuses
    before any work; the same tenant with wiring is admitted (Flow 4; successor of #1108 P4's binding refusal)."""
    admitted = _Calls()
    assert _admits(_run_start(TENANT, tmp_path, active_directory(data_root, TENANT), admitted))
    assert admitted.reached
    calls = _Calls()
    refused = _run_start(TENANT, tmp_path, active_directory(data_root, TENANT, wiring=False), calls)
    _has(refused, "[run.py]", TENANT)
    assert calls.reached == []


def test_drain_start_refuses_an_active_tenant_with_no_forge_wiring(data_root):
    """Same channel for drain start: no wiring -> refused naming the tenant; wiring -> admitted (Flow 4)."""
    assert _admits(_drain_start(TENANT, active_directory(data_root, TENANT)))
    refused = _drain_start(TENANT, active_directory(data_root, TENANT, wiring=False))
    _has(refused, TENANT)


def test_run_start_with_no_directory_and_no_database_address_refuses(tmp_path, data_root, monkeypatch):
    """Fails closed: no directory, no `DEFENDER_DATABASE_DSN` -> refused before any work (Flow 4, principles 2)."""
    monkeypatch.delenv(DSN_ENV, raising=False)
    calls = _Calls()
    refused = _run_start(TENANT, tmp_path, calls=calls)
    _has(refused, "[run.py]", DSN_ENV)
    assert calls.reached == []


#: A database address nothing listens on (port 1).
UNREACHABLE = "postgresql://nobody:not-the-password@127.0.0.1:1/postgres"


def test_run_start_with_an_unreachable_database_refuses_naming_it(tmp_path, data_root, monkeypatch):
    """The address is set but nothing answers: run start refuses before any work, saying the database could not be
    reached, with no traceback and no password (Flow 4)."""
    monkeypatch.setenv(DSN_ENV, UNREACHABLE)
    calls = _Calls()
    refused = _run_start(TENANT, tmp_path, calls=calls)
    _has(refused, "[run.py]", "could not be reached")
    assert "not-the-password" not in refused, refused
    assert "OperationalError" not in refused, refused
    assert calls.reached == []


def test_the_publish_child_reports_an_unreachable_database_as_transient(data_root, monkeypatch):
    """The publish child with an unreachable database: `stale:transient` (the next run may find it up), not
    `misconfigured`, which asks a human to fix the deployment (O-SEE)."""
    from defender.learning.author import version_control as vc
    from defender.learning.author.version_control.status import STALE_TRANSIENT

    monkeypatch.setenv(DSN_ENV, UNREACHABLE)
    line = vc.publish_for_run(TENANT, data_root=data_root)
    assert line.startswith(STALE_TRANSIENT + " "), line
    assert "could not be reached" in line, line
    assert "not-the-password" not in line, line


@pytest.mark.postgres
def test_run_start_builds_its_directory_from_the_database_address(tmp_path, data_root, monkeypatch, migrated_database):  # noqa: F811
    """Same channel as the refusal above, address set: an active row passes the check, an offboarding one is refused (Flow 4)."""
    insert_active_tenant(migrated_database, TENANT, data_root=data_root)
    insert_active_tenant(migrated_database, OTHER, state="offboarding", data_root=data_root)
    for name, value in database_env(migrated_database).items():
        monkeypatch.setenv(name, value)
    assert _admits(_run_start(TENANT, tmp_path))
    refused = _run_start(OTHER, tmp_path)
    _has(refused, "[run.py]", OTHER, "offboarding")


def test_run_start_refuses_a_tenant_being_offboarded_through_the_api(tmp_path, data_root):
    """End to end: the API's offboard makes the next run start refuse, naming `offboarding` (Flow 4, P3, O4)."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld

    world = LifecycleWorld(tmp_path, data_root)
    try:
        tenant = world.active_tenant()
        assert _admits(_run_start(tenant, tmp_path, world.directory()))
        assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
        refused = _run_start(tenant, tmp_path, world.directory())
        _has(refused, "[run.py]", tenant, "offboarding")
    finally:
        world.close()


def test_run_start_does_not_read_a_planted_tenant_json(tmp_path, data_root):
    """O6 dynamic arm: a corrupt `tenant.json` under the tenant's folder changes nothing; the row is the database's."""
    (data_root / TENANT / "tenant.json").write_text("{torn", encoding="utf-8")
    text = _run_start(TENANT, tmp_path, active_directory(data_root, TENANT))
    assert "tenant.json" not in text, text
    assert "not valid JSON" not in text, text


# --- drain start -----------------------------------------------------------------------------------

@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
def test_drain_start_refuses_a_tenant_that_is_not_active_naming_its_state(data_root, state):
    """Drain start refuses any non-`active` state, naming it; an active tenant passes that check (Flow 4, P3)."""
    assert _admits(_drain_start(TENANT, active_directory(data_root, TENANT)))
    refused = _drain_start(TENANT, active_directory(data_root, TENANT, state=state))
    _has(refused, TENANT, state)


def test_drain_start_with_no_directory_and_no_database_address_refuses(data_root, monkeypatch):
    """Fails closed: no directory, no address -> refused (Flow 4); with a directory it is not (same channel)."""
    monkeypatch.delenv(DSN_ENV, raising=False)
    assert _admits(_drain_start(TENANT, active_directory(data_root, TENANT)))
    refused = _drain_start(TENANT)
    assert DSN_ENV in refused, refused


@pytest.mark.postgres
def test_drain_start_builds_its_directory_from_the_database_address(data_root, monkeypatch, migrated_database):  # noqa: F811
    """Address set, no directory: an active row is admitted, an offboarding one refused (Flow 4)."""
    insert_active_tenant(migrated_database, TENANT, data_root=data_root)
    insert_active_tenant(migrated_database, OTHER, state="offboarding", data_root=data_root)
    for name, value in database_env(migrated_database).items():
        monkeypatch.setenv(name, value)
    assert _admits(_drain_start(TENANT))
    assert "offboarding" in _drain_start(OTHER)


# --- the connect command ---------------------------------------------------------------------------

@pytest.fixture
def staged(tmp_path) -> Path:
    folder = tmp_path / "staged"
    (folder / "skills").mkdir(parents=True)
    (folder / "skills" / "note.md").write_text("note\n", encoding="utf-8")
    return folder


@pytest.mark.parametrize("verb", ["update", "check", "propose"])
@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
def test_the_connect_command_refuses_a_tenant_that_is_not_active(data_root, staged, verb, state):
    """`update`, `check`, `propose` refuse a non-active tenant (exit 1, `[tenant.py]`, the state); active passes (Flow 4, P3)."""
    command = [verb, TENANT, *([str(staged)] if verb == "propose" else [])]
    admitted = _connect(command, active_directory(data_root, TENANT))
    if verb == "check":
        assert _admits(admitted), admitted
    else:  # `update`/`propose` go on to delivery, which may refuse later for its own reasons (FRR-1)
        assert not any(word in admitted.lower() for word in NOT_A_REFUSAL_OF_STATE), admitted
    refused = _connect(command, active_directory(data_root, TENANT, state=state))
    assert refused.startswith("1\n"), refused
    _has(refused, "[tenant.py]", state)


@pytest.mark.parametrize("verb", ["update", "check", "propose"])
def test_the_connect_command_with_no_directory_and_no_database_address_refuses(data_root, staged, monkeypatch, verb):
    """Fails closed: no directory, no address -> exit 1 naming the address (Flow 4)."""
    monkeypatch.delenv(DSN_ENV, raising=False)
    command = [verb, TENANT, *([str(staged)] if verb == "propose" else [])]
    refused = _connect(command)
    assert refused.startswith("1\n"), refused
    _has(refused, DSN_ENV)


@pytest.mark.parametrize("retired", ["setup", "scaffold", "new-id", "migrate"])
def test_the_connect_command_has_only_update_propose_and_check(data_root, retired):
    """`setup`, `scaffold`, `new-id`, `migrate` are retired with the on-disk row; `check` still runs (F-12, RC-9, O6)."""
    directory = active_directory(data_root, TENANT)
    assert _admits(_connect(["check", TENANT], directory)), "control: a kept subcommand is not an invalid choice"
    text = _connect([retired, TENANT], directory)
    _has(text, "invalid choice", f"'{retired}'")


# --- read-only commands and the episode launcher (r10 A1) ------------------------------------------

def _command(main: Any, argv: list[str], directory: Any) -> tuple[Any, str]:
    """`main(argv, directory=...)` -> (its exit status, both streams and any exit text)."""
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = main(argv, directory=directory)
    except SystemExit as refused:
        code = refused.code
    return code, f"{code}\n{out.getvalue()}{err.getvalue()}"


def test_a_read_only_command_refuses_an_offboarding_tenant_before_its_folder(data_root):
    """The workspace map refuses an `offboarding` tenant naming it and its state, before the folder rules run: `OTHER`
    has no folder, and the refusal is about its state, not its folder (r10 O-A1, A1 order: record before folder)."""
    from defender.cli import workspace_map

    argv = ["workspace_map.py", "--tenant", OTHER, "run-20261028T000000Z-0001"]
    _, folder_first = _command(workspace_map.main, argv, active_directory(data_root, OTHER))
    assert OTHER in folder_first, folder_first
    assert not any(w in folder_first.lower() for w in NOT_A_REFUSAL_OF_STATE), (
        "control: an active tenant with no folder is refused for its folder, not its state")
    code, refused = _command(workspace_map.main, argv, active_directory(data_root, OTHER, state="offboarding"))
    assert code not in (0, None), refused
    _has(refused, OTHER, "offboarding")
    assert refused != folder_first


def test_the_episode_launcher_refuses_an_offboarding_tenant_before_any_work(data_root):
    """The launcher refuses an `offboarding` tenant naming it and its state; preflight, spawn and the page are never
    reached (r10 O-A1, Flows: "a launch started after offboarding began is refused at acceptance")."""
    from defender.learning.branch import cli as branch_cli

    calls = _Calls()

    def launch(directory: Any) -> str:
        try:
            branch_cli.main(["--tenant", TENANT, "run-20261028T000000Z-0001", "1"], directory=directory,
                            spawn=calls.hook("spawn", 0), preflight=calls.hook("preflight", 0),
                            render_page=calls.hook("render_page", None))
        except SystemExit as refused:
            return str(refused.code)
        return ""

    admitted = launch(active_directory(data_root, TENANT))
    assert not any(w in admitted.lower() for w in NOT_A_REFUSAL_OF_STATE), f"control: {admitted}"
    calls.reached.clear()
    refused = launch(active_directory(data_root, TENANT, state="offboarding"))
    _has(refused, TENANT, "offboarding")
    assert calls.reached == []


# --- each lead-drain claim -------------------------------------------------------------------------

def _twin_directory(tenant: str, origin: str) -> tuple[Any, Any]:
    from defender.tenancy import InMemoryTenantRepository, TenantDirectory

    twin: Any = InMemoryTenantRepository()
    asyncio.run(twin.add_tenant(tenant, created_at=CREATED, state="active", repo=f"tenants/{tenant}",
                                origin=origin))
    directory = TenantDirectory(lambda: twin)

    def offboard() -> None:
        asyncio.run(twin.request_offboard(tenant, now=CREATED))
    return directory, offboard


class _FlipOnFirst:
    """A lead-author step (`LeadStep` shape) that, on its first claim, has the tenant offboarded."""

    def __init__(self, inner: Any, flip: Any) -> None:
        self.inner, self.flip, self.served = inner, flip, []

    def __call__(self, paths: Any, state: Any, run: Any, **kw: Any) -> Any:
        self.served.append(Path(run.run_dir).name)
        if len(self.served) == 1 and self.flip is not None:
            self.flip()
        return self.inner(paths, state, run, **kw)


@pytest.mark.parametrize("offboard_after_first", [False, True])
def test_the_lead_drain_rechecks_the_tenant_state_at_each_claim(p4_tenant, tmp_path, monkeypatch, offboard_after_first):  # noqa: F811
    """Two queued runs of one tenant: both are served while active; once the tenant is offboarded after the first
    claim the second is not served and its row stays queued (Flow 4: re-checked per claim, not once per tick)."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        BoxSpy,
        LeadStep,
        drain_paths,
        executed_lead,
        lead_author_drain,
        product_repo,
        queued_run,
    )

    t = p4_tenant
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1000")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "1000")
    directory, offboard = _twin_directory(t.tenant_id, t.origin)  # the origin the tenant's forge fake serves
    paths = drain_paths(t, product_repo(tmp_path, adapters=("cmdb",)))
    labels = ("claim-1", "claim-2")
    runs = {queued_run(t, paths, label).name: label for label in labels}
    inner = LeadStep(executed={r: [executed_lead("cmdb.owner-by-tag")] for r in runs}, edits={})
    step = _FlipOnFirst(inner, offboard if offboard_after_first else None)
    rc = lead_author_drain(t, paths, box=BoxSpy(), run_lead_author=step, run_pitfalls=lambda *_a, **_k: 0,
                           directory=directory)
    assert rc == 0
    queue = Path(location_path(paths.state_root)) / "author-queue"
    if not offboard_after_first:
        assert sorted(step.served) == sorted(runs)  # control: both claims are served while active
        return
    [served] = step.served
    unserved = next(label for run, label in runs.items() if run != served)
    assert (queue / f"case-{unserved}.json").is_file(), "the claim of a tenant no longer active must stay queued"


# --- the census and layering (RC-9) ----------------------------------------------------------------

def _production() -> dict[str, ast.AST]:
    return {p.relative_to(DEFENDER).as_posix(): ast.parse(p.read_text(encoding="utf-8"))
            for p in DEFENDER.rglob("*.py")
            if "tests" not in p.relative_to(DEFENDER).parts and ".venv" not in p.parts}


def _referencing(name: str) -> set[str]:
    """Production modules that import, call or attribute-reference `name` (a docstring or string does not count)."""
    found = set()
    for rel, tree in _production().items():
        for node in ast.walk(tree):
            if (isinstance(node, ast.ImportFrom) and any(a.name == name for a in node.names)) \
                    or (isinstance(node, ast.Name) and node.id == name) \
                    or (isinstance(node, ast.Attribute) and node.attr == name):
                found.add(rel)
    return found


def test_the_forge_credential_has_only_the_delivery_and_publish_callers():
    """P3 census (RC-9): `forge_credential` is reached only from the delivery opener and the publish child's module."""
    allowed = {"learning/author/version_control/delivery.py", "learning/author/version_control/publish.py"}
    callers = _referencing("forge_credential")
    assert callers, "control: the provider exists and is referenced"
    assert {c for c in callers if not c.endswith(("version_control/__init__.py", "version_control/credential.py"))} <= allowed


def test_the_publish_child_is_spawned_only_by_run_start_and_prepare():
    """P3 census (RC-9): `launch_publish` is referenced by `run.py`, the host actor's prepare, and its own module."""
    allowed_prefixes = ("run.py", "investigation/publish_launch.py", "investigation/__init__.py", "lifecycle/")
    callers = _referencing("launch_publish")
    assert "run.py" in callers
    assert [c for c in callers if not c.startswith(allowed_prefixes)] == []
    assert any(c.startswith("lifecycle/") for c in callers), "prepare must launch the first publish"


def test_the_retired_row_readers_have_no_callers():
    """RC-9: `issuer_login` and `read_forge_binding` are replaced by the provider; nothing references them."""
    assert _referencing("issuer_login") == set()
    assert _referencing("read_forge_binding") == set()


def test_no_tracked_doc_or_script_teaches_the_retired_adopt_command():
    """The lab moves by hand ("Upgrade from before #1214"): the lifecycle has no adopt command, and nothing tracked
    tells an operator to run one (RC-9)."""
    import subprocess

    found = subprocess.run(["git", "-C", str(DEFENDER.parent), "grep", "-n", "-E", r"defender\.lifecycle adopt"],  # noqa: S603, S607
                           capture_output=True, text=True, check=False)
    assert found.returncode in (0, 1), found.stderr
    assert found.stdout.splitlines() == []


def test_the_opened_delivery_is_reached_only_by_drains_and_the_connect_command():
    """P3 census (RC-9): `opened_delivery` callers are the drains, the connect command and the delivery package."""
    allowed = ("learning/core/drains.py", "cli/tenant.py", "learning/author/version_control/")
    assert [c for c in _referencing("opened_delivery") if not c.startswith(allowed)] == []


def test_lifecycle_sits_below_cli_and_above_learning_in_the_import_order():
    """`defender.lifecycle` is a node of `ORDER` between `learning` and `cli` (placement, API_FORBIDDEN)."""
    source = (DEFENDER.parent / "tooling/lint/lint_import_order.py").read_text(encoding="utf-8")
    [order] = [n.value for n in ast.parse(source).body if isinstance(n, ast.Assign)
               and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "ORDER"]
    nodes = [e.value for e in order.elts]
    assert nodes.index("learning") < nodes.index("lifecycle") < nodes.index("cli")


def test_the_api_may_not_load_the_lifecycle_node():
    """`defender.lifecycle` is in `API_FORBIDDEN`, covering its submodules (O12, P5: admin powers off the API)."""
    from defender.tests.tooling.layout_contracts._spec1080 import API_FORBIDDEN, api_forbidden

    assert "defender.lifecycle" in API_FORBIDDEN
    assert api_forbidden(["defender.lifecycle", "defender.lifecycle.service", "defender.api.app"]) == [
        "defender.lifecycle", "defender.lifecycle.service"]


# --- the r10 census: one host acceptance (A1, A3, A4) ---------------------------------------------

def _raw_name(node: ast.AST, env: Any, astlib: Any) -> str | None:
    """The raw-acceptance name `node` refers to (resolved through imports; an unresolved receiver's attribute by name)."""
    from defender.tests.support.tenancy._host1214 import RAW_ACCEPTANCE

    if not isinstance(node, ast.Name | ast.Attribute):
        return None
    origin = astlib.origin(node, env)
    if origin is not None:
        last = origin.rpartition(".")[2]
        return last if last in RAW_ACCEPTANCE else None
    return node.attr if isinstance(node, ast.Attribute) and node.attr in RAW_ACCEPTANCE else None


def _opens_host(node: ast.AST, env: Any, astlib: Any) -> bool:
    """`node` is a `with host_tenant(...)` block."""
    from defender.tests.support.tenancy._host1214 import HOST_ACCEPTANCE

    def is_host(call: ast.expr) -> bool:
        if not isinstance(call, ast.Call):
            return False
        spelled = getattr(call.func, "id", getattr(call.func, "attr", None))
        return (astlib.callee(call, env) or "").rpartition(".")[2] == HOST_ACCEPTANCE or spelled == HOST_ACCEPTANCE
    return isinstance(node, ast.With | ast.AsyncWith) and any(is_host(i.context_expr) for i in node.items)


def _raw_uses(rel: str, tree: ast.Module) -> list[tuple[int, str]]:
    """`(line, name)` of each use of the raw acceptance or a wrapper in `rel` that is NOT inside the host acceptance
    module, a wrapper's own definition, or a `with host_tenant(...)` block (imports and re-exports are not uses)."""
    from defender.tests.support.shared.contracts._by_path import import_lint_lib
    from defender.tests.support.tenancy import _host1214 as H

    astlib = import_lint_lib("_astlib")
    env = astlib.module_env(tree, module="defender." + rel.removesuffix(".py").replace("/", "."))
    found: list[tuple[int, str]] = []
    wrappers = H.WRAPPER_DEFINITIONS.get(rel, set())

    def visit(node: ast.AST, exempt: bool) -> None:
        if isinstance(node, ast.Import | ast.ImportFrom):
            return
        exempt = exempt or getattr(node, "name", None) in wrappers and isinstance(
            node, ast.FunctionDef | ast.AsyncFunctionDef) or _opens_host(node, env, astlib)
        name = _raw_name(node, env, astlib)
        if name is not None and not exempt:
            found.append((node.lineno, name))
        for child in ast.iter_child_nodes(node):
            visit(child, exempt)

    visit(tree, False)
    return found


def test_the_raw_acceptance_is_used_only_under_the_host_acceptance_or_by_the_starter_covered_set():
    """A1/A3 census: outside the host acceptance step and the wrappers' own bodies, the raw folder acceptance and its
    wrappers are used only by the A3 set (exactly) or under an open `with host_tenant(...)` (r10 "The census test")."""
    from defender.tests.support.tenancy import _host1214 as H

    users = {rel for rel, tree in _production().items()
             if rel != H.HOST_MODULE_PATH and _raw_uses(rel, tree)}
    assert users == set(H.A3_SET), {rel: _raw_uses(rel, _production()[rel]) for rel in users ^ set(H.A3_SET)}


def test_the_raw_census_sees_a_by_hand_use_and_spares_one_under_the_host_acceptance():
    """The detector can fail: a by-hand call, a bound method and an alias are seen; one under `with host_tenant` is not."""
    seen = {
        "a call": "from defender.tenancy import requested_tenant\ndef f(r, t):\n    return requested_tenant(r, t)\n",
        "a bound method": "def f(t):\n    return t.accept_requested_tenant\n",
        "an alias": "from defender.tenancy import accept_tenant as take\ndef f():\n    return take(1, 2)\n",
    }
    for what, source in seen.items():
        assert _raw_uses("cli/x.py", ast.parse(source)), f"the census missed {what}"
    spared = ("from defender.systems.run_tenant import host_tenant\nfrom defender import tenancy\n"
              "def main(argv):\n    with host_tenant(1, argv[0]) as a:\n"
              "        return tenancy.open_command_line_run(argv[0], argv[1])\n")
    assert _raw_uses("cli/x.py", ast.parse(spared)) == []


def test_every_listed_entry_point_admits_through_the_host_acceptance():
    """Positive half of the A1 census: each module in the design's "Callers that move to it" table references the
    host acceptance step (r10 O-A1)."""
    from defender.tests.support.tenancy import _host1214 as H

    callers = _referencing(H.HOST_ACCEPTANCE)
    assert [rel for rel in H.ENTRY_POINT_MODULES if rel not in callers] == []


def _dotted(rel: str) -> str:
    return "defender." + rel.removesuffix(".py").removesuffix("/__init__").replace("/", ".")


def _imported_names(rel: str, tree: ast.AST) -> set[str]:
    """Every dotted name `rel` imports, anywhere in it (function-local too), relative imports resolved."""
    package = _dotted(rel) if rel.endswith("__init__.py") else _dotted(rel).rpartition(".")[0]
    wanted: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            wanted |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")[:len(package.split(".")) - (node.level - 1)]
                base = ".".join([*parts, *([base] if base else [])])
            wanted |= {base, *(f"{base}.{a.name}" for a in node.names)}
    return wanted


def _lifecycle_closure() -> set[str]:
    """Production modules (paths under defender/) reachable by import, at any depth and function-local too, from
    `defender.lifecycle`; lazy-door string imports are not followed."""
    production = _production()
    by_name = {_dotted(rel): rel for rel in production}

    def imported(rel: str) -> set[str]:
        wanted = _imported_names(rel, production[rel])
        found = set()
        for want in wanted:
            while want and want not in by_name:
                want = want.rpartition(".")[0]
            if want:
                found.add(by_name[want])
        return found

    seen: set[str] = set()
    todo = [rel for rel in production if rel.startswith("lifecycle/")]
    while todo:
        rel = todo.pop()
        if rel not in seen:
            seen.add(rel)
            todo.extend(imported(rel))
    return seen


def test_nothing_the_lifecycle_runs_calls_the_host_acceptance():
    """A4: no module reachable from `defender.lifecycle` references the host acceptance step (prepare holds the lock
    exclusive in that process; a shared hold there would block its own prepare)."""
    from defender.tests.support.tenancy import _host1214 as H

    closure = _lifecycle_closure()
    assert "investigation/publish_launch.py" in closure, "control: prepare's in-process publish launcher is reached"
    callers = _referencing(H.HOST_ACCEPTANCE)
    assert callers, "control: the host acceptance step exists and is referenced"
    assert sorted(callers & closure) == []
