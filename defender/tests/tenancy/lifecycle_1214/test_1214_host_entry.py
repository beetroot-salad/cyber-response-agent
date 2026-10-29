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
    """True when the entry point got past the tenant-state check (its text names no state refusal)."""
    return not any(word in text for word in NOT_A_REFUSAL_OF_STATE)


# --- run start -------------------------------------------------------------------------------------

@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
def test_run_start_refuses_a_tenant_that_is_not_active_naming_its_state_before_any_work(tmp_path, data_root, state):
    """Run start refuses any non-`active` state, naming it, before preflight or publish run (Flow 4, P3)."""
    assert _admits(_run_start(TENANT, tmp_path, active_directory(data_root, TENANT)))  # control: active passes the check
    calls = _Calls()
    refused = _run_start(TENANT, tmp_path, active_directory(data_root, TENANT, state=state), calls)
    _has(refused, "[run.py]", TENANT, state)
    assert calls.reached == []


def test_run_start_refuses_a_tenant_with_no_row(tmp_path, data_root):
    """An id the directory does not hold is refused as unknown, before any work (Flow 4, P3)."""
    calls = _Calls()
    refused = _run_start(OTHER, tmp_path, active_directory(data_root, TENANT), calls)
    _has(refused, "[run.py]", OTHER)
    assert calls.reached == []


def test_run_start_with_no_directory_and_no_database_address_refuses(tmp_path, data_root, monkeypatch):
    """Fails closed: no directory, no `DEFENDER_DATABASE_DSN` -> refused before any work (Flow 4, principles 2)."""
    monkeypatch.delenv(DSN_ENV, raising=False)
    calls = _Calls()
    refused = _run_start(TENANT, tmp_path, calls=calls)
    _has(refused, "[run.py]", DSN_ENV)
    assert calls.reached == []


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
    folder = data_root / TENANT
    folder.mkdir()
    (folder / "tenant.json").write_text("{torn", encoding="utf-8")
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
    assert _admits(_connect(command, active_directory(data_root, TENANT)))
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


def test_the_connect_command_has_no_setup_subcommand(data_root):
    """`cli/tenant.py setup` is retired with the on-disk row (RC-9, O6)."""
    text = _connect(["setup", TENANT, ], active_directory(data_root, TENANT))
    _has(text, "invalid choice", "'setup'")


# --- each lead-drain claim -------------------------------------------------------------------------

def _twin_directory(tenant: str) -> tuple[Any, Any]:
    from defender.tenancy import InMemoryTenantRepository, TenantDirectory

    twin: Any = InMemoryTenantRepository()
    asyncio.run(twin.add_tenant(tenant, created_at=CREATED, state="active", repo=f"tenants/{tenant}",
                                origin=f"http://forge.test/tenants/{tenant}.git"))
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
    directory, offboard = _twin_directory(t.tenant_id)
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
