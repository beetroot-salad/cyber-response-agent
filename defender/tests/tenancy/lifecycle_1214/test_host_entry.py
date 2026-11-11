"""#1214 Flow 4 / P3: every host entry point proceeds only while the tenant is `active`, read through
`TenantDirectory`; with no directory and no `DEFENDER_DATABASE_DSN` it refuses (fails closed).

Entry points: run start (`run.main`), drain start (`learning.core.cli.main`), each lead-drain claim
(`drains.lead_author_drain`), the connect command (`cli.tenant.main`). Each takes `directory=` (pinned, r9; the last
two are GAP-C-1 additions of the same shape). Each negative has an active positive control on the same channel.
"""
from __future__ import annotations

import ast
import contextlib
import io
import logging
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.tenancy._active1214 import (
    DSN_ENV,
    active_directory,
    database_env,
    insert_active_tenant,
)
from defender.tests.support.tenancy import _host1214 as H
from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING, seed_twin
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


class StoreReached(Exception):
    """What the stand-in learning store raises when an admitted command first asks it for anything."""


@pytest.fixture(autouse=True)
def _the_learning_store_is_reached_not_used(monkeypatch) -> None:
    """The boundary cases judge what a command does up to and including its host acceptance. Past it, a drain, the
    revert and the queue page read the learning store (#1278), which these cases do not stand up: every store a command
    opens is one whose first use raises `StoreReached`, so an admitted command ends in a fault of its own that is
    none of the refusals a control must not show, and a refused one never gets as far."""
    import contextlib

    from defender.learning.core import drains, store_tick

    class Unreached:
        def __getattr__(self, name: str) -> Any:
            raise StoreReached(f"the learning store was reached ({name}); this case stands none up")

    @contextlib.contextmanager
    def opened_store():
        yield Unreached()

    monkeypatch.setattr(store_tick, "opened_store", opened_store)  # lint-monkeypatch: ok — the host entry opens its store through this module-level door; no seam carries a stand-in store to it
    monkeypatch.setattr(drains, "opened_store", opened_store)  # lint-monkeypatch: ok — the drain opens its store through this module-level door; no seam carries a stand-in store to it


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


def test_run_start_whose_database_goes_away_after_the_version_check_refuses_on_one_line(tmp_path, data_root):
    """The database answered the version check, then is gone at the admission read: run start refuses on one line
    saying the records could not be reached, with no traceback, before any work, and leaves no record or lock (PR #1350
    review: a blip after process start)."""
    from defender.tenancy import TenantDirectory

    twin = active_directory(data_root, TENANT)._open()  # noqa: SLF001 — the twin behind the directory

    class Gone:
        def __getattr__(self, name: str) -> Any:
            if name == "close":
                return twin.close

            async def unreachable(*_a: Any, **_k: Any) -> Any:
                import sqlalchemy.exc

                raise sqlalchemy.exc.OperationalError("SELECT", {}, Exception("connection failed: no route to host"))
            return unreachable

    calls = _Calls()
    refused = _run_start(TENANT, tmp_path, TenantDirectory(lambda: Gone()), calls)
    _has(refused, "[run.py]", "could not be reached", "no route to host")
    assert "OperationalError" not in refused, refused
    assert "Traceback" not in refused, refused
    assert calls.reached == []
    assert H.recorded(data_root, TENANT) == []
    assert H.exclusive_free(data_root, TENANT)


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
    # #1345 D2/r5.1: a tenant has no mapping until one is saved and a run for one is refused, so the tenant that is
    # admitted and goes on to start its run is seeded with the mapping it needs; the offboarding one is refused earlier.
    insert_active_tenant(migrated_database, TENANT, data_root=data_root, alert_mapping=FIXTURE_ALERT_MAPPING)
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
        # #1345 D2/r5.1: a tenant the product took through its whole lifecycle to `active` still has no mapping,
        # so its run start is refused naming it; the run admitted below needs one saved.
        from defender.records.formats import ALERT_MAPPING_MISSING
        unmapped = _run_start(tenant, tmp_path, world.directory())
        assert ALERT_MAPPING_MISSING in " ".join(unmapped.split()), unmapped
        seed_twin(world.tenants, tenant, FIXTURE_ALERT_MAPPING)
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


def test_the_drain_is_recorded_while_its_stage_runs_and_nothing_stays_recorded(data_root, monkeypatch):
    """The drain is recorded under its tenant's lock from a seam reached after acceptance (its stage) and leaves
    nothing recorded once `main` returns (r10 O-A2: recorded for as long as the command runs)."""
    from defender.learning.core import cli

    during: list[tuple[list[Any], bool]] = []

    def stage(*_a: Any, **_k: Any) -> int:
        during.append((H.recorded(data_root, TENANT), H.exclusive_free(data_root, TENANT)))
        return 0

    # The drain's stage is the only point after acceptance that a test can reach: `main` takes no stage seam, and an empty
    # queue consults neither the tenant records nor the forge, so there is no injected collaborator to observe from.
    monkeypatch.setattr(cli, "author_drain", stage)  # lint-monkeypatch: ok — `cli.main` has no stage seam (production is out of scope here)
    assert cli.main(["loop.py", "--author-drain", "--tenant", TENANT], directory=active_directory(data_root, TENANT)) == 0
    [(recorded, free)] = during
    assert recorded == H.this_process(), "the drain was not recorded while its stage ran"
    assert not free, "the drain's lock was free while its stage ran"
    assert H.recorded(data_root, TENANT) == []
    assert H.exclusive_free(data_root, TENANT)


# --- every other host entry point (r10 A1): the read-only commands, the one-shot commands and the launcher ------

class _Logged(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def _command(main: Any, argv: list[str], directory: Any, *, refusal: bool = False, **seams: Any) -> tuple[Any, str]:
    """`main(argv, directory=..., **seams)` -> (its exit status, both streams, any exit text and what it logged). With
    `refusal=True` the command must refuse by exiting or returning a status: an exception that escapes fails the case."""
    out, err, logged = io.StringIO(), io.StringIO(), _Logged()
    logging.getLogger().addHandler(logged)
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = main(argv, directory=directory, **seams)
    except SystemExit as refused:
        code = refused.code
    except Exception as failed:  # noqa: BLE001 — past acceptance, the command's next real refusal
        if refusal:
            raise AssertionError(f"a refusal must exit or return a status, not raise {type(failed).__name__}: {failed}") from failed
        code = f"{type(failed).__name__}: {failed}"
    else:
        if refusal and not isinstance(code, int):
            raise AssertionError(f"a refusal must exit or return an int status, returned {code!r}")
    finally:
        logging.getLogger().removeHandler(logged)
    return code, f"{code}\n{out.getvalue()}{err.getvalue()}" + "\n".join(logged.lines)


#: The refusals about the tenant itself, which acceptance alone gives; the generic "not found" / "unknown" / "does not
#: exist" are left out, as an absent run legitimately gets them after acceptance.
TENANT_REFUSALS = ("no row", "not a tenant", "no forge wiring", "defender_database_dsn")


def _no_state_refusal(text: str) -> bool:
    """True when the command got past acceptance: no state refusal, no tenant-specific refusal (no row, not a tenant, no
    forge wiring, no database address), no harness fault and no run-id grammar refusal (the fixture ids are canonical,
    so a `RunRefused` would mean the command judged the id before accepting the tenant)."""
    return (not any(w in text.lower() for w in (*NOT_A_REFUSAL_OF_STATE, *TENANT_REFUSALS))
            and "TypeError" not in text and "RunRefused" not in text)


def _tree(root: Path) -> dict[str, tuple[int, int, int]]:
    """Every path below `root` with its mode, size and mtime: what a command left there."""
    if not root.is_dir():
        return {}
    return {str(p.relative_to(root)): (p.lstat().st_mode, p.lstat().st_size, p.lstat().st_mtime_ns)
            for p in sorted(root.rglob("*"))}


def _launcher(directory: Any, calls: _Calls, **kw: Any) -> tuple[Any, str]:
    """The episode launcher's `main` with stand-ins for its spawn, preflight and page (`calls` records them)."""
    from defender.learning.branch import cli as branch_cli

    return _command(branch_cli.main, ["--tenant", TENANT, H.RUN_ID, "1"], directory,
                    spawn=calls.hook("spawn", 0), preflight=calls.hook("preflight", 0),
                    render_page=calls.hook("render_page", None), **kw)


@pytest.mark.parametrize("state", ["offboarding", "creating"])
@pytest.mark.parametrize("name", list(H.COMMANDS))
def test_a_host_command_refuses_a_tenant_that_is_not_active_before_its_folder_and_holds_nothing(data_root, name, state):
    """Each command of the design's table refuses a non-`active` tenant naming it and its state, before the folder
    rules, holds nothing and writes nothing under the tenant's folder; an active tenant passes the check (r10 O-A1, O-A6)."""
    main, argv = H.command_main(name), H.COMMANDS[name][1]
    _, admitted = _command(main, argv(TENANT), active_directory(data_root, TENANT))
    assert _no_state_refusal(admitted), f"control: an active tenant was refused for its state: {admitted}"
    code, refused = _command(main, argv(OTHER), active_directory(data_root, OTHER, state=state), refusal=True)
    assert code not in (0, None), refused
    _has(refused, OTHER, state)
    assert H.recorded(data_root, OTHER) == [], "the refusal kept a record"
    assert H.exclusive_free(data_root, OTHER), "the refusal kept the lock"
    assert not (data_root / OTHER).exists(), f"the refusal made the folderless tenant's folder: {_tree(data_root / OTHER)}"
    before = _tree(data_root / TENANT)
    assert before, "control: the placed tenant's folder has something to compare"
    code, refused = _command(main, argv(TENANT), active_directory(data_root, TENANT, state=state), refusal=True)
    assert code not in (0, None), refused
    _has(refused, TENANT, state)
    assert _tree(data_root / TENANT) == before, "the refusal wrote under the placed tenant's folder"


def test_an_active_tenant_with_no_folder_is_refused_for_its_folder_not_its_state(data_root):
    """Control for the ordering above: the same command and tenant, active, fails on the folder and names no state
    (r10 A1 order: record before folder)."""
    argv = H.COMMANDS["workspace_map"][1](OTHER)
    _, folder_first = _command(H.command_main("workspace_map"), argv, active_directory(data_root, OTHER))
    assert OTHER in folder_first, folder_first
    assert _no_state_refusal(folder_first), folder_first


def test_the_episode_launcher_refuses_an_offboarding_tenant_before_any_work(data_root):
    """The launcher refuses an `offboarding` tenant naming it and its state; preflight, spawn and the page are never
    reached, nothing is written under the tenant's folder (r10 O-A1, Flows: "a launch started after offboarding began
    is refused at acceptance")."""
    calls = _Calls()
    _, admitted = _launcher(active_directory(data_root, TENANT), calls)
    assert _no_state_refusal(admitted), f"control: {admitted}"
    calls.reached.clear()
    before = _tree(data_root / TENANT)
    code, refused = _launcher(active_directory(data_root, TENANT, state="offboarding"), calls, refusal=True)
    assert code not in (0, None), refused
    _has(refused, TENANT, "offboarding")
    assert calls.reached == []
    assert H.recorded(data_root, TENANT) == []
    assert H.exclusive_free(data_root, TENANT)
    assert _tree(data_root / TENANT) == before, "the refusal wrote under the tenant's folder"


@pytest.mark.parametrize("state", ["offboarding", "creating"])
def test_the_episode_launcher_refuses_a_folderless_tenant_for_its_state_and_makes_no_folder(data_root, state):
    """A tenant that is not `active` and has no folder is refused for its state; no folder appears for it (r10 O-A1, A1 order)."""
    from defender.learning.branch import cli as branch_cli

    code, refused = _command(branch_cli.main, ["--tenant", OTHER, H.RUN_ID, "1"],
                             active_directory(data_root, OTHER, state=state), refusal=True,
                             spawn=lambda *a, **k: 0, preflight=lambda *a, **k: 0, render_page=lambda *a, **k: None)
    assert code not in (0, None), refused
    _has(refused, OTHER, state)
    assert not (data_root / OTHER).exists(), "the refusal made the folderless tenant's folder"


# --- each lead-drain claim: retired -----------------------------------------------------------------
# Retired (#1278 r8 Schema, "Insert is conditional on the tenant being active, in the same transaction"; r8 Offboarding):
# the lead drain re-read the tenant's state at each file-queue claim, and a claim of a tenant that stopped being active
# stayed queued uncounted (`test_the_lead_drain_rechecks_the_tenant_state_at_each_claim` here, and the whole of the
# former `test_1214_atk3_drain_recheck.py`: a tenant that stops being active after the first claim, a directory that
# fails at the second claim, a database blip mid-tick). The queue, its per-claim loop, `attempts` on queue rows and the
# failed/inflight letters are replaced by one store claim per tick. A tenant off `active` gets no batch and a working
# batch of it is told to stop; the surviving obligation is enforced by
# learning/store_1278/test_store_1278.py::test_o6_a_tenant_off_active_gets_no_batch_and_its_working_batch_is_told_to_stop,
# learning/store_1278/test_offboarding_1278.py and tests/migrations/test_1278_learning_schema.py (TenantInactive).


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


# --- the r10.1 census: one host acceptance (A1, A3, A4; C1, C2, C5) -------------------------------

def _units(rel: str, tree: ast.Module) -> list[tuple[str, bool, list[ast.AST]]]:
    """`(name, is_method, nodes)` for each top-level function, each method and the module-level code of `rel`; a
    nested function belongs to its outermost one."""
    units: list[tuple[str, bool, list[ast.AST]]] = []
    loose: list[ast.AST] = []

    def method_units(cls: ast.ClassDef) -> None:
        for stmt in cls.body:
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                units.append((stmt.name, True, list(ast.walk(stmt))))
            elif isinstance(stmt, ast.ClassDef):
                method_units(stmt)

    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            units.append((stmt.name, False, list(ast.walk(stmt))))
        elif isinstance(stmt, ast.ClassDef):
            method_units(stmt)
        else:
            loose.extend(ast.walk(stmt))
    units.append(("<module>", False, loose))
    return units


#: The A3 entry units: where a starter-covered process takes the folder raw. Their private helpers are not entries.
A3_ENTRIES = frozenset({("learning/author/version_control/publish.py", "publish_for_run"),
                        ("learning/author/version_control/publish.py", "publish_child_main"),
                        ("investigation/publish_launch.py", "launch_publish"),
                        ("skills/connect/validate_scaffold.py", "main")})


def _is_barrier(rel: str, name: str) -> bool:
    """The units that stop a reach from propagating to their callers: the host acceptance itself and the A3 entry units.
    A public or private helper of the host module, or a private helper of an A3 module, that reaches the raw step still
    marks whoever calls it from outside."""
    return (rel == H.HOST_MODULE_PATH and name == H.HOST_ACCEPTANCE) or (rel, name) in A3_ENTRIES


def _may_reach(rel: str) -> bool:
    """The modules whose own functions are allowed to reach the raw step: the host module and the A3 set."""
    return rel == H.HOST_MODULE_PATH or rel in H.A3_SET


_Facts = dict[tuple[str, str], tuple[str, bool, list[tuple[str | None, str, bool]]]]


def _facts(production: dict[str, ast.Module]) -> _Facts:
    """Per function: its module, whether it is a method, and what its body refers to as `(resolved origin, last name,
    is an attribute)`."""
    from defender.tests.support.shared.contracts._by_path import import_lint_lib

    astlib = import_lint_lib("_astlib")
    facts: _Facts = {}
    for rel, tree in production.items():
        package = _dotted(rel) if rel.endswith("__init__.py") else None
        env = astlib.module_env(tree, module=_dotted(rel), package=package)
        for name, is_method, nodes in _units(rel, tree):
            refs = []
            for node in nodes:
                if isinstance(node, ast.Name | ast.Attribute):
                    found = astlib.origin(node, env)
                    if found is None and isinstance(node, ast.Name):
                        found = env.own_defs.get(node.id)
                    refs.append((found, node.attr if isinstance(node, ast.Attribute) else node.id,
                                 isinstance(node, ast.Attribute)))
            facts[rel, name] = (_dotted(rel), is_method, refs)
    return facts


def _refers(facts: _Facts, packages: set[str], unit: tuple[str, str], target: tuple[str, str]) -> bool:
    """Whether `unit`'s body refers to `target`: the import's resolved module is the target's module, or a package whose
    direct child module the target is (a re-export); a leaf name elsewhere in the package tree does not count."""
    t_module, t_method = facts[target][0], facts[target][1]
    for found, last, attribute in facts[unit][2]:
        if found is not None:
            home, _, leaf = found.rpartition(".")
            if leaf == target[1] and (t_module == home or (home in packages and t_module.rpartition(".")[0] == home)):
                return True
        elif attribute and last == target[1] and t_method:
            return True
    return False


def _reaching(production: dict[str, ast.Module]) -> set[tuple[str, str]]:
    """`(module path, function name)` of each production function that reaches the raw acceptance `accept_tenant`:
    a fixed point over function bodies, a function reaching when its body refers to `accept_tenant` or to a reaching
    function (resolved through imports; a method by its name on an unresolved receiver). The host acceptance and the
    A3 set are reached but do not pass it on to their callers: they are where acceptance is allowed."""
    facts = _facts(production)
    packages = {_dotted(rel) for rel, _ in facts if rel.endswith("__init__.py")}
    reaching = {unit for unit in facts if unit[1] == "accept_tenant" and unit[0] == H.RAW_LAYER}
    passing = set(reaching)
    grew = True
    while grew:
        grew = False
        for unit in facts:
            if unit not in reaching and any(_refers(facts, packages, unit, target) for target in passing):
                reaching.add(unit)
                grew = True
                if not _is_barrier(*unit):
                    passing.add(unit)
    return reaching


def _offenders(reaching: set[tuple[str, str]]) -> set[tuple[str, str]]:
    return {(rel, name) for rel, name in reaching if rel != H.RAW_LAYER and not _may_reach(rel)}


def test_a_function_reaches_the_raw_acceptance_only_in_the_host_acceptance_and_the_starter_covered_set():
    """C2 (1): derived by reachability, the production functions that reach `accept_tenant` are the host acceptance and
    the A3 set (every other entry point and wrapper takes the accepted tenant it is handed)."""
    reaching = _reaching(_production())
    assert (H.HOST_MODULE_PATH, H.HOST_ACCEPTANCE) in reaching, "control: the host acceptance accepts the tenant"
    assert {rel for rel, _ in reaching if rel in H.A3_SET} == set(H.A3_SET), "the A3 set is exactly these modules"
    assert sorted(_offenders(reaching)) == []


def test_the_reachability_census_sees_a_new_wrapper_under_a_fresh_name_and_spares_an_accepted_tenant():
    """The detector can fail: a by-hand call, a wrapper under a name nobody listed, its caller, a bound method, an
    alias and a use under a `with host_tenant` are offenders; a wrapper taking an accepted tenant, the host acceptance
    and the A3 set are not."""
    raw = ("def accept_tenant(root, raw):\n    return object()\n"
           "def requested_tenant(root, raw):\n    return accept_tenant(root, raw)\n"
           "class Tenant:\n    @staticmethod\n    def accept_requested_tenant(root, raw):\n"
           "        return requested_tenant(root, raw)\n")
    sources = {
        "tenancy/__init__.py": "",
        "tenancy/_tenant.py": raw,
        "cli/by_hand.py": "from defender.tenancy import requested_tenant\ndef main(r, t):\n    return requested_tenant(r, t)\n",
        "cli/fresh.py": ("from defender.tenancy import accept_tenant\n"
                         "def load_for_the_page(root, raw):\n    return accept_tenant(root, raw)\n"),
        "cli/caller.py": ("from defender.cli.fresh import load_for_the_page\n"
                          "def main(argv):\n    return load_for_the_page(1, argv[0])\n"),
        "cli/bound.py": "def main(t):\n    return t.accept_requested_tenant(1, 2)\n",
        "cli/alias.py": "from defender.tenancy import accept_tenant as take\ndef main():\n    return take(1, 2)\n",
        "cli/scoped.py": ("from defender.systems.run_tenant import host_tenant\nfrom defender import tenancy\n"
                          "def main(argv):\n    with host_tenant(1, argv[0]):\n        return tenancy.requested_tenant(1, argv[1])\n"),
        "cli/accepted.py": "def open_command_line_run(tenant, run_id):\n    return (tenant, run_id)\n",
        "cli/uses_accepted.py": ("from defender.cli.accepted import open_command_line_run\n"
                                 "def main(tenant):\n    return open_command_line_run(tenant, 1)\n"),
        H.HOST_MODULE_PATH: ("from defender.tenancy import accept_tenant\n"
                             "def host_tenant(root, raw):\n    return accept_tenant(root, raw)\n"),
        "cli/opens_scope.py": ("from defender.systems.run_tenant import host_tenant\n"
                               "def main(argv):\n    return host_tenant(1, argv[0])\n"),
        sorted(H.A3_SET)[0]: "from defender.tenancy import requested_tenant\ndef launch(r, t):\n    return requested_tenant(r, t)\n",
    }
    offenders = _offenders(_reaching({rel: ast.parse(text) for rel, text in sources.items()}))
    assert offenders == {("cli/by_hand.py", "main"), ("cli/fresh.py", "load_for_the_page"), ("cli/caller.py", "main"),
                         ("cli/bound.py", "main"), ("cli/alias.py", "main"), ("cli/scoped.py", "main")}, offenders


def test_the_reachability_census_sees_through_the_host_modules_and_the_starter_set_helpers():
    """The detector can fail where a barrier was too wide: a launcher reaching the raw step through the host module's
    public resolver and its private loader, a command importing that private loader, and a command calling a private
    acceptor of the scaffold validator are offenders; the host module's own functions and the validator's are not. A
    parent package's same-named `main` does not stand in for a child package's."""
    sources = {
        "tenancy/__init__.py": "",
        "tenancy/_tenant.py": "def accept_tenant(root, raw):\n    return object()\n",
        H.HOST_MODULE_PATH: ("from defender.tenancy._tenant import accept_tenant\n"
                             "def _load(root, raw):\n    return accept_tenant(root, raw)\n"
                             "def host_tenant(root, raw):\n    return _load(root, raw)\n"
                             "def resolve_tenant(root, raw):\n    return _load(root, raw)\n"),
        "learning/branch/cli.py": ("from defender.systems.run_tenant import resolve_tenant\n"
                                   "def _launch(argv):\n    return resolve_tenant(1, argv[0])\n"),
        "cli/private.py": "from defender.systems.run_tenant import _load\ndef main(argv):\n    return _load(1, argv[0])\n",
        "cli/a3.py": ("from defender.skills.connect.validate_scaffold import _accept\n"
                      "def main(argv):\n    return _accept(1, argv[0])\n"),
        "skills/connect/validate_scaffold.py": ("from defender.tenancy._tenant import accept_tenant\n"
                                                "def _accept(r, t):\n    return accept_tenant(r, t)\n"
                                                "def main():\n    return _accept(1, 2)\n"),
        "cli/__init__.py": "",
        "cli/sub/deep.py": "from defender.tenancy._tenant import accept_tenant\ndef go():\n    return accept_tenant(1, 2)\n",
        "cli/other.py": "from defender.cli import go\ndef run():\n    return go()\n",
    }
    offenders = _offenders(_reaching({rel: ast.parse(text) for rel, text in sources.items()}))
    assert offenders == {("learning/branch/cli.py", "_launch"), ("cli/private.py", "main"), ("cli/a3.py", "main"),
                         ("cli/sub/deep.py", "go")}, offenders


def _host_calls(rel: str, tree: ast.Module) -> list[tuple[int, tuple[str, ...]]]:
    """`(line, enclosing function names outermost first)` of each call to the host acceptance in `rel`, by its name,
    its attribute spelling or an import alias."""
    names = {H.HOST_ACCEPTANCE}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom | ast.Import):
            names |= {a.asname for a in node.names if a.asname and a.name.rpartition(".")[2] == H.HOST_ACCEPTANCE}
    found: list[tuple[int, tuple[str, ...]]] = []

    def visit(node: ast.AST, chain: tuple[str, ...]) -> None:
        if isinstance(node, ast.Call):
            f = node.func
            if (f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None) in names:
                found.append((node.lineno, chain))
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            chain = (*chain, node.name)
        for child in ast.iter_child_nodes(node):
            visit(child, chain)

    visit(tree, ())
    return found


def _is_command_scope(chain: tuple[str, ...]) -> bool:
    return len(chain) == 1 and chain[0] in H.COMMAND_FUNCTIONS


def test_the_host_acceptance_is_opened_only_by_the_command_function_of_each_entry_module():
    """C2 (2): the host acceptance is called from `main` (or the launcher's `_launch`) of exactly the design's entry
    modules, as a module-level function, never from a helper whose return would close the scope early."""
    calls = {rel: found for rel, tree in _production().items()
             if rel != H.HOST_MODULE_PATH and (found := _host_calls(rel, tree))}
    assert set(calls) == set(H.ENTRY_POINT_MODULES), set(calls) ^ set(H.ENTRY_POINT_MODULES)
    stray = {rel: [(line, chain) for line, chain in found if not _is_command_scope(chain)]
             for rel, found in calls.items()}
    assert {rel: bad for rel, bad in stray.items() if bad} == {}


def test_the_host_census_sees_a_helper_owned_scope_and_spares_a_commands_own():
    """The detector can fail: a helper, a closure in `main`, module level, an attribute spelling and an alias are seen as
    stray; `main` and `_launch` themselves are not (the policy view's helper-owned scope is the ruled-out case)."""
    stray = {
        "a helper": "def _definition(raw):\n    return host_tenant(root, raw)\ndef main(argv):\n    return _definition(1)\n",
        "a closure in main": "def main(argv):\n    def go():\n        return host_tenant(1, 2)\n    return go()\n",
        "module level": "admitted = host_tenant(1, 2)\n",
        "an attribute": "def helper(t):\n    return run_tenant.host_tenant(1, t)\n",
        "an alias": "from x import host_tenant as admit\ndef helper():\n    return admit(1, 2)\n",
    }
    for what, source in stray.items():
        found = _host_calls("cli/x.py", ast.parse(source))
        assert found, f"the census saw no call in {what}"
        assert not all(_is_command_scope(chain) for _, chain in found), f"the census missed {what}"
    for own in ("def main(argv):\n    return host_tenant(1, argv)\n", "def _launch(argv):\n    return host_tenant(1, argv)\n"):
        assert all(_is_command_scope(chain) for _, chain in _host_calls("learning/branch/cli.py", ast.parse(own)))


def test_the_starter_covered_set_never_calls_the_host_acceptance():
    """A3: the publish child, its in-process launcher and the scaffold validator load the folder with the folder rules
    only; none opens a host acceptance (they have no database address and run under prepare's exclusive hold)."""
    callers = _referencing(H.HOST_ACCEPTANCE)
    assert callers, "control: the host acceptance is referenced"
    assert sorted(callers & set(H.A3_SET)) == []


def test_nothing_under_a_scope_accepts_again_the_drains_separate_acceptor_is_gone():
    """C1: the drain's rehydration uses the drain's own accepted tenant (`paths.tenant`), so `_tenant_acceptor` has no
    definition or caller left, and `drains.py` opens no acceptance of its own."""
    assert _referencing("_tenant_acceptor") == set()
    assert not any(isinstance(n, ast.FunctionDef) and n.name == "_tenant_acceptor"
                   for n in ast.walk(_production()["learning/core/drains.py"]))
    assert "learning/core/drains.py" not in _referencing(H.HOST_ACCEPTANCE)


def test_the_hold_has_one_owner_and_the_admission_helpers_stay_with_the_host_module():
    """C5: `hold_tenant` is gone; `admit_tenant` and `host_directory` are used outside `tenancy/` by the host module
    alone. (The drain's per-claim `still_active` check is retired with the claim loop: see "each lead-drain claim: retired".)"""
    from defender import tenancy

    assert _referencing("hold_tenant") == set()
    assert not hasattr(tenancy, "hold_tenant")
    outside = lambda name: {rel for rel in _referencing(name) if not rel.startswith("tenancy/")}  # noqa: E731
    assert outside("admit_tenant") == {H.HOST_MODULE_PATH}
    assert outside("host_directory") == {H.HOST_MODULE_PATH}


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
    closure = _lifecycle_closure()
    assert "investigation/publish_launch.py" in closure, "control: prepare's in-process publish launcher is reached"
    callers = _referencing(H.HOST_ACCEPTANCE)
    assert callers, "control: the host acceptance step exists and is referenced"
    assert sorted(callers & closure) == []
