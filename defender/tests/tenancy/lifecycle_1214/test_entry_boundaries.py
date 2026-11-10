"""#1214 r10.1 repair: what every host entry point does at its boundary, one table for all of them (O-A1, O-A2, A1).

Entries: run start, a sibling run, drain start, the connect verbs, the episode launcher and the ten commands of
`H.COMMANDS`. Each refusal is a non-zero exit with its words on the error stream; the tenant's folder is untouched
before the state is judged; the hold lasts while the command works; a folder fault is refused for its folder.
"""
from __future__ import annotations

import ast
import contextlib
import io
import logging
import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.tenancy import _host1214 as H
from defender.tests.support.tenancy._active1214 import active_directory
from defender.tests.tenancy.lifecycle_1214.test_host_entry import (
    NOT_A_REFUSAL_OF_STATE,
    TENANT,
    _Calls,
    _Logged,
    _the_learning_store_is_reached_not_used,  # noqa: F401 — autouse fixture
    _no_state_refusal,
    _production,
    _reaching,
    _tenant_placed,  # noqa: F401 — autouse fixture
    place_complete,
)


@pytest.fixture(autouse=True)
def _a_publish_folder(tmp_path, monkeypatch) -> None:
    """A dev deployment with a publish folder, so the page commands get past `NoPublishRoot` and work on the tenant."""
    from defender.configuration import _env, publish_root

    (tmp_path / "published").mkdir()
    monkeypatch.setenv(_env.DEPLOYMENT_ENV, "dev")
    monkeypatch.setenv(publish_root.PUBLISH_DIR_ENV, str(tmp_path / "published"))


@dataclass
class Outcome:
    code: Any
    out: str
    err: str  # the error stream, plus what the command logged (a revert reports through its log)
    raised: BaseException | None

    @property
    def exited_non_zero(self) -> bool:
        """An exit status other than 0, or an exit text (which exits 1)."""
        return self.raised is None and self.code not in (0, None) and isinstance(self.code, str | int)

    @property
    def operator_text(self) -> str:
        return self.err + (self.code if isinstance(self.code, str) else "")

    @property
    def everything(self) -> str:
        return f"{self.code}\n{self.out}{self.operator_text}" + (f"\n{type(self.raised).__name__}: {self.raised}" if self.raised else "")


def _invoke(call: Callable[[], Any]) -> Outcome:
    out, err, logged = io.StringIO(), io.StringIO(), _Logged()
    logging.getLogger().addHandler(logged)
    raised: BaseException | None = None
    code: Any = None
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = call()
    except SystemExit as exited:
        code = exited.code
    except Exception as failed:  # noqa: BLE001 — past acceptance, the entry's next fault
        raised = failed
    finally:
        logging.getLogger().removeHandler(logged)
    return Outcome(code, out.getvalue(), err.getvalue() + "\n".join(logged.lines), raised)


Entry = Callable[[Any], Outcome]


def _entries(tmp_path: Path) -> dict[str, Entry]:
    """name -> `entry(directory) -> Outcome`, each the real `main` of an entry point for `TENANT`."""
    from defender import run as run_py
    from defender.cli import tenant as connect
    from defender.learning.branch import cli as branch_cli
    from defender.learning.core import cli as drain_cli

    alert = tmp_path / "alert.json"
    alert.write_text('{"rule": {"id": "r-1214"}, "alert_timestamp": "2026-10-28T00:00:00Z"}', encoding="utf-8")
    staged = tmp_path / "staged"
    (staged / "skills").mkdir(parents=True)
    (staged / "skills" / "note.md").write_text("note\n", encoding="utf-8")

    def run_seams() -> dict[str, Any]:
        calls = _Calls()
        return dict(preflight=calls.hook("preflight", 0), visualize=calls.hook("visualize", None),
                    enqueue=calls.hook("enqueue", False), publish=calls.hook("publish", ""),
                    lifecycle=calls.hook("lifecycle", {"output": "", "requests": 0, "truncated_by": None}))

    entries: dict[str, Entry] = {
        "run_start": lambda d: _invoke(lambda: run_py.main([str(alert), "--tenant", TENANT, "--no-learn"],
                                                           directory=d, **run_seams())),
        "sibling_run": lambda d: _invoke(lambda: run_py.main(
            ["--tenant", TENANT, "--episode", H.EPISODE_ID, "--world", "w-1214", "--no-learn"],
            directory=d, **run_seams())),
        "drain_start": lambda d: _invoke(lambda: drain_cli.main(["loop.py", "--author-drain", "--tenant", TENANT],
                                                                directory=d)),
        "launcher": lambda d: _invoke(lambda: branch_cli.main(
            ["--tenant", TENANT, H.RUN_ID, "1"], directory=d, spawn=_Calls().hook("spawn", 0),
            preflight=_Calls().hook("preflight", 0), render_page=_Calls().hook("render_page", None))),
    }
    for verb in ("update", "check", "propose"):
        argv = [verb, TENANT, *([str(staged)] if verb == "propose" else [])]
        entries[f"connect_{verb}"] = lambda d, argv=argv: _invoke(lambda: connect.main(argv, directory=d))
    for name, (_module, argv) in H.COMMANDS.items():
        entries[name] = lambda d, name=name, argv=argv: _invoke(lambda: H.command_main(name)(argv(TENANT), directory=d))
    return entries


ENTRY_NAMES = ["run_start", "sibling_run", "drain_start", "launcher", "connect_update", "connect_check",
               "connect_propose", *H.COMMANDS]


def _directory(data_root: Path, condition: str) -> Any:
    """`TENANT` as the tenant records hold it in `condition`, and the words the refusal must carry."""
    from defender.tenancy import InMemoryTenantRepository, TenantDirectory

    if condition == "no row":
        twin: Any = InMemoryTenantRepository()
        return TenantDirectory(lambda: twin)
    if condition == "no wiring":
        return active_directory(data_root, TENANT, wiring=False)
    return active_directory(data_root, TENANT, state=condition)


#: condition -> the fragments a refusal for it may carry beside the tenant id (any one of them): the state for a state, and
#: the base messages' own words for the two the records give no state for.
CONDITIONS = {
    "offboarding": ("offboarding",),
    "creating": ("creating",),
    "offboarded": ("offboarded",),
    "no row": ("not a tenant", "no such tenant", "no row", "unknown tenant"),
    "no wiring": ("no forge wiring", "forge wiring", "not bound to a forge"),
}


def _says(text: str, condition: str) -> str | None:
    """The fragment of `condition` that `text` carries, else None."""
    return next((word for word in CONDITIONS[condition] if word in text), None)


def test_every_entry_point_can_be_driven_here(tmp_path):
    """Control: the table covers the run, sibling, drain, launcher, connect verbs and all ten commands (r10 A1)."""
    assert set(_entries(tmp_path)) == set(ENTRY_NAMES)


@pytest.mark.parametrize("condition", list(CONDITIONS))
@pytest.mark.parametrize("name", ENTRY_NAMES)
def test_an_entry_point_refuses_a_tenant_that_may_not_be_worked_for_before_touching_its_folder(
        data_root, tmp_path, name, condition):
    """Not active, no row or no wiring: a non-zero exit, the tenant and a reason on the error stream and not on stdout, no
    tenant accepted or built, nothing of the tenant's folder touched, nothing left recorded (r10 O-A1, O-A6, C3)."""
    entry = _entries(tmp_path)[name]
    with H.watch_folder(data_root, TENANT) as control_touches:
        admitted = entry(active_directory(data_root, TENANT))
    assert _no_state_refusal(admitted.everything), f"control: an active tenant was refused: {admitted.everything}"
    assert control_touches, "control: an admitted entry reads the tenant's folder, so the watch can see a read"
    with H.watch_folder(data_root, TENANT) as touches, H.acceptance_calls() as calls:
        refused = entry(_directory(data_root, condition))
    assert refused.raised is None, f"a refusal must exit or return, not raise: {refused.everything}"
    assert refused.exited_non_zero, f"a refusal must exit non-zero, exited {refused.code!r}: {refused.everything}"
    assert TENANT in refused.operator_text, f"the tenant is not on the error stream: {refused.everything}"
    assert _says(refused.operator_text, condition), f"{condition!r} is not on the error stream: {refused.everything}"
    for word in (TENANT, *CONDITIONS[condition]):
        assert word not in refused.out, f"{word!r} went to stdout, where other tools read command output: {refused.out}"
    assert touches == [], f"the folder was touched before the state was judged: {[t[:2] for t in touches]}"
    assert (calls["accepted"], calls["built"]) == (0, 0), f"a refused tenant was accepted: {calls.counts}"
    assert H.recorded(data_root, TENANT) == []
    assert H.exclusive_free(data_root, TENANT)


@pytest.mark.parametrize("name", ENTRY_NAMES)
def test_an_admitted_entry_point_accepts_its_tenant_once_builds_one_and_reads_its_record_once(data_root, tmp_path, name):
    """One command accepts the folder once, builds one `Tenant` and reads the record once, counted by code object, so no
    spelling hides a second acceptance (r10.1 C1, A1)."""
    with H.acceptance_calls() as calls:
        outcome = _entries(tmp_path)[name](active_directory(data_root, TENANT))
    assert _no_state_refusal(outcome.everything), f"control: an active tenant was refused: {outcome.everything}"
    assert calls.counts == {"accepted": 1, "built": 1, "admission": 1}, calls.counts


@pytest.mark.parametrize("name", ENTRY_NAMES)
def test_an_entry_point_stays_recorded_and_locked_for_every_read_of_the_tenants_folder(data_root, tmp_path, name):
    """Every read of the tenant's folder by an admitted entry happens while this process is recorded under the tenant's
    host lock and the lock is held, and nothing stays recorded after (r10 O-A2: held for as long as the command works)."""
    with H.watch_folder(data_root, TENANT) as touches:
        outcome = _entries(tmp_path)[name](active_directory(data_root, TENANT))
    assert _no_state_refusal(outcome.everything), f"control: {outcome.everything}"
    assert touches, "control: the entry read the tenant's folder"
    unheld = [(event, path) for event, path, held in touches if held != (True, True)]
    assert unheld == [], f"the entry read the tenant's folder without holding its lock: {unheld[:3]}"
    assert H.recorded(data_root, TENANT) == []
    assert H.exclusive_free(data_root, TENANT)


def test_the_folder_watch_sees_every_kind_of_touch_by_path_or_by_descriptor_and_only_the_tenants_folder(data_root):
    """Self-test: every kind of touch in the folder, and a descriptor-relative leaf, is seen; a prefix-sharing sibling and
    the data root are not (r10 A1 observation)."""
    folder = data_root / TENANT
    sibling = data_root / f"{TENANT}-sibling"
    (sibling / "inner").mkdir(parents=True)
    with H.watch_folder(data_root, TENANT) as touches:
        (folder / "knowledge" / "agent" / ".tenant-id").read_text(encoding="utf-8")
        os.listdir(folder)
        list(os.scandir(folder))
        os.mkdir(folder / "new")
        os.rename(folder / "new", folder / "newer")
        os.chmod(folder / "newer", 0o700)
        os.utime(folder / "newer")
        os.rmdir(folder / "newer")
        (folder / "f").write_text("x", encoding="utf-8")
        os.remove(folder / "f")
        root_fd = os.open(data_root, os.O_RDONLY)
        try:
            os.close(os.open(TENANT, os.O_RDONLY, dir_fd=root_fd))
        finally:
            os.close(root_fd)
        (sibling / "inner").exists()
        os.listdir(sibling)
        (sibling / "g").write_text("x", encoding="utf-8")
    assert {event for event, _path, _held in touches} == {
        "open", "os.listdir", "os.scandir", "os.mkdir", "os.rename", "os.chmod", "os.utime", "os.rmdir", "os.remove"}
    assert not [path for _event, path, _held in touches if "sibling" in path or path == str(data_root)], touches
    assert (("open", TENANT)) in {(event, path) for event, path, _held in touches}, "the descriptor-relative open is missed"
    assert {held for _event, _path, held in touches} == {(False, False)}, "nothing is held here, and the sample says so"


#: A fault of the tenant's folder, by name: what it takes away (each leaves the rest of the folder as prepare made it).
FAULTS = ("settings half missing", "agent half missing", "folder not a directory", "folder absent")


def _faulted(data_root: Path, fault: str) -> None:
    """`TENANT`'s folder made whole, then broken as `fault` says."""
    folder = data_root / TENANT
    if folder.is_file():
        folder.unlink()
    shutil.rmtree(folder, ignore_errors=True)
    place_complete(data_root, TENANT)
    if fault == "settings half missing":
        shutil.rmtree(folder / "knowledge" / "settings")
    elif fault == "agent half missing":
        shutil.rmtree(folder / "knowledge" / "agent")
    else:
        shutil.rmtree(folder)
        if fault == "folder not a directory":
            folder.write_text("not a folder\n", encoding="utf-8")


@pytest.mark.parametrize("fault", FAULTS)
@pytest.mark.parametrize("name", ENTRY_NAMES)
def test_an_active_tenant_with_a_faulted_folder_is_refused_for_its_folder_not_its_state(data_root, tmp_path, name, fault):
    """An active tenant whose folder is faulted is refused naming the tenant and the folder, with no state words and no
    fault past acceptance, for each fault (r10 A1 step 5, O-A1)."""
    entry = _entries(tmp_path)[name]
    assert _no_state_refusal(entry(active_directory(data_root, TENANT)).everything), "control: the folder is sound"
    _faulted(data_root, fault)
    refused = entry(active_directory(data_root, TENANT))
    assert refused.raised is None, refused.everything
    assert refused.exited_non_zero, f"exit {refused.code!r}: {refused.everything}"
    text = refused.operator_text
    for word in (TENANT, str(data_root / TENANT)):
        assert word in text, f"the folder fault is not named ({word!r}): {refused.everything}"
    assert not any(word in text.lower() for word in NOT_A_REFUSAL_OF_STATE), text


@pytest.mark.parametrize("fault", FAULTS)
@pytest.mark.parametrize("name", ENTRY_NAMES)
def test_a_tenant_that_may_not_be_worked_for_is_refused_for_its_state_whatever_is_wrong_with_its_folder(
        data_root, tmp_path, name, fault):
    """Every non-active condition with every folder fault is refused naming the tenant and the state, never the folder, with
    the folder untouched: records before folder rules, however the folder is reached (r10 A1, O-A1)."""
    entry = _entries(tmp_path)[name]
    assert _no_state_refusal(entry(active_directory(data_root, TENANT)).everything), "control: the folder is sound"
    for condition in CONDITIONS:
        _faulted(data_root, fault)
        with H.watch_folder(data_root, TENANT) as touches:
            refused = entry(_directory(data_root, condition))
        where = f"{condition} with {fault}: {refused.everything}"
        assert refused.raised is None, where
        assert refused.exited_non_zero, where
        assert TENANT in refused.operator_text, where
        assert _says(refused.operator_text, condition), f"the state is not named; {where}"
        assert str(data_root / TENANT) not in refused.operator_text, f"the folder is named; {where}"
        assert touches == [], f"the folder was touched; {where}: {[t[:2] for t in touches]}"
        assert H.recorded(data_root, TENANT) == [], where
        assert H.exclusive_free(data_root, TENANT), where


# --- X-H1: no spelling of the acceptance escapes the census (C1, C2) ---------------------------------------------------

#: Each name of the acceptance machinery, with the modules that DEFINE or RE-EXPORT it (the only `tenancy/` modules that may
#: spell it) and the modules that may USE it. `_ACCEPTED` is the folder acceptance's token: nothing but the module that
#: defines it spells it.
_TENANCY_RAW = frozenset({"tenancy/_tenant.py", "tenancy/__init__.py"})
_HOST = frozenset({H.HOST_MODULE_PATH})
_ENTRIES = frozenset(H.ENTRY_POINT_MODULES)
_NAMES: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "accept_tenant": (_TENANCY_RAW, _HOST | H.A3_SET),
    "requested_tenant": (_TENANCY_RAW, _HOST | H.A3_SET),
    "accept_requested_tenant": (_TENANCY_RAW, _HOST | H.A3_SET),
    "admit_tenant": (frozenset({"tenancy/_admission.py", "tenancy/__init__.py"}), _HOST),
    "host_tenant": (frozenset(), _HOST | _ENTRIES),
    "host_directory": (frozenset({"tenancy/_admission.py", "tenancy/__init__.py"}), _HOST),
    "_ACCEPTED": (frozenset({"tenancy/_tenant.py"}), frozenset()),
    # the wrappers that survive (or may return) around the acceptance, and the opener of a run by its accepted tenant
    "resolve_tenant": (frozenset(), _HOST | _ENTRIES),
    "command_line_tenant": (frozenset(), _HOST | _ENTRIES),
    "command_line_paths": (frozenset(), _HOST | _ENTRIES),
    "open_command_line_run": (frozenset({"tenancy/_command_line_run.py", "tenancy/__init__.py"}), _ENTRIES | _HOST),
}
ACCEPTANCE_NAMES = frozenset(_NAMES)


def _mentions(tree: ast.AST) -> set[str]:
    """The acceptance names `tree` spells in any form: a name, an attribute (`pkg.requested_tenant(...)`, also on the
    result of a call such as `importlib.import_module(...)`), an import, a definition, or a string (a `getattr`
    constant, an `import_module` argument, a dotted path ending in the name)."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom | ast.Import):
            found |= {a.name.rpartition(".")[2] for a in node.names} & ACCEPTANCE_NAMES
        elif isinstance(node, ast.Name):
            found |= {node.id} & ACCEPTANCE_NAMES
        elif isinstance(node, ast.Attribute):
            found |= {node.attr} & ACCEPTANCE_NAMES
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            found |= {node.name} & ACCEPTANCE_NAMES
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            found |= {node.value.rpartition(".")[2]} & ACCEPTANCE_NAMES
    return found


def test_the_mention_census_sees_a_lazy_import_and_a_getattr_constant():
    """Self-test: a call through `import_module(...)` and a `getattr` on a string constant are both seen."""
    lazy = ast.parse("import importlib\nimportlib.import_module('defender.tenancy').requested_tenant(r, t)\n")
    assert _mentions(lazy) == {"requested_tenant"}
    named = ast.parse("getattr(importlib.import_module('defender.systems.run_tenant'), 'host_tenant')(r, t)\n")
    assert _mentions(named) == {"host_tenant"}
    assert _mentions(ast.parse("tenant = admitted.tenant\n")) == set()


def test_the_acceptance_names_are_spelled_only_where_the_design_puts_them():
    """C1/C2: the raw acceptance, its wrappers and its token are spelled in production only by the modules that define or
    re-export them and by the host module and the starter-covered set; the host acceptance only in the host module and the
    entry modules. Any spelling counts, so a lazy import or a `getattr` constant cannot hide a second acceptance. The names
    of wrappers that may no longer exist (`resolve_tenant`, ...) are a tripwire only; the reachability census below is the
    real C2(1) guard for wrappers."""
    where: dict[str, set[str]] = {name: set() for name in ACCEPTANCE_NAMES}
    production = _production()
    for rel, tree in production.items():
        for name in _mentions(tree):
            where[name].add(rel)
    for name in ("host_tenant", "accept_tenant", "requested_tenant", "_ACCEPTED", "host_directory"):
        assert where[name], f"control: {name} is spelled somewhere"
    stray = {name: sorted(where[name] - homes - users) for name, (homes, users) in _NAMES.items()}
    assert {name: rels for name, rels in stray.items() if rels} == {}
    assert where["host_tenant"] >= _ENTRIES, "an entry module no longer opens the host acceptance"
    # every function that reaches the raw acceptance from the `tenancy` package or the host module is a name this table knows
    wrappers = {name for rel, name in _reaching(production) if not name.startswith("_")
                and (rel.startswith("tenancy/") or rel == H.HOST_MODULE_PATH)}
    assert wrappers <= ACCEPTANCE_NAMES, f"a wrapper of the acceptance the census does not name: {sorted(wrappers - ACCEPTANCE_NAMES)}"


# --- X-H4: the scaffold validator never asks the tenant records (A3, O-A4) ---------------------------------------------

@pytest.mark.parametrize("database", ["unset", "unreachable"])
def test_the_scaffold_validator_checks_the_config_without_asking_the_tenant_records(tmp_path, database):
    """The validator, run as the connect agent runs it, checks the tenant's config with the database address unset or
    pointing at nothing, and its output names no records and no database (r10 A3, O-A4: advisory, no admission)."""
    from defender.skills.connect import validate_scaffold
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as S

    root = tmp_path / "data"
    S.adopted(root)
    extra = {} if database == "unset" else {"DEFENDER_DATABASE_DSN": "postgresql://nobody:not-the-password@127.0.0.1:1/postgres"}
    proc = S.run_script(S.script_of(validate_scaffold), "cmdb", "--tenant", S.TID, root=root,
                        unset=("DEFENDER_DIR", "DEFENDER_DATABASE_DSN"), **extra)
    S.assert_ran(proc)
    text = S.output(proc)
    assert "config.env" in text, f"the tenant's config was not checked: {text}"
    assert "could not be resolved" not in text, text
    for word in ("database", "records"):
        assert word not in text.lower(), f"the validator asked the tenant records: {text}"
