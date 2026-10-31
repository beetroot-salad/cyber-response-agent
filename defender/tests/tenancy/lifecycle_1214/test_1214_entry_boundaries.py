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
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.tenancy import _host1214 as H
from defender.tests.support.tenancy._active1214 import active_directory
from defender.tests.tenancy.lifecycle_1214.test_1214_host_entry import (
    NOT_A_REFUSAL_OF_STATE,
    TENANT,
    _Calls,
    _Logged,
    _no_state_refusal,
    _production,
    _tenant_placed,  # noqa: F401 — autouse fixture
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
            ["--tenant", TENANT, "--episode", "ep-1214", "--world", "w-1214", "--no-learn"],
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


#: condition -> the words a refusal for it carries beside the tenant id.
CONDITIONS = {
    "offboarding": "offboarding",
    "creating": "creating",
    "offboarded": "offboarded",
    "no row": "not a tenant of this deployment",
    "no wiring": "no forge wiring",
}


def test_every_entry_point_can_be_driven_here(tmp_path):
    """Control: the table covers the run, sibling, drain, launcher, connect verbs and all ten commands (r10 A1)."""
    assert set(_entries(tmp_path)) == set(ENTRY_NAMES)


@pytest.mark.parametrize("condition", list(CONDITIONS))
@pytest.mark.parametrize("name", ENTRY_NAMES)
def test_an_entry_point_refuses_a_tenant_that_may_not_be_worked_for_before_touching_its_folder(
        data_root, tmp_path, name, condition):
    """Not active, no row, or no wiring: a non-zero exit, tenant and reason on the error stream and not on stdout,
    nothing under the tenant's folder opened or listed, nothing left recorded (r10 O-A1, O-A6, C3)."""
    entry = _entries(tmp_path)[name]
    with H.watch_folder(data_root, TENANT) as control_touches:
        admitted = entry(active_directory(data_root, TENANT))
    assert _no_state_refusal(admitted.everything), f"control: an active tenant was refused: {admitted.everything}"
    assert control_touches, "control: an admitted entry reads the tenant's folder, so the watch can see a read"
    with H.watch_folder(data_root, TENANT) as touches:
        refused = entry(_directory(data_root, condition))
    assert refused.raised is None, f"a refusal must exit or return, not raise: {refused.everything}"
    assert refused.exited_non_zero, f"a refusal must exit non-zero, exited {refused.code!r}: {refused.everything}"
    for word in (TENANT, CONDITIONS[condition]):
        assert word in refused.operator_text, f"{word!r} is not on the error stream: {refused.everything}"
        assert word not in refused.out, f"{word!r} went to stdout, where other tools read command output: {refused.out}"
    assert touches == [], f"the folder was touched before the state was judged: {[t[:2] for t in touches]}"
    assert H.recorded(data_root, TENANT) == []
    assert H.exclusive_free(data_root, TENANT)


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


@pytest.mark.parametrize("name", ENTRY_NAMES)
def test_an_active_tenant_with_a_faulted_folder_is_refused_for_its_folder_not_its_state(data_root, tmp_path, name):
    """The folder rules judge every entry point's tenant: a knowledge folder missing its settings half is refused
    naming the folder, with no state words and no fault past acceptance (r10 A1 step 5, O-A1)."""
    entry = _entries(tmp_path)[name]
    assert _no_state_refusal(entry(active_directory(data_root, TENANT)).everything), "control: the folder is sound"
    shutil.rmtree(data_root / TENANT / "knowledge" / "settings")
    refused = entry(active_directory(data_root, TENANT))
    assert refused.raised is None, refused.everything
    assert refused.exited_non_zero, f"exit {refused.code!r}: {refused.everything}"
    text = refused.operator_text
    for word in ("settings/ half", TENANT):
        assert word in text, f"the folder fault is not named ({word!r}): {refused.everything}"
    assert not any(word in text.lower() for word in NOT_A_REFUSAL_OF_STATE), text


# --- X-H1: no spelling of the acceptance escapes the census (C1, C2) ---------------------------------------------------

ACCEPTANCE_NAMES = frozenset({"accept_tenant", "requested_tenant", "accept_requested_tenant", "host_tenant", "admit_tenant"})


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
    """C1/C2: the raw acceptance and its wrappers are spelled in production only in `tenancy/`, the host module and the
    starter-covered set; the host acceptance only in the host module and the entry modules. Any spelling counts, so a
    lazy import or a `getattr` cannot hide a second acceptance."""
    where: dict[str, set[str]] = {name: set() for name in ACCEPTANCE_NAMES}
    for rel, tree in _production().items():
        for name in _mentions(tree):
            where[name].add(rel)
    assert where["host_tenant"], "control: the host acceptance is spelled somewhere"
    assert where["accept_tenant"], "control: the raw acceptance is spelled somewhere"
    assert where["requested_tenant"], "control: its wrapper is spelled somewhere"

    def outside(name: str, *allowed: Any) -> list[str]:
        return sorted(rel for rel in where[name] if not rel.startswith("tenancy/") and rel not in set().union(*allowed))
    host = {H.HOST_MODULE_PATH}
    assert outside("accept_tenant", host, H.A3_SET) == []
    assert outside("requested_tenant", host, H.A3_SET) == []
    assert outside("accept_requested_tenant", host, H.A3_SET) == []
    assert outside("admit_tenant", host) == []
    assert outside("host_tenant", host, set(H.ENTRY_POINT_MODULES)) == []
    assert where["host_tenant"] >= set(H.ENTRY_POINT_MODULES), "an entry module no longer opens the host acceptance"


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
