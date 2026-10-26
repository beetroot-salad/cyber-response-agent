"""The `defender/records/` package door: lazy PEP 562 surface, layout names load without pydantic, import retry, box-bind boundary, frozen handle."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base, location_path

import ast
import json
import os
import subprocess
import sys
from pathlib import Path
from defender.tests.support.shared._fixture_uuid import fixture_uuid


from defender.tests.support.shared.contracts._import_blocker import run_blocked
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H

#: The layout's 10 public IMPORTED names, which the door does not serve (D1.3, R4-42).
LAYOUT_IMPORTED = ("ALIAS_READ_REFUSAL", "Path", "PurePosixPath", "annotations", "dataclasses",
                   "errno", "is_plain_entry", "re", "refuse_bad_case_id", "stat")
#: The private layout helpers `episodes/_episode_paths.py` imports from the submodule (R4-27).
PRIVATE_HELPERS = ("_check_component", "_check_index", "_confine")


def _child_env() -> dict[str, str]:
    """The child's environment: this worktree first on PYTHONPATH (RG-09-a), then whatever
    the parent already carries."""
    inherited = os.environ.get("PYTHONPATH", "")
    return {**os.environ,
            "PYTHONPATH": os.pathsep.join(p for p in (str(H.WORKTREE), inherited) if p)}


def _child(body: str, *, block: tuple[str, ...] = ()) -> subprocess.CompletedProcess[bytes]:
    if block:
        return run_blocked(body, block=block, cwd=H.WORKTREE, env=_child_env())
    return subprocess.run([sys.executable, "-c", body], capture_output=True, check=False,
                          cwd=str(H.WORKTREE), env=_child_env(), timeout=180)


def _out(proc: subprocess.CompletedProcess[bytes]) -> str:
    return proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")


def _type_checking_imports(tree: ast.Module, package: str) -> list[tuple[str, str]]:
    """`(bound name, source module)` for every from-import under `if TYPE_CHECKING:`."""
    out: list[tuple[str, str]] = []
    for node in tree.body:
        if not isinstance(node, ast.If):
            continue
        test = node.test
        name = test.id if isinstance(test, ast.Name) else getattr(test, "attr", None)
        if name != "TYPE_CHECKING":
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.ImportFrom):
                module = sub.module or ""
                if sub.level:
                    base = package.rsplit(".", sub.level - 1)[0] if sub.level > 1 else package
                    module = f"{base}.{module}" if module else base
                out += [(a.asname or a.name, module) for a in sub.names]  # lint-ast-resolve: ok — test helper over its own fixture source; no scoping to resolve
    return out


_DOOR = "defender.records"


def test_1105_run_refused_is_a_plain_exception_distinct_from_tenant_refused():
    from defender.tenancy._tenant import TenantRefused
    from defender.records import RunRefused

    assert isinstance(RunRefused, type), f"the door's RunRefused is not an Exception class: {RunRefused!r}"
    assert issubclass(RunRefused, Exception), f"the door's RunRefused is not an Exception class: {RunRefused!r}"
    assert not issubclass(RunRefused, ValueError), "RunRefused must not be a ValueError (OP-5)"
    assert not issubclass(RunRefused, TenantRefused), "RunRefused must not be a TenantRefused"
    assert not issubclass(TenantRefused, RunRefused), "TenantRefused must not be a RunRefused"

    def catches(raised_cls: type, handler: type) -> bool:
        try:
            raise raised_cls("refused")
        except handler:
            return True
        except Exception:  # noqa: BLE001 — the point: did the narrower handler catch it?
            return False

    assert catches(RunRefused, RunRefused), "positive control: each handler catches its own error"
    assert catches(TenantRefused, TenantRefused), "positive control: each handler catches its own error"
    assert not catches(RunRefused, TenantRefused), "an except TenantRefused caught RunRefused"
    assert not catches(TenantRefused, RunRefused), "an except RunRefused caught TenantRefused"
    assert not catches(RunRefused, ValueError), "an except ValueError caught RunRefused"


def test_1105_the_doors_all_its_type_checking_names_and_its_getattr_names_are_one_set():
    import importlib

    from defender import records as door

    all_names = list(door.__all__)
    assert all_names, f"__all__ is empty or holds duplicates: {all_names[:5]}"
    assert len(all_names) == len(set(all_names)), f"__all__ is empty or holds duplicates: {all_names[:5]}"
    tree = ast.parse((H.PACKAGE / "__init__.py").read_text(encoding="utf-8"))
    declared = _type_checking_imports(tree, _DOOR)
    declared_names = [n for n, _ in declared]
    assert len(declared_names) == len(set(declared_names)), "a TYPE_CHECKING name is duplicated"
    assert set(declared_names) == set(all_names), (
        f"TYPE_CHECKING declares {sorted(set(declared_names) ^ set(all_names))} differently "
        "from __all__ (mypy would type an undeclared door name as Any, R4-30)")
    # `annotations` is left out: the door's own `from __future__ import annotations` binds it.
    probes = set(all_names) | set(declared_names) | set(LAYOUT_IMPORTED) | set(PRIVATE_HELPERS)
    probes = (probes | {"NotAName", "Tenant", "hold"}) - {"annotations"}
    served = {n for n in probes if H.raised(getattr, door, n) is None}
    assert served == set(all_names), (
        f"__getattr__ serves {sorted(served ^ set(all_names))} differently from __all__")
    for name, module in declared:
        own = getattr(importlib.import_module(module), name)
        assert getattr(door, name) is own, f"door.{name} is not {module}.{name} itself"
    for name in ("NotAName", "Path", "_check_component", "refuse_bad_case_id"):
        assert isinstance(H.raised(getattr, door, name), AttributeError), (
            f"__getattr__ did not raise AttributeError for {name!r}")


def test_1105_a_layout_name_from_the_door_loads_the_layout_submodule_alone_without_pydantic():
    from defender.records import RUN_LAYOUT, RunPaths

    probe = (
        "import json, sys\n"
        "from defender.records import RunPaths, RUN_LAYOUT\n"
        "mods = sorted(sys.modules)\n"
        "print(json.dumps({'layout': 'defender.records._layout' in mods,\n"
        "  'handle': 'defender.records._handle' in mods,\n"
        "  'tenant': 'defender.tenancy._tenant' in mods,\n"
        "  'pydantic': [m for m in mods if m.split('.')[0].startswith('pydantic')],\n"
        "  'alert': str(RUN_LAYOUT.alert), 'paths': RunPaths.__name__}))\n")
    proc = _child(probe, block=("pydantic*",))
    assert proc.returncode == 0, f"the layout names do not import without pydantic: {_out(proc)}"
    seen = json.loads(proc.stdout.decode("utf-8"))
    assert seen["layout"], f"the layout submodule did not load: {seen}"
    assert not seen["handle"], f"a layout name loaded more than the layout (R4-6): {seen}"
    assert not seen["tenant"], f"a layout name loaded more than the layout (R4-6): {seen}"
    assert not seen["pydantic"], f"a layout name loaded more than the layout (R4-6): {seen}"
    assert seen["alert"] == str(RUN_LAYOUT.alert) == "alert_input/alert.json", (
        f"the child's RUN_LAYOUT is not the door's: {seen}")
    assert seen["paths"] == RunPaths.__name__ == "RunPaths", f"the child's RunPaths: {seen}"
    # #1187 declared change 1: `RunId` admits only canonical lowercase uuid4 text.
    rid = fixture_uuid("package-pydantic-free")
    proc = _child("from defender.records import RunId, RunRefused\n"
                  f"print(RunId.parse({rid!r}), RunRefused.__name__)\n", block=("pydantic*",))
    assert proc.returncode == 0, f"RunId and RunRefused must import pydantic-free (NM-05): {_out(proc)}"
    assert _out(proc).split()[:2] == [rid, "RunRefused"], f"RunId and RunRefused must import pydantic-free (NM-05): {_out(proc)}"
    proc = _child("import defender.records as rr\n"
                  "missing = [n for n in rr.__all__ if getattr(rr, n, None) is None]\n"
                  "print(len(rr.__all__), missing)\n")
    assert proc.returncode == 0, f"not every public name imports in a fresh interpreter: {_out(proc)}"
    # F18(b): the door's count as the flipped `__all__` test above pins it (#1187 R6; +1 for #1279's `sidecar_names`).
    assert _out(proc).split()[0] == "72", f"not every public name imports in a fresh interpreter: {_out(proc)}"
    assert "[]" in _out(proc), f"not every public name imports in a fresh interpreter: {_out(proc)}"



def test_1105_a_failed_first_import_through_the_door_propagates_and_is_retried():
    from defender.records import Run

    probe = (
        "import json, sys\n"
        "import defender.records as rr\n"
        "first = None\n"
        "try:\n"
        "    rr.Run\n"
        "except ImportError as e:\n"
        "    first = type(e).__name__\n"
        "sys.meta_path[:] = [f for f in sys.meta_path if type(f).__name__ != '_Blocker']\n"
        "second = rr.Run\n"
        "print(json.dumps({'first': first, 'second': getattr(second, '__name__', None),\n"
        "                  'module': getattr(second, '__module__', None)}))\n")
    proc = _child(probe, block=("pydantic*",))
    assert proc.returncode == 0, f"the retry raised: {_out(proc)}"
    seen = json.loads(proc.stdout.decode("utf-8"))
    assert seen["first"] in ("ModuleNotFoundError", "ImportError"), (
        f"reading Run with pydantic blocked did not propagate the import error: {seen}")
    assert seen["second"] == Run.__name__, f"the second read did not return the handle's Run — the failure was cached: {seen}"
    assert (seen["module"] == Run.__module__ == (
            f"{_DOOR}._handle")), f"the second read did not return the handle's Run — the failure was cached: {seen}"


def test_1105_no_box_bind_reaches_the_episode_records_or_the_tenant_record(tmp_path):
    from defender.records import RunId
    from defender.box import BoxSpec
    from defender.box._lifecycle import _create_argv, _run_lane_mounts

    t = H.tenant(tmp_path / "data", H.T_ID)
    runs = H.runs_folder(t)
    rid, neighbour = fixture_uuid("box-bind-run"), fixture_uuid("box-bind-neighbour")
    H.make_run(runs, rid)
    H.make_run(runs, neighbour)
    from defender.tests.support.storage._alert_plant import plant_alert
    plant_alert(runs / rid)
    run = t.runs_repository().open(RunId.parse(rid))
    assert getattr(run, "run_dir", None) == runs / rid, f"runs.open handed out {run!r}"
    create = _create_argv("defender-run-r1", run.run_dir, H.DEFENDER, BoxSpec(runtime="runc", rootfs="busybox"), lane=_run_lane_mounts(run.run_dir, H.DEFENDER, t.agent))
    argv = create.argv
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
    binds = []
    for spec in mounts:
        fields = dict(f.split("=", 1) for f in spec.split(",") if "=" in f)
        binds.append((Path(fields["source"]), "readonly" in spec.split(",")))
    writable = [src for src, ro in binds if not ro]
    assert writable == [runs / rid], (
        f"the box's writable binds are {writable}, not exactly the run's own folder")
    for protected in (runs, runs / neighbour):
        under = [src for src in writable if protected == src or src in protected.parents]
        assert under == [], f"{protected} sits under a writable box bind: {under}"
    assert "--read-only" in argv, "the box's own root is read-only"



def test_1105_a_handles_address_is_frozen_after_init(tmp_path):
    from defender.records import Run

    # #1187: a uuid run id (declared change 1) in a container with no record (R1); the
    # record-reading `Run.for_tenant` goes (R1), `Run.under` is its replacement.
    runs = tmp_path / H.T_ID / "runs"
    rid = fixture_uuid("package-frozen")
    run_dir = H.make_run(runs, rid)
    for run in (Run.under(fixture_runs_base(runs), rid, tenant_id=H.T_ID),
                Run(run_dir, runs_base=fixture_runs_base(runs), tenant_id=H.T_ID)):
        for attr, value in (("run_dir", tmp_path / "elsewhere"), ("runs_base", tmp_path),
                            ("tenant_id", H.U_ID)):
            err = H.raised(setattr, run, attr, value)
            assert isinstance(err, AttributeError), f"assigning {attr} gave {err!r}"
            err = H.raised(delattr, run, attr)
            assert isinstance(err, AttributeError), f"deleting {attr} gave {err!r}"
        assert (run.run_dir, location_path(run.runs_base), run.tenant_id) == (run_dir, runs, H.T_ID), (
            "the address changed")
        run.partial_failures = ("noted",)
        assert run.partial_failures == ("noted",), "partial_failures stays the handle's state"
        for group in ("tables", "facts", "documents", "observability", "session"):
            assert getattr(run, group, None) is not None, f"the {group} group is gone"
            setattr(run, group, getattr(run, group))
    at = Run.at(run_dir)
    err = H.raised(setattr, at, "tenant_id", H.T_ID)
    assert isinstance(err, AttributeError), f"a Run.at handle took a tenant_id: {err!r}"
    assert not hasattr(at, "tenant_id"), "a Run.at handle has no tenant_id"
    err = H.raised(setattr, at, "run_dir", tmp_path)
    assert isinstance(err, AttributeError), f"a Run.at handle's run_dir moved: {err!r}"
