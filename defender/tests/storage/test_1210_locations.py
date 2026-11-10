"""#1210: opaque locations plus structural ownership across Python call boundaries."""
from __future__ import annotations

import ast
from dataclasses import asdict
from os import fspath
import subprocess
from pathlib import Path

import pytest

from defender.records import _locations as L
from defender.tests.support.shared.contracts._by_path import load_lint_gate
from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

ROOT = Path(__file__).resolve().parents[3]
TYPES = [value for name, value in vars(L).items()
         if isinstance(value, type) and issubclass(value, L._Location) and name != "_Location"]


@pytest.mark.parametrize("kind", TYPES, ids=lambda kind: kind.__name__)
def test_locations_do_not_implement_filesystem_operations(kind, tmp_path):
    value = kind(tmp_path / "private-root")
    assert str(tmp_path) not in str(value)
    assert str(tmp_path) not in repr(value)
    with pytest.raises(TypeError):
        value / "child"
    with pytest.raises(TypeError):
        Path(value)
    with pytest.raises(TypeError):
        fspath(value)
    with pytest.raises(TypeError):
        asdict(value)
    assert not hasattr(value, "parent")
    assert not hasattr(value, "joinpath")
    with pytest.raises((AttributeError, TypeError)):
        value._record_location_path = tmp_path


def findings(rel: str, source: str) -> list[str]:
    gate = load_lint_gate("lint_run_records", name="locations_1210_gate")
    return [f.display for f in gate._scan_location_pass(rel, ast.parse(source), source.splitlines())]


def test_every_record_location_is_rejected_without_receiver_tracking():
    gate = load_lint_gate("lint_run_records", name="locations_1210_names")
    for attr in gate.RECORD_LOCATION_NAMES:
        found = findings("investigation/probe.py", f"def f(anything):\n    return anything.{attr}\n")
        assert any(f"owner-only record location (.{attr})" in line and ":2 " in line for line in found)
    assert findings("investigation/probe.py", "def f(t):\n    return t.knowledge / 'child'\n") == []


@pytest.mark.parametrize("source", [
    "from defender.tenancy._tenant import unwrap_data_root as raw\ndef f(value):\n    return raw(value)\n",
    "import defender.records._layout as layout\ndef f(path):\n    return layout.RunsBase(path)\n",
    "from defender.records._locations import unwrap_learning_root as raw\ndef f(value):\n    return raw(value)\n",
    "from defender.records import _locations as loc\ndef f(value):\n    convert = loc.unwrap_learning_root\n    return convert(value)\n",
    "def f(value):\n    return value._record_location_path\n",
    "def f(value):\n    return value.__reduce__()[1][0]\n",
    "def f(value):\n    return value.__getstate__()\n",
    "from defender.records._locations import LearningRoot\ndef f(value, path):\n    if isinstance(value, (alias := LearningRoot)):\n        return alias(path)\n",
    "from typing import Annotated\nfrom defender.records._locations import unwrap_learning_root as raw\ndef f(value: Annotated[object, raw(outside)]):\n    return value\n",
    "from defender.records._locations import LearningRoot as Root\nconstructor = Root\n",
    "def f(runs_base):\n    return runs_base\n",
    "def f(value):\n    return value.run_end_sidecar(value.parent)\n",
])
def test_unsafe_references_are_rejected_even_without_types(source):
    assert findings("investigation/probe.py", source)


def test_type_annotations_and_safe_forwarding_remain_legal():
    assert findings("investigation/probe.py", "from defender.records._locations import LearningRoot as R\ndef f(value: R) -> R:\n    return value\n") == []


def test_conversion_permissions_are_function_and_role_specific():
    """(#1278 O10: the learning folder's one converter, `LearningState.open`, is gone with the handle; the same rule is shown
    on the curators' call-folder owner, a converter that stays.)"""
    source = "from defender.records._locations import unwrap_scratch_root as raw\ndef call_folder(value):\n    return raw(value)\ndef unrelated(value):\n    return raw(value)\n"
    found = findings("learning/call_folders.py", source)
    assert len(found) == 1
    assert "unrelated()" in found[0]
    wrong_role = source.replace("unwrap_scratch_root", "unwrap_data_root")
    assert len(findings("learning/call_folders.py", wrong_role)) == 2
    assert findings("tenancy/_tenant.py", "def f(value):\n    return value._record_location_path\n")


def test_conversion_defaults_do_not_inherit_body_permissions():
    source = "from defender.records._locations import unwrap_scratch_root as raw\ndef call_folder(value=raw(outside)):\n    return raw(value)\n"
    found = findings("learning/call_folders.py", source)
    assert len(found) == 1
    assert ":2 " in found[0]


def test_all_declared_storage_boundaries_have_narrow_permissions():
    gate = load_lint_gate("lint_run_records", name="locations_1210_matrix")
    for (role, rel), functions in gate.CONVERSION_PERMISSIONS.items():
        for qualified in functions:
            prefix = f"from defender.records._locations import unwrap_{role} as raw\n"
            if "." in qualified:
                cls, method = qualified.split(".")
                source = prefix + f"class {cls}:\n    def {method}(self, value):\n        return raw(value)\n"
            else:
                source = prefix + f"def {qualified}(value):\n    return raw(value)\n"
            assert findings(rel, source) == [], (role, rel, qualified)
            assert findings("investigation/unrelated.py", source), (role, qualified)


def test_tenant_and_hidden_carriers_preserve_location_roles(tmp_path):
    from defender.records import RunPaths

    tenant = set_up_tenant(tmp_path / "data")
    expected = {
        "data_root": L.DataRoot, "tenant_root": L.TenantRoot,
        "runs": L.RunsBase, "sessions": L.SessionsRoot, "episodes": L.EpisodesRoot,
        "learning": L.LearningRoot, "worktrees": L.WorktreesRoot, "scratch": L.ScratchRoot, "exports": L.ExportsRoot,
        "drafts": L.DraftsRoot, "knowledge_lock": L.KnowledgeLock,
        "runs_legacy": L.LegacyRunsRoot,
        "episodes_legacy": L.LegacyEpisodesRoot,
    }
    for name, kind in expected.items():
        assert isinstance(getattr(tenant, name), kind), name
    assert not hasattr(tenant, "dir")
    sessions = RunPaths(tmp_path / "runs" / "run").session_paths()
    assert isinstance(sessions.runs_base, L.RunsBase)
    assert isinstance(sessions.store("case-alpha")[1], L.SessionTrustRoot)
    with tenant.runs_repository().create_episode() as episode:
        assert isinstance(episode._folder, L.RunsBase)
    from defender import _io
    from defender.records._held import plan_retire

    with plan_retire(tenant, tmp_path / "external-archive", io=_io) as plan:
        assert isinstance(plan.lanes[0].source_path, L.RunsBase)
        assert isinstance(plan.lanes[0].destination, L.LegacyRunsRoot)
        assert isinstance(plan.lanes[1].destination, L.LegacyEpisodesRoot)


# retired: test_tenant_and_scratch_state_cannot_exchange_location_kinds pinned `LoopPaths`' two spellings of the learning
# state root (a tenant's `LearningRoot`, a scratch `Path`). The handle and the root are gone (#1278 A1/O10, design D10): a
# `LoopPaths` names no state root; the tenant's `learning` stays a `LearningRoot` (asserted above) for the cutover import only.


def test_mypy_reports_the_actual_forbidden_operations(tmp_path):
    source = '''from pathlib import Path
from os import fspath
from defender.records._locations import LearningRoot, RunsBase

def forward(value: LearningRoot) -> LearningRoot:
    return value

async def async_forward(value: LearningRoot) -> LearningRoot:
    return forward(value)

def needs_runs(value: RunsBase) -> None:
    pass

def invalid(value: LearningRoot) -> None:
    alias = forward(value)
    values = [alias]
    values[0] / 'child'  # bad-join
    Path(alias)  # bad-path
    fspath(alias)  # bad-fspath
    needs_runs(alias)  # bad-role

async def invalid_async(value: LearningRoot) -> None:
    alias = await async_forward(value)
    alias / 'child'  # bad-async
'''
    probe = tmp_path / "probe.py"
    probe.write_text(source)
    result = subprocess.run([str(ROOT / "defender/.venv/bin/mypy"), "--config-file", str(ROOT / "defender/pyproject.toml"), "--cache-dir", str(tmp_path / "cache"), str(probe)], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert result.returncode == 1, result.stdout + result.stderr
    for marker in ("bad-join", "bad-path", "bad-fspath", "bad-role", "bad-async"):
        line = next(i for i, text in enumerate(source.splitlines(), 1) if marker in text)
        assert f"probe.py:{line}: error:" in result.stdout, result.stdout
    assert "Found 5 errors" in result.stdout, result.stdout
