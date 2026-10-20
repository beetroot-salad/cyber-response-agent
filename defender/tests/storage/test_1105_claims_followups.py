"""Run-record refusals stay one line under a forged folder name; the run-layout lint reports unparseable modules."""
from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

from defender import run_repository as R
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.support.shared._fixture_uuid import fixture_uuid

_FORGED = "x\nFORGED LINE: all good"


def _tenant_under_a_hostile_folder(tmp_path: Path):
    t = H.tenant(tmp_path / _FORGED)
    runs = Path(t.runs)
    runs.mkdir(parents=True)
    return t, runs


def _one_line(exc: BaseException) -> str:
    text = str(exc)
    assert "\n" not in text, f"the refusal broke its line: {text!r}"
    assert "\r" not in text, f"the refusal broke its line: {text!r}"
    return text


def test_a_lookup_refusal_under_a_folder_with_a_newline_stays_one_line(tmp_path):
    t, runs = _tenant_under_a_hostile_folder(tmp_path)
    (runs / "stray").write_text("x", encoding="utf-8")
    with pytest.raises(R.RunRefused) as stray:
        t.runs_repository().list()
    _one_line(stray.value)
    (runs / "stray").unlink()
    with pytest.raises(R.RunRefused) as absent:
        t.runs_repository().open(R.RunId.parse(fixture_uuid("claims-followups-absent")))
    _one_line(absent.value)


def _lint():
    path = H.WORKTREE / "tooling" / "lint" / "lint_run_layout_imports.py"
    sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location("_lint_run_layout_imports_1105f", path)
        assert spec is not None
        assert spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod  # its dataclasses resolve their module by name
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path.remove(str(path.parent))


def test_the_layout_lint_reports_a_module_too_deep_to_parse(tmp_path):
    root = tmp_path / "defender"
    shutil.copytree(H.PACKAGE, root / "run_repository",
                    ignore=shutil.ignore_patterns("__pycache__"))
    deep = root / "hooks" / "deep.py"
    deep.parent.mkdir(parents=True)
    deep.write_text("x = " + "+".join(["1"] * 20000) + "\n", encoding="utf-8")
    findings = _lint().scan(root, allow_list=[])
    shown = [f.display for f in findings]
    assert any("hooks/deep.py" in d and "RecursionError" in d for d in shown), shown


def _package_copy(tmp_path):
    root = tmp_path / "defender"
    shutil.copytree(H.PACKAGE, root / "run_repository",
                    ignore=shutil.ignore_patterns("__pycache__"))
    return root


def test_the_layout_lint_reports_a_module_that_parses_but_is_too_deep_to_walk(tmp_path):
    root = _package_copy(tmp_path)
    deep = root / "hooks" / "deep.py"
    deep.parent.mkdir(parents=True)
    deep.write_text("x = " + "+".join(["1"] * 1500) + "\n", encoding="utf-8")
    findings = _lint().scan(root, allow_list=[])
    shown = [f.display for f in findings]
    assert any("hooks/deep.py" in d and "too deeply" in d for d in shown), shown


@pytest.mark.parametrize("state", ["missing", "empty"])
def test_the_layout_lint_with_no_layout_universe_is_a_finding(tmp_path, state):
    """No `_layout.py`, or one binding nothing, gates no name: the sweep reports it rather than
    passing everything."""
    root = _package_copy(tmp_path)
    layout = root / "run_repository" / "_layout.py"
    if state == "missing":
        layout.unlink()
    else:
        layout.write_text("", encoding="utf-8")
    findings = _lint().scan(root, allow_list=[])
    assert any("_layout.py" in f.display for f in findings), [f.display for f in findings]


def _plant(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_the_layout_lint_follows_a_layout_name_through_a_relay_module(tmp_path):
    """A layout name read off a module that re-binds it (`relay.ALERT`) is the door's name: the
    xhigh review's bypass, where only a read off the door itself was flagged."""
    root = _package_copy(tmp_path)
    _plant(root, "learning/relay.py", "from defender.run_repository import ALERT, RUN_LAYOUT\n")
    _plant(root, "learning/probe_relay.py",
           "from defender.learning import relay as ep\n\n\n"
           "def f(d):\n    return d / ep.ALERT, ep.RUN_LAYOUT.report\n")
    shown = [f.display for f in _lint().scan(root, allow_list=[])]
    hits = [d for d in shown if "learning/probe_relay.py" in d]
    assert any("ALERT" in d for d in hits), shown
    assert any("RUN_LAYOUT" in d for d in hits), shown


@pytest.mark.parametrize(("rel", "text"), [
    ("runtime/rel2.py", "from .. import run_repository as rr\n\n\ndef f(d):\n    return rr.RunPaths(d)\n"),
    ("learning/branch/rel1.py",
     "from ... import run_repository\n\n\ndef f(d):\n    return run_repository.RunPaths(d)\n"),
    ("runtime/rel3.py", "from ..run_repository import ALERT\n"),
])
def test_the_layout_lint_resolves_a_relative_import_as_the_absolute_one(tmp_path, rel, text):
    """The xhigh review's case: a layout name reached through a relative import is the same
    name its absolute spelling is (the scope tree is built knowing the module's package)."""
    root = _package_copy(tmp_path)
    _plant(root, rel, text)
    shown = [f.display for f in _lint().scan(root, allow_list=[])]
    assert [d for d in shown if rel in d], shown
