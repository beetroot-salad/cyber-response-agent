"""The gate that holds #1127's "no YAML the tree reads may reuse a node by alias": lint_raw_yaml.

`defender/_yaml.py` refuses aliases on every read and never writes one. A raw PyYAML load
accepts aliases again and a raw PyYAML dump writes them, so either reopens the class. The gate
AST-scans defender/ production code for such calls and ratchets them against an empty baseline.

Driven through its seam: `main(argv, *, scope, baseline_path)` over tmp trees.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests._by_path import load_lint_gate

_GATE = load_lint_gate("lint_raw_yaml")


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _baseline(path: Path, fingerprints: tuple[str, ...] | list[str] = ()) -> Path:
    path.write_text(json.dumps({"//": "test", "entries": {fp: "" for fp in fingerprints}}),
                    encoding="utf-8")
    return path


def _fingerprints(tree: Path) -> list[str]:
    return sorted(f.fingerprint for f in _GATE._scan(tree))


@pytest.mark.parametrize(("src", "kind"), [
    ("import yaml\n\ndef f(t):\n    return yaml.safe_load(t)\n", "load"),
    ("import yaml\n\ndef f(t):\n    return yaml.load(t, Loader=yaml.SafeLoader)\n", "load"),
    ("import yaml\n\ndef f(t):\n    return yaml.compose(t)\n", "load"),
    ("import yaml as y\n\ndef f(t):\n    return y.safe_load(t)\n", "load"),
    ("from yaml import safe_load\n\ndef f(t):\n    return safe_load(t)\n", "load"),
    ("import yaml\n\ndef f(d):\n    return yaml.safe_dump(d)\n", "dump"),
    ("def f(d):\n    import yaml\n    return yaml.dump(d)\n", "dump"),
], ids=["safe_load", "load", "compose", "aliased-module", "from-import", "safe_dump", "local-dump"])
def test_a_raw_pyyaml_load_or_dump_is_flagged(tmp_path, src, kind):
    _pyfile(tmp_path, "pkg/mod.py", src)

    assert _fingerprints(tmp_path) == [f"pkg/mod.py:f:{kind}"]
    assert _GATE.main([], scope=tmp_path, baseline_path=_baseline(tmp_path / "b.json")) == 1


def test_the_shared_module_and_its_callers_are_clean(tmp_path):
    """The canonical module itself, a caller of it, and other `yaml.` names (the error class,
    a loader subclass) are not loads or dumps."""
    _pyfile(tmp_path, "_yaml.py", "import yaml\n\ndef safe_load(t):\n    return yaml.load(t)\n")
    _pyfile(tmp_path, "pkg/mod.py", (
        "import yaml\nfrom defender import _yaml\n\n"
        "def f(t):\n    try:\n        return _yaml.safe_load(t)\n"
        "    except yaml.YAMLError:\n        return _yaml.safe_dump({})\n"))

    assert _fingerprints(tmp_path) == []


def test_tests_are_excluded_and_a_marked_site_is_suppressed(tmp_path):
    _pyfile(tmp_path, "tests/test_x.py", "import yaml\n\ndef f(t):\n    return yaml.safe_load(t)\n")
    _pyfile(tmp_path, "pkg/mod.py", (
        "import yaml\n\ndef f(t):\n"
        "    return yaml.safe_load(t)  # lint-yaml: ok — a reason\n"))

    assert _fingerprints(tmp_path) == []


def test_a_baselined_site_passes_and_a_missing_scope_is_exit_2(tmp_path):
    _pyfile(tmp_path, "pkg/mod.py", "import yaml\n\ndef f(t):\n    return yaml.safe_load(t)\n")
    baseline = _baseline(tmp_path / "b.json", ["pkg/mod.py:f:load"])

    assert _GATE.main([], scope=tmp_path, baseline_path=baseline) == 0
    assert _GATE.main([], scope=tmp_path / "absent", baseline_path=baseline) == 2


@pytest.mark.gate
def test_the_real_tree_is_clean():
    assert _GATE.main([]) == 0
