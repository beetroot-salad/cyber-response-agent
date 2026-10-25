"""Tests for the lint_isolated_modules gate: the box image scripts import only the standard library
and the tacit-knowledge registry adapter never writes."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_isolated_modules")

_CLEAN = {
    "box/_image.py": "import json, hashlib\nfrom pathlib import Path\n",
    "box/image_cli.py": "from __future__ import annotations\nimport sys\n",
    "integrations/tacit_knowledge_adapter.py":
        "import yaml\nfrom pathlib import Path\n"
        "def load(p):\n    return yaml.safe_load(Path(p).read_text())\n",
}


def _tree(tmp_path: Path, **overrides: str) -> Path:
    root = tmp_path / "defender"
    files = {**_CLEAN, **{k.replace("__", "/"): v for k, v in overrides.items()}}
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_a_clean_tree_has_no_findings(tmp_path):
    assert _GATE.scan(_tree(tmp_path)) == []


@pytest.mark.parametrize("src", [
    "import yaml\n",
    "from defender.box import x\n",
    "from . import sibling\n",
    "import json\nimport pydantic.v1\n",
])
def test_an_image_script_importing_beyond_the_stdlib_is_found(tmp_path, src):
    found = _GATE.scan(_tree(tmp_path, **{"box__image_cli.py": src}))
    assert len(found) == 1 and "image_cli.py" in found[0], found


@pytest.mark.parametrize("body", [
    "Path(p).write_text('x')",
    "Path(p).parent.mkdir()",
    "Path(p).unlink()",
    "yaml.safe_dump({}, f)",
    "os.replace(a, b)",
    "shutil.rmtree(p)",
    "open(p, 'w')",
    "open(p, 'a')",
    "Path(p).open('w')",
])
def test_a_registry_write_is_found(tmp_path, body):
    src = ("import os, shutil, yaml\nfrom pathlib import Path\n"
           f"def f(p, a, b, f):\n    {body}\n")
    found = _GATE.scan(_tree(tmp_path, **{"integrations__tacit_knowledge_adapter.py": src}))
    assert len(found) >= 1 and all("tacit_knowledge_adapter" in f for f in found), found


def test_registry_reads_are_not_writes(tmp_path):
    src = ("import yaml\ndef f(p, d):\n    d.get('x')\n    d.update({})\n"
           "    return open(p).read(), open(p, 'r').read()\n")
    assert _GATE.scan(_tree(tmp_path, **{"integrations__tacit_knowledge_adapter.py": src})) == []


def test_a_missing_file_is_a_finding(tmp_path):
    root = _tree(tmp_path)
    (root / "box/_image.py").unlink()
    assert any("_image.py" in f and "missing" in f for f in _GATE.scan(root))


def test_a_file_that_does_not_parse_is_exit_2(tmp_path):
    root = _tree(tmp_path, **{"box___image.py": "def (:\n"})
    assert _GATE.main(["--root", str(root)]) == 2
