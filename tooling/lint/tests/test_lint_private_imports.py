"""Tests for the lint_private_imports gate (#1315): an underscore below a top-level area is private
to that area, and every lazy door's map, type mirror and homes agree."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_private_imports")

_DOOR = (
    "from typing import TYPE_CHECKING\n"
    "from defender.lazy_door import lazy_door\n"
    "if TYPE_CHECKING:\n"
    "    from defender.tenancy._tenant import Tenant as Tenant\n"
    '_HOMES: dict[str, str] = {**dict.fromkeys(("Tenant",), "_tenant")}\n'
    "__getattr__ = lazy_door(globals(), _HOMES)\n"
)

#: A small tree: two areas with private modules, a door, and the root seams.
_BASE = {
    "lazy_door.py": "def lazy_door(namespace, homes): pass\n",
    "_io.py": "from defender._filesystem.bound import _descend\ndef _helper(): pass\ndef read(): pass\n",
    "_filesystem/__init__.py": "",
    "_filesystem/bound.py": "def _descend(): pass\n",
    "tenancy/__init__.py": _DOOR,
    "tenancy/_tenant.py": "class Tenant: pass\ndef _secret(): pass\n",
    "tenancy/reader.py": "from defender.tenancy._tenant import Tenant, _secret\n",
    "records/__init__.py": "",
    "records/_layout.py": "LAYOUT = 1\n",
    "records/public.py": "def _private(): pass\ndef open_it(): pass\n",
    "cli/__init__.py": "",
    "cli/main.py": "from defender.tenancy import Tenant\nfrom defender._io import read\nfrom defender.records import public\n",
}


def _tree(tmp_path: Path, **files: str) -> Path:
    root = tmp_path / "defender"
    for rel, text in {**_BASE, **{k.replace(":", "/"): v for k, v in files.items()}}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_a_clean_tree_has_no_findings(tmp_path):
    assert _GATE.scan(_tree(tmp_path)) == []


@pytest.mark.parametrize("src", [
    "from defender.tenancy._tenant import Tenant\n",
    "import defender.tenancy._tenant as t\n",
    "from defender.tenancy import _tenant\n",
    "def f():\n    from defender.tenancy._tenant import Tenant\n",
    "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from defender.tenancy._tenant import Tenant\n",
    "from ..tenancy._tenant import Tenant\n",
], ids=["from-module", "import-as", "from-package", "function-body", "type-checking", "relative"])
def test_another_areas_private_module_is_found(tmp_path, src):
    found = _GATE.scan(_tree(tmp_path, **{"cli:main.py": src}))
    assert len(found) == 1 and "defender.tenancy._tenant" in found[0], found


def test_another_areas_private_name_is_found(tmp_path):
    found = _GATE.scan(_tree(tmp_path, **{"cli:main.py": "from defender.records.public import _private\n"}))
    assert len(found) == 1 and "defender.records.public._private" in found[0], found


def test_a_private_read_through_a_module_alias_is_found(tmp_path):
    src = "from defender.records import public\npublic._private()\n"
    found = _GATE.scan(_tree(tmp_path, **{"cli:main.py": src}))
    assert len(found) == 1 and "reads `defender.records.public._private`" in found[0], found


def test_a_private_attribute_of_a_value_is_not_judged(tmp_path):
    src = "from defender.tenancy import Tenant\nTenant()._internal\n"
    assert _GATE.scan(_tree(tmp_path, **{"cli:main.py": src})) == []


def test_the_root_seams_are_one_shared_area(tmp_path):
    # Any area may import a root seam; the seams may reach each other's privates.
    assert _GATE.scan(_tree(tmp_path)) == []
    found = _GATE.scan(_tree(tmp_path, **{"cli:main.py": "from defender._io import _helper\n"}))
    assert len(found) == 1 and "private to `root`" in found[0], found


def test_tests_are_not_swept(tmp_path):
    root = _tree(tmp_path, **{"tests:test_x.py": "from defender.tenancy._tenant import _secret\n"})
    assert _GATE.scan(root) == []


def test_a_door_relaying_another_areas_private_is_found(tmp_path):
    door = _DOOR.replace("    from defender.tenancy._tenant import Tenant as Tenant\n",
                         "    from defender.tenancy._tenant import Tenant as Tenant\n"
                         "    from defender.records._layout import LAYOUT as LAYOUT\n")
    found = _GATE.scan(_tree(tmp_path, **{"tenancy:__init__.py": door}))
    assert any("defender.records._layout" in f for f in found), found


@pytest.mark.parametrize(("door", "expected"), [
    (_DOOR.replace("    from defender.tenancy._tenant import Tenant as Tenant\n", "    pass\n"),
     "TYPE_CHECKING block does not import it"),
    (_DOOR.replace('("Tenant",)', '("Tenant", "Absent")'), "`Absent` is not bound"),
    (_DOOR.replace('"_tenant")', '"_missing")'), "is not a module"),
], ids=["mirror-missing", "name-not-in-home", "home-missing"])
def test_a_door_whose_map_mirror_and_homes_disagree_is_found(tmp_path, door, expected):
    found = _GATE.scan(_tree(tmp_path, **{"tenancy:__init__.py": door}))
    assert any(expected in f for f in found), found


def test_importing_a_name_the_door_does_not_serve_is_found(tmp_path):
    found = _GATE.scan(_tree(tmp_path, **{"cli:main.py": "from defender.tenancy import Missing\n"}))
    assert len(found) == 1 and "does not serve `Missing`" in found[0], found


def test_a_file_that_does_not_parse_is_exit_2(tmp_path):
    assert _GATE.main(["--root", str(_tree(tmp_path, **{"cli:main.py": "def (:\n"}))]) == 2


def test_a_name_bound_only_inside_a_function_is_not_a_home_binding(tmp_path):
    home = "if True:\n    def make():\n        class Tenant: pass\n"
    found = _GATE.scan(_tree(tmp_path, **{"tenancy:_tenant.py": home}))
    assert any("`Tenant` is not bound" in f for f in found), found


def test_a_name_bound_under_if_or_try_is_a_home_binding(tmp_path):
    home = "try:\n    from x import Tenant\nexcept ImportError:\n    class Tenant: pass\n"
    assert _GATE.scan(_tree(tmp_path, **{"tenancy:_tenant.py": home})) == []
