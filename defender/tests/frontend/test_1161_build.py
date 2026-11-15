"""#1161 S2, Am-4: the frontend build type-checks and reads the one shape list (no hand-kept copy in the router)."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.frontend._ingress1161 import FRONTEND

LIST = FRONTEND.parent / "api" / "addresses.json"


def _entries(document: Any) -> Any:
    """The container of the shapes in the file (its format is agent-local): the list or mapping of them."""
    if isinstance(document, list):
        return document
    holders = [v for v in document.values() if isinstance(v, list | dict) and v]
    assert len(holders) == 1, f"cannot find the shape list in {list(document)}"
    return holders[0]


def _add_one(document: Any) -> None:
    entries = _entries(document)
    if isinstance(entries, list):
        extra = copy.deepcopy(entries[0])
        for key, value in extra.items():
            if isinstance(value, str) and not value.startswith("/"):
                extra[key] = "zz-added"
        entries.append(extra)
    else:
        entries["zz-added"] = copy.deepcopy(next(iter(entries.values())))


def _drop_one(document: Any) -> None:
    entries = _entries(document)
    if isinstance(entries, list):
        entries.pop()
    else:
        entries.pop(next(reversed(entries)))


def _build(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["npm", "run", "build"], cwd=root / "defender" / "frontend", capture_output=True, text=True,
                          check=False, timeout=600)


@pytest.mark.parametrize("edit", [None, _add_one, _drop_one], ids=["unmodified", "shape-added", "shape-removed"])
def test_1161_s2_the_build_follows_the_shape_list_and_fails_on_a_type_error(built_frontend, tmp_path, edit):
    """A copy builds as is; with one shape added to or removed from the list the build fails, so every shape has a
    route and every route a shape, and the type check is part of the build. (S2, Am-4)"""
    root = tmp_path / "copy"
    shutil.copytree(FRONTEND, root / "defender" / "frontend", ignore=shutil.ignore_patterns("node_modules", "dist"))
    (root / "defender" / "api").mkdir()
    (root / "defender" / "frontend" / "node_modules").symlink_to(FRONTEND / "node_modules")
    document = json.loads(LIST.read_text(encoding="utf-8"))
    if edit is not None:
        edit(document)
    (root / "defender" / "api" / "addresses.json").write_text(json.dumps(document), encoding="utf-8")
    done = _build(root)
    if edit is None:
        assert done.returncode == 0, (done.stdout[-1500:], done.stderr[-1500:])
        assert (root / "defender" / "frontend" / "dist" / "index.html").is_file()
    else:
        assert done.returncode != 0, "the build accepted a shape list its router does not match"
        assert not (root / "defender" / "frontend" / "dist" / "index.html").exists()
