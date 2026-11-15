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


def _add_one(document: Any) -> None:
    """Append a shape with a fresh name and a fresh literal template (the bound format, record "Chosen names")."""
    document["shapes"].append({"name": "zz-added", "template": "/zz-added", "returnable": False})


def _drop_one(document: Any) -> None:
    """Remove the `sign-in-failed` shape; exactly one entry goes."""
    before = len(document["shapes"])
    document["shapes"] = [s for s in document["shapes"] if s["name"] != "sign-in-failed"]
    assert before - len(document["shapes"]) == 1


EXAMPLE = {"placeholders": {"uuid": "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"},
           "shapes": [{"name": "root", "template": "/", "returnable": True},
                      {"name": "investigation", "template": "/t/{uuid}/investigations/{uuid}", "returnable": True},
                      {"name": "sign-in-failed", "template": "/sign-in-failed", "returnable": False}]}


def test_the_list_edits_act_on_the_bound_format() -> None:
    """Machinery self-test, green without a frontend: each helper edits the bound example as intended."""
    added = copy.deepcopy(EXAMPLE)
    _add_one(added)
    assert {s["name"] for s in added["shapes"]} == {"root", "investigation", "sign-in-failed", "zz-added"}
    assert added["shapes"][-1]["template"] == "/zz-added"
    assert added["placeholders"] == EXAMPLE["placeholders"]
    dropped = copy.deepcopy(EXAMPLE)
    _drop_one(dropped)
    assert {s["name"] for s in dropped["shapes"]} == {"root", "investigation"}
    assert dropped["placeholders"] == EXAMPLE["placeholders"]


def _build(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["npm", "run", "build"], cwd=root / "defender" / "frontend", capture_output=True, text=True,
                          check=False, timeout=600)


def _copy(root: Path, document: Any) -> Path:
    """A copy of the frontend (sharing `node_modules`) over the shape list `document`; the copy's root."""
    shutil.copytree(FRONTEND, root / "defender" / "frontend", ignore=shutil.ignore_patterns("node_modules", "dist"))
    (root / "defender" / "api").mkdir()
    (root / "defender" / "frontend" / "node_modules").symlink_to(FRONTEND / "node_modules")
    (root / "defender" / "api" / "addresses.json").write_text(json.dumps(document), encoding="utf-8")
    return root


@pytest.mark.parametrize("edit", [None, _add_one, _drop_one], ids=["unmodified", "shape-added", "shape-removed"])
def test_1161_s2_the_build_follows_the_shape_list_and_fails_on_a_type_error(built_frontend, tmp_path, edit):
    """A copy builds as is; with one shape added to or removed from the list the build fails, so every shape has a
    route and every route a shape, and the type check is part of the build. (S2, Am-4)"""
    document = json.loads(LIST.read_text(encoding="utf-8"))
    if edit is not None:
        edit(document)
    root = _copy(tmp_path / "copy", document)
    done = _build(root)
    if edit is None:
        assert done.returncode == 0, (done.stdout[-1500:], done.stderr[-1500:])
        assert (root / "defender" / "frontend" / "dist" / "index.html").is_file()
    else:
        assert done.returncode != 0, "the build accepted a shape list its router does not match"
        assert not (root / "defender" / "frontend" / "dist" / "index.html").exists()


def test_1161_s2_the_build_fails_on_a_type_error_in_any_source_file(built_frontend, tmp_path):
    """One unrelated type error, put in each source file in turn (the shell, the router, a screen, the rest), fails the
    build and leaves no `index.html`; the unmodified copy builds (control). The type check is the whole project's. (S2, B8)"""
    document = json.loads(LIST.read_text(encoding="utf-8"))
    sources = sorted(p.relative_to(FRONTEND) for p in (FRONTEND / "src").rglob("*.ts") if "generated" not in p.parts)
    assert {p.name for p in sources} >= {"main.ts", "router.ts", "root.ts", "signInFailed.ts"}, sources
    problems = []
    for index, source in enumerate([None, *sources]):
        root = _copy(tmp_path / f"copy-{index}", document)
        if source is not None:
            with (root / "defender" / "frontend" / source).open("a", encoding="utf-8") as handle:
                handle.write("\nexport const unrelatedTypeError: number = 'not a number';\n")
        done = _build(root)
        built = (root / "defender" / "frontend" / "dist" / "index.html").exists()
        if source is None:
            assert done.returncode == 0, (done.stdout[-1500:], done.stderr[-1500:])
            assert built
        elif done.returncode == 0 or built:
            problems.append(f"{source}: exit {done.returncode}, index.html {'made' if built else 'absent'}")
    assert not problems, problems
