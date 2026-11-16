"""#1540 F3: the committed OpenAPI document is the API's own, as `create_app` produces it now, and one command writes it.
Pure Python, no database: the app is built over placeholder dependencies (grounding C3: the document does not depend on them)."""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from defender._git import REPO_ROOT  # noqa: E402
from defender.api.app import create_app  # noqa: E402
from defender.api.ports import ApiDeps  # noqa: E402

DOCUMENT = REPO_ROOT / "defender" / "api" / "openapi.json"
MODULE = "defender.api.openapi_document"
COMMAND = f"python -m {MODULE}"


def _produced() -> dict[str, Any]:
    """What the app says about itself: `create_app` over a placeholder for every dependency."""
    deps: dict[str, Any] = {f.name: object() for f in dataclasses.fields(ApiDeps)}
    deps["frontend_origin"] = "http://localhost:1"
    return create_app(ApiDeps(**deps)).openapi()


def test_1540_f3_the_committed_document_is_what_the_app_produces_now() -> None:
    """An API change that alters a shape fails here until the document is regenerated; the message names the command. (F3)"""
    assert DOCUMENT.is_file(), f"{DOCUMENT} is missing: run `{COMMAND}`"
    committed = json.loads(DOCUMENT.read_text(encoding="utf-8"))
    assert committed == _produced(), f"{DOCUMENT.name} is stale: run `{COMMAND}` and commit the result"


def test_1540_f3_the_command_writes_the_document_the_app_produces(tmp_path: Path) -> None:
    """Run in a copy of the source tree, `python -m defender.api.openapi_document` writes `defender/api/openapi.json`
    equal to the app's own document; the checkout is not written. (F3)"""
    source = REPO_ROOT / "defender"
    copy = tmp_path / "tree" / "defender"
    top = {"tests", ".venv", "node_modules", "frontend", ".testmondata"}  # not Python; the learning package's `frontend` is
    shutil.copytree(source, copy, ignore=lambda here, names: [  # only the top level's
        n for n in names if n == "__pycache__" or (Path(here) == source and n in top) or n == "openapi.json"])
    written = copy / "api" / "openapi.json"
    assert not written.exists(), "the copy must start without a document, or a pass proves nothing"
    before = DOCUMENT.read_bytes() if DOCUMENT.exists() else None
    ran = subprocess.run([sys.executable, "-m", MODULE], cwd=copy.parent, capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": str(copy.parent)}, timeout=300, check=False)
    assert ran.returncode == 0, ran.stderr[-2000:]
    assert written.is_file(), f"`{COMMAND}` wrote no defender/api/openapi.json beside addresses.json: {ran.stdout[-500:]}"
    assert json.loads(written.read_text(encoding="utf-8")) == _produced()
    assert (DOCUMENT.read_bytes() if DOCUMENT.exists() else None) == before, "the command wrote the checkout under test"


def test_1540_f3_the_document_carries_the_shapes_the_screens_read() -> None:
    """Positive control on the produced side: the investigation read names `status` and `disposition`, and `/api/me`
    answers `Me` (with `user`) or `ProgramMe`. (F3)"""
    doc = _produced()
    schemas = doc["components"]["schemas"]
    assert {"status", "disposition"} <= set(schemas["Investigation"]["properties"])
    assert "user" in schemas["Me"]["properties"]
    me = doc["paths"]["/api/me"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert {ref["$ref"].rsplit("/", 1)[1] for ref in me["anyOf"]} == {"Me", "ProgramMe"}
