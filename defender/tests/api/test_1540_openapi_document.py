"""#1540 F3: one command writes the committed OpenAPI document, and running it on the current source writes exactly the
committed file. Whether that file is the API's own document is pinned against the real server, which serves it over
its real dependencies (`test_1083_real_server.py`'s `test_1540_f3_...`): this module never rebuilds the document the
way the command does, so a mistake in the command cannot also be the test's expectation."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from defender._git import REPO_ROOT  # noqa: E402

DOCUMENT = REPO_ROOT / "defender" / "api" / "openapi.json"
MODULE = "defender.api.openapi_document"
COMMAND = f"python -m {MODULE}"


def test_1540_f3_the_command_run_on_the_current_source_writes_the_committed_document(tmp_path: Path) -> None:
    """Run in a copy of the source tree, `python -m defender.api.openapi_document` writes `defender/api/openapi.json`
    byte for byte equal to the committed one; the checkout is not written. An API change that alters a shape fails here
    until the document is regenerated; the message names the command. (F3)"""
    assert DOCUMENT.is_file(), f"{DOCUMENT} is missing: run `{COMMAND}`"
    source = REPO_ROOT / "defender"
    copy = tmp_path / "tree" / "defender"
    top = {"tests", ".venv", "node_modules", "frontend", ".testmondata"}  # not Python; the learning package's `frontend` is
    shutil.copytree(source, copy, ignore=lambda here, names: [  # only the top level's
        n for n in names if n == "__pycache__" or (Path(here) == source and n in top) or n == "openapi.json"])
    written = copy / "api" / "openapi.json"
    assert not written.exists(), "the copy must start without a document, or a pass proves nothing"
    before = DOCUMENT.read_bytes()
    ran = subprocess.run([sys.executable, "-m", MODULE], cwd=copy.parent, capture_output=True, text=True,
                         env={**os.environ, "PYTHONPATH": str(copy.parent)}, timeout=300, check=False)
    assert ran.returncode == 0, ran.stderr[-2000:]
    assert written.is_file(), f"`{COMMAND}` wrote no defender/api/openapi.json beside addresses.json: {ran.stdout[-500:]}"
    assert written.read_bytes() == before, f"{DOCUMENT.name} is stale: run `{COMMAND}` and commit the result"
    assert DOCUMENT.read_bytes() == before, "the command wrote the checkout under test"


def test_1540_f3_the_document_carries_the_shapes_the_screens_read() -> None:
    """Positive control on the committed document: the investigation read names `status` and `disposition`, and
    `/api/me` answers `Me` (with `user`) or `ProgramMe`. (F3)"""
    doc = json.loads(DOCUMENT.read_text(encoding="utf-8"))
    schemas = doc["components"]["schemas"]
    assert {"status", "disposition"} <= set(schemas["Investigation"]["properties"])
    assert "user" in schemas["Me"]["properties"]
    me = doc["paths"]["/api/me"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert {ref["$ref"].rsplit("/", 1)[1] for ref in me["anyOf"]} == {"Me", "ProgramMe"}
