"""What the built box image contains, observed from inside a real box (needs a daemon)."""
from __future__ import annotations

import re
import shutil
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender import box as box_mod
from defender.box import BOX_ENV_ALLOWLIST
from defender.tests.support.sandbox._docker import dood_anchor, is_dood
from defender.tests.support.sandbox._spec1092 import (
    DEFENDER,
    IMAGE_WALK_PROBE,
    box_probe,
    box_run,
    image_shell,
    make_run_dir,
    real_box,
    requires_daemon,
    requires_live_box,
    requires_real_box,
)

SITE = "/usr/local/lib/python3.11/site-packages"


_IMPORTS = """
import importlib, json, sys
out = {}
for name in sys.argv[1:]:
    try:
        mod = importlib.import_module(name)
        out[name] = getattr(mod, "__file__", "") or ""
    except ModuleNotFoundError:
        out[name] = None
print(json.dumps(out))
"""

_ENV_DUMP = "import json, os; print(json.dumps(dict(os.environ)))"


@pytest.fixture
def image_run_base(tmp_path: Path) -> Iterator[Path]:
    """Give only mounted live-image cases a daemon-visible base under DooD."""
    if not is_dood():
        yield tmp_path
        return
    anchor = dood_anchor()
    assert anchor is not None, "the real-box guard requires a shared repo mount under DooD"
    base = anchor / f"t1092-{uuid.uuid4().hex[:12]}"
    base.mkdir(parents=True)
    try:
        yield base
    finally:
        # Image probes write as root; cleanup follows the other live shared fixtures.
        shutil.rmtree(base, ignore_errors=True)


# ---- d18 -------------------------------------------------------------------------------------
@requires_real_box
def test_duckdb_imports_inside_the_box(image_run_base):
    run_dir = make_run_dir(image_run_base)
    with real_box(run_dir) as box:
        res = box_run(box, "python3 -c 'import duckdb'", cwd=Path("/runs/current"))
        seen = box_probe(box, run_dir, "duckdb", _IMPORTS, "duckdb")
    assert res.rc == 0, res.err
    assert seen["duckdb"], seen
    assert seen["duckdb"].startswith(SITE + "/"), seen


# ---- d23 (negative; positive control: the two copied files ARE in the image) ----------------------
@requires_daemon
def test_the_image_holds_no_checkout_no_env_file_and_no_ssh_material():
    seen = image_shell(IMAGE_WALK_PROBE)
    files, dirs = seen["files"], seen["dirs"]
    assert [f for f in files if f.endswith("/.env") or f.endswith(".env.bak")] == []
    assert [d for d in dirs if d.endswith("/.ssh")] == []
    assert [f for f in files if re.search(r"/id_(rsa|ed25519|ecdsa|dsa)$", f)] == []
    assert [f for f in files if f.endswith("/box.Dockerfile") or f.endswith("/defender/run.py")] == []
    assert [d for d in dirs if d.endswith("/defender/investigation")] == []
    locks = [f for f in files if f.endswith("/uv.lock")]
    assert len(locks) == 1, locks
    assert str(Path(locks[0]).with_name("pyproject.toml")) in files, locks


# ---- d31 -------------------------------------------------------------------------------------
@requires_real_box
def test_a_command_inside_the_box_sees_defender_box_1_and_the_env_is_still_exactly_the_allowlist(image_run_base):
    daemon_injected = {"HOSTNAME", "HOME", "PWD", "SHLVL", "_", "OLDPWD", "TERM"}
    run_dir = make_run_dir(image_run_base)
    with real_box(run_dir) as box:
        first = box_probe(box, run_dir, "env1", _ENV_DUMP)
        second = box_probe(box, run_dir, "env2", _ENV_DUMP)
    assert first.get("DEFENDER_BOX") == "1", sorted(first)
    assert second.get("DEFENDER_BOX") == "1", sorted(second)
    assert "DEFENDER_BOX" in BOX_ENV_ALLOWLIST
    expected = set(BOX_ENV_ALLOWLIST) - {"DEFENDER_AGENT_DIR"}
    assert set(first) - daemon_injected == expected, sorted(first)
    assert set(second) - daemon_injected == expected, sorted(second)
    assert "DEFENDER_AGENT_DIR" not in first
    assert "DEFENDER_AGENT_DIR" not in second


# ---- d49 (the live suite's own row, re-sited) --------------------------------------------------
@pytest.mark.live
@requires_live_box
def test_the_live_suites_duckdb_startup_probe_exits_zero_in_a_box_from_the_owned_image(tmp_path):
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod._docker)
    try:
        res = box_run(box, "python3 -c 'import duckdb'", cwd=Path("/"))
    finally:
        box_mod.stop_box(box)
    assert res.rc == 0, res.err
