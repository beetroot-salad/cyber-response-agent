"""The in-box mark DEFENDER_BOX=1: set by both docker-run builders, stripped by both host lanes, honoured by the shims and reexec_into_venv."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from defender.box import run_env
from defender import box as box_mod
from defender.box import BOX_ENV_ALLOWLIST, BoxRequest, BoxSpec, Mount
from defender.tests.support.sandbox._spec1092 import (
    DEFENDER,
    STOCK_ROOTFS,
    env_pairs,
    make_run_dir,
    run_shim,
    shim_world,
)

SHIMS = ("defender-sql", "defender-invlang", "defender-lessons")


def _request(root: Path, run_dir: Path, env: dict[str, str] | None = None) -> BoxRequest:
    return BoxRequest(
        name="defender-drain-1092", workdir=root, env=dict(env or {}),
        mounts=(Mount(source=run_dir, target=run_dir, writable=True),),
        spec=BoxSpec(rootfs=STOCK_ROOTFS),
    )


# ---- d29 -------------------------------------------------------------------------------------
def test_the_run_dir_lane_argv_carries_env_defender_box_1(tmp_path):
    assert box_mod._BOX_MARK_ENV == {"DEFENDER_BOX": "1"}  # type: ignore[attr-defined]
    assert "DEFENDER_BOX" in BOX_ENV_ALLOWLIST
    run_dir = make_run_dir(tmp_path)
    argv = box_mod._create_argv(
        "defender-run-1092", run_dir, tmp_path / "srv" / "defender", BoxSpec(rootfs=STOCK_ROOTFS), (),
        lane=box_mod._run_lane_mounts(run_dir, tmp_path / "srv" / "defender", None),
    ).argv
    pairs = env_pairs(argv)
    assert pairs.count(("DEFENDER_BOX", "1")) == 1, pairs
    assert {k for k, _ in pairs} == set(BOX_ENV_ALLOWLIST) - {"DEFENDER_AGENT_DIR"}, pairs
    assert "DEFENDER_AGENT_DIR" not in {k for k, _ in pairs}


# ---- d30 -------------------------------------------------------------------------------------
@pytest.mark.parametrize("request_env", [
    {},
    {"DEFENDER_BOX": ""},
    {"DEFENDER_BOX": "0"},
    {"defender_box": "1", " DEFENDER_BOX": "1", "DEFENDER_BOX ": "1"},
])
def test_the_request_lane_argv_carries_env_defender_box_1_whatever_the_request_env_says(tmp_path, request_env):
    run_dir = make_run_dir(tmp_path)
    request = _request(tmp_path / "wt", run_dir, request_env)
    argv = box_mod._render_argv(request, ()).argv
    pairs = env_pairs(argv)
    assert pairs.count(("DEFENDER_BOX", "1")) == 1, pairs
    assert [k for k, _ in pairs if k.strip().upper() == "DEFENDER_BOX"] == ["DEFENDER_BOX"], pairs
    assert box_mod._render_env(request_env, Path(tmp_path / "wt"))["DEFENDER_BOX"] == "1"


# ---- d32 (negative; positive control: d30 — the same request env DOES carry the mark on the box lane) ----
def test_both_host_lanes_strip_defender_box_from_the_shell_and_request_env_and_the_locale_env_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENDER_BOX", "1")
    monkeypatch.setenv("SPEC1092_SHELL_KEY", "kept")
    request_env = {"DEFENDER_BOX": "1", "TZ": "Europe/Oslo"}
    run_dir = make_run_dir(tmp_path)
    request = _request(tmp_path / "wt", run_dir, request_env)

    host = box_mod._host_fallback_env(request)
    assert "DEFENDER_BOX" not in host, sorted(k for k in host if "BOX" in k)
    assert host["TZ"] == "Europe/Oslo"
    assert host["SPEC1092_SHELL_KEY"] == "kept"

    lane = run_env(tmp_path / "srv" / "defender", run_dir)
    assert "DEFENDER_BOX" not in lane, sorted(k for k in lane if "BOX" in k)
    assert lane["SPEC1092_SHELL_KEY"] == "kept"

    assert box_mod._LOCALE_ENV == {"LANG": "C.UTF-8", "TZ": "UTC"}
    assert box_mod._render_env(request_env, tmp_path / "wt")["DEFENDER_BOX"] == "1"


# ---- d33 -------------------------------------------------------------------------------------
@pytest.mark.parametrize("shim", SHIMS)
def test_each_granted_shim_execs_bare_python3_when_defender_box_is_set_and_the_venv_python_otherwise(tmp_path, shim):
    world = shim_world(tmp_path)
    assert run_shim(shim, world, marked=False) == str(world.venv_python)
    assert run_shim(shim, world, marked=True) == str(world.bare_python)


# ---- d34 -------------------------------------------------------------------------------------
def test_reexec_into_venv_does_not_exec_when_defender_box_is_set_and_does_otherwise(tmp_path):
    """`reexec_into_venv`, with a venv interpreter present beside its own tree, does not exec
    when `DEFENDER_BOX` is set and does exec into it when the variable is unset."""
    tree = tmp_path / "defender"
    (tree / "execution").mkdir(parents=True)
    shutil.copy(DEFENDER / "execution/_venv.py", tree / "execution/_venv.py")
    venv_bin = tree / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    stub = venv_bin / "python3"
    stub.write_text("#!/bin/sh\necho \"STUB-EXEC $*\"\n", encoding="utf-8")
    stub.chmod(0o755)
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(tree / 'execution')!r})\n"
        "import _venv\n"
        "_venv.reexec_into_venv('lessons_fm.py')\n"
        "print('NO-EXEC')\n"
    )

    def run(marked: bool) -> str:
        env = {"PATH": os.environ.get("PATH", "")}
        if marked:
            env["DEFENDER_BOX"] = "1"
        proc = subprocess.run(
            [sys.executable, "-c", code, "--tags"], env=env, capture_output=True, text=True,
            encoding="utf-8", timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        return proc.stdout.strip()

    assert run(marked=False) == "STUB-EXEC lessons_fm.py --tags"
    assert run(marked=True) == "NO-EXEC"
