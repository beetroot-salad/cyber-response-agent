"""The image-name hash module and the stdlib-only build script (box_image.py)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts._import_blocker import run_blocked
from defender.tests.support.sandbox._spec1092 import (
    BOX_IMAGE_PY,
    DEFENDER,
    HASH_INPUTS,
    IMAGE_PY,
    builder_log,
    fake_docker_on_path,
    image_tag,
    plant_tree,
    recorded_docker_calls,
)


def _planted_script(tmp_path: Path, *, root_name: str = "tree") -> tuple[Path, Path]:
    """A planted tree carrying copies of the two code files; returns (root, script)."""
    root = tmp_path / root_name
    defender_dir = plant_tree(root)
    script = defender_dir / "box" / "image_cli.py"
    assert script.is_file(), f"{BOX_IMAGE_PY} does not exist to copy — the script is unbuilt"
    return root, script


def _run_script(script: Path, *args: str, cwd: Path, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(script), *args], capture_output=True, text=True,
        encoding="utf-8", cwd=str(cwd), env=env, timeout=120,
    )


# ---- d6 --------------------------------------------------------------------------------------
def test_the_image_module_imports_only_the_stdlib_and_loads_by_file_path_without_the_box_package(tmp_path):
    assert IMAGE_PY.is_file(), f"{IMAGE_PY} does not exist"

    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    code = (
        "import importlib.util, json, sys\n"
        "from pathlib import Path\n"
        f"spec = importlib.util.spec_from_file_location('_image_by_path', {str(IMAGE_PY)!r})\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n"
        f"tag = mod.image_tag(Path({str(defender_dir)!r}))\n"
        "print(json.dumps({'tag': tag, 'defender': sorted(m for m in sys.modules if m.startswith('defender'))}))\n"
    )
    out = run_blocked(code, block=("pydantic", "pydantic_core"), no_site=True, cwd=tmp_path,
                      env={"PATH": os.environ.get("PATH", "")})
    assert out.returncode == 0, out.stderr
    seen = json.loads(out.stdout)
    assert seen["defender"] == [], seen
    assert seen["tag"] == image_tag(defender_dir)


# ---- d7 --------------------------------------------------------------------------------------
def test_the_box_image_script_imports_only_the_stdlib_and_never_the_defender_package(tmp_path):
    assert BOX_IMAGE_PY.is_file(), f"{BOX_IMAGE_PY} does not exist"

    root, script = _planted_script(tmp_path)
    code = (
        "import json, runpy, sys\n"
        f"sys.argv = [{str(script)!r}, 'tag']\n"
        "code = 0\n"
        "try:\n"
        f"    runpy.run_path({str(script)!r}, run_name='__main__')\n"
        "except SystemExit as e:\n"
        "    code = e.code or 0\n"
        "print(json.dumps({'code': code, 'defender': sorted(m for m in sys.modules if m.startswith('defender'))}), file=sys.stderr)\n"
    )
    out = run_blocked(code, block=("pydantic", "pydantic_core"), no_site=True, cwd=tmp_path,
                      env={"PATH": os.environ.get("PATH", "")})
    assert out.returncode == 0, out.stderr
    report = json.loads(out.stderr.decode("utf-8").strip().splitlines()[-1])
    assert report["code"] == 0, out.stderr
    assert report["defender"] == [], report
    assert out.stdout.decode("utf-8") == image_tag(root / "defender") + "\n"


# ---- d8 --------------------------------------------------------------------------------------
def test_box_image_tag_prints_the_name_derived_from_the_scripts_own_tree_and_nothing_else(tmp_path):
    root, script = _planted_script(tmp_path)
    expected = image_tag(root / "defender")
    for cwd in (tmp_path, DEFENDER.parent, Path("/")):
        out = _run_script(script, "tag", cwd=cwd)
        assert out.returncode == 0, (cwd, out.stderr)
        assert out.stdout == expected + "\n", (cwd, out.stdout)
        assert out.stderr == "", (cwd, out.stderr)
    assert expected != image_tag(DEFENDER), "the planted tree must name a different image"
    # `export` included: #1097 round 1's exported-list verb is gone with the list (the design
    # amendment) — the contract is exactly `tag` | `build` again.
    for argv in ((), ("frobnicate",), ("export",), ("tag", "extra")):
        out = _run_script(script, *argv, cwd=tmp_path)
        assert out.returncode == 2, (argv, out.returncode, out.stderr)
        assert "usage" in out.stderr.lower(), (argv, out.stderr)
        assert out.stdout == "", (argv, out.stdout)


# ---- d9 --------------------------------------------------------------------------------------
def test_box_image_build_runs_docker_build_on_the_trees_dockerfile_tagged_with_the_derived_name(tmp_path):
    root, script = _planted_script(tmp_path, root_name="tree with space")
    expected_tag = image_tag(root / "defender")

    env, log = fake_docker_on_path(tmp_path, rc=0)
    out = _run_script(script, "build", cwd=Path("/"), env=env)
    assert out.returncode == 0, out.stderr
    calls = recorded_docker_calls(log)
    assert len(calls) == 1, calls
    argv = calls[0]
    assert argv[0] == "build", argv
    assert argv[argv.index("-f") + 1] == str(root / "defender" / "box.Dockerfile"), argv
    assert argv[argv.index("-t") + 1] == expected_tag, argv
    assert argv[-1] == str(root / "defender"), argv
    assert not any("{" in t or "}" in t for t in argv), argv
    assert builder_log(log) == ["1"], builder_log(log)

    env, log = fake_docker_on_path(tmp_path / "failing", rc=7)
    out = _run_script(script, "build", cwd=Path("/"), env=env)
    assert out.returncode != 0, "a failed docker build exited 0"
    assert len(recorded_docker_calls(log)) == 1, "the build was retried"


# ---- #1095 round 2: no docker to run ---------------------------------------------------------------
def test_box_image_build_without_docker_on_path_prints_one_line_and_exits_1(tmp_path):
    _, script = _planted_script(tmp_path)
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    out = _run_script(script, "build", cwd=Path("/"), env={"PATH": str(empty)})
    assert out.returncode == 1, (out.returncode, out.stderr)
    assert out.stdout == "", out.stdout
    assert out.stderr.startswith("box_image.py: could not run docker:"), out.stderr
    assert "Traceback" not in out.stderr, out.stderr


# ---- MF1's script side (CLI #18) ----------------------------------------------------------------
@pytest.mark.parametrize("verb", ["tag", "build"])
def test_box_image_reports_a_tree_whose_input_it_cannot_read_and_exits_1(tmp_path, verb):
    root, script = _planted_script(tmp_path)
    defender_dir = root / "defender"
    (defender_dir / "uv.lock").unlink()
    (defender_dir / "uv.lock").mkdir()
    env, log = fake_docker_on_path(tmp_path, rc=0)
    out = _run_script(script, verb, cwd=tmp_path, env=env)
    assert out.returncode == 1, (out.returncode, out.stderr)
    assert out.stdout == "", out.stdout
    assert str(defender_dir) in out.stderr, out.stderr
    assert "cannot read" in out.stderr, out.stderr
    assert "uv.lock" in out.stderr, out.stderr
    assert HASH_INPUTS[0] not in out.stderr.split("cannot read", 1)[1], out.stderr
    assert recorded_docker_calls(log) == []


_ALPHA_BETA_LINK = b'{ name = "beta", extra = ["speed"] }'
_ALPHA_LINKS = (
    b'dependencies = [\n    ' + _ALPHA_BETA_LINK + b',\n'
    b'    { name = "winonly", marker = "sys_platform == \'win32\'" },\n]\n'
)
_UNUSABLE_LOCKS: dict[str, tuple[bytes, bytes]] = {
    # case -> (the bytes replaced — b"" appends — , what replaces them)
    "not TOML": (b"", b"[[package]\n"),
    "a link with no name": (_ALPHA_BETA_LINK, b'{ extra = ["speed"] }'),
    "dependencies a string": (_ALPHA_LINKS, b'dependencies = "beta"\n'),
    "a value nested past the encoder": (b"", b"\n[package." + b".".join([b"x"] * 20_000) + b"]\nb = 1\n"),
    "a nameless entry nested past repr": (b"", b"\n[[package]]\n[package." + b".".join([b"x"] * 20_000) + b"]\nb = 1\n"),
    "an integer past the digit limit": (b"", b'\n[[package]]\nname = "zz"\nversion = "1.0.0"\nx = ' + b"1" * 5000 + b"\n"),
}
