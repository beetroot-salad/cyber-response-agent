"""#1092 — the hash module and the stdlib build script (M3 revised: `runtime/box/_image.py`
and `defender/scripts/box_image.py`).

The script runs on the CI runner's bare `python3` 3.12 with no uv and no venv (F14/G5) and
loads `_image.py` BY FILE PATH, never through `defender.runtime.box` (once `BoxSpec` is
pydantic that import pulls pydantic). Its `docker` is whatever is first on PATH — which is the
seam these tests use: a real executable that records its argv and exits with a scripted code.
"""
from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests._import_blocker import run_blocked
from defender.tests._spec1092 import (
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


def _imported_modules(path: Path) -> tuple[set[str], list[ast.ImportFrom]]:
    """Top-level module names a file imports (absolute), and its relative imports."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    relative: list[ast.ImportFrom] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                relative.append(node)
            elif node.module:
                names.add(node.module.split(".")[0])
    return names, relative


def _planted_script(tmp_path: Path, *, root_name: str = "tree") -> tuple[Path, Path]:
    """A planted tree carrying copies of the two code files; returns (root, script)."""
    root = tmp_path / root_name
    defender_dir = plant_tree(root)
    script = defender_dir / "scripts" / "box_image.py"
    assert script.is_file(), f"{BOX_IMAGE_PY} does not exist to copy — the script is unbuilt"
    return root, script


def _run_script(script: Path, *args: str, cwd: Path, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, str(script), *args], capture_output=True, text=True,
        encoding="utf-8", cwd=str(cwd), env=env, timeout=120,
    )


# ---- d6 --------------------------------------------------------------------------------------
def test_the_image_module_imports_only_the_stdlib_and_loads_by_file_path_without_the_box_package(tmp_path):
    """`runtime/box/_image.py` imports only standard-library modules and no package-relative
    name, and loading it through `importlib.util.spec_from_file_location` on a bare
    interpreter with `pydantic` blocked leaves no `defender.*` module imported — and names
    the same image the package import names."""
    assert IMAGE_PY.is_file(), f"{IMAGE_PY} does not exist"
    names, relative = _imported_modules(IMAGE_PY)
    assert relative == [], "the module uses a package-relative import (G22: it cannot)"
    assert names <= sys.stdlib_module_names, names - sys.stdlib_module_names

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
    """`defender/scripts/box_image.py` imports only standard-library modules, obtains
    `image_tag` by loading `runtime/box/_image.py` from its file path (never
    `import defender…`), and so runs on a bare runner `python3` with no uv and no venv:
    executed as `__main__` with `pydantic` blocked and nothing but the stdlib on `sys.path`,
    `tag` prints the planted tree's name and leaves no `defender.*` module imported."""
    assert BOX_IMAGE_PY.is_file(), f"{BOX_IMAGE_PY} does not exist"
    names, relative = _imported_modules(BOX_IMAGE_PY)
    assert relative == []
    assert "defender" not in names
    assert names <= sys.stdlib_module_names, names - sys.stdlib_module_names

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
    """`python3 <tree>/defender/scripts/box_image.py tag` prints `image_tag(<tree>/defender)`
    — the tree derived from the script's own location, the same from any working directory
    (this checkout's, a scratch dir) and different from this checkout's own name — alone on
    stdout and exits 0. Its argument contract is argparse's: no subcommand, an unknown one,
    or trailing arguments print usage on stderr and exit 2 (CLI #27/#28/#29)."""
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
    """`python3 <tree>/defender/scripts/box_image.py build` runs `docker build -f
    <tree>/defender/box.Dockerfile -t <image_tag(<tree>/defender)> <tree>/defender` — an argv list,
    never a shell string (a tree path with a space arrives as ONE argument; no `{`-template
    token survives on the argv), the context is the tree's `defender/` — the only directory the
    recipe COPYs from, so no repo-root exclusion list has to keep the context lean (#1098) — the build runs under BuildKit (`DOCKER_BUILDKIT=1` in docker's environment —
    the recipe's `RUN --mount` is BuildKit syntax, #1095) — and propagates a non-zero build
    exit as its own non-zero exit. The daemon-side failures settled at phase C (a base pull,
    a hash mismatch, a full daemon, no `docker` on PATH) are all the same observable: the
    build's non-zero exit, no fallback, no retry.

    # rejected: `start_box` does NOT auto-build (D2 C: a sandbox start that reaches the
    # network to build its own boundary inverts fail-loud). A registry pull path is not added."""
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
    """`build` on a machine with no `docker` on PATH prints `box_image.py: could not run
    docker: …` on stderr, nothing on stdout, and exits 1 — the CLI's own surface, not a
    `FileNotFoundError` traceback (d9's "no docker on PATH is the build's non-zero exit")."""
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
    """On a tree whose input it cannot read — a directory sitting where `uv.lock` should be —
    `tag` and `build` print `<tree>/defender: cannot read uv.lock: <reason>` on stderr
    (the same sentence shape as the resolver's `BoxFault`, which the stdlib script cannot
    import), print nothing on stdout, exit 1, and `build` never invokes `docker`."""
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


#: A lock that READS but cannot be used, each spelled as bytes over the planted lock: not TOML;
#: a reached entry's link with no `name` (#1097 amendment 2's shape check — today's walk would
#: go hunting a package called "name"); a reached entry's `dependencies` as a string (a walk
#: over it raises TypeError); a reached entry nested past what the canonical form can encode
#: (RecursionError). Each must reach the operator as the resolver's one-line fault.
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
}


@pytest.mark.parametrize("verb", ["tag", "build"])
@pytest.mark.parametrize("case", list(_UNUSABLE_LOCKS))
def test_box_image_reports_a_lock_it_cannot_use_in_the_resolvers_words_and_exits_1(tmp_path, verb, case):
    """On a tree whose `uv.lock` reads but cannot be used — not TOML (#1097: the name is
    computed from the PARSED lock), a reached entry's link with no `name`, a reached entry's
    `dependencies` written as a string, a reached entry nested 20000 tables deep (#1097
    amendment 2: the shape check at the parse seam, and a value the canonical form cannot
    encode) — `tag` and `build` print ONE line on stderr naming `<tree>/defender` and `uv.lock`
    and saying "cannot use" — the resolver's `ImageInputError`, never a traceback — print
    nothing on stdout, exit 1, and `build` never invokes `docker`. Positive control: the same
    tree, before the lock is broken, prints its name and exits 0."""
    root, script = _planted_script(tmp_path)
    defender_dir = root / "defender"
    assert _run_script(script, "tag", cwd=tmp_path).returncode == 0
    lock = defender_dir / "uv.lock"
    old, new = _UNUSABLE_LOCKS[case]
    text = lock.read_bytes()
    if old:
        assert text.count(old) == 1, (case, old)
        lock.write_bytes(text.replace(old, new))
    else:
        lock.write_bytes(text + new)
    env, log = fake_docker_on_path(tmp_path, rc=0)
    out = _run_script(script, verb, cwd=tmp_path, env=env)
    assert out.returncode == 1, (out.returncode, out.stderr[-2000:])
    assert out.stdout == "", out.stdout
    assert "Traceback" not in out.stderr, out.stderr[-2000:]
    assert len(out.stderr.strip().splitlines()) == 1, out.stderr[-2000:]
    assert str(defender_dir) in out.stderr, out.stderr
    assert "uv.lock" in out.stderr, out.stderr
    assert "cannot use" in out.stderr, out.stderr
    assert "cannot read" not in out.stderr, out.stderr
    assert recorded_docker_calls(log) == []
