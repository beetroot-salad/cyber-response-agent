"""The owned image's name is derived at box start from the mounted tree's recipe and lock.

The image-name hash module and the stdlib-only build script (image_cli.py).

Static shape of defender/box.Dockerfile and the box extra.

What the built box image contains, observed from inside a real box (needs a daemon).
"""
from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any
import json
import os
import sys
import re
import shlex
import tomllib
import uuid
from collections.abc import Iterator

import pytest

from defender import box as box_mod
from defender.box import BoxRequest, BoxSpec, Mount
from defender.execution.box_codec import BoxFault
from defender.tests.support.sandbox._spec1092 import (
    DEFENDER,
    HASH_INPUTS,
    PLANTED_INPUT_BYTES,
    STOCK_ROOTFS,
    TAG_RE,
    RecordingDocker,
    image_tag,
    image_token,
    make_run_dir,
    plant_tree,
    recipe_version,
    subcommands,
)
from defender.tests.support.tenancy._host1214 import TEST_TENANT
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
from defender.tests.support.sandbox._spec1092 import DEFENDER, DOCKERFILE
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


#: The devcontainer-shaped mount table `test_box_dood_c46.py` uses: `/workspace` is shared
#: with the daemon, a pytest `tmp_path` is not.
MOUNTS: tuple[tuple[Path, Path], ...] = (
    (Path("/var/run/docker.sock"), Path("/var/run/docker.sock")),
    (Path("/workspace"), Path("/home/dev/projects/repo")),
)


def _request(defender_root: Path, run_dir: Path, *, spec: BoxSpec | None = None,
             name: str = "defender-drain-1092") -> BoxRequest:
    """A request-lane box in the drain's shape: `workdir` is the tree ROOT (the worktree),
    the defender dir is `workdir / "defender"`, one rw mount for the markers."""
    kw = {} if spec is None else {"spec": spec}
    return BoxRequest(
        name=name, workdir=defender_root, env={}, tenant_id=TEST_TENANT,
        mounts=(Mount(source=run_dir, target=run_dir, writable=True),),
        **kw,
    )


def _no_unsandboxed(monkeypatch) -> None:
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(BoxSpec.ENV_VAR, raising=False)


# ---- #0 --------------------------------------------------------------------------------------
def test_an_unset_rootfs_resolves_to_the_image_named_by_the_mounted_trees_three_inputs_on_every_docker_run_site(tmp_path):
    from defender.tests.e2e._spec771 import run_probe_under_profile

    runner: Callable[..., Any] = run_probe_under_profile
    assert BoxSpec().rootfs is None
    assert BoxSpec.from_env({}).rootfs is None
    assert box_mod.DEFAULT_SPEC.rootfs is None
    root = tmp_path / "tree"
    run_dir = make_run_dir(tmp_path)
    # Constructed BEFORE the tree holds any input: an eager resolver would fault here.
    spec = BoxSpec()
    request = _request(root, run_dir)
    assert not (root / "defender" / HASH_INPUTS[0]).exists()

    defender_dir = plant_tree(root)
    expected = image_tag(defender_dir)
    shape = TAG_RE.match(expected)
    assert shape is not None, expected
    assert shape.group("version") == recipe_version()

    rec = RecordingDocker()
    box_mod._start_boxed(run_dir, defender_dir, spec, rec, lambda _d: ())
    assert image_token(rec.create_argv or []) == expected
    assert not any("{" in t or "}" in t for t in rec.create_argv or []), rec.create_argv

    rec2 = RecordingDocker()
    box_mod._start_boxed_request(request, rec2, lambda _d: ())
    assert image_token(rec2.create_argv or []) == expected

    seen: list[list[str]] = []

    def fake_run(argv, **kw):
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout='{"ok": true}', stderr="")

    runner("print('{}')", None, run=fake_run)
    runs = [a for a in seen if a[:2] == ["docker", "run"]]
    assert len(runs) == 1, seen
    assert runs[0][-3:] == [image_tag(DEFENDER), "python3", "-"]
    assert runs[0].count("--pull=never") == 1


# ---- d1 --------------------------------------------------------------------------------------
def test_an_explicit_rootfs_is_appended_verbatim_and_reads_no_file(tmp_path):
    root = tmp_path / "bare"
    defender_dir = plant_tree(root, missing=HASH_INPUTS, copy_code=False)
    run_dir = make_run_dir(tmp_path)
    spec = BoxSpec(rootfs=STOCK_ROOTFS)

    rec = RecordingDocker()
    box_mod._start_boxed(run_dir, defender_dir, spec, rec, lambda _d: ())
    assert image_token(rec.create_argv or []) == STOCK_ROOTFS

    rec2 = RecordingDocker()
    box_mod._start_boxed_request(_request(root, run_dir, spec=spec), rec2, lambda _d: ())
    assert image_token(rec2.create_argv or []) == STOCK_ROOTFS


# ---- d3 (the recipe and the box closure name the image; nothing else does) -------------------
def test_a_recipe_byte_or_a_box_closure_entry_moves_the_tag_and_an_edit_outside_the_closure_does_not(tmp_path):
    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    baseline = image_tag(defender_dir)
    assert baseline.startswith("defender-box:v2-"), baseline
    assert image_tag(defender_dir) == baseline, "the name is not deterministic on re-call"

    def edited(name: str, old: bytes, new: bytes) -> str:
        original = PLANTED_INPUT_BYTES[name]
        assert original.count(old) == 1, (name, old)
        (defender_dir / name).write_bytes(original.replace(old, new))
        try:
            return image_tag(defender_dir)
        finally:
            (defender_dir / name).write_bytes(original)

    moving = {
        "a Dockerfile byte": edited("box.Dockerfile", b"RUN true", b"RUN tru3"),
        "a closure entry's version": edited(
            "uv.lock", b'name = "alpha"\nversion = "1.0.0"', b'name = "alpha"\nversion = "1.0.1"',
        ),
        "[tool.uv]": edited("pyproject.toml", b"package = false", b"package = true"),
    }
    for what, moved in moving.items():
        assert moved != baseline, f"{what} did not move the tag"
        assert moved.startswith("defender-box:v2-"), f"the version prefix moved: {moved}"
    assert image_tag(defender_dir) == baseline, "restoring the inputs did not restore the tag"

    holding = {
        "a lock comment": edited("uv.lock", b"revision = 3\n", b"revision = 3\n# a comment\n"),
        "a dev-extra entry's version": edited(
            "uv.lock", b'name = "devtool"\nversion = "7.0.0"', b'name = "devtool"\nversion = "7.0.1"',
        ),
        "[tool.ruff]": edited("pyproject.toml", b"line-length = 100", b"line-length = 120"),
    }
    for what, held in holding.items():
        assert held == baseline, f"{what} moved the tag"
    (defender_dir / "README.md").write_text("not a hash input\n", encoding="utf-8")
    (defender_dir / "runtime").mkdir(exist_ok=True)
    (defender_dir / "runtime" / "extra.py").write_text("x = 1\n", encoding="utf-8")
    assert image_tag(defender_dir) == baseline, "a file outside the three moved the tag"


# ---- d4 --------------------------------------------------------------------------------------
def test_two_trees_with_identical_inputs_name_the_same_image_wherever_they_sit(tmp_path):
    a = plant_tree(tmp_path / "checkout", copy_code=False)
    b = plant_tree(tmp_path / "worktrees" / "lessons-abc123" / "deeper", copy_code=False)
    copied = tmp_path / "repo-view" / "defender"
    shutil.copytree(a, copied)
    tags = {image_tag(a), image_tag(b), image_tag(copied)}
    assert len(tags) == 1, tags
    assert TAG_RE.match(next(iter(tags))), tags
    # A closure entry moved in one tree only (a lock comment cannot rename).
    (b / "uv.lock").write_bytes(PLANTED_INPUT_BYTES["uv.lock"].replace(
        b'name = "gamma"\nversion = "3.0.0"', b'name = "gamma"\nversion = "3.0.1"'))
    assert image_tag(b) != image_tag(a), "the positive control: a different closure, same name"


# ---- d10 (an input that is missing or cannot be read) ------------------------------------------
@pytest.mark.parametrize("lane", ["run-dir", "request"])
@pytest.mark.parametrize(("unreadable", "first_named"), [  # lint-stale-ref: ok — this test's own parameter, not the removed helper
    ("all-missing", "box.Dockerfile"),
    ("uv.lock-missing", "uv.lock"),
    ("uv.lock-and-pyproject.toml-missing", "uv.lock"),
    ("pyproject.toml-is-a-directory", "pyproject.toml"),
    ("uv.lock-is-not-toml", "uv.lock"),
    ("uv.lock-dependencies-is-a-string", "uv.lock"),
    ("uv.lock-holds-a-nameless-entry-nested-deep", "uv.lock"),
    ("uv.lock-holds-an-integer-past-the-digit-limit", "uv.lock"),
])
def test_a_mounted_tree_without_the_three_inputs_raises_boxfault_naming_the_tree_before_any_docker_call(
    tmp_path, monkeypatch, lane, unreadable, first_named,  # lint-stale-ref: ok — this test's own parameter, not the removed helper
):
    _no_unsandboxed(monkeypatch)
    root = tmp_path / "tree"
    if unreadable == "all-missing":
        defender_dir = plant_tree(root, missing=HASH_INPUTS, copy_code=False)
    elif unreadable == "uv.lock-missing":
        defender_dir = plant_tree(root, missing=("uv.lock",), copy_code=False)
    elif unreadable == "uv.lock-and-pyproject.toml-missing":
        defender_dir = plant_tree(root, missing=("uv.lock", "pyproject.toml"), copy_code=False)
    elif unreadable == "uv.lock-is-not-toml":
        defender_dir = plant_tree(root, copy_code=False)
        (defender_dir / "uv.lock").write_bytes(PLANTED_INPUT_BYTES["uv.lock"] + b"[[package]\n")
    elif unreadable == "uv.lock-dependencies-is-a-string":
        defender_dir = plant_tree(root, copy_code=False)
        alpha_links = (
            b'dependencies = [\n    { name = "beta", extra = ["speed"] },\n'
            b'    { name = "winonly", marker = "sys_platform == \'win32\'" },\n]\n'
        )
        lock = PLANTED_INPUT_BYTES["uv.lock"]
        assert lock.count(alpha_links) == 1, "the planted lock no longer spells alpha's links this way"
        (defender_dir / "uv.lock").write_bytes(lock.replace(alpha_links, b'dependencies = "beta"\n'))
    elif unreadable == "uv.lock-holds-a-nameless-entry-nested-deep":
        defender_dir = plant_tree(root, copy_code=False)
        (defender_dir / "uv.lock").write_bytes(
            PLANTED_INPUT_BYTES["uv.lock"] + b"\n[[package]]\n[package." + b".".join([b"x"] * 20_000) + b"]\nb = 1\n")
    elif unreadable == "uv.lock-holds-an-integer-past-the-digit-limit":
        defender_dir = plant_tree(root, copy_code=False)
        (defender_dir / "uv.lock").write_bytes(PLANTED_INPUT_BYTES["uv.lock"].replace(
            b'name = "alpha"\nversion = "1.0.0"\n', b'name = "alpha"\nversion = "1.0.0"\nx = ' + b"1" * 5000 + b"\n", 1))
    else:
        defender_dir = plant_tree(root, missing=("pyproject.toml",), copy_code=False)
        (defender_dir / "pyproject.toml").mkdir()
    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    start = (
        (lambda: box_mod.start_box(run_dir, defender_dir, docker=rec, tenant_id=TEST_TENANT)) if lane == "run-dir"
        else (lambda: box_mod.start_box(_request(root, run_dir), docker=rec))
    )
    with pytest.raises(BoxFault) as e:
        start()
    message = str(e.value)
    assert str(defender_dir) in message, message
    assert first_named in message, message  # lint-stale-ref: ok — this test's own parameter, not the removed helper
    for later in HASH_INPUTS[HASH_INPUTS.index(first_named) + 1:]:  # lint-stale-ref: ok — this test's own parameter, not the removed helper
        assert later not in message, (later, message)
    malformed = unreadable.startswith("uv.lock-") and unreadable not in (
        "uv.lock-missing", "uv.lock-and-pyproject.toml-missing")
    verb, other = ("cannot use", "cannot read") if malformed else ("cannot read", "cannot use")
    assert verb in message, (verb, message)
    assert other not in message, (other, message)
    assert "run" not in subcommands(rec.calls), rec.calls
    assert rec.create_argv is None


# ---- the C46 refusal runs before the resolver (both lanes) ---------------------------------------
def test_the_c46_uncovered_mount_refusal_fires_before_the_resolver_on_both_lanes(tmp_path):
    root = tmp_path / "lacking"
    defender_dir = plant_tree(root, missing=HASH_INPUTS, copy_code=False)
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)

    rec = RecordingDocker()
    with pytest.raises(BoxFault) as e:
        box_mod._start_boxed(run_dir, defender_dir, BoxSpec(), rec, lambda _d: MOUNTS)
    assert "C46" in str(e.value)
    assert "box.Dockerfile" not in str(e.value)
    assert not {"image", "run"} & set(subcommands(rec.calls)), rec.calls   # the stale-name check only
    assert rec.create_argv is None

    rec = RecordingDocker()
    with pytest.raises(BoxFault) as e:
        box_mod._start_boxed_request(_request(root, run_dir), rec, lambda _d: MOUNTS)
    assert "C46" in str(e.value)
    assert "box.Dockerfile" not in str(e.value)
    assert not {"image", "run"} & set(subcommands(rec.calls)), rec.calls
    assert rec.create_argv is None

    with pytest.raises(BoxFault) as e:
        box_mod._start_boxed(run_dir, defender_dir, BoxSpec(), RecordingDocker(), lambda _d: ())
    assert "C46" not in str(e.value)
    assert "box.Dockerfile" in str(e.value)
    with pytest.raises(BoxFault) as e:
        box_mod._start_boxed_request(_request(root, run_dir), RecordingDocker(), lambda _d: ())
    assert "C46" not in str(e.value)
    assert "box.Dockerfile" in str(e.value)


# ---- the running package's recipe is authoritative; the name carries its version ----------------
def test_the_image_name_carries_the_running_packages_recipe_version_and_never_the_mounted_trees_recipe(tmp_path):
    version = recipe_version()
    assert isinstance(version, str)
    assert TAG_RE.match(f"defender-box:{version}-{'0' * 12}"), version
    root = tmp_path / "tree"
    defender_dir = plant_tree(root, copy_code=False)
    foreign = defender_dir / "box"
    foreign.mkdir(parents=True)
    (foreign / "_image.py").write_text(
        "RECIPE_VERSION = 'v99'\n"
        "def image_tag(tree):\n"
        "    return 'defender-box:v99-000000000000'\n",
        encoding="utf-8",
    )
    (foreign / "__init__.py").write_text("", encoding="utf-8")
    expected = image_tag(defender_dir)
    assert expected.startswith(f"defender-box:{version}-"), expected
    assert expected != "defender-box:v99-000000000000"

    run_dir = make_run_dir(tmp_path)
    rec = RecordingDocker()
    box_mod._start_boxed(run_dir, defender_dir, BoxSpec(), rec, lambda _d: ())
    assert image_token(rec.create_argv or []) == expected
    rec2 = RecordingDocker()
    box_mod._start_boxed_request(_request(root, run_dir), rec2, lambda _d: ())
    assert image_token(rec2.create_argv or []) == expected


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
    # `export` included: the verbs are exactly `tag` | `build`.
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


# ---- no docker to run ---------------------------------------------------------------------------
def test_box_image_build_without_docker_on_path_prints_one_line_and_exits_1(tmp_path):
    _, script = _planted_script(tmp_path)
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    out = _run_script(script, "build", cwd=Path("/"), env={"PATH": str(empty)})
    assert out.returncode == 1, (out.returncode, out.stderr)
    assert out.stdout == "", out.stdout
    assert out.stderr.startswith("box_image.py: could not run docker:"), out.stderr
    assert "Traceback" not in out.stderr, out.stderr


# ---- an unreadable input, script side ----------------------------------------------------------
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


_FROM_DIGEST = re.compile(r"^FROM\s+python:3\.11-slim@sha256:[0-9a-f]{64}(\s+AS\s+\S+)?\s*$")


def _instructions(path: Path = DOCKERFILE) -> list[str]:
    """The Dockerfile's instructions, one per entry, line continuations joined and comment
    lines dropped (a `#` inside a RUN's shell text is kept — only whole comment lines go)."""
    assert path.is_file(), f"{path} does not exist"
    joined: list[str] = []
    pending = ""
    # Split on "\n" ONLY, as BuildKit does — `str.splitlines()` also breaks on \x1c, \x0b,
    # \x0c, \x85, U+2028…, which would show a test two lines where BuildKit runs one.
    for raw in path.read_text(encoding="utf-8").split("\n"):
        line = raw.rstrip()
        if not pending and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        joined.append((pending + line).strip())
        pending = ""
    if pending:
        joined.append(pending.strip())
    return joined


def _index_of(instructions: list[str], needle: str) -> int:
    hits = [i for i, ins in enumerate(instructions) if needle in ins]
    assert len(hits) == 1, f"expected exactly one instruction containing {needle!r}, got {hits}"
    return hits[0]


def _run_parts(instruction: str) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """A `RUN` split into its `--mount=` options (each a `key=value` dict; a bare option maps
    to ""), every OTHER `--` flag before the command, verbatim (`--network=none`, a `--mount`
    spelled without `=`, …), and the shell words it runs, as `shlex` splits them."""
    assert instruction.startswith("RUN "), instruction
    words = shlex.split(instruction[len("RUN "):])
    mounts: list[dict[str, str]] = []
    flags: list[str] = []
    while words and words[0].startswith("--"):
        flag = words.pop(0)
        if flag.startswith("--mount="):
            opts = {}
            for part in flag[len("--mount="):].split(","):
                key, _, value = part.partition("=")
                opts[key] = value
            mounts.append(opts)
        else:
            flags.append(flag)
    return mounts, flags, words


# ---- d11 -------------------------------------------------------------------------------------
def test_the_dockerfile_pins_its_base_by_sha256_digest():
    froms = [ins for ins in _instructions() if ins.startswith("FROM ")]
    assert froms, "no FROM instruction"
    assert _FROM_DIGEST.match(froms[0]), froms[0]
    for ins in froms:
        assert "@sha256:" in ins, ins


# ---- d13 (negative; positive control: d14 — the two files ARE copied and synced) -----------------
def test_the_dockerfile_copies_exactly_pyproject_and_uv_lock_and_no_code():
    instructions = _instructions()
    assert not any(ins.startswith("ADD ") for ins in instructions)
    copies = [
        (i, ins) for i, ins in enumerate(instructions)
        if ins.startswith("COPY ") and "--from=" not in ins
    ]
    assert len(copies) == 1, copies
    copy_at, copy = copies[0]
    assert copy.split()[1:] == ["pyproject.toml", "uv.lock", "./"], copy
    workdirs = [i for i, ins in enumerate(instructions) if ins.startswith("WORKDIR ")]
    assert workdirs, "no WORKDIR: the COPY's `./` is the image root"
    assert workdirs[0] < copy_at, "the COPY lands before any WORKDIR is set"
    assert copy_at < _index_of(instructions, "uv sync"), "the sync precedes the COPY it reads"

    runs = [ins for ins in instructions if ins.startswith("RUN ")]
    mounts = [m for ins in runs for m in _run_parts(ins)[0]]
    assert any("astral-sh/uv" in m.get("from", "") for m in mounts), mounts
    context_binds = [m for m in mounts if m.get("type", "bind") == "bind" and "from" not in m]
    assert context_binds == [], f"a RUN binds the build context: {context_binds}"


# ---- d16 -------------------------------------------------------------------------------------
def test_the_box_extra_is_exactly_duckdb_libfaketime_and_pytz_and_the_lock_provides_it():
    pyproject = tomllib.loads((DEFENDER / "pyproject.toml").read_text(encoding="utf-8"))
    extras = pyproject["project"]["optional-dependencies"]
    assert "box" in extras, sorted(extras)
    names = [re.split(r"[<>=!~;\[ ]", entry, maxsplit=1)[0].strip().lower() for entry in extras["box"]]
    assert names == ["duckdb", "libfaketime", "pytz"], extras["box"]

    lock = tomllib.loads((DEFENDER / "uv.lock").read_text(encoding="utf-8"))
    defender = [p for p in lock["package"] if p["name"] == "defender"]
    assert len(defender) == 1
    box_extra = defender[0].get("optional-dependencies", {}).get("box")
    assert box_extra is not None, "the lock has no `box` extra: relock"
    assert [d["name"] for d in box_extra] == ["duckdb", "libfaketime", "pytz"], box_extra
    assert "box" in defender[0]["metadata"]["provides-extras"], defender[0]["metadata"]


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


# ---- d49 (the live suite's startup probe) -----------------------------------------------------
@pytest.mark.live
@requires_live_box
def test_the_live_suites_duckdb_startup_probe_exits_zero_in_a_box_from_the_owned_image(tmp_path):
    run_dir = make_run_dir(tmp_path)
    box = box_mod.start_box(run_dir, DEFENDER, docker=box_mod.run_docker, tenant_id=TEST_TENANT)
    try:
        res = box_run(box, "python3 -c 'import duckdb'", cwd=Path("/"))
    finally:
        box_mod.stop_box(box)
    assert res.rc == 0, res.err
