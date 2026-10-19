"""The owned image's name is derived at box start from the mounted tree's recipe and lock."""
from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

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

#: The devcontainer-shaped mount table `test_box_dood_c46.py` uses: `/workspace` is shared
#: with the daemon, a pytest `tmp_path` is not.
MOUNTS: tuple[tuple[Path, Path], ...] = (
    (Path("/var/run/docker.sock"), Path("/var/run/docker.sock")),
    (Path("/workspace"), Path("/home/dev/projects/repo")),
)


def _request(defender_root: Path, run_dir: Path, *, spec: BoxSpec | None = None,
             name: str = "defender-drain-1092") -> BoxRequest:
    """A request-lane box in the drain's shape: `workdir` is the tree ROOT (the worktree),
    the defender dir is `workdir / "defender"` (N5), one rw mount for the markers."""
    kw = {} if spec is None else {"spec": spec}
    return BoxRequest(
        name=name, workdir=defender_root, env={},
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


# ---- d3 (#1097 O1/O2: the recipe and the box closure name the image; nothing else does) ----
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
    # A closure entry moved in one tree only (a comment would not do: it cannot rename, #1097).
    (b / "uv.lock").write_bytes(PLANTED_INPUT_BYTES["uv.lock"].replace(
        b'name = "gamma"\nversion = "3.0.0"', b'name = "gamma"\nversion = "3.0.1"'))
    assert image_tag(b) != image_tag(a), "the positive control: a different closure, same name"


# ---- d10 (widened by MF1: "missing" → "cannot be read") ----------------------------------------
@pytest.mark.parametrize("lane", ["run-dir", "request"])
@pytest.mark.parametrize(("unreadable", "first_named"), [
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
    tmp_path, monkeypatch, lane, unreadable, first_named,
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
        (lambda: box_mod.start_box(run_dir, defender_dir, docker=rec)) if lane == "run-dir"
        else (lambda: box_mod.start_box(_request(root, run_dir), docker=rec))
    )
    with pytest.raises(BoxFault) as e:
        start()
    message = str(e.value)
    assert str(defender_dir) in message, message
    assert first_named in message, message
    for later in HASH_INPUTS[HASH_INPUTS.index(first_named) + 1:]:
        assert later not in message, (later, message)
    malformed = unreadable.startswith("uv.lock-") and unreadable not in (
        "uv.lock-missing", "uv.lock-and-pyproject.toml-missing")
    verb, other = ("cannot use", "cannot read") if malformed else ("cannot read", "cannot use")
    assert verb in message, (verb, message)
    assert other not in message, (other, message)
    assert "run" not in subcommands(rec.calls), rec.calls
    assert rec.create_argv is None


# ---- MF1 part 2: the C46 refusal keeps running first (both lanes) --------------------------------
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


# ---- MF3: the running package's recipe is authoritative; the name carries its version ---------------
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
