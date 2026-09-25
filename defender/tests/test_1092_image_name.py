"""#1092 — the owned image's NAME: derived at box start from the mounted tree (M3 revised).

Demand #0 and its neighbourhood in `spec-flow/specs/spec_graph_1092.yaml`: the resolver
`runtime/box/_image.py::image_tag(tree)`, the three `docker run` sites that call it when
`rootfs` is unset, the explicit-rootfs escape, and what a tree that cannot name an image does
(MF1, resolved at §7: any read error → `BoxFault` naming the folder and the first file, raised
in the argv builder before docker; the C46 refusal keeps running FIRST; no run-dir marker).

Hermetic: the trees are planted by the tests and the daemon is `RecordingDocker`. Whether
the three inputs were read is observed tier-1 (`_spec1092`'s hierarchy): over a tree that
HOLDS none of them a read faults, so a lane that completes — or refuses for another reason —
read nothing; and a name that equals the digest of the planted inputs was read from them
(an edit to the recipe or to the lock's box closure renames it, d3). Since #1097 the name is
the Dockerfile's bytes plus the lock's core + `box` closure, so the planted `uv.lock` and
`pyproject.toml` are well-formed TOML (`_spec1092.PLANTED_LOCK`) and an edit OUTSIDE the
closure does not rename the image; the full O1/O2 matrix is `test_1097_image_name_closure.py`. No process-wide audit hook is installed for it — the one
in-process hook a spec test needs (d5) lives in a child interpreter.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender.runtime import box as box_mod
from defender.runtime.box import BoxRequest, BoxSpec, Mount
from defender.runtime.box_codec import BoxFault
from defender.runtime.scrub import verdict_path
from defender.tests._spec1092 import (
    DEFENDER,
    HASH_INPUTS,
    PLANTED_INPUT_BYTES,
    REPO_ROOT,
    STOCK_ROOTFS,
    TAG_RE,
    DockerFault,
    NoSuchImageDocker,
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
    """`BoxSpec()` leaves `rootfs` unset (`None`), and with it unset the run-dir lane's
    `docker run` argv names `image_tag(defender_dir)`, the request lane's names
    `image_tag(Path(request.workdir) / "defender")`, and `_spec771`'s rootfs runner names
    `image_tag(DEFENDER)` — `defender-box:<RECIPE_VERSION>-` followed by 12 hex of a sha256
    over `box.Dockerfile`, `uv.lock` and `pyproject.toml` in that directory (#1097: the
    Dockerfile's bytes, `[tool.uv]`, and the lock's core + `box` closure; MF3: the running
    package's `_image.RECIPE_VERSION` prefixes the digest) — resolved on
    the host when the argv is built, never earlier: the spec and the request are constructed
    over a root that does not yet hold the three files (a read there would fault), and the
    name on the argv is the digest of bytes planted only afterwards. Every slot of the create
    payload is bound (no `{`-template token survives on the argv).

    # rejected: no checked-in tag constant, no "constant equals recomputed hash" test, no
    # "bump the tag" step, no stale-constant loop (M3 revised). The run record gains NO
    # image/provenance field — the name is derivable from the commit (JF6; platform-design.md's
    # `defender_image_digest` stays a recorded follow-up). The per-start stat+hash of three
    # small files is an accepted cost with NO cache (2.3 ms, N2). No registry, no digest
    # round-trip, no bot commit (D2 B, strictly additive later)."""
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
    """With `rootfs` set explicitly (`BoxSpec(rootfs="python:3.11-slim")` on either lane) the
    argv appends that token verbatim and no input file is read — the tree holds NONE of the
    three inputs, so a read would have faulted and the start would not have completed — so a
    test that needs the stock image pins one (fake-docker tests; a real-daemon test pins
    `image_tag(DEFENDER)` instead — #94)."""
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


# ---- d2 --------------------------------------------------------------------------------------
def test_no_runtime_path_names_or_falls_back_to_the_stock_image(tmp_path, monkeypatch):
    """No module under `defender/runtime` names `python:3.11-slim` in code (a comment may
    recall it), and a missing owned image raises rather than retrying with any other image:
    the one image the daemon is asked for is the derived one, no `run` and no `pull` follows
    the daemon's `no`, and the `BoxFault` propagates out of `start_box`."""
    naming = sorted(
        str(p.relative_to(DEFENDER)) for p in (DEFENDER / "runtime").rglob("*.py")
        if any(
            STOCK_ROOTFS in line.split("#", 1)[0]
            for line in p.read_text(encoding="utf-8").splitlines()
        )
    )
    assert naming == [], f"the stock image is still named as a rootfs by {naming}"

    _no_unsandboxed(monkeypatch)
    defender_dir = plant_tree(tmp_path / "tree")
    run_dir = make_run_dir(tmp_path)
    rec = NoSuchImageDocker()
    with pytest.raises(BoxFault):
        box_mod.start_box(run_dir, defender_dir, docker=rec)
    subs = subcommands(rec.calls)
    assert "run" not in subs, subs
    assert "pull" not in subs, subs
    assert rec.inspected_images == [image_tag(defender_dir)], rec.inspected_images
    assert rec.create_argv is None


# ---- d3 (#1097 O1/O2: the recipe and the box closure name the image; nothing else does) ----
def test_a_recipe_byte_or_a_box_closure_entry_moves_the_tag_and_an_edit_outside_the_closure_does_not(tmp_path):
    """Changing one byte of `box.Dockerfile`, the version of a lock entry in the core + `box`
    closure, or `[tool.uv]` changes `image_tag(tree)` — the 12-hex digest moves, the
    `defender-box:v2-` prefix does not — and restoring it restores the name (O2). A comment in
    the lock, a version bump of a `dev`-extra entry, a `[tool.ruff]` edit, and a file outside
    the three inputs leave the name where it was (O1: an edit that cannot change the image does
    not rename it). Each file's moving edit is that file's positive control: the resolver
    demonstrably reads it, so an unmoved name is not a resolver that reads nothing.

    The full matrix — extras on edges, the superset rule, reordering and reformatting, the real
    lock — is `test_1097_image_name_closure.py`'s.

    # rejected: hashing the three files' whole bytes (the #1092 recipe): 18 of 20 manifest
    # edits in the c4 replay renamed an image whose contents they could not change (#1097 O1);
    # a committed `uv export` of the closure as the input (#1097 round 1): a second copy of the
    # lock, with its own drift check and an unpinned exporter's bytes (the design amendment)."""
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
    """Two directories holding byte-identical copies of the three inputs — a checkout and a
    worktree, the runner's checkout and the DooD container's `/repo` view of it — yield the
    same `image_tag`, so the same commit names one image wherever it is mounted."""
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


# ---- d5 --------------------------------------------------------------------------------------
def test_importing_the_image_module_and_constructing_boxspec_opens_no_file(tmp_path):
    """Importing `runtime/box/_image.py`, importing `defender.runtime.box`, and constructing
    `BoxSpec()` / evaluating `DEFAULT_SPEC` read none of `box.Dockerfile`, `uv.lock` or
    `pyproject.toml` (an audit hook on `open` filtered to those three names sees nothing): the
    name is computed only when an argv builder asks for it, so the box's own import of the
    package reads no input off the mounted tree. Positive control, same process: calling
    `image_tag(<tree>)` afterwards opens all three."""
    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    code = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "seen = []\n"
        "def hook(event, args):\n"
        "    if event == 'open' and isinstance(args[0], (str, bytes)):\n"
        "        seen.append(str(args[0]))\n"
        "sys.addaudithook(hook)\n"
        "names = ('box.Dockerfile', 'uv.lock', 'pyproject.toml')\n"
        "from defender.runtime.box import _image\n"
        "from defender.runtime import box\n"
        "box.BoxSpec(); box.DEFAULT_SPEC\n"
        "at_import = [p for p in seen if Path(p).name in names]\n"
        "del seen[:]\n"
        f"tag = _image.image_tag(Path({str(defender_dir)!r}))\n"
        "on_call = sorted({Path(p).name for p in seen if Path(p).name in names})\n"
        "print(json.dumps({'at_import': at_import, 'on_call': on_call, 'tag': tag}))\n"
    )
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, encoding="utf-8",
        env=env, cwd=str(tmp_path), timeout=120,
    )
    assert out.returncode == 0, out.stderr
    import json

    seen = json.loads(out.stdout)
    assert seen["at_import"] == [], seen
    assert seen["on_call"] == sorted(HASH_INPUTS), seen
    assert seen["tag"] == image_tag(defender_dir)


# ---- d10 (widened by MF1: "missing" → "cannot be read") ----------------------------------------
@pytest.mark.parametrize("lane", ["run-dir", "request"])
@pytest.mark.parametrize(("unreadable", "first_named"), [
    ("all-missing", "box.Dockerfile"),
    ("uv.lock-missing", "uv.lock"),
    ("uv.lock-and-pyproject.toml-missing", "uv.lock"),
    ("pyproject.toml-is-a-directory", "pyproject.toml"),
    ("uv.lock-is-not-toml", "uv.lock"),
    ("uv.lock-dependencies-is-a-string", "uv.lock"),
])
def test_a_mounted_tree_without_the_three_inputs_raises_boxfault_naming_the_tree_before_any_docker_call(
    tmp_path, monkeypatch, lane, unreadable, first_named,
):
    """Starting a box on either lane over a mounted tree whose three inputs cannot be read —
    a file missing, or a directory sitting in a file's place (any `OSError`, not only
    `FileNotFoundError`) — raises `BoxFault` (never the bare OSError) naming the tree and the
    FIRST unreadable file in the resolver's order `box.Dockerfile`, `uv.lock`,
    `pyproject.toml` (and no later one), and the recorded docker calls contain no `run` (the
    reap scan and the shared-mounts discovery that precede argv construction may still be
    recorded). A `uv.lock` that reads but is not TOML takes the same door (#1097: the name is
    computed from the PARSED lock, and a parse fault is the resolver's `ImageInputError`
    naming the file, never a fallback hash of its bytes) — and so does a lock that parses but
    has the wrong SHAPE, a reached entry's `dependencies` written as a string (#1097 amendment
    2's shape check: a `BoxFault`, never the TypeError a walk over it would raise). The
    message says "cannot read" for a file that is missing or a directory, "cannot use" for one
    that reads but is not usable.

    # rejected: hashing a missing input as empty (a name for an image nobody can build, with a
    # remedy pointing at a tree with no Dockerfile) — F-A; a raw OSError (the in-file
    # precedent `_plant` wraps it, and on the drain lane a non-BoxFault dead-letters case
    # after case instead of aborting) — MF1 option D."""
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
    malformed = unreadable in ("uv.lock-is-not-toml", "uv.lock-dependencies-is-a-string")
    verb, other = ("cannot use", "cannot read") if malformed else ("cannot read", "cannot use")
    assert verb in message, (verb, message)
    assert other not in message, (other, message)
    assert "run" not in subcommands(rec.calls), rec.calls
    assert rec.create_argv is None


# ---- MF1 part 2: the C46 refusal keeps running first (both lanes) --------------------------------
def test_the_c46_uncovered_mount_refusal_fires_before_the_resolver_on_both_lanes(tmp_path):
    """Over a tree that lacks the three inputs AND sits on no path this container shares with
    the daemon, both argv builders raise the pre-existing C46 uncovered-mount refusal — not the
    resolver's missing-input fault, which is what a read of the lacking tree would have raised
    first — and no daemon call is made; the same lacking tree on a native daemon (no mount
    table) raises the resolver's fault naming `box.Dockerfile`. The six existing `match="C46"`
    sites keep their assertion unchanged."""
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


# ---- MF1 part 3: no run-dir marker for a resolver refusal ----------------------------------------
def test_a_resolver_refusal_leaves_no_did_not_run_marker_while_a_create_fault_still_does(tmp_path, monkeypatch):
    """A resolver refusal is raised while the argv is being assembled, before the code that
    writes markers runs, so it leaves NO "this run did not happen" marker — beside the run dir
    on the run-dir lane, beside any writable mount source on the request lane — the same
    silence as the C46 refusal; the exception is the carrier. Positive control on both lanes:
    a create fault over a complete tree still writes the marker (`ran: false`)."""
    _no_unsandboxed(monkeypatch)
    lacking = plant_tree(tmp_path / "lacking", missing=HASH_INPUTS, copy_code=False)
    complete = plant_tree(tmp_path / "complete", copy_code=False)

    run_dir = make_run_dir(tmp_path, "run-a")
    with pytest.raises(BoxFault):
        box_mod.start_box(run_dir, lacking, docker=RecordingDocker())
    assert not verdict_path(run_dir).exists(), "a resolver refusal wrote a run-dir marker"

    mount = make_run_dir(tmp_path, "run-b")
    with pytest.raises(BoxFault):
        box_mod.start_box(_request(lacking.parent, mount), docker=RecordingDocker())
    assert not verdict_path(mount).exists(), "a resolver refusal wrote a mount-source marker"

    bind_gone = DockerFault(rc=125, stderr="bind source path does not exist\n", cite="po1")
    run_dir_c = make_run_dir(tmp_path, "run-c")
    with pytest.raises(BoxFault):
        box_mod.start_box(run_dir_c, complete, docker=RecordingDocker(create=bind_gone))
    assert verdict_path(run_dir_c).is_file(), "the positive control: a create fault marks"
    assert '"ran": false' in verdict_path(run_dir_c).read_text(encoding="utf-8")

    mount_d = make_run_dir(tmp_path, "run-d")
    with pytest.raises(BoxFault):
        box_mod.start_box(_request(complete.parent, mount_d), docker=RecordingDocker(create=bind_gone))
    assert verdict_path(mount_d).is_file(), "the positive control: a create fault marks"


# ---- MF3: the running package's recipe is authoritative; the name carries its version ---------------
def test_the_image_name_carries_the_running_packages_recipe_version_and_never_the_mounted_trees_recipe(tmp_path):
    """The image name is `defender-box:<RECIPE_VERSION>-<12 hex>` with `RECIPE_VERSION` a
    constant in the running package's `runtime/box/_image.py`; both argv builders resolve
    through that plain import and never load the MOUNTED tree's `_image.py` by path — a
    mounted tree carrying a different recipe (a `RECIPE_VERSION = "v99"` module that names a
    different image) still yields the running package's name, so a drift between the two
    recipes is legible in the fault text (`v2-…` vs the build's `v99-…`) instead of silent."""
    version = recipe_version()
    assert isinstance(version, str)
    assert TAG_RE.match(f"defender-box:{version}-{'0' * 12}"), version
    root = tmp_path / "tree"
    defender_dir = plant_tree(root, copy_code=False)
    foreign = defender_dir / "runtime" / "box"
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
