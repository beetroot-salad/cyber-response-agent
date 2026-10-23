"""A missing box image faults naming the build command; start_box never builds."""
from __future__ import annotations

import contextlib
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from defender import box as box_mod
from defender.box import BoxRequest, Mount
from defender.execution.box_codec import BoxFault
from defender.tests.support.sandbox._spec1092 import (
    BUILD_COMMAND_TAIL,
    DEFENDER,
    REPO_ROOT,
    DockerFault,
    NoSuchImageDocker,
    RecordingDocker,
    image_tag,
    inspected_image,
    make_run_dir,
    no_such_image_stderr,
    plant_tree,
    remedy_command,
    subcommands,
)
from defender.tests.tenancy.tenant_1108_delivery._support import (
    LANES,
    ForgeHTTP,
    build_tenant,
    configured_origin,
    fixture_identity,
)
from defender.tests.tenancy.tenant_1108_delivery._support import target as p3_target


def _request(root: Path, run_dir: Path) -> BoxRequest:
    return BoxRequest(
        name="defender-drain-1092", workdir=root, env={},
        mounts=(Mount(source=run_dir, target=run_dir, writable=True),),
    )


def _no_unsandboxed(monkeypatch) -> None:
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)


#: N1's create WITHOUT `--pull=never`: the CLI's two-line pull-path text. Not a shape the
#: create path can produce any more (JF5) — exactly why it must NOT select the remedy.
PULL_PATH_STDERR = (
    "Unable to find image 'defender-box:v1-0123456789ab:latest' locally\n"
    "docker: Error response from daemon: pull access denied for defender-box, repository does "
    "not exist or may require 'docker login'\n"
)


# ---- d42 -------------------------------------------------------------------------------------
def test_a_no_such_image_create_fault_names_the_build_command_with_the_mounted_trees_path_on_both_lanes(tmp_path, monkeypatch):
    _no_unsandboxed(monkeypatch)
    root = tmp_path / "tree with space"
    defender_dir = plant_tree(root, copy_code=False)
    run_dir = make_run_dir(tmp_path)
    expected = image_tag(defender_dir)

    rec = NoSuchImageDocker()
    with pytest.raises(BoxFault) as e:
        box_mod.start_box(run_dir, defender_dir, docker=rec)
    message = str(e.value)
    assert inspected_image(rec.calls) == expected, rec.calls
    assert "run" not in subcommands(rec.calls), rec.calls
    assert f"No such image: {expected}" in message
    assert remedy_command(message) == [
        "python3", f"{defender_dir.parent.resolve()}/{BUILD_COMMAND_TAIL.split(' ')[0]}", "build",
    ], message

    rec = NoSuchImageDocker()
    with pytest.raises(BoxFault) as e:
        box_mod.start_box(_request(root, run_dir), docker=rec)
    message = str(e.value)
    assert inspected_image(rec.calls) == expected, rec.calls
    assert "run" not in subcommands(rec.calls), rec.calls
    assert f"No such image: {expected}" in message
    assert remedy_command(message) == [
        "python3", f"{root.resolve()}/{BUILD_COMMAND_TAIL.split(' ')[0]}", "build",
    ], message


# ---- d43 (negative; positive control: d42) ----------------------------------------------------
@pytest.mark.parametrize("lane", ["run-dir", "request"])
@pytest.mark.parametrize("shape", ["absent-bind-source", "pull-path-text", "no-such-image-text"])
def test_a_create_fault_of_any_other_shape_never_names_the_build_command(tmp_path, monkeypatch, lane, shape):
    _no_unsandboxed(monkeypatch)
    root = tmp_path / "tree"
    defender_dir = plant_tree(root, copy_code=False)
    run_dir = make_run_dir(tmp_path)
    if shape == "absent-bind-source":
        stderr = "docker: Error response from daemon: bind source path does not exist\n"
        cite = "po1"
    elif shape == "pull-path-text":
        stderr = PULL_PATH_STDERR
        cite = "N1"
    else:
        stderr = f"docker: Error response from daemon: No such image: {image_tag(defender_dir)}.\n"
        cite = "N1 (27.x spelling, #1095)"
    rec = RecordingDocker(create=DockerFault(rc=125, stderr=stderr, cite=cite))
    start = (
        (lambda d: box_mod.start_box(run_dir, defender_dir, docker=d)) if lane == "run-dir"
        else (lambda d: box_mod.start_box(_request(root, run_dir), docker=d))
    )
    with pytest.raises(BoxFault) as e:
        start(rec)
    message = str(e.value)
    assert inspected_image(rec.calls) == image_tag(defender_dir), rec.calls
    assert stderr.strip().splitlines()[-1] in message, message
    assert remedy_command(message) is None, message
    assert "box_image.py" not in message, message

    with pytest.raises(BoxFault) as e:
        start(NoSuchImageDocker())
    assert remedy_command(str(e.value)) is not None, str(e.value)


# ---- #1095 round 2: the other reading of a non-zero inspect --------------------------------------
@pytest.mark.parametrize("lane", ["run-dir", "request"])
def test_a_daemon_that_stopped_answering_is_reported_as_that_and_never_told_to_build(tmp_path, monkeypatch, lane):
    _no_unsandboxed(monkeypatch)
    root = tmp_path / "tree"
    defender_dir = plant_tree(root, copy_code=False)
    run_dir = make_run_dir(tmp_path)
    start = (
        (lambda d: box_mod.start_box(run_dir, defender_dir, docker=d)) if lane == "run-dir"
        else (lambda d: box_mod.start_box(_request(root, run_dir), docker=d))
    )
    rec = NoSuchImageDocker(daemon_down=True)
    with pytest.raises(BoxFault) as e:
        start(rec)
    message = str(e.value)
    assert "run" not in subcommands(rec.calls), rec.calls
    assert "daemon" in message, message
    assert "failed to connect" in message, message
    assert remedy_command(message) is None, message
    assert "box_image.py" not in message, message

    with pytest.raises(BoxFault) as e:
        start(NoSuchImageDocker())
    assert remedy_command(str(e.value)) is not None, str(e.value)


# ---- d44 (negative; positive control: d9 — the script DOES build) -----------------------------
@pytest.mark.parametrize("opt_out", [None, "0", "yes"])
def test_a_missing_image_raises_and_no_docker_build_is_ever_attempted(tmp_path, monkeypatch, opt_out):
    _no_unsandboxed(monkeypatch)
    if opt_out is not None:
        monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", opt_out)
    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    run_dir = make_run_dir(tmp_path)
    rec = NoSuchImageDocker()
    with pytest.raises(BoxFault):
        box_mod.start_box(run_dir, defender_dir, docker=rec)
    subs = subcommands(rec.calls)
    assert "build" not in subs, subs
    assert "pull" not in subs, subs
    assert "run" not in subs, subs

    held = RecordingDocker()
    box_mod.start_box(run_dir, defender_dir, docker=held)
    subs = subcommands(held.calls)
    assert "build" not in subs, subs
    assert "pull" not in subs, subs
    assert subs.count("run") == 1, subs
    assert (held.create_argv or []).count("--pull=never") == 1, held.create_argv
    assert "--pull" not in (held.create_argv or []), "the two-token spelling"


# ---- d46 -------------------------------------------------------------------------------------
def test_the_rootfs_runner_names_the_derived_image_with_pull_never_and_its_failure_carries_the_remedy(tmp_path):
    from defender.tests.e2e._spec771 import run_probe_under_profile

    runner: Callable[..., Any] = run_probe_under_profile
    profile = tmp_path / "profile.json"
    profile.write_text("{}", encoding="utf-8")
    seen: list[tuple[list[str], dict]] = []

    def healthy(argv, **kw):
        seen.append((list(argv), kw))
        return subprocess.CompletedProcess(argv, 0, stdout='{"ran": true}', stderr="")

    assert runner("print('{\"ran\": true}')", profile, run=healthy) == {"ran": True}
    asked, _ = seen[-2]
    assert asked[1:3] == ["image", "inspect"], asked
    assert asked[-1] == image_tag(DEFENDER), asked
    argv, kw = seen[-1]
    assert argv[:2] == ["docker", "run"]
    assert "--rm" in argv
    assert "-i" in argv
    assert argv[argv.index("--security-opt") + 1] == f"seccomp={profile}"
    assert argv.count("--pull=never") == 1
    assert "--pull" not in argv
    assert argv[-3:] == [image_tag(DEFENDER), "python3", "-"]
    assert kw.get("input") == "print('{\"ran\": true}')"

    runner("print(1)", None, run=healthy)
    argv, _ = seen[-1]
    assert "--security-opt" not in argv
    assert argv[-3:] == [image_tag(DEFENDER), "python3", "-"]

    runs: list[list[str]] = []

    def missing(argv, **kw):
        if argv[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr=no_such_image_stderr(argv[-1]))
        if argv[1:2] == ["version"]:      # the liveness probe: the daemon IS answering
            return subprocess.CompletedProcess(argv, 0, stdout="29.5.3\n", stderr="")
        runs.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout="{}", stderr="")

    with pytest.raises(AssertionError) as e:
        runner("print(1)", None, run=missing)
    message = str(e.value)
    assert runs == [], "a `docker run` was attempted after the daemon said no"
    assert f"No such image: {image_tag(DEFENDER)}" in message
    assert remedy_command(message) == [
        "python3", f"{REPO_ROOT.resolve()}/{BUILD_COMMAND_TAIL.split(' ')[0]}", "build",
    ], message


# ---- MF2 on the P4 drain (#1108 P4 re-spelling, OD12 class ii): the tenant drain's box --------
# The drain box is `Batch.box_request()` over a git-free draft, started through
# `TenantDelivery.start_box`; its `code` mount is the product's defender dir. The legacy row's
# cut-commit pointer (`origin/main @ <sha>` + a checkout instruction) is gone with the worktree:
# there is no deleted tree to point back to, so the message must not carry one.
@contextlib.contextmanager
def _tenant_batch(tmp_path: Path, defender_dir: Path) -> Iterator[tuple[Any, Any]]:
    with build_tenant(tmp_path / "tenant") as built:
        http = ForgeHTTP(remote=built[1])
        origin = configured_origin(built[0].knowledge)
        if origin is not None:
            http.serve(origin)
        delivery = p3_target().TenantDelivery.open(
            built[0], defender_dir=defender_dir, client=http.client,
            identity=fixture_identity(str(built[0].id)), origin=origin)
        yield delivery, delivery.start_batch("mf2", lanes=LANES)


def _tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


def test_the_tenant_drains_missing_image_fault_names_the_build_command_and_no_cut_commit(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    defender_dir = plant_tree(tmp_path / "product tree", copy_code=False)
    expected = image_tag(defender_dir)
    with _tenant_batch(tmp_path, defender_dir) as (delivery, batch):
        # `<T>/drafts`, whichever depth the staged root sits at (#1108 P4 amendment A / U9).
        drafts = next(p for p in batch.draft_root.parents if p.name == "drafts")
        before = _tree(drafts)

        def fault(docker: RecordingDocker) -> str:
            with pytest.raises(BoxFault) as e:
                delivery.start_box(batch.box_request(), docker=docker)
            assert _tree(drafts) == before, "a start fault left something under the drafts"
            return str(e.value)

        rec = NoSuchImageDocker()
        message = fault(rec)
        assert inspected_image(rec.calls) == expected, rec.calls
        assert "run" not in subcommands(rec.calls), rec.calls
        assert f"No such image: {expected}" in message
        assert remedy_command(message) == [
            "python3", f"{defender_dir.parent.resolve()}/{BUILD_COMMAND_TAIL.split(' ')[0]}", "build",
        ], message
        assert "origin/main @" not in message, f"a cut-commit pointer with no worktree: {message}"

        message = fault(RecordingDocker(create=DockerFault(
            rc=125, stderr="docker: Error response from daemon: bind source path does not exist\n",
            cite="po1",
        )))
        assert "bind source path does not exist" in message
        assert remedy_command(message) is None, message
        assert "box_image.py" not in message, message
        assert "origin/main @" not in message, message
