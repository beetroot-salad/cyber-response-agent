"""A missing box image faults naming the build command; start_box never builds."""
from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender.learning.core.config import AUTHOR_DRAIN_LABEL
from defender import box as box_mod
from defender.box import BoxRequest, Mount
from defender.execution.box_codec import BoxFault
from defender.tests.support.learning.curation._curator1134 import open_state
from defender.tests.support.sandbox._spec1092 import (
    BUILD_COMMAND_TAIL,
    DEFENDER,
    REPO_ROOT,
    DockerFault,
    FaultingStartBox,
    GitWorktreeBranch,
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
from defender.tests.e2e._box665 import BoxLifecycleRecorder, loop_paths


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


# ---- MF2: the drain lane's fault names the commit the deleted worktree was cut from --------------
def test_the_drain_lanes_missing_image_fault_names_the_cut_commit_and_a_checkout_instruction_after_cleanup(tmp_path, monkeypatch):
    from defender.learning.core.drains import _run_worktree_batch

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)

    def drive(docker: RecordingDocker) -> tuple[str, GitWorktreeBranch, FaultingStartBox]:
        rec = BoxLifecycleRecorder()
        branch: Any = GitWorktreeBranch(tmp_path / f"wt-{id(docker)}", events=rec.events)
        starter = FaultingStartBox(docker)
        paths = loop_paths(tmp_path)
        state = open_state(paths)
        with pytest.raises(BoxFault) as e:
            _run_worktree_batch(
                paths, state, branch, label=AUTHOR_DRAIN_LABEL, has_work=lambda p: True,
                do_work=lambda *a, **k: None, start_box=starter, stop_box=rec.stop_box,
                scrub=rec.scrub,
            )
        assert "cleanup" in rec.events, rec.events
        assert len(starter.requests) == 1
        assert not Path(starter.requests[0].workdir).exists(), "the worktree survived cleanup"
        return str(e.value), branch, starter

    message, branch, starter = drive(NoSuchImageDocker())
    wt = Path(starter.requests[0].workdir)
    assert "No such image:" in message, message
    assert remedy_command(message) == [
        "python3", f"{wt.resolve()}/{BUILD_COMMAND_TAIL.split(' ')[0]}", "build",
    ], message
    pointer = re.search(r"origin/main @ ([0-9a-f]{12,40})", message)
    assert pointer, message
    assert branch.cut_commit is not None
    assert branch.cut_commit.startswith(pointer.group(1)), (pointer.group(1), branch.cut_commit)
    tail = message[pointer.end():].lower()
    assert "check out" in tail, message
    assert "build" in tail, message

    other = RecordingDocker(create=DockerFault(
        rc=125, stderr="docker: Error response from daemon: bind source path does not exist\n",
        cite="po1",
    ))
    message, branch, _ = drive(other)
    assert "bind source path does not exist" in message
    pointer = re.search(r"origin/main @ ([0-9a-f]{12,40})", message)
    assert pointer, message
    assert branch.cut_commit is not None
    assert branch.cut_commit.startswith(pointer.group(1)), (pointer.group(1), branch.cut_commit)
    tail = message[pointer.end():].lower()
    assert "check out" in tail, message
    assert "build" not in tail, message
    assert remedy_command(message) is None, message
    assert "box_image.py" not in message, message
