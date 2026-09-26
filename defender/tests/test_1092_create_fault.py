"""#1092 — the missing-image fault names the build command and the tree (M5 amended, O4,
JF5 amended by #1095), `start_box` never builds (D2 C), the `_spec771` rootfs runner takes the
same resolver, the same preflight and the same `--pull=never` (the fourth `docker run` site),
and the learning drain's fault handler appends a durable pointer to the worktree it deletes
(MF2).

JF5 AMENDED (#1095): a missing image is found by ASKING the daemon — `docker image inspect`,
a yes/no by exit code, before the create — never by classifying the create's stderr. The
create's text is the CLI's to phrase and varied across CLI versions (27.x appends a period
to `No such image: <ref>`), which made the remedy silently vanish on distro CLIs. The daemon
is `NoSuchImageDocker`: its inspect answers rc 1 for the image the start asked about, its
create stays healthy. Every "other shape" fixture is a shape the ledger observed on a real
daemon (po1's absent bind source; N1's pull-path text, which `--pull=never` removes from the
create path).
"""
from __future__ import annotations

import inspect
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender.runtime import box as box_mod
from defender.runtime.box import BoxRequest, Mount
from defender.runtime.box_codec import BoxFault
from defender.tests._spec1092 import (
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
    """Before the create, both lanes ask the daemon for the image they resolved (`docker
    image inspect <image_tag(tree)>`); a `no` (rc 1) raises a `BoxFault` — with NO create
    attempted — that keeps the daemon's text and names `python3 <tree>/defender/scripts/
    box_image.py build`, `<tree>` being the absolute path of the tree the box mounts —
    `defender_dir.parent` on the run-dir lane, `Path(request.workdir).resolve()` (the drain's
    worktree) on the request lane — `shlex.quote`d, so a tree path with a space is copy-paste
    safe. The image asked about is the one the tree names, never one read off the argv.

    # rejected: the `write_did_not_run` marker text is NOT required to carry the remedy — the
    # BoxFault message is the surface O4 names (F6). Classifying the create's stderr (JF5 as
    # first written): the text is the CLI's and varied by version (#1095) — the decision is
    # the exit code of a question asked before the create."""
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
    """A create that fails AFTER the daemon confirmed the image — a bind source that does not
    exist (po1), the CLI's pull-path text (N1, without `--pull=never`), or even a create
    stderr that happens to carry `No such image: <the resolved name>` — raises a `BoxFault`
    that keeps the daemon's text and does not mention the build command, on both lanes: the
    remedy rides the preflight's `no`, and nothing reads the create's text for it.

    # rejected: disk exhaustion and every other daemon error are generic — O4 names the
    # missing-image shape "that shape only", and no command the fault could name fixes them
    # (M5-MATCH #70); non-UTF-8 stderr is pre-existing (#36). The former `no-such-other-image`
    # row (silent #35: a `No such image:` line about SOME OTHER image) is impossible by
    # construction now — no text is classified — and was deleted rather than rewritten."""
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

    # The positive control, same lane, same tree: the daemon answering `no` to the preflight
    # DOES name the build command — so the silence above is the preflight's verdict, not an
    # absent mechanism.
    with pytest.raises(BoxFault) as e:
        start(NoSuchImageDocker())
    assert remedy_command(str(e.value)) is not None, str(e.value)


# ---- #1095 round 2: the other reading of a non-zero inspect --------------------------------------
@pytest.mark.parametrize("lane", ["run-dir", "request"])
def test_a_daemon_that_stopped_answering_is_reported_as_that_and_never_told_to_build(tmp_path, monkeypatch, lane):
    """`docker image inspect` exits 1 both for "no such image" and for "cannot reach the
    daemon". When the preflight's `no` is followed by a `docker version` that also fails, the
    `BoxFault` says the daemon could not be asked (its own words kept) and names NO build
    command; no create is attempted. Positive control: the same start with the daemon
    answering names the remedy (d42)."""
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
    """With no `DEFENDER_ALLOW_UNSANDBOXED` — or with it set to anything but `"1"`, which is
    not an opt-out (#37) — a missing image makes `start_box` raise `BoxFault` with no create
    attempted, and the recorded docker calls contain no `build` and no `pull`; when the daemon
    does hold the image, the create argv carries `--pull=never` (a create never reaches the
    network — JF5).

    # rejected: a real opt-out (`DEFENDER_ALLOW_UNSANDBOXED=1`) is NOT this test's case — it
    # is demanded by `opt_out_warning_carries_the_swallowed_fault` (ENV #78, phase F): the
    # `[box] WARNING` line carries the swallowed fault and the build command; the
    # investigation driver surfaces the BoxFault as a traceback with a non-zero exit — no
    # wrapper, no run-record field (silent #77)."""
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


# ---- phase F (F2, human): the opt-out lane still surfaces the remedy -----------------------------
def test_the_unsandboxed_opt_out_warning_carries_the_swallowed_missing_image_fault_and_the_build_command(tmp_path, monkeypatch, caplog):
    """With `DEFENDER_ALLOW_UNSANDBOXED=1` and a missing image, `start_box` swallows the
    `BoxFault`, degrades to the unboxed host executor, and the box's WARNING log record
    carries the swallowed fault's message — the daemon's `No such image` line and the build
    command `python3 <tree>/defender/scripts/box_image.py build` — so O4's remedy still
    reaches the operator under the opt-out; without the opt-out the same fault raises (d44)."""
    _no_unsandboxed(monkeypatch)
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    defender_dir = plant_tree(tmp_path / "tree", copy_code=False)
    run_dir = make_run_dir(tmp_path)
    rec = NoSuchImageDocker()
    box = box_mod.start_box(run_dir, defender_dir, docker=rec)
    assert box.sandboxed is False
    err = caplog.text
    warnings = [r.getMessage() for r in caplog.records
                if r.name == "defender.runtime.box._lifecycle" and r.levelname == "WARNING"]
    assert warnings, err
    warning = warnings[0]
    assert f"No such image: {image_tag(defender_dir)}" in warning, err
    assert remedy_command(warning) == [
        "python3", f"{defender_dir.parent.resolve()}/{BUILD_COMMAND_TAIL.split(' ')[0]}", "build",
    ], err


# ---- the seam d46 needs -----------------------------------------------------------------------
def test_the_rootfs_runner_spawns_docker_through_an_injectable_run_seam_defaulting_to_subprocess_run():
    """`_spec771.run_probe_under_profile(script, profile, *, run=subprocess.run)` spawns its
    docker calls — the image preflight and then the `docker run` — through the `run`
    parameter, a keyword-only seam whose default is `subprocess.run`, so a test can observe
    the argv without a daemon: a fake `run` receives each argv, no real process is spawned,
    and the fake's stdout on the run is what the runner decodes."""
    from defender.tests.e2e._spec771 import run_probe_under_profile

    runner: Callable[..., Any] = run_probe_under_profile
    param = inspect.signature(run_probe_under_profile).parameters.get("run")
    assert param is not None, "run_probe_under_profile has no `run` parameter"
    assert param.kind is inspect.Parameter.KEYWORD_ONLY, param
    assert param.default is subprocess.run, param.default
    seen: list[list[str]] = []

    def fake_run(argv, **kw):
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout='{"seam": "ok"}', stderr="")

    assert runner("print(1)", None, run=fake_run) == {"seam": "ok"}
    assert [a[1:3] for a in seen] == [["image", "inspect"], ["run", "--rm"]], seen


# ---- d46 -------------------------------------------------------------------------------------
def test_the_rootfs_runner_names_the_derived_image_with_pull_never_and_its_failure_carries_the_remedy(tmp_path):
    """`_spec771.run_probe_under_profile` asks the daemon for `image_tag(DEFENDER)` (`docker
    image inspect`) and then runs `docker run --rm -i [--security-opt seccomp=<profile>]
    --pull=never <image_tag(DEFENDER)> python3 -` — the script on stdin, the profile only
    when one is given; when the daemon answers `no` to the preflight, the runner's assertion
    message carries the daemon's line and the build remedy naming the test tree, and no
    `docker run` is attempted.

    # rejected: the live suite (`test_665_box_live.py`) reads no `rootfs` of its own — its
    # two-arg starts reach the resolver through `start_box` (N7); its two tmp-workdir requests
    # (:128, :278) pin `rootfs=image_tag(DEFENDER)` as part of the migration (N4). No
    # `--read-only` is added to this runner — it mounts nothing (O7-SHAPE #69)."""
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
    """When the learning drain's `start_box` faults on a missing image (the preflight's
    `no`), `_run_worktree_batch` still removes the worktree (the pre-existing unwind — its
    did-not-run markers go with it, an accepted cost) and re-raises the `BoxFault` with the
    shared fault text unchanged (the daemon's line, the build command naming the now-deleted
    `<wt>`) PLUS a durable
    pointer appended: `origin/main @ <sha>` — the commit the worktree was cut from, its HEAD,
    read before the tree is gone — and the instruction to check out that commit and run the
    build from it. The pointer rides EVERY drain-lane start `BoxFault` (phase F, human): a
    create fault of any OTHER shape is unwound and re-raised with the same commit and
    checkout instruction appended but NO build command and no "run the build" clause (O4:
    the command rides the missing-image shape only — a name collision or a bind fault is not
    fixed by a build, #1095 round 2).

    # rejected: keeping the message literal (a dead-end command on every re-lock, on a lane
    # that runs unattended); not deleting the copy on this fault (changes the drain's unwind
    # discipline); tick repetition and branch accumulation are pre-existing, recorded, not
    # mechanised (#76, P44)."""
    from defender.learning.core.drains import _run_worktree_batch

    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)

    def drive(docker: RecordingDocker) -> tuple[str, GitWorktreeBranch, FaultingStartBox]:
        rec = BoxLifecycleRecorder()
        branch: Any = GitWorktreeBranch(tmp_path / f"wt-{id(docker)}", events=rec.events)
        starter = FaultingStartBox(docker)
        with pytest.raises(BoxFault) as e:
            _run_worktree_batch(
                loop_paths(tmp_path), branch, label="author_drain", has_work=lambda p: True,
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
