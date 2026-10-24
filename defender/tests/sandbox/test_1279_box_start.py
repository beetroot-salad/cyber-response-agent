"""#1279 O3 / O6 / A1 / A2 — a box start refuses (never degrades, never reaps) when a mount source
overlaps the publish root, or when a container already holds the box's name.

Every lane that reaches `box.start_box` is covered: the run lane, a caller-composed request, and the
drain, the oracle and (in tenancy/tenant_1108_delivery/test_box.py) the tenant draft, each through
its real request builder. The refusal is `box.BoxStartConflict`, a `BoxFault` subtype (name chosen
by this contract). The docker daemon is faked through the real `docker=` seam."""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from defender import box as box_mod
from defender.tests.e2e._box665 import (
    DEFENDER,
    RecordingBranch,
    RecordingDocker,
    loop_paths,
)
from defender.tests.support.sandbox import _box1279 as X
from defender.tests.support.sandbox._box1195 import FakeDaemon
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared.contracts._data_root_1078 import current_data_root

_PINNED = box_mod.BoxSpec(runtime="runc", rootfs="defender-box:t1279")


def _gone(argv, **_kw):
    """A daemon that cannot be reached at all (no docker binary, no socket)."""
    raise FileNotFoundError(2, "No such file or directory: 'docker'")


# ---------------------------------------------------------------------------------------
# O3 + A1, run lane: one case per mount kind
# ---------------------------------------------------------------------------------------

#: Where the root sits for each mount kind of the run lane: inside the mount's tree (the source
#: contains the root), or equal to it (the clock directory).
_RUN_ROOTS = {
    "run dir": lambda lane: lane.run_dir / "published",
    "defender dir": lambda lane: lane.defender_dir / "published-1279",
    "tenant agent": lambda lane: lane.agent / "published",
    "run clock directory": lambda lane: lane.clock,
}


@pytest.mark.parametrize("kind", sorted(_RUN_ROOTS))
def test_o3_a_run_lane_mount_overlapping_the_publish_root_refuses_the_start_naming_both(
        tmp_path, monkeypatch, kind):
    lane = X.run_lane(tmp_path)
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    clear = RecordingDocker()
    lane.start(clear)
    rendered = X.bound_sources(clear.calls)
    assert lane.sources()[kind].resolve() in {p.resolve() for p in rendered}, (
        f"control: the {kind} is not among the mounts a started box renders")

    root = X.dev_root(monkeypatch, _RUN_ROOTS[kind](lane))
    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()) as refused:
        lane.start(rec)
    X.assert_refused_for_overlap(refused.value, root=root, mounts=[lane.sources()[kind]],
                                 rendered=rendered)
    assert not X.created(rec.calls), "a box was created over a mount overlapping the publish root"
    assert not X.removed(rec.calls)
    verdict = box_mod.verdict_path(lane.run_dir)
    assert verdict.is_file(), "the refusal left the run unjudged: no did-not-run verdict"
    assert '"ran": false' in verdict.read_text(encoding="utf-8").replace('":false', '": false')


def test_o3_the_run_lane_marker_goes_through_the_write_verdict_seam(tmp_path, monkeypatch):
    lane = X.run_lane(tmp_path)
    X.dev_root(monkeypatch, lane.run_dir / "published")
    docs: list[dict] = []
    with pytest.raises(X.conflict_type()):
        lane.start(RecordingDocker(), write_verdict=docs.append)
    assert [d["ran"] for d in docs] == [False], docs


def test_o3_the_override_set_to_the_data_root_refuses_the_run_box(tmp_path, monkeypatch):
    """The scenario: the run dir sits inside the data root, so a root equal to the data root
    contains it (the direction a one-sided check misses)."""
    data_root = current_data_root()
    lane = X.run_lane(data_root / "box-1279")
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    clear = RecordingDocker()
    lane.start(clear)
    rendered = X.bound_sources(clear.calls)

    root = X.dev_root(monkeypatch, data_root)
    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()) as refused:
        lane.start(rec)
    inside = X.overlapping(list(lane.sources().values()), root)
    assert lane.run_dir in inside and lane.agent in inside, "the scenario is not set up"
    X.assert_refused_for_overlap(refused.value, root=root, mounts=inside, rendered=rendered)
    assert not X.created(rec.calls)


def test_o3_the_root_is_host_wide_a_mount_in_any_tenants_area_overlaps_it(tmp_path, monkeypatch):
    root = tmp_path / "publish"
    other = fixture_uuid("tenant:other")
    lane = X.run_lane(root / other)
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    clear = RecordingDocker()
    lane.start(clear)
    rendered = X.bound_sources(clear.calls)

    X.dev_root(monkeypatch, root)
    with pytest.raises(X.conflict_type()) as refused:
        lane.start(RecordingDocker())
    X.assert_refused_for_overlap(
        refused.value, root=root, mounts=X.overlapping(list(lane.sources().values()), root),
        rendered=rendered)


# ---------------------------------------------------------------------------------------
# O3 + A1, request lane
# ---------------------------------------------------------------------------------------

#: Where the root sits for the request lane: inside each kind of mount (the source contains the
#: root), above the sources (the root contains them), or equal to one.
_REQUEST_ROOTS = {
    "inside the writable lane": lambda lane: lane.lane / "published",
    "inside the read-only data": lambda lane: lane.data / "published",
    "inside the code tree": lambda lane: lane.code / "published-1279",
    "above the sources": lambda lane: lane.base,
    "equal to the writable lane": lambda lane: lane.lane,
    "the filesystem root": lambda lane: Path("/"),
}


@pytest.mark.parametrize("require_sandbox", [False, True], ids=["opt-out-capable", "sandbox-required"])
@pytest.mark.parametrize("where", sorted(_REQUEST_ROOTS))
def test_o3_a_request_mount_overlapping_the_publish_root_refuses_the_start_naming_both(
        tmp_path, monkeypatch, where, require_sandbox):
    lane = X.request_lane(tmp_path)
    request = lane.request(require_sandbox=require_sandbox)
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    clear = RecordingDocker()
    box_mod.start_box(request, docker=clear)
    rendered = X.bound_sources(clear.calls)
    assert {p.resolve() for p in lane.sources().values()} <= {p.resolve() for p in rendered}

    root = X.dev_root(monkeypatch, _REQUEST_ROOTS[where](lane))
    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()) as refused:
        box_mod.start_box(request, docker=rec)
    X.assert_refused_for_overlap(
        refused.value, root=root, mounts=X.overlapping(list(lane.sources().values()), root),
        rendered=rendered)
    assert not X.created(rec.calls)
    marker = box_mod.verdict_path(lane.lane)
    if require_sandbox:
        assert not marker.exists(), "a sandbox-required refusal left a stray marker"
    else:
        assert marker.is_file(), "the request lane's refusal wrote no did-not-run verdict"
        assert "false" in marker.read_text(encoding="utf-8").lower()


@pytest.mark.parametrize("spelling", ["root-through-a-link", "source-through-a-link"])
def test_o3_overlap_is_judged_on_resolved_paths(tmp_path, monkeypatch, spelling):
    lane = X.request_lane(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(lane.lane, target_is_directory=True)
    request = lane.request()
    if spelling == "source-through-a-link":
        mounts = tuple(replace(m, source=link, target=link) if m.writable else m
                       for m in request.mounts)
        request = replace(request, mounts=mounts)
        root = lane.lane / "published"
    else:
        root = link / "published"
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    clear = RecordingDocker()
    box_mod.start_box(request, docker=clear)
    rendered = X.bound_sources(clear.calls)

    X.dev_root(monkeypatch, root)
    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()) as refused:
        box_mod.start_box(request, docker=rec)
    X.assert_refused_for_overlap(refused.value, root=root, mounts=[lane.lane, link],
                                 rendered=rendered)
    assert not X.created(rec.calls)


# ---------------------------------------------------------------------------------------
# O3 positive controls: dev with a clear root starts; not dev checks nothing
# ---------------------------------------------------------------------------------------


def test_o3_dev_with_a_root_clear_of_every_mount_starts_both_lanes(tmp_path, monkeypatch):
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "published")
    run = X.run_lane(tmp_path / "run")
    rec = RecordingDocker()
    run.start(rec)
    assert rec.create_argv is not None, "a clear root blocked the run lane"
    req = X.request_lane(tmp_path / "req")
    rec = RecordingDocker()
    box_mod.start_box(req.request(), docker=rec)
    assert rec.create_argv is not None, "a clear root blocked the request lane"


def test_o3_a_root_that_only_shares_a_name_prefix_with_a_mount_does_not_overlap(
        tmp_path, monkeypatch):
    run = X.run_lane(tmp_path / "run")
    X.dev_root(monkeypatch, run.run_dir.with_name(run.run_dir.name + "-published"))
    rec = RecordingDocker()
    run.start(rec)
    assert rec.create_argv is not None, "a sibling that shares a string prefix was taken as inside"
    req = X.request_lane(tmp_path / "req")
    X.dev_root(monkeypatch, req.lane.with_name(req.lane.name + "-published"))
    rec = RecordingDocker()
    box_mod.start_box(req.request(), docker=rec)
    assert rec.create_argv is not None


def test_o3_outside_dev_there_is_no_publish_root_and_nothing_is_checked(tmp_path, monkeypatch):
    run = X.run_lane(tmp_path / "run")
    X.non_dev_root(monkeypatch, run.run_dir)
    rec = RecordingDocker()
    run.start(rec)
    assert rec.create_argv is not None, "a non-dev start was judged against the override"
    req = X.request_lane(tmp_path / "req")
    X.non_dev_root(monkeypatch, req.lane)
    rec = RecordingDocker()
    box_mod.start_box(req.request(), docker=rec)
    assert rec.create_argv is not None


# ---------------------------------------------------------------------------------------
# A7: box start resolves the root through the owner, from the box's own code mount
# ---------------------------------------------------------------------------------------


def _agent_at(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / ".tenant-id").write_text(f"{X.TENANT}\n", encoding="utf-8")
    return path


def test_a7_a_worktrees_box_resolves_the_root_to_the_main_checkouts_folder(tmp_path, monkeypatch):
    """A7: with the override unset, a box whose code mount is a worktree's `defender/` is judged
    against `<main checkout>/run-visualizations/`, as the mirror resolves it: a mount in the
    worktree's own `run-visualizations/` is clear, one in the main checkout's is refused."""
    main, wt = X.fake_main_and_worktree(tmp_path / "checkouts")
    X.dev_default_root(monkeypatch)
    lane = replace(X.run_lane(tmp_path / "lane"), defender_dir=wt / "defender")

    own = replace(lane, agent=_agent_at(wt / "run-visualizations" / "agent"))
    clear = RecordingDocker()
    own.start(clear)
    assert clear.create_argv is not None, "the worktree's own folder was taken as the publish root"

    root = main / "run-visualizations"
    inside = replace(lane, agent=_agent_at(root / "agent"))
    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()) as refused:
        inside.start(rec)
    assert X.names_path(str(refused.value), root) or X.names_path(str(refused.value), root.resolve()), (
        f"the refusal does not name the main checkout's root {root}: {refused.value}")
    assert X.names_path(str(refused.value), root / "agent") or X.names_path(
        str(refused.value), (root / "agent").resolve()), f"it does not name the mount: {refused.value}"
    assert not X.created(rec.calls)
    assert not X.removed(rec.calls)


def test_a7_a_mount_above_the_resolved_root_is_refused_and_a_clear_one_starts(tmp_path, monkeypatch):
    """A7 + A1: the main checkout itself, mounted, contains the resolved root (the other direction)."""
    main, wt = X.fake_main_and_worktree(tmp_path / "checkouts")
    X.dev_default_root(monkeypatch)
    lane = replace(X.run_lane(tmp_path / "lane"), defender_dir=wt / "defender")
    clear = RecordingDocker()
    lane.start(clear)
    assert clear.create_argv is not None, "control: a clear worktree box did not start"

    above = replace(lane, agent=_agent_at(main))
    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()) as refused:
        above.start(rec)
    assert X.names_path(str(refused.value), main.resolve()) or X.names_path(
        str(refused.value), main), f"the refusal does not name the mount {main}: {refused.value}"
    assert not X.created(rec.calls)


def _request_without_a_code_mount(req: X.RequestLane) -> box_mod.BoxRequest:
    """A caller-composed request that names no code tree: nothing to resolve the root from."""
    mounts = (
        box_mod.Mount(source=req.data, target=req.data, writable=False, kind="data"),
        box_mod.Mount(source=req.lane, target=req.lane, writable=True),
    )
    return box_mod.BoxRequest(name=X.REQUEST_NAME, mounts=mounts, workdir=DEFENDER.parent, env={},
                              require_sandbox=False)


@pytest.mark.parametrize("opt_out", [False, True], ids=["plain", "opt-out"])
def test_o3_the_refusal_class_is_non_degradable_when_the_root_owner_refuses_the_pytest_detector(
        tmp_path, monkeypatch, opt_out):
    """The refusal class is non-degradable: a root resolution the owner refuses (here only its
    pytest detector: no code mount to resolve from, the override unset) refuses the start, the
    opt-out does not degrade it, and it is no "no root". This is NOT the A7 coverage -- the
    worktree-pointer and main-without-defender cases below are. Control: the same request starts
    with the override set, and outside `dev`, where there is no root to resolve."""
    req = X.request_lane(tmp_path)
    request = _request_without_a_code_mount(req)

    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    clear = RecordingDocker()
    box_mod.start_box(request, docker=clear)
    assert clear.create_argv is not None, "control: the request does not start even with a root"

    X.dev_default_root(monkeypatch)
    if opt_out:
        X.allow_unsandboxed(monkeypatch)
    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()):
        box_mod.start_box(request, docker=rec)
    assert not X.created(rec.calls)

    monkeypatch.delenv(X.DEPLOYMENT_ENV, raising=False)
    outside = RecordingDocker()
    box_mod.start_box(request, docker=outside)
    assert outside.create_argv is not None, "outside dev there is no root to fail to resolve"


@pytest.mark.parametrize("opt_out", [False, True], ids=["plain", "opt-out"])
@pytest.mark.parametrize("broken", X.BREAKAGES)
def test_a7_in_dev_an_undeterminable_main_checkout_refuses_the_start(
        tmp_path, monkeypatch, broken, opt_out):
    """A7: a worktree whose `.git` pointer cannot be followed (gitdir leads nowhere), or whose
    main checkout has no `defender/`, makes the root unresolvable. In `dev` with the override unset
    the start is refused as an O3 refusal -- plain and with the opt-out -- and nothing is created.
    Positive control: the intact pointer starts the same lane."""
    X.dev_default_root(monkeypatch)
    _, good_wt = X.fake_main_and_worktree(tmp_path / "good")
    good = RecordingDocker()
    replace(X.run_lane(tmp_path / "lane-good"), defender_dir=good_wt / "defender").start(good)
    assert good.create_argv is not None, "control: the intact worktree did not start"

    _, wt = X.fake_main_and_worktree(tmp_path / "bad", broken=broken)
    lane = replace(X.run_lane(tmp_path / "lane-bad"), defender_dir=wt / "defender")
    if opt_out:
        X.allow_unsandboxed(monkeypatch)
    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()):
        lane.start(rec)
    assert not X.created(rec.calls)
    assert not X.removed(rec.calls)


# ---------------------------------------------------------------------------------------
# A2: neither refusal is degraded by DEFENDER_ALLOW_UNSANDBOXED; an unreachable daemon still is
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("lane_kind", ["run", "request"])
def test_a2_the_opt_out_never_degrades_an_overlap_refusal(tmp_path, monkeypatch, lane_kind):
    if lane_kind == "run":
        lane = X.run_lane(tmp_path)
        root, start = lane.run_dir / "published", lambda d: lane.start(d)
    else:
        lane = X.request_lane(tmp_path)
        root, start = lane.lane / "published", lambda d: box_mod.start_box(lane.request(), docker=d)
    X.dev_root(monkeypatch, root)
    X.allow_unsandboxed(monkeypatch)
    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()):
        start(rec)
    assert not X.created(rec.calls)


@pytest.mark.parametrize("lane_kind", ["run", "request"])
def test_a2_an_overlap_is_refused_even_when_the_daemon_is_unreachable(tmp_path, monkeypatch,
                                                                       lane_kind):
    """The overlap needs no daemon, so a gone daemon cannot turn it into the degradable case."""
    if lane_kind == "run":
        lane = X.run_lane(tmp_path)
        root, start = lane.run_dir / "published", lambda d: lane.start(d)
    else:
        lane = X.request_lane(tmp_path)
        root, start = lane.lane / "published", lambda d: box_mod.start_box(lane.request(), docker=d)
    X.dev_root(monkeypatch, root)
    X.allow_unsandboxed(monkeypatch)
    with pytest.raises(X.conflict_type()):
        start(_gone)


@pytest.mark.parametrize("state", ["exited", "dead", "created", "running", "paused", ""])
@pytest.mark.parametrize("lane_kind", ["run", "request"])
def test_a2_the_opt_out_never_degrades_an_existing_same_name_container(
        tmp_path, monkeypatch, lane_kind, state):
    """O6 + A2: whatever the container's state, with the opt-out on, the start refuses, removes
    nothing and creates nothing."""
    monkeypatch.delenv(X.DEPLOYMENT_ENV, raising=False)
    X.allow_unsandboxed(monkeypatch)
    rec = RecordingDocker(status=state)
    if lane_kind == "run":
        lane = X.run_lane(tmp_path)
        start = lambda: lane.start(rec)  # noqa: E731
    else:
        lane = X.request_lane(tmp_path)
        start = lambda: box_mod.start_box(lane.request(), docker=rec)  # noqa: E731
    with pytest.raises(X.conflict_type()) as refused:
        start()
    assert isinstance(refused.value, box_mod.BoxFault)
    assert not X.removed(rec.calls), "the start removed a container that holds its name"
    assert not X.created(rec.calls)


@pytest.mark.parametrize("lane_kind", ["run", "request"])
def test_a2_an_unreachable_daemon_still_degrades_and_is_not_the_refusal_subtype(
        tmp_path, monkeypatch, lane_kind):
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    if lane_kind == "run":
        lane = X.run_lane(tmp_path)
        start = lambda: lane.start(_gone)  # noqa: E731
    else:
        lane = X.request_lane(tmp_path)
        start = lambda: box_mod.start_box(lane.request(), docker=_gone)  # noqa: E731
    with pytest.raises(box_mod.BoxFault) as faulted:
        start()
    assert not isinstance(faulted.value, X.conflict_type()), (
        "an unreachable daemon was reported as a same-name container")
    X.allow_unsandboxed(monkeypatch)
    degraded = start()
    assert degraded.sandboxed is False, "hermetic replays rely on the unreachable daemon degrading"


@pytest.mark.parametrize("lane_kind", ["run", "request"])
def test_a2_a_name_conflict_raised_by_docker_run_itself_stays_a_degradable_create_fault(
        tmp_path, monkeypatch, lane_kind):
    """A2: inspect found nothing (the name looked free), then `docker run` itself reports the
    name taken (a race). That stays a create fault as today: not the refusal subtype, and the
    opt-out degrades it."""
    from defender.tests.e2e._box665 import DockerFault

    def rec() -> RecordingDocker:
        return RecordingDocker(
            status=None, existing_token="another-lane-holds-this-name",
            create=DockerFault(
                rc=125, cite="C43a — the daemon's own name-conflict rc/text",
                stderr='Conflict. The container name "/defender-run-x" is already in use'))

    if lane_kind == "run":
        lane = X.run_lane(tmp_path)
        start = lambda docker: lane.start(docker)  # noqa: E731
    else:
        lane = X.request_lane(tmp_path)
        start = lambda docker: box_mod.start_box(lane.request(), docker=docker)  # noqa: E731
    monkeypatch.delenv(X.DEPLOYMENT_ENV, raising=False)
    monkeypatch.delenv(X.ALLOW_ENV, raising=False)
    with pytest.raises(box_mod.BoxFault) as faulted:
        start(rec())
    assert not isinstance(faulted.value, X.conflict_type()), (
        "a name conflict found by `docker run` was reported as the pre-create refusal")
    X.allow_unsandboxed(monkeypatch)
    docker = rec()
    degraded = start(docker)
    assert degraded.sandboxed is False, "the opt-out no longer degrades a create-time name conflict"
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in docker.calls), (
        "the create fault reaped the container another lane owns")


@pytest.mark.parametrize("lane_kind", ["run", "request"])
def test_o6_an_inspect_that_finds_no_container_is_not_a_conflict(tmp_path, lane_kind):
    """The positive control: the daemon answered 'no such object', so the name is free."""
    rec = RecordingDocker(status=None)
    if lane_kind == "run":
        X.run_lane(tmp_path).start(rec)
    else:
        box_mod.start_box(X.request_lane(tmp_path).request(), docker=rec)
    assert rec.create_argv is not None


# ---------------------------------------------------------------------------------------
# O6 against the stateful daemon: the container survives the refused start
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["exited", "dead", "running"])
def test_o6_the_run_lane_leaves_a_same_name_container_alone(tmp_path, state):
    lane = X.run_lane(tmp_path / "lane")
    daemon = FakeDaemon(tmp_path)
    name = box_mod.container_name(lane.run_dir.name)
    daemon.hold(name, state)
    with pytest.raises(X.conflict_type()) as refused:
        lane.start(daemon, spec=_PINNED)
    assert name in str(refused.value), "the refusal does not name the container"
    assert daemon.status(name) == state
    assert daemon.created() == []
    assert not X.removed(daemon.docker_calls())
    assert box_mod.verdict_path(lane.run_dir).is_file(), "no did-not-run verdict"


@pytest.mark.parametrize("state", ["exited", "dead", "running"])
def test_o6_the_request_lane_leaves_a_same_name_container_alone(tmp_path, state):
    lane = X.request_lane(tmp_path / "lane")
    request = replace(lane.request(), spec=_PINNED)
    daemon = FakeDaemon(tmp_path)
    daemon.hold(request.name, state)
    with pytest.raises(X.conflict_type()) as refused:
        box_mod.start_box(request, docker=daemon)
    assert request.name in str(refused.value)
    assert daemon.status(request.name) == state
    assert daemon.created() == []
    assert not X.removed(daemon.docker_calls())
    assert box_mod.verdict_path(lane.lane).is_file()


def test_the_subtype_is_exported_from_box_and_is_a_box_fault():
    assert issubclass(X.conflict_type(), box_mod.BoxFault)
    assert X.conflict_type() is not box_mod.BoxFault


# ---------------------------------------------------------------------------------------
# The drain lane, through its real request builder
# ---------------------------------------------------------------------------------------


def _drain(tmp_path: Path):
    from defender.learning.core import drains
    from defender.learning.core.config import AUTHOR_DRAIN_LABEL

    wt = tmp_path / "wt" / "author-b1279"
    return wt, drains._drain_box_request(wt, "b1279", AUTHOR_DRAIN_LABEL, loop_paths(tmp_path))


def _drain_ready(wt: Path, request):
    """The disk a real start reads back: the product check file under the worktree's `defender/`
    (its code mount), each writable tree present, the image named outright."""
    (wt / "defender").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(DEFENDER / box_mod.CODE_CHECK_FILE, wt / "defender" / box_mod.CODE_CHECK_FILE)
    for m in request.mounts:
        if m.writable:
            Path(m.source).mkdir(parents=True, exist_ok=True)
    return replace(request, spec=_PINNED)


_DRAIN_ROOTS = {
    "inside the worktree (code)": lambda wt, req: wt / "published-1279",
    "inside a writable tree": lambda wt, req: next(
        Path(m.source) for m in req.mounts if m.writable) / "published",
    "above the worktree": lambda wt, req: wt.parent,
}


@pytest.mark.parametrize("where", sorted(_DRAIN_ROOTS))
def test_o3_the_drain_box_refuses_a_mount_overlapping_the_publish_root(
        tmp_path, monkeypatch, where):
    wt, request = _drain(tmp_path)
    request = _drain_ready(wt, request)
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    clear = FakeDaemon(tmp_path / "clear")
    box_mod.start_box(request, docker=clear)
    rendered = X.bound_sources(clear.docker_calls())
    assert rendered, "control: the clear start rendered no mounts"

    root = X.dev_root(monkeypatch, _DRAIN_ROOTS[where](wt, request))
    daemon = FakeDaemon(tmp_path / "refused")
    with pytest.raises(X.conflict_type()) as refused:
        box_mod.start_box(request, docker=daemon)
    sources = [Path(m.source) for m in request.mounts]
    X.assert_refused_for_overlap(refused.value, root=root,
                                 mounts=X.overlapping(sources, root), rendered=rendered)
    assert daemon.created() == []
    assert daemon.names() == []


def _drive_batch(tmp_path: Path, starter):
    """The real `_run_worktree_batch` over a recording branch, with `starter` as its start_box."""
    from defender.learning.core.config import AUTHOR_DRAIN_LABEL
    from defender.learning.core.drains import _run_worktree_batch
    from defender.learning.core.state import LearningState

    events: list[str] = []
    paths = loop_paths(tmp_path)
    branch = RecordingBranch(tmp_path / "wt", events=events)
    with LearningState.open(paths) as state:
        try:
            _run_worktree_batch(
                paths, state, branch, label=AUTHOR_DRAIN_LABEL, has_work=lambda p: True,
                do_work=lambda p, box: pytest.fail("the work ran beside a refused box"),
                start_box=starter, stop_box=lambda *a, **k: None, scrub=lambda *a, **k: None)
        except BaseException as e:  # noqa: BLE001 — judged by the caller
            return e, events
    return None, events


def _chain(exc):
    out = []
    while exc is not None and exc not in out:
        out.append(exc)
        exc = exc.__cause__ or exc.__context__
    return out


def test_o3_a_drain_batch_halts_on_the_refusal_and_unwinds_its_worktree(tmp_path, monkeypatch):
    X.dev_root(monkeypatch, tmp_path)  # the root holds the batch's worktree
    daemon = FakeDaemon(tmp_path / "d")

    def starter(request, *_a, **_kw):
        return box_mod.start_box(request, docker=daemon)

    got, events = _drive_batch(tmp_path, starter)
    assert isinstance(got, box_mod.BoxFault), f"the batch did not halt on a BoxFault: {got!r}"
    assert any(isinstance(e, X.conflict_type()) for e in _chain(got)), (
        f"the refusal is lost from the raised fault's chain: {_chain(got)}")
    assert "cleanup" in events, "the worktree was left behind"
    assert daemon.created() == []


def test_o6_a_drain_batch_halts_on_a_same_name_container_and_leaves_it(tmp_path, monkeypatch):
    X.allow_unsandboxed(monkeypatch)
    daemon = FakeDaemon(tmp_path / "d")
    held: list[str] = []

    def starter(request, *_a, **_kw):
        daemon.hold(request.name, "exited")
        held.append(request.name)
        return box_mod.start_box(request, docker=daemon)

    got, events = _drive_batch(tmp_path, starter)
    assert isinstance(got, box_mod.BoxFault), f"the batch did not halt on a BoxFault: {got!r}"
    assert any(isinstance(e, X.conflict_type()) for e in _chain(got))
    assert "cleanup" in events
    assert daemon.names() == held, "the refused start removed the container that held its name"
    assert daemon.created() == []


def test_o6_the_drain_request_name_refuses_a_finished_container(tmp_path):
    wt, request = _drain(tmp_path)
    daemon = FakeDaemon(tmp_path)
    daemon.hold(request.name, "exited")
    with pytest.raises(X.conflict_type()):
        box_mod.start_box(replace(request, spec=_PINNED), docker=daemon)
    assert daemon.names() == [request.name]
    assert not X.removed(daemon.docker_calls())


# ---------------------------------------------------------------------------------------
# The oracle lane, through its real request builder
# ---------------------------------------------------------------------------------------


@pytest.fixture
def oracle_tree(tmp_path):
    """A real runner folder and a scratch folder, as the oracle's start makes them."""
    from defender.box import _oracle

    runner = _oracle._make_runner()
    scratch = Path(tempfile.mkdtemp(prefix="defender-oracle-"))
    try:
        yield runner, scratch
    finally:
        shutil.rmtree(runner, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


_ORACLE_ROOTS = {
    "inside the runner (code)": lambda runner, scratch: runner / "published",
    "inside the scratch": lambda runner, scratch: scratch / "published",
    "above both": lambda runner, scratch: Path(tempfile.gettempdir()),
}


@pytest.mark.parametrize("where", sorted(_ORACLE_ROOTS))
def test_o3_the_oracle_box_refuses_a_mount_overlapping_the_publish_root(
        tmp_path, monkeypatch, oracle_tree, where):
    from defender.box import _oracle

    runner, scratch = oracle_tree
    request = _oracle.oracle_box_request(scratch, runner, env={"DEFENDER_BOX_RUNTIME": "runc"})
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    clear = FakeDaemon(tmp_path / "clear")
    box_mod.start_box(request, docker=clear)
    rendered = X.bound_sources(clear.docker_calls())
    assert {runner.resolve(), scratch.resolve()} <= {p.resolve() for p in rendered}

    root = X.dev_root(monkeypatch, _ORACLE_ROOTS[where](runner, scratch))
    daemon = FakeDaemon(tmp_path / "refused")
    with pytest.raises(X.conflict_type()) as refused:
        box_mod.start_box(request, docker=daemon)
    X.assert_refused_for_overlap(refused.value, root=root, mounts=[runner, scratch],
                                 rendered=rendered)
    assert daemon.created() == []
    assert not box_mod.verdict_path(scratch).exists(), "a sandbox-required refusal left a marker"


def test_o3_the_oracle_start_carries_the_refusal_as_the_cause_of_its_own(tmp_path, monkeypatch):
    from defender.box import _oracle

    X.dev_root(monkeypatch, Path(tempfile.gettempdir()))
    daemon = FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    with pytest.raises(_oracle.BoxStartRefused) as refused:
        _oracle.start_oracle_box(env={"PATH": os.environ["PATH"], "DEFENDER_BOX_RUNTIME": "runc"})
    assert any(isinstance(e, X.conflict_type()) for e in _chain(refused.value)), (
        f"the refusal's text did not survive as the cause: {_chain(refused.value)}")
    assert daemon.created() == []


def test_o3_the_estate_oracle_start_turns_the_refusal_into_its_own_failure_keeping_its_text(
        tmp_path, monkeypatch):
    """A2 tail: `estate.oracle.start_box` re-wraps `_oracle.BoxStartRefused` as
    `OracleSandboxError`; the BoxStartConflict, with its text, stays in the chain and in the
    message the operator reads."""
    from defender.learning.branch.estate import oracle as estate_oracle

    root = X.dev_root(monkeypatch, Path(tempfile.gettempdir()))
    daemon = FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    with pytest.raises(estate_oracle.OracleSandboxError) as refused:
        estate_oracle.start_box(env={"PATH": os.environ["PATH"], "DEFENDER_BOX_RUNTIME": "runc"})
    conflicts = [e for e in _chain(refused.value) if isinstance(e, X.conflict_type())]
    assert conflicts, f"the refusal did not survive the oracle's re-wrapping: {_chain(refused.value)}"
    assert str(conflicts[0]) in str(refused.value), (
        f"the operator's message dropped the refusal's text: {refused.value}")
    assert X.names_path(str(refused.value), root) or X.names_path(str(refused.value), root.resolve())
    assert daemon.created() == []


def test_o6_the_oracle_request_name_refuses_a_finished_container(tmp_path, oracle_tree):
    from defender.box import _oracle

    runner, scratch = oracle_tree
    request = _oracle.oracle_box_request(scratch, runner, env={"DEFENDER_BOX_RUNTIME": "runc"})
    daemon = FakeDaemon(tmp_path)
    daemon.hold(request.name, "exited")
    with pytest.raises(X.conflict_type()):
        box_mod.start_box(request, docker=daemon)
    assert daemon.names() == [request.name]
    assert not X.removed(daemon.docker_calls())
