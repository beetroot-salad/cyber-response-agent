"""#1279 O3 / O6 / A1 / A2 — a box start refuses (never degrades, never reaps) when a mount source
overlaps the publish root, or when a container already holds the box's name.

Every lane that reaches `box.start_box` is covered: the run lane, a caller-composed request, and the
oracle and (in tenancy/tenant_1108_delivery/test_box.py) the tenant draft drain, each through its
real request builder. The refusal is `box.BoxStartConflict`, a `BoxFault` subtype. The docker
daemon is faked through the real `docker=` seam."""
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
    RecordingDocker,
)
from defender.tests.support.sandbox import _box1279 as X
from defender.tests.support.sandbox._box1195 import FakeDaemon
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.tenancy._host1214 import TEST_TENANT
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
    "run copy stage": lambda lane: lane.stage / "published",
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
    assert lane.run_dir in inside, "the scenario is not set up"
    assert lane.agent in inside, "the scenario is not set up"
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
# A8: box start judges against the root this process publishes into, whatever its code mount
# A9: in dev, a root that cannot be determined starts the box, with a warning naming the cause
# ---------------------------------------------------------------------------------------


def _stage_at(path: Path) -> dict[str, Path]:
    """A run copy's stage at `path`: `agent/` and the startup token beside it."""
    (path / "agent").mkdir(parents=True, exist_ok=True)
    token = path / ".startup-token"
    token.write_text("run-1279-token\n", encoding="utf-8")
    return {"agent": path / "agent", "token": token}


def _request_in_a_worktree(tmp_path: Path, wt: Path, *, data: Path | None = None) -> box_mod.BoxRequest:
    """A request whose code mount and code root are the worktree's `defender/`; `data` relocates
    the read-only data tree (created if absent)."""
    base = X.request_lane(Path(tempfile.mkdtemp(prefix="req-", dir=tmp_path)))
    moved = replace(base, code=wt / "defender", data=data or base.data)
    moved.data.mkdir(parents=True, exist_ok=True)
    return replace(moved.request(), workdir=wt, defender_dir=wt / "defender")


@pytest.mark.parametrize("lane_kind", ["run", "request"])
def test_a8_a_box_is_judged_against_this_processes_root_not_its_code_mounts_checkout(
        tmp_path, monkeypatch, lane_kind):
    """A box whose code mount is a worktree is judged against the root the starting process
    publishes into (here the override), not against the folder its code mount's main checkout
    would give. A mount in that checkout's `run-visualizations/` starts; one in the process's root
    is refused naming both, and nothing is created or removed."""
    main, wt = X.fake_main_and_worktree(tmp_path / "checkouts")
    root = X.dev_root(monkeypatch, tmp_path / "process" / "pub")
    code_side = main / "run-visualizations" / "mount"
    if lane_kind == "run":
        lane = replace(X.run_lane(tmp_path / "lane"), defender_dir=wt / "defender")
        def start(folder: Path, docker: RecordingDocker) -> None:
            replace(lane, **_stage_at(folder)).start(docker)
    else:
        def start(folder: Path, docker: RecordingDocker) -> None:
            box_mod.start_box(_request_in_a_worktree(tmp_path, wt, data=folder), docker=docker)

    clear = RecordingDocker()
    start(code_side, clear)
    assert clear.create_argv is not None, "the code mount's checkout folder was taken as the root"

    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()) as refused:
        start(root / "mount", rec)
    said = str(refused.value)
    assert X.names_path(said, root), f"the refusal does not name the process's root {root}: {said}"
    # A run lane's stage holds its agent folder: either of the two may be the one named.
    assert any(X.names_path(said, m) for m in (root / "mount", root / "mount" / "agent")), (
        f"it does not name the mount: {said}")
    assert not X.created(rec.calls)
    assert not X.removed(rec.calls)


def _request_without_a_code_mount(req: X.RequestLane) -> box_mod.BoxRequest:
    """A caller-composed request that names no code tree: A8 needs none."""
    mounts = (
        box_mod.Mount(source=req.data, target=req.data, writable=False, kind="data"),
        box_mod.Mount(source=req.lane, target=req.lane, writable=True),
    )
    return box_mod.BoxRequest(name=X.REQUEST_NAME, mounts=mounts, workdir=DEFENDER.parent, env={},
                              require_sandbox=False, tenant_id=TEST_TENANT, data_root=current_data_root())


def test_a8_a_request_with_no_code_mount_is_still_judged(tmp_path, monkeypatch):
    """The root does not come from a mount, so a request with no code mount is judged too."""
    req = X.request_lane(tmp_path)
    X.dev_root(monkeypatch, req.data / "pub")
    rec = RecordingDocker()
    with pytest.raises(X.conflict_type()):
        box_mod.start_box(_request_without_a_code_mount(req), docker=rec)
    assert not X.created(rec.calls)


@pytest.mark.parametrize("opt_out", [False, True], ids=["plain", "opt-out"])
@pytest.mark.parametrize("lane_kind", ["run", "request"])
def test_a9_in_dev_an_unset_root_starts_the_box_and_warns_naming_the_setting(
        tmp_path, monkeypatch, caplog, lane_kind, opt_out):
    """In `dev` with no publish folder set there is nowhere to publish, not a conflict.
    The box starts, plain and with the opt-out, and a warning names the box and the setting, so a
    skipped check never passes as a clear one. Control: outside `dev` it starts with no such
    warning."""
    if lane_kind == "run":
        lane = X.run_lane(tmp_path)
        start, name = lane.start, box_mod.container_name(lane.run_dir.name)
    else:
        req = X.request_lane(tmp_path)
        def start(docker: RecordingDocker) -> None:
            box_mod.start_box(req.request(), docker=docker)
        name = X.REQUEST_NAME
    X.dev_unset_root(monkeypatch)
    if opt_out:
        X.allow_unsandboxed(monkeypatch)
    rec = RecordingDocker()
    with caplog.at_level("WARNING", logger="defender.box._lifecycle"):
        start(rec)
    assert rec.create_argv is not None, "an unset root refused the start"
    warned = [r.getMessage() for r in caplog.records if r.name == "defender.box._lifecycle"
              and "no publish root" in r.getMessage()]
    assert len(warned) == 1, f"no single warning that there is no publish root: {caplog.text}"
    assert name in warned[0], f"the warning does not name the box {name}: {warned[0]}"
    assert "DEFENDER_RUN_VISUALIZATIONS_DIR" in warned[0], f"the warning does not name the setting: {warned[0]}"

    caplog.clear()
    monkeypatch.delenv(X.DEPLOYMENT_ENV, raising=False)
    outside = RecordingDocker()
    with caplog.at_level("WARNING", logger="defender.box._lifecycle"):
        start(outside)
    assert outside.create_argv is not None
    assert "no publish root" not in caplog.text, "outside dev there is no root to miss"


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
    """Whatever the container's state, with the opt-out on, the start refuses, removes nothing
    and creates nothing."""
    monkeypatch.delenv(X.DEPLOYMENT_ENV, raising=False)
    X.allow_unsandboxed(monkeypatch)
    rec = RecordingDocker(status=state)
    if lane_kind == "run":
        lane = X.run_lane(tmp_path)
        start = lambda: lane.start(rec)  # noqa: E731
        name = box_mod.container_name(lane.run_dir.name)
    else:
        lane = X.request_lane(tmp_path)
        start = lambda: box_mod.start_box(lane.request(), docker=rec)  # noqa: E731
        name = lane.request().name
    with pytest.raises(X.conflict_type()) as refused:
        start()
    assert isinstance(refused.value, box_mod.BoxFault)
    assert name in str(refused.value), "the refusal does not name the container"
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


def _daemon_down(argv, **_kw):
    """A daemon that answers every call with an error (the socket is there, nothing behind it)."""
    import subprocess
    return subprocess.CompletedProcess(list(argv), 1, "", "Cannot connect to the Docker daemon")


@pytest.mark.parametrize("lane_kind", ["run", "request"])
def test_a2_a_daemon_that_answers_errors_to_inspect_and_version_degrades_and_is_not_the_refusal(
        tmp_path, monkeypatch, lane_kind):
    """A daemon that cannot say what a name holds and cannot answer for itself is a plain
    BoxFault (not the same-name subtype); the opt-out degrades it; nothing is created or removed."""
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    calls: list[list[str]] = []

    def down(argv, **kw):
        calls.append(list(argv))
        return _daemon_down(argv, **kw)

    if lane_kind == "run":
        lane = X.run_lane(tmp_path)
        start = lambda: lane.start(down)  # noqa: E731
    else:
        lane = X.request_lane(tmp_path)
        start = lambda: box_mod.start_box(lane.request(), docker=down)  # noqa: E731
    with pytest.raises(box_mod.BoxFault) as faulted:
        start()
    assert not isinstance(faulted.value, X.conflict_type()), (
        "an unreachable daemon was reported as a same-name container")
    assert any(c[1:2] == ["version"] for c in calls), "control: the daemon was never probed"
    X.allow_unsandboxed(monkeypatch)
    degraded = start()
    assert degraded.sandboxed is False, "the opt-out no longer degrades an unreachable daemon"
    assert not X.created(calls)
    assert not X.removed(calls)


@pytest.mark.parametrize("lane_kind", ["run", "request"])
def test_a2_a_name_conflict_raised_by_docker_run_itself_stays_a_degradable_create_fault(
        tmp_path, monkeypatch, lane_kind):
    """Inspect found the name free, then `docker run` itself reports it taken (a race): that
    stays a degradable create fault, not the refusal subtype."""
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


def _chain(exc):
    out = []
    while exc is not None and exc not in out:
        out.append(exc)
        exc = exc.__cause__ or exc.__context__
    return out


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
    request = _oracle.oracle_box_request(scratch, runner, env={"DEFENDER_BOX_RUNTIME": "runc"}, tenant_id=TEST_TENANT, data_root=tmp_path)
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
        _oracle.start_oracle_box(env={"PATH": os.environ["PATH"], "DEFENDER_BOX_RUNTIME": "runc"}, tenant_id=TEST_TENANT, data_root=tmp_path)
    assert any(isinstance(e, X.conflict_type()) for e in _chain(refused.value)), (
        f"the refusal's text did not survive as the cause: {_chain(refused.value)}")
    assert daemon.created() == []


def test_o3_the_estate_oracle_start_turns_the_refusal_into_its_own_failure_keeping_its_text(
        tmp_path, monkeypatch):
    """`estate.oracle.start_box` re-wraps `_oracle.BoxStartRefused` as
    `OracleSandboxError`; the BoxStartConflict, with its text, stays in the chain and in the
    message the operator reads."""
    from defender.learning.branch.estate import oracle as estate_oracle

    root = X.dev_root(monkeypatch, Path(tempfile.gettempdir()))
    daemon = FakeDaemon(tmp_path)
    daemon.install(monkeypatch)
    with pytest.raises(estate_oracle.OracleSandboxError) as refused:
        estate_oracle.start_box(env={"PATH": os.environ["PATH"], "DEFENDER_BOX_RUNTIME": "runc"}, tenant_id=TEST_TENANT, data_root=tmp_path)
    conflicts = [e for e in _chain(refused.value) if isinstance(e, X.conflict_type())]
    assert conflicts, f"the refusal did not survive the oracle's re-wrapping: {_chain(refused.value)}"
    assert str(conflicts[0]) in str(refused.value), (
        f"the operator's message dropped the refusal's text: {refused.value}")
    assert X.names_path(str(refused.value), root) or X.names_path(str(refused.value), root.resolve())
    assert daemon.created() == []


def test_o6_the_oracle_request_name_refuses_a_finished_container(tmp_path, oracle_tree):
    from defender.box import _oracle

    runner, scratch = oracle_tree
    request = _oracle.oracle_box_request(scratch, runner, env={"DEFENDER_BOX_RUNTIME": "runc"}, tenant_id=TEST_TENANT, data_root=tmp_path)
    daemon = FakeDaemon(tmp_path)
    daemon.hold(request.name, "exited")
    with pytest.raises(X.conflict_type()) as refused:
        box_mod.start_box(request, docker=daemon)
    assert request.name in str(refused.value), "the refusal does not name the container"
    assert daemon.names() == [request.name]
    assert not X.removed(daemon.docker_calls())


def test_o6_the_oracle_entry_refuses_a_held_same_name_container_and_leaves_it(
        tmp_path, monkeypatch):
    """`start_oracle_box`, through its own docker closure, refuses when the daemon reports a
    container under the oracle's minted name, with the conflict in the cause chain; it removes and
    creates nothing. Control: a daemon holding nothing starts the same oracle."""
    from defender.box import _oracle

    env = {"PATH": os.environ["PATH"], "DEFENDER_BOX_RUNTIME": "runc"}
    free = FakeDaemon(tmp_path / "free")
    free.install(monkeypatch)
    started = _oracle.start_oracle_box(env=env, tenant_id=TEST_TENANT, data_root=tmp_path)
    try:
        assert started.sandboxed, "control: the oracle did not start on a free name"
        assert len(free.created()) == 1
    finally:
        _oracle.stop_oracle_box(started)

    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    log = X.hold_every_name(tmp_path / "holding", monkeypatch)
    with pytest.raises(_oracle.BoxStartRefused) as refused:
        _oracle.start_oracle_box(env={"PATH": os.environ["PATH"], "DEFENDER_BOX_RUNTIME": "runc"}, tenant_id=TEST_TENANT, data_root=tmp_path)
    conflicts = [e for e in _chain(refused.value) if isinstance(e, X.conflict_type())]
    assert conflicts, f"the refusal did not survive as the cause: {_chain(refused.value)}"
    calls = X.logged_calls(log)
    asked = [c[-1] for c in calls if c[:2] == ["inspect", "-f"]]
    assert asked, calls
    assert asked[0].startswith("defender-oracle-"), calls
    assert asked[0] in str(conflicts[0]), "the refusal does not name the container"
    assert not any(c[:1] == ["run"] for c in calls), "a box was created beside the held container"
    assert not any(c[:1] == ["rm"] for c in calls), "the held container was removed"


def test_o6_every_oracle_box_name_is_fresh(tmp_path, oracle_tree):
    from defender.box import _oracle

    runner, scratch = oracle_tree
    env = {"DEFENDER_BOX_RUNTIME": "runc"}
    names = [_oracle.oracle_box_request(scratch, runner, env=env, tenant_id=TEST_TENANT, data_root=tmp_path).name for _ in range(3)]
    assert len(set(names)) == 3, f"an oracle name repeated: {names}"


def _sibling_serving(tenant: str):
    """A sibling's oracle side, as `run.py` settles it for its world."""
    from defender import run as run_mod

    return run_mod._world_seams(object(), oracle=None, verifier=None, source=None, tenant_id=tenant,
                                  data_root=current_data_root())["serving"]


def _launcher_serving(tenant: str):
    from defender.learning.branch.estate.registry import oracle_serving
    from defender.learning.core.config import oracle_settings_with

    return oracle_serving(oracle_settings_with(), tenant_id=tenant, data_root=current_data_root())


@pytest.mark.parametrize("serving", [_launcher_serving, _sibling_serving], ids=["registry", "sibling"])
def test_the_production_oracle_box_carries_its_tenant_label(tmp_path, monkeypatch, serving):
    """The oracle's box a world is served with is labelled `defender.tenant=<T>` as the run box is, so the tenant's
    teardown finds and removes it (#1214 O4)."""
    tenant = fixture_uuid("oracle-label-tenant")
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    monkeypatch.setenv("DEFENDER_BOX_RUNTIME", "runc")
    daemon = FakeDaemon(tmp_path / "daemon")
    daemon.install(monkeypatch)
    started = serving(tenant).box()
    try:
        [create] = [c for c in daemon.docker_calls() if c[:2] == ["docker", "create"]]  # #1344 amendment 2
        labels = [create[i + 1] for i, arg in enumerate(create) if arg == "--label"]
        assert f"defender.tenant={tenant}" in labels, labels
    finally:
        from defender.box import _oracle

        _oracle.stop_oracle_box(started)


@pytest.mark.parametrize("given", [{}, {"tenant_id": None}, {"tenant_id": ""}], ids=["omitted", "none", "empty"])
def test_a_box_request_without_a_tenant_is_a_construction_error(tmp_path, given):
    """Every box carries its tenant: a `BoxRequest` with no tenant (omitted, None, empty) is refused at construction; one
    naming a tenant is made (r10 B1, O-B1; r10.1 C8)."""
    made = box_mod.BoxRequest(name="defender-box-b1", workdir=tmp_path, tenant_id=TEST_TENANT, data_root=tmp_path)
    assert made.tenant_id == TEST_TENANT, "control: a request naming its tenant is made"
    with pytest.raises((TypeError, ValueError)):
        box_mod.BoxRequest(name="defender-box-b1", workdir=tmp_path, data_root=tmp_path, **given)


def test_a_box_request_names_its_tenant_without_judging_the_grammar(tmp_path):
    """A `BoxRequest` naming any non-empty tenant id is made; the id's grammar is judged at acceptance only (r10.1 C8)."""
    made = box_mod.BoxRequest(name="defender-box-b1", workdir=tmp_path, tenant_id="not-a-uuid", data_root=tmp_path)
    assert made.tenant_id == "not-a-uuid"


@pytest.mark.parametrize(("given", "refusal"), [
    ({}, TypeError), ({"tenant_id": None}, TypeError), ({"tenant_id": ""}, (TypeError, ValueError)),
], ids=["omitted", "none", "empty"])
def test_the_run_box_start_refuses_a_missing_tenant_like_its_missing_defender_dir(tmp_path, monkeypatch, given, refusal):
    """`start_box(run_dir, defender_dir, ...)` with no tenant is a `TypeError` (omitted, None) or `TypeError`/`ValueError`
    (empty), naming the tenant, before any container is asked for; with one the same call starts, labelled (r10.1 C8, O-B1)."""
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "published")
    lane = X.run_lane(tmp_path / "run")
    rec = RecordingDocker()
    lane.start(rec, spec=_PINNED)
    assert f"defender.tenant={lane.tenant_id}" in rec.create_argv, "control: the run box carries its tenant label"
    bare = RecordingDocker()
    with pytest.raises(refusal, match="tenant"):
        box_mod.start_box(lane.run_dir, lane.defender_dir, tenant_agent=lane.agent, staged_token=lane.token,
                          docker=bare, spec=_PINNED, **given)
    assert bare.create_argv is None, "a tenantless run box reached the container runtime"


def test_the_run_box_start_judges_no_grammar_of_a_non_empty_tenant_id(tmp_path, monkeypatch):
    """`start_box(run_dir, ...)` with a non-empty id that is not a tenant-id grammar starts and labels the box with it:
    the grammar is judged at acceptance only (r10.1 C8)."""
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "published")
    lane = replace(X.run_lane(tmp_path / "run"), tenant_id="not-a-uuid")
    rec = RecordingDocker()
    lane.start(rec, spec=_PINNED)
    assert "defender.tenant=not-a-uuid" in rec.create_argv, rec.create_argv


def _oracle_box_entries() -> dict:
    import importlib

    oracle = importlib.import_module("defender.box._oracle")
    estate = importlib.import_module("defender.learning.branch.estate.oracle")
    registry = importlib.import_module("defender.learning.branch.estate.registry")
    return {
        "oracle_box_request": oracle.oracle_box_request, "start_oracle_box": oracle.start_oracle_box,
        "start_process_oracle_box": oracle.start_process_oracle_box, "estate start_box": estate.start_box,
        "start_process_box": estate.start_process_box, "oracle_serving": registry.oracle_serving,
    }


@pytest.mark.parametrize("entry", ["oracle_box_request", "start_oracle_box", "start_process_oracle_box",
                                   "estate start_box", "start_process_box", "oracle_serving"])
def test_every_oracle_box_entry_requires_its_tenant(entry):
    """No oracle box function defaults its tenant, so no caller can serve a world a tenantless box (r10 B1: the oracle's
    box functions all require the tenant)."""
    import inspect

    param = inspect.signature(_oracle_box_entries()[entry]).parameters["tenant_id"]
    assert param.default is inspect.Parameter.empty, f"{entry} defaults its tenant to {param.default!r}"


@pytest.mark.parametrize("entry", ["oracle_box_request", "start_oracle_box", "start_process_oracle_box",
                                   "estate start_box", "start_process_box", "oracle_serving"])
def test_every_oracle_box_entry_requires_its_data_root(entry):
    """No oracle box function defaults its data root, as none defaults its tenant: a caller that forgets it fails at once,
    and the check always has a folder to run in (#1469 D1)."""
    import inspect

    param = inspect.signature(_oracle_box_entries()[entry]).parameters["data_root"]
    assert param.default is inspect.Parameter.empty, f"{entry} defaults its data root to {param.default!r}"


def test_the_oracle_serving_requires_its_tenant():
    """The launcher's oracle serving takes no default tenant, so a call that names none is a `TypeError` (r10 B1,
    `learning/branch/preflight.py:120`)."""
    from defender.learning.branch.estate.registry import oracle_serving
    from defender.learning.core.config import oracle_settings_with

    assert oracle_serving(oracle_settings_with(), tenant_id=TEST_TENANT,
                          data_root=current_data_root()).box is not None, "control: named, it is built"
    with pytest.raises(TypeError):
        oracle_serving(oracle_settings_with(), data_root=current_data_root())


@pytest.mark.parametrize("entry", ["oracle_box_request", "start_oracle_box", "estate start_box",
                                   "start_process_oracle_box", "start_process_box", "oracle_serving"])
def test_every_oracle_box_entry_labels_a_non_empty_tenant_id_without_judging_its_grammar(
        tmp_path, monkeypatch, entry, oracle_tree):
    """Each oracle box entry starts a box for a non-empty id that is no tenant-id grammar, labelled with it; the grammar is
    judged at acceptance only (r10.1 C8)."""
    from defender.box import _oracle
    from defender.learning.branch.estate import oracle as estate_oracle

    bad = "not-a-uuid"
    env = {"PATH": os.environ["PATH"], "DEFENDER_BOX_RUNTIME": "runc"}
    X.dev_root(monkeypatch, tmp_path / "elsewhere" / "pub")
    monkeypatch.setenv("DEFENDER_BOX_RUNTIME", "runc")
    daemon = FakeDaemon(tmp_path / "daemon")
    daemon.install(monkeypatch)
    if entry == "oracle_box_request":  # builds the request only: the label is read off the box that request starts
        runner, scratch = oracle_tree
        box_mod.start_box(_oracle.oracle_box_request(scratch, runner, env=env, tenant_id=bad, data_root=tmp_path), docker=daemon)
        [create] = [c for c in daemon.docker_calls() if c[:2] == ["docker", "create"]]  # #1344 amendment 2
        labels = [create[i + 1] for i, arg in enumerate(create) if arg == "--label"]
        assert f"defender.tenant={bad}" in labels, labels
        return
    starts = {
        "start_oracle_box": lambda: _oracle.start_oracle_box(env=env, tenant_id=bad, data_root=tmp_path),
        "estate start_box": lambda: estate_oracle.start_box(env=env, tenant_id=bad, data_root=tmp_path),
        "start_process_oracle_box": lambda: _oracle.start_process_oracle_box(tenant_id=bad, data_root=tmp_path),
        "start_process_box": lambda: estate_oracle.start_process_box(tenant_id=bad, data_root=tmp_path),
        "oracle_serving": lambda: _launcher_serving(bad).box(),
    }
    started = starts[entry]()
    try:
        [create] = [c for c in daemon.docker_calls() if c[:2] == ["docker", "create"]]  # #1344 amendment 2
        labels = [create[i + 1] for i, arg in enumerate(create) if arg == "--label"]
        assert f"defender.tenant={bad}" in labels, labels
    finally:
        _oracle.stop_oracle_box(started)
