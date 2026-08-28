"""Start, stop, scrub — and the faults each step can raise.

Split out of `box.py` at 1077 lines. The sentinel planting and mount checks live here
because they are steps of starting a box, not properties of one.
"""
from __future__ import annotations

import os
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from defender._io import sweep_staged, write_guarded
from defender._run_id import RUN_ID_ALLOWED, is_valid_run_id
from defender.runtime.box_codec import (
    REQUEST_MAGIC,  # noqa: F401 — re-exported: test_540_exec_seam.py imports it as `box.REQUEST_MAGIC`
    RESPONSE_MAGIC,  # noqa: F401 — re-exported: test_540_exec_seam.py imports it as `box.RESPONSE_MAGIC`
    BoxFault,
)
from defender.runtime.scrub import (  # noqa: F401 — re-exported: run.py/drains.py/tests import `box.scrub`, `box.RunTainted`
    Finding,
    RunTainted,
    scrub,
    verdict_path,
    write_did_not_run,
)
from ._spec import ALIAS_PROFILE_PATH, BOX_ENV_ALLOWLIST, BoxExecutor, BoxRequest, BoxSpec, Mount
from ._alias import _probe_alias_ban
from ._docker import DockerFn, START_TOKEN_LABEL, SharedMountsFn, _ALLOW_UNSANDBOXED, _LOCALE_ENV, _call, _covered, _daemon_source, _docker, _reap_on_fault, _reap_stale_before_create, _render_env, _shared_mounts, _uncovered_fault, container_name, infra_env
from ._spec import DEFAULT_SPEC, _HostTransport
from ._spec import _DockerTransport


def _create_argv(
    name: str, run_dir: Path, defender_dir: Path, spec: BoxSpec,
    mounts: Sequence[tuple[Path, Path]] = (), start_token: str = "",
) -> list[str]:
    env_pairs = {**infra_env(defender_dir, run_dir), **_LOCALE_ENV}
    # The remedy is per-subject: DEFENDER_RUNS_BASE relocates the RUN dir and nothing else,
    # so naming it for an uncovered defender_dir would send the operator at the wrong knob.
    for subject, path, remedy in (
        ("run dir", run_dir, "Set DEFENDER_RUNS_BASE to a path"),
        ("defender dir", defender_dir, "Check out the tree"),
    ):
        if mounts and not _covered(path, mounts):
            raise _uncovered_fault(subject, path, mounts, remedy)
    run_src = _daemon_source(run_dir, mounts)
    defender_src = _daemon_source(defender_dir, mounts)
    argv = [
        "docker", "run", "--detach", "--name", name,
        "--label", f"{START_TOKEN_LABEL}={start_token}",
        "--runtime", spec.runtime,
        "--network", "none",
        "--read-only",
        "--security-opt", f"seccomp={ALIAS_PROFILE_PATH}",
        "--mount", f"type=bind,source={run_src},target={run_dir}",
        "--mount", f"type=bind,source={defender_src},target={defender_dir},readonly",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,mode=1777,size={spec.tmpfs_size}",
        "--workdir", str(run_dir),
    ]
    for key in BOX_ENV_ALLOWLIST:
        argv += ["--env", f"{key}={env_pairs[key]}"]
    argv += [spec.rootfs, "sleep", "infinity"]
    return argv


def _plant(sentinel: Path, token: str) -> None:
    """Host-side half of a sentinel probe. An unwritable/absent SOURCE is a box-startup fault
    like any other (BoxFault), not a bare OSError that would escape start_box's classification
    and the loud DEFENDER_ALLOW_UNSANDBOXED fallback."""
    try:
        write_guarded(sentinel, token)
    except OSError as e:
        raise BoxFault(
            f"could not plant the startup sentinel at {sentinel} — the bind source is not "
            f"writable by this process: {e}"
        ) from e


def _probe_sentinel(
    source: Path, target: Path, docker: DockerFn, name: str, sentinel_name: str,
    *, unlink_on_fault: bool,
) -> None:
    token = uuid.uuid4().hex
    sentinel = source / sentinel_name
    _plant(sentinel, token)
    try:
        proc = _call(docker, ["docker", "exec", name, "cat", str(target / sentinel_name)])
        if proc.returncode != 0 or (proc.stdout or "").strip() != token:
            raise BoxFault(
                f"the box could not read back the startup sentinel at {sentinel} — the tree "
                "inside the box does not match the host"
            )
    except BaseException:
        # The run-dir tier deliberately LEAVES its sentinel behind on a fault — the residue is
        # the evidence the probe really wrote. The per-mount tier cleans up, because its
        # sources include the live repo/worktree trees.
        if unlink_on_fault:
            sentinel.unlink(missing_ok=True)
        raise
    sentinel.unlink(missing_ok=True)


def _plant_sentinel(run_dir: Path, docker: DockerFn, name: str) -> None:
    _probe_sentinel(run_dir, run_dir, docker, name, ".box-sentinel", unlink_on_fault=False)


def _check_mount_sentinel(mount: Mount, docker: DockerFn, name: str) -> None:
    """M11 — every mount is individually probed at start: a host-planted token, read back
    through the box, proves the tree inside the container is the tree on the host. An absent
    bind SOURCE is caught earlier, at create; this catches a bind that SUCCEEDED but mapped
    the wrong or empty tree."""
    _probe_sentinel(
        Path(mount.source), Path(mount.target), docker, name,
        f".box-sentinel-{uuid.uuid4().hex}", unlink_on_fault=True,
    )


def _start_boxed(
    run_dir: Path, defender_dir: Path, spec: BoxSpec, docker: DockerFn,
    shared_mounts: SharedMountsFn = _shared_mounts,
) -> BoxExecutor:
    name = container_name(run_dir.name)
    try:
        _reap_stale_before_create(docker, name)
    except BoxFault as e:
        # The §7 D2 marker, on the arm that now raises MOST often. Every other fault path in
        # this function writes it before raising, and `test_a_reap_that_cannot_reach_the_
        # daemon_still_leaves_the_did_not_run_marker` pins the rule for the sibling arm: a
        # startup fault that leaves no verdict makes the tree read "nobody has judged this
        # run yet", which is the one state `write_did_not_run` exists to prevent. #955 F-49
        # widened this arm's trigger from `running` alone to every state but exited/dead —
        # i.e. to every leaked container on a REUSED name, repeatably — so the gap that was
        # a rare corner is now the common wedge.
        write_did_not_run(run_dir, f"box start refused before create: {e}")
        raise
    start_token = uuid.uuid4().hex
    created = _call(
        docker,
        _create_argv(
            name, run_dir, defender_dir, spec, shared_mounts(docker), start_token,
        ),
    )
    if created.returncode != 0:
        # `docker run --detach` is create-THEN-start, so a non-zero rc does not prove no
        # container exists: a failure at task start (a profile the runtime rejects, a missing
        # `runsc`, cgroup or pid exhaustion) leaves it behind in `created`, and nothing
        # revisits this name — so without this reap the leak accrues one per faulted start.
        # Marker and reap are BEST-EFFORT and may not replace the create's stderr, the only
        # account of why the box failed. `owned_token` decides WHOSE container this is.
        write_did_not_run(
            run_dir, f"box create faulted before the box was startable: "
                     f"{(created.stderr or '').strip()}"
        )
        _reap_on_fault(docker, name, owned_token=start_token)
        raise BoxFault(
            f"could not create the box {name}: {(created.stderr or '').strip()}"
        )
    try:
        _plant_sentinel(run_dir, docker, name)
        _probe_alias_ban(docker, name, run_dir, spec.runtime)
    except BaseException as e:
        # Unconditional (this box IS ours — create succeeded) but best-effort: a reap that
        # raises here must not take the §7 D2 marker below down with it, nor replace the
        # startup fault `e` with "could not invoke docker".
        _reap_on_fault(docker, name)
        write_did_not_run(
            run_dir, f"box startup faulted before the reap scan could run: {e}"
        )
        raise
    return BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name)


def _render_argv(
    request: BoxRequest, mounts: Sequence[tuple[Path, Path]] = (),
    start_token: str = "",
) -> list[str]:
    argv = [
        "docker", "run", "--detach", "--name", request.name,
        "--label", f"{START_TOKEN_LABEL}={start_token}",
        "--runtime", request.spec.runtime,
        "--network", "none",
        "--read-only",
        "--security-opt", f"seccomp={ALIAS_PROFILE_PATH}",
    ]
    for m in request.mounts:
        if mounts and not _covered(Path(m.source), mounts):
            raise _uncovered_fault(
                "mount source", Path(m.source), mounts, "Compose the mount",
            )
        spec_str = f"type=bind,source={_daemon_source(Path(m.source), mounts)},target={m.target}"
        if not m.writable:
            spec_str += ",readonly"
        argv += ["--mount", spec_str]
    argv += [
        "--tmpfs", f"/tmp:rw,noexec,nosuid,mode=1777,size={request.spec.tmpfs_size}",
        "--workdir", str(request.workdir),
    ]
    env = _render_env(request.env, Path(request.workdir))
    for key in sorted(env):
        argv += ["--env", f"{key}={env[key]}"]
    argv += [request.spec.rootfs, "sleep", "infinity"]
    return argv


def _did_not_run_for_request(request: BoxRequest, reason: str) -> None:
    """§7 D2's marker for the request lane — one per WRITABLE mount source, none at all for a
    lane that has no writable mount. A request composes its own geography, so "which tree does
    this verdict belong to" must be answered explicitly, by `stop_and_scrub`'s rule: a tree is
    worth a verdict exactly when the box could write it. Best-effort per tree, for the reason
    `scrub._write_verdict` carries."""
    for m in request.mounts:
        if m.writable:
            write_did_not_run(Path(m.source), reason)


def _start_boxed_request(
    request: BoxRequest, docker: DockerFn, shared_mounts: SharedMountsFn = _shared_mounts,
) -> BoxExecutor:
    if not is_valid_run_id(request.name):
        raise BoxFault(
            f"composed container name {request.name!r} fails the run-id grammar "
            f"(allowed: {RUN_ID_ALLOWED})"
        )
    try:
        _reap_stale_before_create(docker, request.name)
    except BoxFault as e:
        # `_start_boxed`'s reason, on the request lane's own geography — with the caveat that
        # geography makes: `_did_not_run_for_request` writes one verdict per WRITABLE mount,
        # and `run_cycle._run_cycle_box_request` composes every mount `writable=False`. So on
        # the RUN-CYCLE lane — the one caller that reuses a name, and therefore the one this
        # arm exists for — this writes NOTHING. That is `stop_and_scrub`'s rule holding, not
        # an omission (a tree the box could not write needs no verdict about what it wrote),
        # but it means the §7 D2 cover the sibling arm gets is not cover this lane gets.
        _did_not_run_for_request(request, f"box start refused before create: {e}")
        raise
    start_token = uuid.uuid4().hex
    created = _call(
        docker, _render_argv(request, shared_mounts(docker), start_token),
    )
    if created.returncode != 0:
        # `_start_boxed`'s reason, verbatim: create-then-start means a non-zero rc can still
        # leave a `created` container, and this lane's names are no more revisited than that
        # one's (`defender-drain-{uuid4}` per invocation). The name-conflict guard matters MORE
        # here: the run-cycle caller REUSES its name, so a create that lost the race to a
        # concurrent batch of the same run id is exactly the create that must not reap.
        _did_not_run_for_request(
            request, f"box create faulted before the box was startable: "
                     f"{(created.stderr or '').strip()}"
        )
        _reap_on_fault(docker, request.name, owned_token=start_token)
        raise BoxFault(
            f"could not create the box {request.name}: {(created.stderr or '').strip()}"
        )
    try:
        for m in request.mounts:
            _check_mount_sentinel(m, docker, request.name)
        _probe_alias_ban(docker, request.name, _probe_cwd_for_request(request), request.spec.runtime)
    except BaseException as e:
        # Unconditional (this box IS ours — create succeeded) but best-effort: a reap that
        # raises here must not take the markers below down with it, nor replace the startup
        # fault `e` with "could not invoke docker".
        _reap_on_fault(docker, request.name)
        # Both fault arms mark, as `_start_boxed` does. The host has already planted sentinels
        # into these trees by the time a mount probe or the alias probe fails; without the
        # marker the tree has no verdict at all, which `tree_verified` cannot tell apart from
        # a tree nobody has judged yet.
        _did_not_run_for_request(
            request, f"box startup faulted before the reap scan could run: {e}"
        )
        raise
    return BoxExecutor(
        spec=request.spec, transport=_DockerTransport(request.name, request.spec),
        name=request.name,
    )


def _probe_cwd_for_request(request: BoxRequest) -> Path:
    """Where M2's probe acts inside this lane's box: the first WRITABLE mount's target, or the
    box's own `/tmp` tmpfs when the lane has none. The ban is a syscall filter, not a path
    policy, so the observation is equally valid in either."""
    for m in request.mounts:
        if m.writable:
            return Path(m.target)
    return Path("/tmp")


def _opt_out_or_raise(fault: BoxFault) -> None:
    """M9: the ONE loud host lane. Without the env var a startup fault aborts; with it, the
    caller degrades to `unboxed_executor` after a greppable warning."""
    if os.environ.get(_ALLOW_UNSANDBOXED) != "1":
        raise fault
    print(
        f"[box] WARNING: {_ALLOW_UNSANDBOXED}=1 — running UNSANDBOXED. The bash lane "
        "executes on the host with no filesystem or network boundary.",
        file=sys.stderr,
    )


def _host_fallback_env(request: BoxRequest) -> dict[str, str]:
    """R8: the unboxed opt-out is a bare HOST subprocess, so it inherits the host env (minus
    provider keys) as `run_common.run_env` does — NOT the box's key-allowlisted,
    container-shaped `_render_env`, which carries no HOME and a `_BOX_PATH` the host lacks."""
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    env.update({k: v for k, v in request.env.items() if k in BOX_ENV_ALLOWLIST})
    defender_dir = Path(request.workdir) / "defender"
    env["DEFENDER_DIR"] = str(defender_dir)
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    # PREPENDED like PATH above, not assigned: a bare host subprocess keeps whatever
    # PYTHONPATH the operator's shell set (the whole point of "inherits the host env").
    inherited = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        f"{request.workdir}{os.pathsep}{inherited}" if inherited else str(request.workdir)
    )
    return env


def start_box(
    run_dir_or_request: Path | BoxRequest, defender_dir: Path | None = None, *,
    spec: BoxSpec | None = None, docker: DockerFn = _docker,
) -> BoxExecutor:
    if isinstance(run_dir_or_request, BoxRequest):
        request = run_dir_or_request
        # An explicit `spec=` beside a BoxRequest names two geographies. Tested with
        # `is not None` rather than against DEFAULT_SPEC: the default is env-resolved, so a
        # value comparison would fire spuriously whenever DEFENDER_BOX_RUNTIME is set. The env
        # is NOT read on this path — `BoxRequest.spec`'s factory owns the lever, and reading it
        # here would let a typo'd value raise ValueError out of a call that never uses `spec`,
        # escaping both `_opt_out_or_raise` and core/faults.py's SYSTEMIC_FAULTS.
        if spec is not None:
            raise TypeError(
                "start_box(request, spec=…) is ambiguous — a BoxRequest carries its own spec; "
                "set it on the request (BoxRequest(..., spec=…)) instead of the call"
            )
        if defender_dir is not None:
            raise TypeError(
                "start_box(request, defender_dir) is ambiguous — a BoxRequest carries its own "
                "geography; put the tree in its mounts/workdir instead of the call"
            )
        try:
            return _start_boxed_request(request, docker)
        except BoxFault as e:
            _opt_out_or_raise(e)
        return unboxed_executor(request.spec, env=_host_fallback_env(request))

    run_dir = run_dir_or_request
    if defender_dir is None:
        raise TypeError("start_box(run_dir, defender_dir, ...) needs defender_dir")
    # The runtime knob: the dataclass anchors the default (runsc), ONE env var is its external
    # lever, resolved here for the run_dir overload as `BoxRequest.spec`'s factory does for the
    # request one. runc is the weaker isolation tier, so it is reached only by an operator
    # explicitly setting DEFENDER_BOX_RUNTIME=runc — never by fallback.
    if spec is None:
        # lint-default: ok — the env lever IS this default's single source. The signature
        # cannot carry it: `spec=` must stay distinguishable from unset for the BoxRequest
        # overload's ambiguity check above.
        spec = BoxSpec.from_env(os.environ)
    try:
        return _start_boxed(run_dir, defender_dir, spec, docker)
    except BoxFault as e:
        _opt_out_or_raise(e)
    from defender import run_common
    return unboxed_executor(spec, env=run_common.run_env(defender_dir, run_dir))


def stop_box(box: BoxExecutor, *, docker: DockerFn = _docker) -> None:
    if not box.name:
        return
    proc = _call(docker, ["docker", "rm", "-f", box.name])
    if proc.returncode != 0:
        raise BoxFault(
            f"could not tear down the box {box.name}: {(proc.stderr or '').strip()}"
        )


def stop_and_scrub(
    box: BoxExecutor,
    tree: Path,
    *,
    stop_box: Callable[..., None],
    scrub_tree: Callable[[Path], None],
    in_flight: bool,
) -> None:
    """Reap a boxed run: tear the box down, then walk the tree it could write.

    Both writable lanes call it. `run_cycle` does not, correctly: all of its mounts are
    read-only, so it has no tree to walk. Call it from a `finally`, with `in_flight` saying
    whether an exception is already propagating. Three rules, and their ordering is the point:

    - **The scrub runs only once the box is provably dead.** "No live writer" is the scrub's
      entire justification, so a swallowed teardown fault leaves that unproven and the walk is
      SKIPPED rather than raced.
    - **An in-flight exception outranks a teardown fault**, which would otherwise replace the
      more informative signal (implicit chaining keeps it on `__context__`). Outranked is not
      unrecorded: a suppressed fault means BOTH a possibly-leaked container and an unwalked
      tree, so it is logged rather than dropped.
    - **A taint outranks everything.** `RunTainted` wins over the work's own failure — the
      crash path's tree is the one most likely to hold what the box planted, and the one a
      human then opens by hand. That falls out of not catching it.

    `stop_box` and `scrub_tree` are required, not defaulted: each lane anchors its own defaults
    in its own signature. `scrub_tree` rather than `scrub`, which this module re-exports.
    """
    box_down = False
    try:
        stop_box(box)
        box_down = True
    except BoxFault as e:
        # §7 D2: the scan cannot run (the box is not provably dead), on BOTH teardown-fault
        # arms — with nothing in flight the fault still propagates, but the tree is just as
        # unscanned, so the marker is written before the branch below decides what to do next.
        write_did_not_run(tree, f"teardown faulted before the reap scan could run: {e}")
        if not in_flight:
            raise
        print(
            f"[box] WARNING: teardown failed under an in-flight failure: {e} — the box may "
            f"be leaked, and {tree} was NOT scrubbed (the walk needs a provably dead box).",
            file=sys.stderr,
        )
    if box_down:
        scrub_tree(tree)
        # Unpredictable staged names mean no later write ever replaces a crash-orphaned one by
        # name, so without a sweep they accumulate forever. Strictly AFTER the walk: sweeping
        # first would delete entries the scan exists to report. A tainted tree never reaches
        # this line — `RunTainted` propagates out of `scrub_tree` — so quarantine still gets
        # the tree exactly as the box left it.
        swept = sweep_staged(tree)
        if swept:
            print(
                f"[box] swept {len(swept)} orphaned staged file(s) under {tree}",
                file=sys.stderr,
            )


def unboxed_executor(
    spec: BoxSpec = DEFAULT_SPEC, *, env: Mapping[str, str] | None = None,
) -> BoxExecutor:
    return BoxExecutor(
        spec=spec,
        transport=_HostTransport(dict(env) if env is not None else dict(os.environ)),
        name="",
    )
