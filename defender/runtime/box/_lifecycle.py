"""Start, stop, scrub — and the faults each step can raise.

The sentinel planting and mount checks live here because they are steps of starting a
box, not properties of one.
"""
from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from defender._io import sweep_staged, write_guarded
from defender._run_id import RUN_ID_ALLOWED, is_valid_run_id
from defender._run_paths import RUN_LAYOUT
from defender.runtime.box_codec import (
    BOX_ENV_ALLOWLIST,
    _BOX_MARK_ENV,
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
from ._spec import ALIAS_PROFILE_PATH, BoxExecutor, BoxRequest, BoxSpec, Mount
from ._alias import _probe_alias_ban
from ._docker import Create, DockerFn, START_TOKEN_LABEL, SharedMountsFn, _ALLOW_UNSANDBOXED, _LOCALE_ENV, _call, _covered, _daemon_source, _docker, _reap_on_fault, _reap_stale_before_create, _render_env, _shared_mounts, _uncovered_fault, container_name, infra_env, require_image, resolve_rootfs
from ._spec import DEFAULT_SPEC, _HostTransport
from ._spec import _DockerTransport

_logger = logging.getLogger(__name__)


#: Where the box sees its tenant's model-facing `agent/` half: a fixed target, so the model's
#: view never depends on where the operator keeps the tenants root. Read-only; the tenant's
#: `settings/` half is never mounted.
TENANT_AGENT_TARGET = Path("/tenant/agent")


def _create_argv(  # noqa: PLR0913 — the run's geography: its two trees plus its tenant's half
    name: str, run_dir: Path, defender_dir: Path, spec: BoxSpec,
    mounts: Sequence[tuple[Path, Path]] = (), start_token: str = "",
    *, tenant_agent: Path | None = None,
) -> Create:
    # The uncovered-mount refusal runs before the image resolver: a topology fault must not be
    # masked by the resolver's file-read refusal on the same tree.
    subjects = [
        ("run dir", run_dir, "Set DEFENDER_DATA_ROOT to a path"),
        ("defender dir", defender_dir, "Check out the tree"),
    ]
    if tenant_agent is not None:
        subjects.append(("tenant agent half", tenant_agent, "Put the tenants root"))
    for subject, path, remedy in subjects:
        if mounts and not _covered(path, mounts):
            raise _uncovered_fault(subject, path, mounts, remedy)
    # Resolved here, not at BoxSpec construction, which reads nothing off the tree.
    rootfs = resolve_rootfs(spec.rootfs, defender_dir)
    env_pairs = {**infra_env(defender_dir, run_dir), **_LOCALE_ENV, **_BOX_MARK_ENV}
    run_src = _daemon_source(run_dir, mounts)
    defender_src = _daemon_source(defender_dir, mounts)
    argv = [
        "docker", "run", "--detach", "--name", name,
        "--label", f"{START_TOKEN_LABEL}={start_token}",
        "--runtime", spec.runtime,
        "--network", "none",
        "--read-only",
        "--pull=never",
        "--security-opt", f"seccomp={ALIAS_PROFILE_PATH}",
        "--mount", f"type=bind,source={run_src},target={run_dir}",
        "--mount", f"type=bind,source={defender_src},target={defender_dir},readonly",
    ]
    if tenant_agent is not None:
        # Not sentinel-probed (a read-only bind cannot be planted into), so a wrong daemon
        # mapping of this mount goes unnoticed.
        argv += [
            "--mount",
            f"type=bind,source={_daemon_source(tenant_agent, mounts)},"
            f"target={TENANT_AGENT_TARGET},readonly",
        ]
    argv += [
        "--tmpfs", f"/tmp:rw,noexec,nosuid,mode=1777,size={spec.tmpfs_size}",
        "--workdir", str(run_dir),
    ]
    for key in BOX_ENV_ALLOWLIST:
        argv += ["--env", f"{key}={env_pairs[key]}"]
    argv += [rootfs.image, "sleep", "infinity"]
    return Create(argv, rootfs)


def _plant(sentinel: Path, token: str) -> None:
    """Host-side half of a sentinel probe. An unwritable source raises `BoxFault`, not a bare
    OSError that would escape start_box's fault handling."""
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
        # The run-dir tier leaves its sentinel as evidence the probe wrote; the per-mount tier
        # cleans up because its sources include live repo/worktree trees.
        if unlink_on_fault:
            sentinel.unlink(missing_ok=True)
        raise
    sentinel.unlink(missing_ok=True)


def _plant_sentinel(run_dir: Path, docker: DockerFn, name: str) -> None:
    _probe_sentinel(run_dir, run_dir, docker, name, RUN_LAYOUT.box_sentinel.name,
                    unlink_on_fault=False)


def _check_mount_sentinel(mount: Mount, docker: DockerFn, name: str) -> None:
    """Probe one mount: a host-planted token read back through the box proves the bind mapped
    the right tree (an absent source is already caught at create)."""
    _probe_sentinel(
        Path(mount.source), Path(mount.target), docker, name,
        f"{RUN_LAYOUT.box_sentinel.name}-{uuid.uuid4().hex}", unlink_on_fault=True,
    )


def _start_boxed(
    run_dir: Path, defender_dir: Path, spec: BoxSpec, docker: DockerFn,
    shared_mounts: SharedMountsFn = _shared_mounts, tenant_agent: Path | None = None,
) -> BoxExecutor:
    name = container_name(run_dir.name)
    try:
        _reap_stale_before_create(docker, name)
    except BoxFault as e:
        # Every startup fault path writes the did-not-run marker, so the tree never reads as
        # "not yet judged". This arm fires on any leaked container under a reused name.
        write_did_not_run(run_dir, f"box start refused before create: {e}")
        raise
    start_token = uuid.uuid4().hex
    create = _create_argv(
        name, run_dir, defender_dir, spec, shared_mounts(docker), start_token,
        tenant_agent=tenant_agent,
    )
    try:
        # Confirm the image before the create, so a missing image is its own refusal (with
        # the build remedy) rather than a create fault told apart by its text.
        require_image(docker, create.rootfs)
    except BoxFault as e:
        write_did_not_run(run_dir, f"box start refused before create: {e}")
        raise
    created = _call(docker, create.argv)
    if created.returncode != 0:
        # `docker run --detach` is create-then-start, so a failure at task start can leave a
        # `created` container behind; reap it if it carries our token. Marker and reap are
        # best-effort and must not replace the create's stderr.
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
        # The box is ours (create succeeded); the reap is best-effort so it cannot skip the
        # marker or replace `e`.
        _reap_on_fault(docker, name)
        write_did_not_run(
            run_dir, f"box startup faulted before the reap scan could run: {e}"
        )
        raise
    return BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name)


def _render_argv(
    request: BoxRequest, mounts: Sequence[tuple[Path, Path]] = (),
    start_token: str = "",
) -> Create:
    argv = [
        "docker", "run", "--detach", "--name", request.name,
        "--label", f"{START_TOKEN_LABEL}={start_token}",
        "--runtime", request.spec.runtime,
        "--network", "none",
        "--read-only",
        "--pull=never",
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
    # Resolved here, never at BoxRequest construction.
    rootfs = resolve_rootfs(request.spec.rootfs, Path(request.workdir) / "defender")
    argv += [rootfs.image, "sleep", "infinity"]
    return Create(argv, rootfs)


def _did_not_run_for_request(request: BoxRequest, reason: str) -> None:
    """The did-not-run marker for the request lane: one per writable mount source, since a
    tree needs a verdict exactly when the box could write it. Best-effort per tree."""
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
        # As in `_start_boxed`. A lane with no writable mount gets no marker.
        _did_not_run_for_request(request, f"box start refused before create: {e}")
        raise
    start_token = uuid.uuid4().hex
    create = _render_argv(request, shared_mounts(docker), start_token)
    try:
        require_image(docker, create.rootfs)
    except BoxFault as e:
        _did_not_run_for_request(request, f"box start refused before create: {e}")
        raise
    created = _call(docker, create.argv)
    if created.returncode != 0:
        # As in `_start_boxed`: reap a leftover `created` container only if it is ours.
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
        # The box is ours; best-effort reap, then mark (sentinels were already planted).
        _reap_on_fault(docker, request.name)
        _did_not_run_for_request(
            request, f"box startup faulted before the reap scan could run: {e}"
        )
        raise
    return BoxExecutor(
        spec=request.spec, transport=_DockerTransport(request.name, request.spec),
        name=request.name,
    )


def _probe_cwd_for_request(request: BoxRequest) -> Path:
    """Where the alias-ban probe acts: the first writable mount's target, else `/tmp`. The ban
    is a syscall filter, so either location is valid."""
    for m in request.mounts:
        if m.writable:
            return Path(m.target)
    return Path("/tmp")


def _opt_out_or_raise(fault: BoxFault) -> None:
    """Without `DEFENDER_ALLOW_UNSANDBOXED=1` a startup fault aborts; with it, the caller
    degrades to `unboxed_executor` after a warning carrying the fault verbatim (so remedies
    such as the image build command still reach the operator)."""
    if os.environ.get(_ALLOW_UNSANDBOXED) != "1":
        raise fault
    _logger.warning(
        f"{_ALLOW_UNSANDBOXED}=1 — running UNSANDBOXED. The bash lane "
        f"executes on the host with no filesystem or network boundary. The swallowed startup "
        f"fault: {fault}",
    )


def _host_fallback_env(request: BoxRequest) -> dict[str, str]:
    """Env for the unboxed opt-out: the host env minus provider keys, like
    `run_common.run_env`, not the container-shaped `_render_env` (no HOME, box-only PATH)."""
    from defender.runtime import providers

    env = dict(os.environ)
    for var in providers.api_key_vars():
        env.pop(var, None)
    env.update({k: v for k, v in request.env.items() if k in BOX_ENV_ALLOWLIST})
    defender_dir = Path(request.workdir) / "defender"
    env["DEFENDER_DIR"] = str(defender_dir)
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    # Prepended, keeping the operator's PYTHONPATH.
    inherited = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        f"{request.workdir}{os.pathsep}{inherited}" if inherited else str(request.workdir)
    )
    # A host lane never carries the in-box mark.
    env.pop("DEFENDER_BOX", None)
    return env


def start_box(
    run_dir_or_request: Path | BoxRequest, defender_dir: Path | None = None, *,
    spec: BoxSpec | None = None, docker: DockerFn = _docker, tenant_agent: Path | None = None,
) -> BoxExecutor:
    """Start the run's box. `tenant_agent` is the resolved tenant `agent/` half, bound
    read-only at `TENANT_AGENT_TARGET`; illegal with a `BoxRequest`, which carries its own
    mounts."""
    if isinstance(run_dir_or_request, BoxRequest):
        request = run_dir_or_request
        # `is not None`, not a comparison with the env-resolved DEFAULT_SPEC. The env is not
        # read on this path, so a typo'd DEFENDER_BOX_RUNTIME cannot raise here.
        if spec is not None:
            raise TypeError(
                "start_box(request, spec=…) is ambiguous — a BoxRequest carries its own spec; "
                "set it on the request (BoxRequest(..., spec=…)) instead of the call"
            )
        if tenant_agent is not None:
            raise TypeError(
                "start_box(request, tenant_agent=…) is ambiguous — a BoxRequest carries its "
                "own mounts; put the tenant's agent half in them instead of the call"
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
    # Default runtime is runsc; runc (weaker isolation) only when the operator sets
    # DEFENDER_BOX_RUNTIME=runc, never by fallback.
    if spec is None:
        # lint-default: ok — the env lever is this default's single source; `spec=` must stay
        # distinguishable from unset for the BoxRequest ambiguity check.
        spec = BoxSpec.from_env(os.environ)
    try:
        return _start_boxed(run_dir, defender_dir, spec, docker, tenant_agent=tenant_agent)
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

    Call it from a `finally`, with `in_flight` saying whether an exception is already
    propagating.

    - The scrub runs only once the box is provably dead; after a teardown fault it is skipped
      rather than raced against a live writer.
    - An in-flight exception outranks a teardown fault, which is logged rather than raised.
    - `RunTainted` outranks everything, including the work's own failure: a crashed run's
      tree is the one most likely to hold what the box planted.
    """
    box_down = False
    try:
        stop_box(box)
        box_down = True
    except BoxFault as e:
        # The scan cannot run either way, so mark before deciding whether to raise.
        write_did_not_run(tree, f"teardown faulted before the reap scan could run: {e}")
        if not in_flight:
            raise
        _logger.error(
            f"teardown failed under an in-flight failure: {e} — the box may "
            f"be leaked, and {tree} was NOT scrubbed (the walk needs a provably dead box).",
        )
    if box_down:
        scrub_tree(tree)
        # Crash-orphaned staged files are never overwritten by name, so sweep them. Only after
        # the walk (which must see them); a tainted tree never gets here.
        swept = sweep_staged(tree)
        if swept:
            _logger.info(
                f"swept {len(swept)} orphaned staged file(s) under {tree}",
            )


def unboxed_executor(
    spec: BoxSpec = DEFAULT_SPEC, *, env: Mapping[str, str] | None = None,
) -> BoxExecutor:
    return BoxExecutor(
        spec=spec,
        transport=_HostTransport(dict(env) if env is not None else dict(os.environ)),
        name="",
    )
