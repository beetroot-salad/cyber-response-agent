"""Start, stop, scrub — and the faults each step can raise.

The sentinel planting and mount checks live here because they are steps of starting a
box, not properties of one.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import logging
import os
import stat
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any
from pathlib import Path

from defender._io import bind, read_text_utf8, READ_LIMIT, stat_entries, sweep_staged, write_guarded
from defender._run_id import RUN_ID_ALLOWED, is_valid_run_id
from defender._tenant import TenantId, TenantRefused, parse_tenant_id_bytes, read_tenant_id_file
from defender.run_repository import RUN_LAYOUT
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
    mark_unsandboxed,
    write_did_not_run,
)
from ._spec import ALIAS_PROFILE_PATH, CODE_CHECK_FILE, BoxExecutor, BoxRequest, BoxSpec, Mount
from ._alias import _probe_alias_ban
from ._docker import Create, DockerFn, START_TOKEN_LABEL, SharedMountsFn, _ALLOW_UNSANDBOXED, _LOCALE_ENV, _call, _covered, _inspect_field, _daemon_source, _docker, _reap_on_fault, _reap_stale_before_create, _remove_container, _render_env, _shared_mounts, _uncovered_fault, container_name, infra_env, require_image, resolve_rootfs
from ._spec import DEFAULT_SPEC, _HostTransport
from ._spec import _DockerTransport

_logger = logging.getLogger(__name__)


#: The `docker run` flags every box starts with (#1188). `fsize`: no process in the box can make
#: a file, sparse or real, larger than a host whole-file read takes in (`_io.READ_LIMIT`, bytes,
#: soft = hard; the box holds no `CAP_SYS_RESOURCE` to raise it). `core=0`: the kernel kills an
#: over-limit writer with SIGXFSZ, whose default action dumps core into the writer's cwd, which
#: is a run dir or a drain's writable tree.
_BOX_ULIMITS: tuple[str, ...] = (
    "--ulimit", f"fsize={READ_LIMIT}:{READ_LIMIT}",
    "--ulimit", "core=0:0",
)


def _input_dir_source(run_dir: Path) -> Path:
    """The run's input directory (the alert and its record), checked to be a real, populated
    directory before it is bound read-only over the writable run folder. A missing, empty or
    non-directory source, or a link at its name, is a `BoxFault` naming the directory: a bind
    source that is not that directory would hand the box a tree the host did not set up, and
    there is no fallback to a writable bind."""
    where = Path(run_dir) / RUN_LAYOUT.alert_input_dir
    try:
        mode = where.lstat().st_mode
        populated = stat.S_ISDIR(mode) and any(where.iterdir())
    except OSError:
        populated = False
    if not populated:
        raise BoxFault(
            f"the run's input directory {RUN_LAYOUT.alert_input_dir} is missing, empty, not a "
            "directory, or a link — the box is not started over it")
    return where


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
        # The agent half lives under the data root, beside the run dir: moving it means moving
        # the data root.
        subjects.append(("tenant agent half", tenant_agent, "Set DEFENDER_DATA_ROOT to a path"))
    for subject, path, remedy in subjects:
        if mounts and not _covered(path, mounts):
            raise _uncovered_fault(subject, path, mounts, remedy)
    # Resolved here, not at BoxSpec construction, which reads nothing off the tree.
    rootfs = resolve_rootfs(spec.rootfs, defender_dir)
    env_pairs = {**infra_env(defender_dir, run_dir), **_LOCALE_ENV, **_BOX_MARK_ENV}
    if tenant_agent is not None:
        env_pairs["DEFENDER_AGENT_DIR"] = str(tenant_agent)
    run_src = _daemon_source(run_dir, mounts)
    input_dir = _input_dir_source(run_dir)
    defender_src = _daemon_source(defender_dir, mounts)
    argv = [
        "docker", "run", "--detach", "--name", name,
        "--label", f"{START_TOKEN_LABEL}={start_token}",
        "--runtime", spec.runtime,
        "--network", "none",
        "--read-only",
        "--pull=never",
        "--security-opt", f"seccomp={ALIAS_PROFILE_PATH}",
        *_BOX_ULIMITS,
        "--mount", f"type=bind,source={run_src},target={run_dir}",
        # Over the writable run folder, a directory of its own: a file bind is undone by a host
        # rename, a directory bind is not (#1222 A1).
        "--mount", f"type=bind,source={_daemon_source(input_dir, mounts)},target={input_dir},readonly",
        "--mount", f"type=bind,source={defender_src},target={defender_dir},readonly",
    ]
    if tenant_agent is not None:
        # Never plant a sentinel here: it would dirty the tenant clone. Its existing
        # identity marker is read back through the box before the executor is returned.
        argv += [
            "--mount",
            f"type=bind,source={_daemon_source(tenant_agent, mounts)},"
            f"target={tenant_agent},readonly",
        ]
    argv += [
        "--tmpfs", f"/tmp:rw,noexec,nosuid,mode=1777,size={spec.tmpfs_size}",
        "--workdir", str(run_dir),
    ]
    for key in BOX_ENV_ALLOWLIST:
        if key in env_pairs:
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
    *, unlink_on_fault: bool, exact: bool = False,
) -> None:
    """Plant a fresh random token at `source / sentinel_name`, read it back through the box at
    `target`, and remove it. The answer is compared after trimming surrounding whitespace, or,
    when `exact`, byte for byte (a staged copy's token: no prefix, suffix or padding passes)."""
    token = uuid.uuid4().hex
    sentinel = source / sentinel_name
    _plant(sentinel, token)
    try:
        proc = _call(docker, ["docker", "exec", name, "cat", str(target / sentinel_name)])
        answer = proc.stdout or ""
        if proc.returncode != 0 or (answer if exact else answer.strip()) != token:
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


def _data_probe_file(source: Path) -> Path | None:
    """A `data` mount's read-back file: its first regular file by name, or `None` for an empty
    folder, which #665 Decision 9 permits (its host inode is the non-absence evidence)."""
    try:
        info = source.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise BoxFault(f"read-only mount source is not a real directory: {source}")
        entries = sorted(source.iterdir(), key=lambda entry: entry.name)
        if not entries:
            _logger.debug("empty read-only mount source %s: device=%s inode=%s",
                          source, info.st_dev, info.st_ino)
            return None
        for entry in entries:
            if stat.S_ISREG(entry.lstat().st_mode):
                return Path(entry.name)
    except OSError as e:
        raise BoxFault(f"could not read mount probe source {source}: {e}") from e
    raise BoxFault(f"read-only mount has no regular file for its readback probe: {source}")


def _readonly_probe_file(mount: Mount, code_dir: Path | None) -> Path | None:
    """The file a read-only mount is checked by, relative to both its source and its target,
    chosen by the kind the mount declares (#1108 D7) and never by its name or path. `None`
    only for an empty `data` mount. A mount that declares no kind is refused."""
    if mount.kind == "code":
        target = Path(mount.target)
        if code_dir is None:
            raise BoxFault(f"the read-only code mount at {target} was checked without the "
                           "request's code root — the box's code could not be checked")
        # By path components, not a string prefix, and with no `..` climbing back out: the
        # check file is read at the same relative path on the host source and in the box.
        if not code_dir.is_relative_to(target) or ".." in code_dir.relative_to(target).parts:
            raise BoxFault(
                f"the code root {code_dir} does not lie inside the read-only code mount at "
                f"{target} — the box's code could not be checked"
            )
        return code_dir.relative_to(target) / CODE_CHECK_FILE
    if mount.kind == "data":
        return _data_probe_file(Path(mount.source))
    raise BoxFault(
        f"read-only mount {mount.source} declares no kind (code, data or staged) — box start "
        f"cannot tell how to check it (got {mount.kind!r})"
    )


#: What a host-made copy's root may hold besides the token a start plants there (#1108
#: amendment 2): its `agent/` half always, and a run copy's `settings/` half. Each must be a real
#: folder; anything else (a stray file, a `.git`, a link) means the bind is not the copy the host
#: made for this start.
_STAGED_HALVES = frozenset({"agent", "settings"})


def _check_staged_root(mount: Mount, docker: DockerFn, name: str) -> None:
    """A `staged` mount is the root of a copy the host made (a drain's draft, a run's
    knowledge): it holds exactly `agent/` (a real folder), at most a `settings/` beside it, and
    nothing else, judged on the host without following any entry (so no earlier start's token
    remains). Then a fresh random token is planted at the root, outside `agent/`, read back
    through the box byte for byte, and removed, so a box bound to another copy, or to an empty
    or stale folder, refuses before any workload runs. The
    copy's `agent/` is never written and `.tenant-id` is never a probe: identity was checked
    once, when the copy's commit was published."""
    source = Path(mount.source)
    with bind(source) as root:
        listed = stat_entries(root)
    if listed.stats is None:
        raise BoxFault(f"could not list the staged copy's root {source}: "
                       f"{listed.refusal or 'it is absent'}")
    halves = {entry: st for entry, st in listed.stats.items() if entry in _STAGED_HALVES}
    strays = sorted(set(listed.stats) - set(halves))
    if "agent" not in halves or strays or not all(stat.S_ISDIR(st.st_mode) for st in halves.values()):
        raise BoxFault(
            f"the staged copy's root {source} must hold exactly a real agent/ folder (and a run "
            f"copy's settings/); it holds {sorted(listed.stats)} — not the copy made for this start"
        )
    _probe_sentinel(
        source, Path(mount.target), docker, name,
        f"{RUN_LAYOUT.box_sentinel.name}-{uuid.uuid4().hex}", unlink_on_fault=True, exact=True,
    )


def _check_mount_sentinel(
    mount: Mount, docker: DockerFn, name: str, *, code_dir: Path | None = None,
) -> None:
    """Check one mount through the started box. A writable source gets a planted sentinel. A
    read-only source is never written: an existing file, chosen by the mount's kind, is read
    back through the box and compared with the host's own read of it, line endings
    normalized on both sides and exact otherwise. `code_dir` is the request's code root,
    which a `code` mount must contain. A `staged` mount, a host-made copy's root, gets a token
    planted at its root for this start (`_check_staged_root`). A writable mount declares no
    kind: a writable `staged` mount, or any writable mount with a kind, is refused."""
    if mount.writable and mount.kind is not None:
        raise BoxFault(
            f"the writable mount {mount.source} declares the kind {mount.kind!r} — a writable "
            "mount is checked by its planted sentinel and declares none (a staged copy's root "
            "is never writable)"
        )
    if mount.kind == "staged":
        _check_staged_root(mount, docker, name)
        return
    if not mount.writable:
        source = Path(mount.source)
        relative = _readonly_probe_file(mount, code_dir)
        if relative is None:
            return
        try:
            if not stat.S_ISREG((source / relative).lstat().st_mode):
                raise BoxFault(f"mount readback probe is not a regular file: {source / relative}")
            expected = read_text_utf8(source / relative)
            proc = _call(docker, ["docker", "exec", name, "cat", str(Path(mount.target) / relative)])
        except (OSError, UnicodeError) as e:
            raise BoxFault(f"could not read mount probe at {source / relative}: {e}") from e
        # Known limit: the box answers over Docker's text channel, which translates line
        # endings, so both sides are compared with universal newlines (the host read applies
        # them; the answer is put through the same translation) and a CR-only difference is
        # invisible. Every other difference, a trailing newline or whitespace included,
        # refuses; catching a wrong mapping does not depend on line endings.
        if proc.returncode != 0 or _universal_newlines(proc.stdout) != expected:
            raise BoxFault(f"could not read back the startup sentinel at {source / relative} — "
                           "the mount probe does not match the host")
        return
    _probe_sentinel(
        Path(mount.source), Path(mount.target), docker, name,
        f"{RUN_LAYOUT.box_sentinel.name}-{uuid.uuid4().hex}", unlink_on_fault=True,
    )


def _universal_newlines(text: object) -> str | None:
    """`text` with CRLF and lone CR read as LF, as a text-mode subprocess reads its output;
    `None` for anything that is not text, which then matches no host read."""
    return text.replace("\r\n", "\n").replace("\r", "\n") if isinstance(text, str) else None


def _refuse_a_second_code_mount(request: BoxRequest) -> None:
    """A request has one code root, so it declares at most one `code` mount (#1108 D7)."""
    code_targets = [str(m.target) for m in request.mounts if m.kind == "code"]
    if len(code_targets) > 1:
        raise BoxFault(
            f"the box request {request.name} declares {len(code_targets)} code mounts "
            f"({', '.join(code_targets)}) — a request declares at most one"
        )


def _check_tenant_identity(path: Path, expected: TenantId, docker: DockerFn, name: str) -> None:
    """Read bounded marker bytes through the bind, then judge them with their sole parser.

    Base64 preserves raw CR and invalid UTF-8 across Docker's text-mode boundary.
    The in-box reader shares the owner's nonblocking, no-follow, regular-file checks.
    """
    command = (
        "import base64, sys; from pathlib import Path; "
        "from defender._tenant import read_tenant_id_bytes; "
        "print(base64.b64encode(read_tenant_id_bytes(Path(sys.argv[1]))).decode('ascii'))"
    )
    proc = _call(docker, ["docker", "exec", name, "python3", "-c", command, str(path)])
    if proc.returncode != 0:
        raise BoxFault(f"could not read tenant identity {path}: {(proc.stderr or '').strip()}")
    try:
        data = base64.b64decode((proc.stdout or "").removesuffix("\n"), validate=True)
        found = parse_tenant_id_bytes(data, path)
    except (ValueError, binascii.Error, TenantRefused) as error:
        raise BoxFault(f"{path}: {error}") from error
    _require_tenant_identity(path, found, expected)


def _require_tenant_identity(path: Path, found: str, expected: TenantId) -> None:
    if found != expected:
        raise BoxFault(f"{path} names tenant {found!r}; expected tenant {expected!r}")


def _start_boxed(
    run_dir: Path, defender_dir: Path, spec: BoxSpec, docker: DockerFn,
    shared_mounts: SharedMountsFn = _shared_mounts, tenant_agent: Path | None = None,
    write_verdict: Callable[[dict], None] | None = None,
    tenant_id: TenantId | None = None,
) -> BoxExecutor:
    name = container_name(run_dir.name)
    try:
        _reap_stale_before_create(docker, name)
    except BoxFault as e:
        # Every startup fault path writes the did-not-run marker, so the tree never reads as
        # "not yet judged". This arm fires on any leaked container under a reused name.
        write_did_not_run(run_dir, f"box start refused before create: {e}", write_verdict=write_verdict)
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
        write_did_not_run(run_dir, f"box start refused before create: {e}", write_verdict=write_verdict)
        raise
    created = _call(docker, create.argv)
    if created.returncode != 0:
        # `docker run --detach` is create-then-start, so a failure at task start can leave a
        # `created` container behind; reap it if it carries our token. Marker and reap are
        # best-effort and must not replace the create's stderr.
        write_did_not_run(
            run_dir, f"box create faulted before the box was startable: "
                     f"{(created.stderr or '').strip()}", write_verdict=write_verdict
        )
        _reap_on_fault(docker, name, owned_token=start_token)
        raise BoxFault(
            f"could not create the box {name}: {(created.stderr or '').strip()}"
        )
    try:
        _plant_sentinel(run_dir, docker, name)
        if tenant_agent is not None:
            assert tenant_id is not None
            _check_tenant_identity(tenant_agent / ".tenant-id", tenant_id, docker, name)
        _probe_alias_ban(docker, name, run_dir, spec.runtime)
    except BaseException as e:
        # The box is ours (create succeeded); the reap is best-effort so it cannot skip the
        # marker or replace `e`.
        _reap_on_fault(docker, name)
        write_did_not_run(
            run_dir, f"box startup faulted before the reap scan could run: {e}",
            write_verdict=write_verdict
        )
        raise
    return BoxExecutor(
        spec=spec, transport=_DockerTransport(name, spec), name=name, docker=docker,
    )


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
        *_BOX_ULIMITS,
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
    env = _render_env(request.env, Path(request.workdir), defender_dir=request.code_dir)
    for key in sorted(env):
        argv += ["--env", f"{key}={env[key]}"]
    # Resolved here, never at BoxRequest construction.
    rootfs = resolve_rootfs(request.spec.rootfs, request.code_dir)
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
        # Each read-only mount is checked by the kind it declares; a second code mount, or a
        # read-only mount with no kind, is refused here, after create, so the container is
        # reaped and the trees marked like any other startup fault.
        _refuse_a_second_code_mount(request)
        for m in request.mounts:
            _check_mount_sentinel(m, docker, request.name, code_dir=request.code_dir)
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
        name=request.name, docker=docker,
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
    env.pop("DEFENDER_AGENT_DIR", None)
    for var in providers.api_key_vars():
        env.pop(var, None)
    env.update({k: v for k, v in request.env.items() if k in BOX_ENV_ALLOWLIST})
    defender_dir = request.code_dir
    env["DEFENDER_DIR"] = str(defender_dir)
    env["PATH"] = f"{defender_dir / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    # Prepended, keeping the operator's PYTHONPATH.
    inherited = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        f"{defender_dir.parent}{os.pathsep}{inherited}" if inherited else str(defender_dir.parent)
    )
    # A host lane never carries the in-box mark.
    env.pop("DEFENDER_BOX", None)
    return env


def start_box(
    run_dir_or_request: Path | BoxRequest, defender_dir: Path | None = None, *,
    spec: BoxSpec | None = None, docker: DockerFn = _docker, tenant_agent: Path | None = None,
    write_verdict: Callable[[dict], None] | None = None,
    tenant_id: TenantId | None = None,
) -> BoxExecutor:
    """Start the run's box. `tenant_agent` is the resolved tenant `agent/` half, bound
    read-only at that same path. `tenant_id` is the accepted identity, not a reread of
    the host marker. Direct callers without an accepted record capture it before create.
    Both tenant arguments are illegal with a `BoxRequest`, which carries its own mounts."""
    if isinstance(run_dir_or_request, BoxRequest):
        request = run_dir_or_request
        # `is not None`, not a comparison with the env-resolved DEFAULT_SPEC. The env is not
        # read on this path, so a typo'd DEFENDER_BOX_RUNTIME cannot raise here.
        if spec is not None:
            raise TypeError(
                "start_box(request, spec=…) is ambiguous — a BoxRequest carries its own spec; "
                "set it on the request (BoxRequest(..., spec=…)) instead of the call"
            )
        if tenant_agent is not None or tenant_id is not None:
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
            if request.require_sandbox:
                raise
            _opt_out_or_raise(e)
        return unboxed_executor(request.spec, env=_host_fallback_env(request))

    return _start_run_box(run_dir_or_request, defender_dir, spec, docker, tenant_agent, tenant_id,
                          write_verdict)


def _start_run_box(
    run_dir: Path, defender_dir: Path | None, spec: BoxSpec | None, docker: DockerFn,
    tenant_agent: Path | None, tenant_id: TenantId | None,
    write_verdict: Callable[[dict], None] | None,
) -> BoxExecutor:
    if defender_dir is None:
        raise TypeError("start_box(run_dir, defender_dir, ...) needs defender_dir")
    # Default runtime is runsc; runc (weaker isolation) only when the operator sets
    # DEFENDER_BOX_RUNTIME=runc, never by fallback.
    if spec is None:
        # lint-default: ok — the env lever is this default's single source; `spec=` must stay
        # distinguishable from unset for the BoxRequest ambiguity check.
        spec = BoxSpec.from_env(os.environ)
    if tenant_agent is None and tenant_id is not None:
        raise TypeError("tenant_id needs tenant_agent")
    if tenant_agent is not None and tenant_id is None:
        tenant_id = read_tenant_id_file(tenant_agent / ".tenant-id")
    try:
        return _start_boxed(run_dir, defender_dir, spec, docker,
                            tenant_agent=tenant_agent, tenant_id=tenant_id,
                            write_verdict=write_verdict)
    except BoxFault as e:
        _opt_out_or_raise(e)
    from defender import run_common
    if tenant_agent is not None:
        assert tenant_id is not None
        path = tenant_agent / ".tenant-id"
        _require_tenant_identity(path, read_tenant_id_file(path), tenant_id)
    return unboxed_executor(
        spec, env=run_common.run_env(defender_dir, run_dir, tenant_agent=tenant_agent))


def stop_box(box: BoxExecutor, *, docker: DockerFn | None = None) -> None:
    """Remove the box's container. Through `docker` when one is given, else through the docker
    the box was created with (#1195), so the whole lifecycle reaches one daemon."""
    if not box.name:
        return
    reason = _remove_container(docker or _carried_docker(box), box.name)
    if reason is not None:
        raise BoxFault(f"could not tear down the box {box.name}: {reason}")


def _carried_docker(box: object) -> DockerFn:
    """The docker a sandboxed box was created with; the real one for the unsandboxed fallback.
    A sandboxed box that carries none is a `BoxFault`, never a silent fall back to a daemon it
    was not created through."""
    if not getattr(box, "sandboxed", False):
        return _docker
    docker = getattr(box, "docker", None)
    if docker is None:
        raise BoxFault(
            f"the sandboxed box {getattr(box, 'name', '')!r} carries no docker to manage it through"
        )
    return docker


#: The states a stopped box may be in: nothing runs in either (main's `_FROZEN_STATES`, less
#: `paused`, which no run leaves).
_STOPPED_STATES = frozenset({"exited", "dead"})


class BoxRuns:
    """The lanes' handle on the batch's box (#1195): the box is reachable only inside `.run()`,
    one agent run's window, so no spawn can run in it outside one and none can forget to.

    The box is stopped between runs. `.run()` refuses to start it unless it is proven stopped
    (`docker start` on a running box succeeds and does nothing), starts it, proves it running,
    yields it, and stops it on every exit; a stop that can't be proven wins over whatever the
    run raised, since the host's next step must not run beside the box. Every call goes through
    the docker the box was created with. The unsandboxed fallback's handle makes no docker
    call."""

    def __init__(self, box: object) -> None:
        sandboxed = getattr(box, "sandboxed", None)
        if sandboxed is None:
            raise BoxFault(f"cannot tell whether {box!r} is a sandboxed box; refusing to run beside it")
        self._name = str(getattr(box, "name", "") or "")
        if sandboxed and not self._name:
            raise BoxFault(f"the sandboxed box {box!r} names no container")
        self._box: Any = box
        self._docker: DockerFn | None = _carried_docker(box) if sandboxed else None

    def _status(self) -> str | None:
        assert self._docker is not None
        return _inspect_field(self._docker, self._name, "{{.State.Status}}")

    def stop(self) -> None:
        """Stop the box, proven: `docker stop -t 0` kills every process in it, an agent's
        leftovers included, and the box must then report `exited` or `dead`, else `BoxFault`."""
        if self._docker is None:
            return
        name = self._name
        proc = _call(self._docker, ["docker", "stop", "-t", "0", name])
        status = self._status()
        if status not in _STOPPED_STATES:
            raise BoxFault(
                f"could not stop the box {name} (stop rc={proc.returncode}: "
                f"{(proc.stderr or '').strip()}; status {status!r})"
            )

    @contextlib.contextmanager
    def run(self) -> Iterator[BoxExecutor]:
        """One agent run's window on the box."""
        if self._docker is None:
            yield self._box
            return
        name = self._name
        try:
            status = self._status()
            if status != "exited":
                raise BoxFault(
                    f"refusing to start the box {name} for an agent run: its status is "
                    f"{status!r}, not 'exited'"
                )
            proc = _call(self._docker, ["docker", "start", name])
            status = self._status()
            if status != "running":
                raise BoxFault(
                    f"could not start the box {name} (start rc={proc.returncode}: "
                    f"{(proc.stderr or '').strip()}; status {status!r})"
                )
        except BaseException:
            # Best-effort, before the refusal unwinds through host steps.
            with contextlib.suppress(BoxFault):
                self.stop()
            raise
        try:
            yield self._box
        except BaseException:
            # A stop that can't be proven wins: raised from here, it carries the run's own
            # exception as its context.
            self.stop()
            raise
        else:
            self.stop()


@contextlib.contextmanager
def box_for_run(runs: BoxRuns | None) -> Iterator[BoxExecutor | None]:
    """The spawn sites' `with`: one agent run's window on the batch's box, or no box when there
    is none. Anything but a `BoxRuns` is refused, so a spawn can't be handed the box itself."""
    if runs is None:
        yield None
        return
    if not isinstance(runs, BoxRuns):
        raise BoxFault(f"{runs!r} is not a run handle on a box; refusing to run beside it")
    with runs.run() as box:
        yield box


def stop_and_scrub(
    box: BoxExecutor,
    tree: Path,
    *,
    stop_box: Callable[..., None],
    scrub_tree: Callable[[Path], None],
    in_flight: bool,
    read_verdict: Callable[[], str | None] | None = None,
    write_verdict: Callable[[dict], None] | None = None,
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
        write_did_not_run(tree, f"teardown faulted before the reap scan could run: {e}",
                          write_verdict=write_verdict)
        if not in_flight:
            raise
        _logger.error(
            f"teardown failed under an in-flight failure: {e} — the box may "
            f"be leaked, and {tree} was NOT scrubbed (the walk needs a provably dead box).",
        )
    if box_down:
        try:
            scrub_tree(tree)
        finally:
            if not getattr(box, "sandboxed", True):
                mark_unsandboxed(tree, read_verdict=read_verdict, write_verdict=write_verdict)
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
