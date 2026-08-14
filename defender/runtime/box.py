
from __future__ import annotations

import os
import re
import subprocess
import sys
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Protocol

from defender._io import read_text_soft, sweep_staged, write_guarded
from defender._run_id import RUN_ID_ALLOWED, is_valid_run_id
from defender.runtime import bash_exec
from defender.runtime.box_codec import (
    REQUEST_MAGIC,  # noqa: F401 — re-exported: test_540_exec_seam.py imports it as `box.REQUEST_MAGIC`
    RESPONSE_MAGIC,  # noqa: F401 — re-exported: test_540_exec_seam.py imports it as `box.RESPONSE_MAGIC`
    BoxFault,
    BoxResult,
    RawExec,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)
from defender.runtime.scrub import (  # noqa: F401 — re-exported: run.py/drains.py/tests import `box.scrub`, `box.RunTainted`
    Finding,
    RunTainted,
    scrub,
    verdict_path,
    write_did_not_run,
)


@dataclass(frozen=True)
class BoxSpec:

    runtime: str = "runsc"
    rootfs: str = "python:3.11-slim"
    lifecycle: str = "per_run"
    tmpfs_size: str = "64m"

    ENV_VAR: ClassVar[str] = "DEFENDER_BOX_RUNTIME"
    RUNTIMES: ClassVar[tuple[str, ...]] = ("runsc", "runc")

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> BoxSpec:
        raw = environ.get(cls.ENV_VAR)
        if not raw:
            return cls()
        if raw not in cls.RUNTIMES:
            raise ValueError(
                f"{cls.ENV_VAR}={raw!r} is not a known box runtime "
                f"(expected one of {', '.join(cls.RUNTIMES)})"
            )
        return cls(runtime=raw)




@dataclass(frozen=True)
class Mount:

    source: Path
    target: Path
    writable: bool = False


@dataclass(frozen=True)
class BoxRequest:

    name: str
    mounts: tuple[Mount, ...] = ()
    workdir: Path = Path(".")
    env: dict[str, str] = field(default_factory=dict)
    # Same lever as start_box's run_dir path (F1): unset anchors to the dataclass default,
    # runsc. A request carries its own spec, so resolving it anywhere but here would leave
    # the BoxRequest callers — the learning run-cycle and the curator drains — pinned to
    # runsc with the env var silently ignored.
    spec: BoxSpec = field(default_factory=lambda: BoxSpec.from_env(os.environ))


class Transport(Protocol):

    def __call__(self, frame: bytes, /, *, cwd: Path, timeout: float) -> RawExec: ...


def _unattached(_frame: bytes, *, cwd: Path, timeout: float) -> RawExec:  # noqa: ARG001
    raise BoxFault(
        "this box has no container attached — the run was never started through start_box"
    )


@dataclass
class BoxExecutor:

    spec: BoxSpec = field(default_factory=BoxSpec)
    transport: Transport = _unattached
    name: str = ""

    @property
    def sandboxed(self) -> bool:
        # Derived from the transport (M5/O5), never independently settable: only a
        # transport that actually confines a process may claim the boundary.
        return isinstance(self.transport, _DockerTransport)

    def run_parsed(
        self, pipelines: Sequence[bash_exec.Pipeline], *,
        command: str, cwd: Path, timeout: float,
    ) -> BoxResult:
        frame = encode_request(pipelines)
        try:
            raw = self.transport(frame, cwd=cwd, timeout=timeout)
        except BoxFault:
            raise
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            raise BoxFault(f"the box was unreachable while running {command!r}: {e}") from e
        try:
            return decode_response(raw.stdout)
        except BoxFault as e:
            raise BoxFault(f"{e}: {_text(raw.stderr).strip()}") from None

    run = run_parsed


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")



BOX_ENV_ALLOWLIST: tuple[str, ...] = (
    "DEFENDER_DIR",
    "DEFENDER_RUN_DIR",
    "DEFENDER_RUNS_BASE",
    "PATH",
    "PYTHONPATH",
    "LANG",
    "TZ",
)

DEFAULT_SPEC = BoxSpec()

#: M1 — the alias-ban seccomp profile, resolved ONCE so every box lane (the investigation
#: builder and the generic request builder alike, C8-new) attaches the identical value. Denies
#: exactly the six shapes `BANNED_SHAPES` in _spec771.py names; ships under `runtime/` so it
#: sits outside every box's writable mount, including the drain lane's repo-relative checkout
#: (the same reason the CI workflow and the write lint's baseline live outside a triggered
#: corpus — a box that could rewrite the file it is banned by would leave the NEXT box unbanned).
ALIAS_PROFILE_PATH: Path = Path(__file__).resolve().parent / "seccomp" / "alias-deny.json"

BANNED_SHAPES: tuple[str, ...] = ("symlink", "symlinkat", "link", "linkat", "mknod", "mknodat")

_OCI_SECCOMP_FLAG = "--oci-seccomp"
_RUNSC_INSTALL_CMD = "runsc install -- --oci-seccomp"


class AliasBanNotInForce(Exception):
    """§7 D5 — the ban-not-in-force fault, its OWN exception type rather than `BoxFault`.

    F4's not-opt-out-able decision is only enforceable if this fault cannot be caught by the
    broad `except BoxFault: degrade` handler every other startup fault survives through — so
    this deliberately does NOT subclass `BoxFault`, and `BoxFault` does not subclass this."""


def _alias_ban_fault_message(runtime: str, detail: str) -> str:
    detail = (detail or "").strip()
    if runtime == "runsc":
        remedy = (
            f"register the runsc runtime with {_OCI_SECCOMP_FLAG} — run "
            f"`{_RUNSC_INSTALL_CMD}` (writes runtimeArgs: [\"{_OCI_SECCOMP_FLAG}\"] into the "
            "daemon's runsc entry) and restart the docker daemon"
        )
    else:
        remedy = (
            f"the {runtime} runtime is not enforcing the alias-deny seccomp profile attached "
            f"at container creation — check that docker is actually invoking {runtime}"
        )
    message = f"the alias ban is not in force under the {runtime} box runtime: {remedy}."
    if detail:
        message += f" probe reported: {detail}"
    return message


#: The probe's own I/O failed, so nothing it observed about the ban means anything. Distinct
#: from "a banned shape was allowed" because the two demand OPPOSITE operator actions, and the
#: probe is the only thing that can tell them apart — by the time the host reads an exit code
#: they look identical. Both still fail closed (see `_probe_alias_ban`).
_CONTROL_FAILED_MARKER = "alias-probe: CONTROL-FAILED: "


def _alias_probe_inconclusive_message(cwd: Path, detail: str) -> str:
    detail = (detail or "").strip()
    message = (
        f"the alias ban could not be OBSERVED inside the box: the probe's own control "
        f"operations failed under {cwd}, so nothing it saw about the six banned shapes is "
        f"evidence either way. This is the box's writable mount — full, read-only, or not "
        f"there — and not the seccomp registration; check {cwd} inside the container."
    )
    if detail:
        message += f" probe reported: {detail}"
    return message


def _alias_probe_script(name_prefix: str) -> str:
    """One probe body, attempting each of the six banned shapes plus one ordinary create, all
    under a name no later write will ever collide with (`{name_prefix}` carries a random
    suffix — the probe's own leavings are swept regardless of which arm it takes). Reports
    success/failure the way `AliasProbeDocker.ProbeVerdict.as_completed` fakes it: rc 0 and a
    stdout line on total denial + a working control, rc 1 and a stderr line naming what was
    allowed (or that a control operation itself failed) otherwise — so the SAME reader
    classifies both the fake and a real box's output.

    EVERY file operation the probe performs on its own behalf is guarded, and a failure in one
    ABANDONS the observation rather than folding into it. Two reasons, and the second is the
    load-bearing one: an unguarded `open` for the hard-link source turned a full or read-only
    mount into a traceback the host could only read as "the ban is not in force" (an
    un-opt-out-able fault whose remedy text sent the operator at the seccomp registration) —
    and worse, had the link attempts run anyway, a MISSING source would have made `os.link`
    fail with `ENOENT` and be counted as DENIED, reporting a clean ban that was never tested."""
    return f'''
import os, stat, sys

prefix = {name_prefix!r}
allowed = []
control_error = None

def attempt(shape, fn):
    try:
        fn()
        allowed.append(shape)
    except OSError:
        pass

def control(what, fn):
    global control_error
    if control_error is not None:
        return False
    try:
        fn()
        return True
    except OSError as e:
        control_error = what + ": " + repr(e)
        return False

def probe():
    dfd = os.open(".", os.O_RDONLY)
    try:
        attempt("symlink", lambda: os.symlink("t", prefix + "-symlink"))
        attempt("symlinkat", lambda: os.symlink("t", prefix + "-symlinkat", dir_fd=dfd))
        if control("the hard-link probe's source file could not be created", write_src):
            attempt("link", lambda: os.link(prefix + "-src", prefix + "-link"))
            attempt("linkat", lambda: os.link(prefix + "-src", prefix + "-linkat", dst_dir_fd=dfd))
        attempt("mknod", lambda: os.mknod(prefix + "-mknod", mode=stat.S_IFIFO | 0o600))
        attempt("mknodat", lambda: os.mknod(prefix + "-mknodat", mode=stat.S_IFIFO | 0o600, dir_fd=dfd))
    finally:
        os.close(dfd)

def write_src():
    with open(prefix + "-src", "w") as fh:
        fh.write("x")

def write_create():
    with open(prefix + "-create", "w") as fh:
        fh.write("x")

control("the probe could not open its working directory", probe)
control("an ordinary create did not succeed", write_create)

for suffix in ("-symlink", "-symlinkat", "-link", "-linkat", "-mknod", "-mknodat", "-src", "-create"):
    try:
        os.remove(prefix + suffix)
    except OSError:
        pass

if control_error is not None:
    sys.stderr.write({_CONTROL_FAILED_MARKER!r} + control_error + "\\n")
    sys.exit(1)
if allowed:
    sys.stderr.write("alias-probe: " + " ".join(s + " was ALLOWED" for s in allowed) + "\\n")
    sys.exit(1)
sys.stdout.write("alias-probe: all banned shapes denied; ordinary create ok\\n")
sys.exit(0)
'''


def _alias_probe_argv(name: str, cwd: Path) -> list[str]:
    prefix = f".alias-probe-{uuid.uuid4().hex}"
    return [
        "docker", "exec", "-w", str(cwd), name, "python3", "-c", _alias_probe_script(prefix),
    ]


def _probe_alias_ban(docker: DockerFn, name: str, cwd: Path, runtime: str) -> None:
    """M2 — the startup positive control (O2, O3). Observes the ban's EFFECT at every box
    start rather than trusting the runtime's configuration (C1-fix): runs exactly once per
    start, attempts each of the six banned shapes plus one ordinary create inside `cwd` (the
    box's own writable mount, or `/tmp` when it has none), and faults unless every banned shape
    was refused AND the ordinary create succeeded. Any non-zero exit — including one the exec
    itself never completed — reads as failed, never as a pass.

    A probe that could not run its own controls still raises `AliasBanNotInForce`, and still
    is not opt-out-able: "the ban could not be observed" and "the ban is not in force" carry
    the same obligation to refuse, and softening the first into a `BoxFault` would hand the
    box a way to buy a degraded start by breaking the probe's writable mount. Only the MESSAGE
    differs — pointing at the mount rather than at the seccomp registration, so a disk-full
    box stops telling the operator to re-register the runtime."""
    proc = _call(docker, _alias_probe_argv(name, cwd))
    if proc.returncode == 0:
        return
    detail = proc.stderr or proc.stdout or ""
    if _CONTROL_FAILED_MARKER in detail:
        raise AliasBanNotInForce(_alias_probe_inconclusive_message(cwd, detail))
    raise AliasBanNotInForce(_alias_ban_fault_message(runtime, detail))


_ALLOW_UNSANDBOXED = "DEFENDER_ALLOW_UNSANDBOXED"
# The full container id as docker writes it into every container's own mount table.
_CONTAINER_ID_RE = re.compile(r"/containers/([0-9a-f]{64})")
_HOSTNAME_PATH = Path("/etc/hostname")
_MOUNTINFO_PATH = Path("/proc/self/mountinfo")
_BOX_PATH = "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
_NAME_PREFIX = "defender-run-"

# The encoding/clock contract every tier's box renders (#589): a `C` locale inside the box
# would decode a granted program's UTF-8 output differently than the host does.
_LOCALE_ENV: dict[str, str] = {"LANG": "C.UTF-8", "TZ": "UTC"}


def container_name(run_id: str) -> str:
    if not is_valid_run_id(run_id):
        raise ValueError(
            f"run id {run_id!r} cannot name a container (allowed: {RUN_ID_ALLOWED})"
        )
    return f"{_NAME_PREFIX}{run_id}"


def infra_env(defender_dir: Path, run_dir: Path) -> dict[str, str]:
    """The infra env every tier's box needs (M2): the shims + package location. One shared
    helper — a caller composing a BoxRequest merges this in (or box.py's own request render
    derives the same shape off the request's workdir, §_render_env)."""
    return {
        "DEFENDER_DIR": str(defender_dir),
        "DEFENDER_RUN_DIR": str(run_dir),
        "DEFENDER_RUNS_BASE": str(run_dir.parent),
        "PATH": f"{defender_dir / 'bin'}:{_BOX_PATH}",
        "PYTHONPATH": str(defender_dir.parent),
    }


def _derived_infra_env(workdir: Path) -> dict[str, str]:
    """The three INFRA keys box.py derives off the request's own workdir — the convention
    every box-carrying role anchors at `defender_dir.parent`. These always win (R11)."""
    defender_dir = Path(workdir) / "defender"
    return {
        "DEFENDER_DIR": str(defender_dir),
        "PATH": f"{defender_dir / 'bin'}:{_BOX_PATH}",
        "PYTHONPATH": str(workdir),
    }


def _render_env(request_env: Mapping[str, str], workdir: Path) -> dict[str, str]:
    """S8: a positive allowlist by key. R11: on a collision with an INFRA key
    (DEFENDER_DIR/PATH/PYTHONPATH, derived off the request's workdir — the convention every
    box-carrying role anchors at `defender_dir.parent`) the derived value wins; any other
    allowlisted key the caller supplies passes through unexamined (value-blind, RF-G).
    `LANG`/`TZ` keep the encoding/clock contract the two-arg `_create_argv` tier has always
    rendered (#589) — supplied as DEFAULTS, so a caller that names them still wins."""
    merged = dict(_LOCALE_ENV)
    merged.update({k: v for k, v in request_env.items() if k in BOX_ENV_ALLOWLIST})
    merged.update(_derived_infra_env(workdir))
    return merged


def _docker(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, capture_output=True, text=True, check=False, timeout=120,
        encoding="utf-8",
        errors="replace",
    )


DockerFn = Callable[..., subprocess.CompletedProcess]


def _call(docker: DockerFn, argv: list[str]) -> subprocess.CompletedProcess:
    try:
        return docker(argv)
    except (OSError, subprocess.SubprocessError) as e:
        # SubprocessError covers `_docker`'s own `timeout=120` (TimeoutExpired), which is NOT
        # an OSError — an unclassified TimeoutExpired would escape both the loud
        # DEFENDER_ALLOW_UNSANDBOXED fallback and core/faults.py's SYSTEMIC_FAULTS classification.
        raise BoxFault(f"could not invoke docker ({argv[:2]}): {e}") from e


def _is_running(docker: DockerFn, name: str) -> bool:
    proc = _call(docker, ["docker", "inspect", "-f", "{{.State.Status}}", name])
    return proc.returncode == 0 and "running" in (proc.stdout or "")


def _own_container_ids(
    hostname_path: Path = _HOSTNAME_PATH, mountinfo_path: Path = _MOUNTINFO_PATH,
) -> tuple[str, ...]:
    """Candidate identifiers for THIS container, most specific first; empty off-container.

    `/etc/hostname` is the container's short id only by DEFAULT. `--hostname`, docker
    compose, and Kubernetes all override it, and then `docker inspect <hostname>` fails, the
    C46 translation silently degrades to the identity, and the operator is back to docker's
    illegible "bind source path does not exist" — i.e. the exact failure this module now
    exists to replace. `/proc/self/mountinfo` carries the full 64-hex id inside the paths
    docker bind-mounts into every container, so it survives a renamed host.

    `read_text_soft`, not a bare `except OSError`: an undecodable file raises
    UnicodeDecodeError, which is a ValueError and would escape `start_box` past both
    `_opt_out_or_raise` and core/faults.py's SYSTEMIC_FAULTS (#589).
    """
    ids: list[str] = []
    hostname, _ = read_text_soft(hostname_path)
    if hostname and hostname.strip():
        ids.append(hostname.strip())
    mountinfo, _ = read_text_soft(mountinfo_path)
    for cid in _CONTAINER_ID_RE.findall(mountinfo or ""):
        if cid not in ids:
            ids.append(cid)
    return tuple(ids)


def _own_container_mounts(
    docker: DockerFn, ids: Sequence[str],
) -> tuple[tuple[Path, Path], ...]:
    """This process's own mounts as `(destination, source)`, longest destination first.

    Empty when we are not in a container, or when no candidate id resolves on the daemon —
    both of which make `_daemon_source` the identity, i.e. exactly today's behavior.
    """
    for cid in ids:
        proc = _call(docker, [
            "docker", "inspect", cid,
            "--format", "{{range .Mounts}}{{.Destination}}\t{{.Source}}\n{{end}}",
        ])
        if proc.returncode != 0:
            continue
        pairs = []
        for line in (proc.stdout or "").splitlines():
            dest, _, source = line.partition("\t")
            if dest.strip() and source.strip():
                pairs.append((Path(dest.strip()), Path(source.strip())))
        if pairs:
            # Longest destination first, so `_covering_mount` picks the most specific: a
            # nested destination is strictly longer than any ancestor of it.
            return tuple(sorted(pairs, key=lambda p: len(str(p[0])), reverse=True))
    return ()


def _shared_mounts(docker: DockerFn) -> tuple[tuple[Path, Path], ...]:
    """This container's mount table, discovered end to end — the ONE seam both start paths
    reach the translation through.

    A seam rather than two inline calls because the discovery half is not injectable any
    other way: `_own_container_ids` reads `/etc/hostname` and `/proc/self/mountinfo`, which
    answer differently on a devcontainer and on a bare CI runner, so a test that fed a table
    through the `docker=` fake alone would assert the wiring on one machine and vacuously
    pass on the other.
    """
    return _own_container_mounts(docker, _own_container_ids())


SharedMountsFn = Callable[[DockerFn], Sequence[tuple[Path, Path]]]


def _covering_mount(
    path: Path, mounts: Sequence[tuple[Path, Path]],
) -> tuple[Path, Path] | None:
    """The most specific `(destination, source)` whose destination contains `path`, else None.

    `os.path.normpath` FIRST: `PurePath` does not collapse a `..` component, so a path that
    walks out of a mount destination still reports that destination among its parents — it
    would pass the coverage check and then translate to a daemon-side source OUTSIDE the
    shared mount, precisely the bind the check exists to refuse.
    """
    resolved = Path(os.path.normpath(path))
    for dest, source in mounts:
        if resolved.is_relative_to(dest):
            return dest, source
    return None


def _daemon_source(path: Path, mounts: Sequence[tuple[Path, Path]]) -> Path:
    """Translate a path THIS process can see into the one the DAEMON must be given as a bind
    source.

    C46 — under docker-outside-of-Docker the caller's namespace and the daemon's differ, so
    `source=<our path>` names a directory the daemon cannot resolve and `docker run` fails at
    create. Only the bind SOURCE is translated: `target=`, `--workdir`, and `infra_env` keep
    the path this process uses, because that is the path the agent records into
    investigation.md, orient's workspace map, and `raw_command`, and the learning loop and
    visualizer read those back through this same namespace. The equality the RSD's
    mount-ordering note actually depends on — in-isolate path == the path the downstream
    reader uses — is therefore preserved, not broken.

    Identity when no mapping covers `path`, keeping the native-daemon case byte-identical.

    A wrong mapping is caught at startup wherever a sentinel covers the mount: the rw run dir
    (`_plant_sentinel`) and every `BoxRequest` mount (M11's `_check_mount_sentinel`) fail the
    run closed. The two-arg tier's READ-ONLY defender_dir bind is the one gap — planting a
    sentinel there would write into the source tree it declares read-only — so a wrong
    mapping of that mount instead surfaces on first use, as an unresolvable
    `defender.runtime.bash_exec` inside the box.
    """
    covering = _covering_mount(path, mounts)
    if covering is None:
        return path
    dest, source = covering
    return source / Path(os.path.normpath(path)).relative_to(dest)


def _covered(path: Path, mounts: Sequence[tuple[Path, Path]]) -> bool:
    return _covering_mount(path, mounts) is not None


def _uncovered_fault(subject: str, path: Path, mounts: Sequence[tuple[Path, Path]],
                     remedy: str) -> BoxFault:
    """The ONE C46 refusal both argv builders raise — a bind source on no shared mount.

    Pre-fix this surfaced as docker's "bind source path does not exist", which reads like a
    bug rather than a topology mismatch and sends the operator straight to
    DEFENDER_ALLOW_UNSANDBOXED — trading away the boundary O10 exists to guarantee.
    """
    return BoxFault(
        f"the {subject} {path} is not on any path this container shares with the docker "
        "daemon, so the box's bind source cannot be resolved (C46: docker-outside-of-Docker). "
        f"{remedy} under one of {', '.join(str(d) for d, _ in mounts)}, or run the driver "
        "where it shares a path namespace with the daemon."
    )


def _create_argv(
    name: str, run_dir: Path, defender_dir: Path, spec: BoxSpec,
    mounts: Sequence[tuple[Path, Path]] = (),
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
        # The run-dir tier deliberately LEAVES its sentinel behind on a fault (pinned by
        # test_540_scrub_lifecycle: the residue is the evidence the probe really wrote); the
        # per-mount tier cleans up, because its sources include the live repo/worktree trees.
        if unlink_on_fault:
            sentinel.unlink(missing_ok=True)
        raise
    sentinel.unlink(missing_ok=True)


def _plant_sentinel(run_dir: Path, docker: DockerFn, name: str) -> None:
    _probe_sentinel(run_dir, run_dir, docker, name, ".box-sentinel", unlink_on_fault=False)


def _check_mount_sentinel(mount: Mount, docker: DockerFn, name: str) -> None:
    """M11 — every mount is individually probed at start, not only the original single rw
    run_dir: a host-planted token, read back through the box, proves the tree inside the
    container is the tree on the host (an absent bind SOURCE is caught earlier, at create —
    DC1; this catches a bind that SUCCEEDED but mapped the wrong/empty tree)."""
    _probe_sentinel(
        Path(mount.source), Path(mount.target), docker, name,
        f".box-sentinel-{uuid.uuid4().hex}", unlink_on_fault=True,
    )


def _start_boxed(
    run_dir: Path, defender_dir: Path, spec: BoxSpec, docker: DockerFn,
    shared_mounts: SharedMountsFn = _shared_mounts,
) -> BoxExecutor:
    name = container_name(run_dir.name)
    if _is_running(docker, name):
        raise BoxFault(
            f"a LIVE container named {name} already exists — refusing rather than reaping "
            "it, because that box belongs to another run still writing its artifacts"
        )
    _call(docker, ["docker", "rm", "-f", name])
    created = _call(
        docker,
        _create_argv(name, run_dir, defender_dir, spec, shared_mounts(docker)),
    )
    if created.returncode != 0:
        # `docker run --detach` is create-THEN-start, so a non-zero rc does not prove no
        # container exists: a failure at task start (a seccomp/AppArmor profile the runtime
        # rejects, a missing `runsc`, cgroup or pid exhaustion) leaves the container behind in
        # `created`. Nothing revisits this name — run ids are not reused and there is no prefix
        # sweeper — so without this reap the leak accrues forever, one per faulted start, and
        # O11 ("no box outlives the run that created it") is broken by the host rather than by
        # a principal. Unconditional, like the pre-create reap above and for the same reason:
        # C43a records `docker rm -f <missing>` as rc=0 with `Error response from daemon` on
        # stderr, so a caller that read either would misfire on the success path (#884).
        #
        # The MARKER goes first: §7 D2's verdict is best-effort by construction, but a `_call`
        # that raises (a daemon that died between create and reap) would otherwise leave the
        # tree with no verdict at all AND swap this arm's create stderr for "could not invoke
        # docker" — the marker's own failure replacing the signal, which is the one thing
        # `_write_verdict` says must not happen.
        #
        # Guarded by `_is_running` for the reason the pre-create arm above refuses outright: a
        # create that failed on a NAME CONFLICT says the container under this name is someone
        # else's, still writing its artifacts, and no lane may reap that. The `created`
        # container this arm exists for never started, so the guard never withholds the reap
        # from the leak it is here to close.
        write_did_not_run(
            run_dir, f"box create faulted before the box was startable: "
                     f"{(created.stderr or '').strip()}"
        )
        if not _is_running(docker, name):
            _call(docker, ["docker", "rm", "-f", name])
        raise BoxFault(
            f"could not create the box {name}: {(created.stderr or '').strip()}"
        )
    try:
        _plant_sentinel(run_dir, docker, name)
        _probe_alias_ban(docker, name, run_dir, spec.runtime)
    except BaseException as e:
        _call(docker, ["docker", "rm", "-f", name])
        write_did_not_run(
            run_dir, f"box startup faulted before the reap scan could run: {e}"
        )
        raise
    return BoxExecutor(spec=spec, transport=_DockerTransport(name, spec), name=name)


def _render_argv(
    request: BoxRequest, mounts: Sequence[tuple[Path, Path]] = (),
) -> list[str]:
    argv = [
        "docker", "run", "--detach", "--name", request.name,
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
    """§7 D2's marker for the request lane — one per WRITABLE mount source, and none at all for
    a lane that has no writable mount.

    The investigation lane's marker keys off its single run dir; a request composes its own
    geography, so "which tree does this box's verdict belong to" has to be answered explicitly.
    The writable mounts are the answer, and the rule falls straight out of the one
    `stop_and_scrub` already follows: a tree is worth a verdict exactly when the box could
    write it. That makes the read-only run-cycle lane (every mount rendered readonly, X16) mint
    no sidecar — it has no tree to judge, which is the same reason it is the one boxed lane
    that never scrubs — rather than orphaning one beside a tree nothing cleans up.

    Best-effort per tree, for the reason `scrub._write_verdict` carries: these calls sit on a
    path that is already unwinding a startup fault, and the marker must never replace it."""
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
    if _is_running(docker, request.name):
        raise BoxFault(
            f"a LIVE container named {request.name} already exists — refusing rather than "
            "reaping it, because that box belongs to another batch still writing its artifacts"
        )
    _call(docker, ["docker", "rm", "-f", request.name])
    created = _call(docker, _render_argv(request, shared_mounts(docker)))
    if created.returncode != 0:
        # The investigation lane's reason, verbatim (`_start_boxed`): create-then-start means a
        # non-zero rc can still leave a `created` container, and this lane's names are no more
        # revisited than that one's — `defender-drain-{uuid4}` per invocation. The run-cycle
        # lane happens to self-heal at its own pre-create reap, being keyed on a reused run id;
        # that is a property of one caller, not of this arm (#884). Marker-then-guarded-reap
        # for that lane's reasons too, and the name-conflict guard matters MORE here: this is
        # the lane whose names are reused, so a create that lost the race to a concurrent
        # batch of the same run id is exactly the create that must not reap.
        _did_not_run_for_request(
            request, f"box create faulted before the box was startable: "
                     f"{(created.stderr or '').strip()}"
        )
        if not _is_running(docker, request.name):
            _call(docker, ["docker", "rm", "-f", request.name])
        raise BoxFault(
            f"could not create the box {request.name}: {(created.stderr or '').strip()}"
        )
    try:
        for m in request.mounts:
            _check_mount_sentinel(m, docker, request.name)
        _probe_alias_ban(docker, request.name, _probe_cwd_for_request(request), request.spec.runtime)
    except BaseException as e:
        _call(docker, ["docker", "rm", "-f", request.name])
        # Both fault arms mark, exactly as the investigation lane's `_start_boxed` does. The
        # host has already planted sentinels into these trees by the time a mount probe or the
        # alias probe fails; without the marker the tree is left with no verdict at all, which
        # `tree_verified` cannot tell apart from a tree nobody has judged yet, and which
        # quarantine records as an empty verdict in its manifest.
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
    box's own `/tmp` tmpfs when the lane has none (the learning run-cycle box, X16 — every
    mount rendered read-only). The ban is a syscall filter, not a path policy, so the
    observation is equally valid in either (§7 H10, pinned provisionally)."""
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
    provider keys) exactly as `run_common.run_env` does for the two-arg tier — NOT the box's
    key-allowlisted, container-shaped `_render_env` (which carries no HOME and a `_BOX_PATH`
    that does not exist on the host)."""
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
        # `is not None` rather than compared against DEFAULT_SPEC: now that the default is
        # env-resolved, a value comparison would fire spuriously whenever
        # DEFENDER_BOX_RUNTIME is set. The env is deliberately NOT read on this path —
        # `BoxRequest.spec`'s factory already owns the lever, and reading it here would let a
        # typo'd DEFENDER_BOX_RUNTIME raise ValueError out of a call that never uses `spec`,
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
    # F1 (intent_540 §542) settled the runtime knob as "the dataclass anchors the default,
    # ONE env var is its external lever". `BoxSpec.from_env` implemented the lever, but no
    # call path read it — `DEFAULT_SPEC` hard-pinned every run to runsc, which made the RSD's
    # "ships on whatever the host supports rather than waiting on a privileged runsc host"
    # unreachable. Resolving it here is what connects the two on the run_dir overload;
    # `BoxRequest.spec`'s factory does the same for the request overload.
    #
    # The DEFAULT IS UNCHANGED (runsc). runc is the weaker isolation tier, so it is reached
    # only by an operator explicitly setting DEFENDER_BOX_RUNTIME=runc — never by fallback.
    if spec is None:
        # lint-default: ok — the env lever IS this default's single source (F1/§542). The
        # signature cannot carry it: `spec=` must stay distinguishable from unset for the
        # BoxRequest overload's ambiguity check above.
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

    #741: this is the exit half of a boxed lifecycle, owned in ONE place rather than
    hand-assembled at each call site. Both writable lanes call it — `run.py`'s investigation
    and `drains.py`'s worktree batch. `run_cycle` does not, and correctly: all of its mounts
    are read-only, so it has no tree to walk.

    Call it from a `finally`, with `in_flight` saying whether an exception is already
    propagating. Three rules, and the ordering between them is the whole point:

    - **The scrub runs only once the box is provably dead.** "No live writer" is the scrub's
      entire justification, so a teardown whose fault was swallowed leaves that unproven and
      the walk is SKIPPED rather than raced. A check that races a live writer is a check in
      name only.
    - **An in-flight exception outranks a teardown fault.** The work's own failure is the
      more informative signal; a `BoxFault` raised on top of it would replace it. Python's
      implicit chaining keeps the teardown fault reachable on `__context__`. With nothing in
      flight there is nothing to outrank, so the fault propagates normally. Outranked is not
      the same as unrecorded: a suppressed fault means BOTH a possibly-leaked container (one
      genuinely survives its parent's death, C42) and a tree that was never walked, so it is
      logged rather than dropped — a silent leak is exactly the residue this helper exists
      to retire.
    - **A taint outranks everything.** `RunTainted` from the scrub deliberately wins over the
      work's own failure — a tainted tree is the worse signal, and the crash path's tree is
      the one most likely to hold what the box planted, and the one a human then opens by
      hand. That falls out of not catching it.

    `stop_box` and `scrub_tree` are required, not defaulted: each lane already anchors its own
    defaults in its own signature, and re-defaulting them here would be a second source.
    `scrub_tree` rather than `scrub` because this module re-exports the real `scrub` for its
    callers, and a parameter of that name would shadow it.
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
        # §7 D1's accepted cost, finally paid — and paid HERE because this is the only point
        # where it can be. Unpredictable staged names mean no later write ever replaces a
        # crash-orphaned one by name, so without a sweep they accumulate in every run dir and
        # drain worktree forever. It runs strictly AFTER the walk: sweeping first would delete
        # entries the scan exists to report, the sanitizing move the design refuses everywhere
        # else, and it costs nothing to wait — the scan permits any regular file, and an
        # orphaned staged file is one. A tainted tree never reaches this line at all
        # (`RunTainted` propagates out of `scrub_tree`), so quarantine still gets the tree
        # exactly as the box left it.
        swept = sweep_staged(tree)
        if swept:
            print(
                f"[box] swept {len(swept)} orphaned staged file(s) under {tree}",
                file=sys.stderr,
            )


@dataclass(frozen=True)
class _DockerTransport:

    name: str
    spec: BoxSpec

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> RawExec:
        proc = subprocess.run(  # noqa: S603
            [
                "docker", "exec", "-i", "-w", str(cwd), self.name,
                "python3", "-m", "defender.runtime.bash_exec",
            ],
            input=frame, capture_output=True, check=False, timeout=timeout,
        )
        return RawExec(rc=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


@dataclass(frozen=True)
class _HostTransport:

    env: dict[str, str]

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> RawExec:
        rc, out, err = bash_exec.run_parsed(
            decode_request(frame), command="", env=self.env, cwd=cwd, timeout=timeout,
        )
        return RawExec(rc=rc, stdout=encode_response(BoxResult(
            rc=rc,
            out=out.encode("utf-8", "replace"),
            err=err.encode("utf-8", "replace"),
        )), stderr=b"")


def unboxed_executor(
    spec: BoxSpec = DEFAULT_SPEC, *, env: Mapping[str, str] | None = None,
) -> BoxExecutor:
    return BoxExecutor(
        spec=spec,
        transport=_HostTransport(dict(env) if env is not None else dict(os.environ)),
        name="",
    )
