
from __future__ import annotations

import contextlib
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
    # Same lever as start_box's run_dir path: unset anchors to the dataclass default, runsc.
    # A request carries its own spec, so resolving it anywhere but here would leave the
    # BoxRequest callers pinned to runsc with the env var silently ignored.
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

#: M1 — the alias-ban seccomp profile, resolved ONCE so every box lane attaches the identical
#: value. Denies exactly the six shapes `BANNED_SHAPES` names. Ships under `runtime/`, outside
#: every box's writable mount: a box that could rewrite the file it is banned by would leave
#: the NEXT box unbanned.
ALIAS_PROFILE_PATH: Path = Path(__file__).resolve().parent / "seccomp" / "alias-deny.json"

BANNED_SHAPES: tuple[str, ...] = ("symlink", "symlinkat", "link", "linkat", "mknod", "mknodat")

_OCI_SECCOMP_FLAG = "--oci-seccomp"
_RUNSC_INSTALL_CMD = "runsc install -- --oci-seccomp"


class AliasBanNotInForce(Exception):
    """§7 D5 — the ban-not-in-force fault. Deliberately NOT a `BoxFault` subclass (nor a
    superclass): being not-opt-out-able is only enforceable if the broad
    `except BoxFault: degrade` handler every other startup fault survives cannot catch it."""


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


#: The probe's own I/O failed, so nothing it observed means anything. Distinct from "a banned
#: shape was allowed" because the two demand OPPOSITE operator actions and are identical in an
#: exit code. Both still fail closed (see `_probe_alias_ban`).
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
    """One probe body: each of the six banned shapes plus one ordinary create, under a
    randomly-suffixed prefix whose leavings are swept whichever arm it takes. rc 0 + stdout on
    total denial with a working control, rc 1 + stderr naming what was allowed (or which
    control failed) otherwise — the shape `AliasProbeDocker.ProbeVerdict.as_completed` fakes,
    so one reader classifies both.

    EVERY file operation the probe makes on its own behalf is guarded, and a failure ABANDONS
    the observation: an unguarded `open` for the hard-link source turns a full or read-only
    mount into a traceback the host reads as "the ban is not in force", and running the link
    attempts anyway would let a MISSING source fail `ENOENT` and count as DENIED."""
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
    """M2 — the startup positive control: observes the ban's EFFECT at every box start rather
    than trusting the runtime's configuration, and faults unless every banned shape was
    refused AND the ordinary create succeeded. Any non-zero exit reads as failed.

    A probe that could not run its own controls still raises `AliasBanNotInForce`: "could not
    be observed" and "is not in force" carry the same obligation to refuse, and softening the
    first into a `BoxFault` would let the box buy a degraded start by breaking the probe's
    writable mount. Only the MESSAGE differs."""
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
    """The infra env every tier's box needs: the shims + package location. A caller composing
    a BoxRequest merges this in (or `_render_env` derives the same shape off its workdir)."""
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
    (DEFENDER_DIR/PATH/PYTHONPATH, derived off the request's workdir) the derived value wins;
    any other allowlisted key the caller supplies passes through unexamined (value-blind).
    `LANG`/`TZ` keep the two-arg tier's encoding/clock contract, supplied as DEFAULTS so a
    caller that names them still wins."""
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


#: The container states from which nothing can still be starting or running — whatever holds
#: the name is FINISHED with it, and reaping it costs nobody anything.
#:
#: Every other state is refused, `created` above all, and that is the point of the set rather
#: than a `running` test (#955 F-49). `docker run --detach` is create-then-start, so a
#: concurrent lane's box sits in `created` for the whole window in which two lanes can collide
#: on one name — precisely the window a liveness test reads as "not live, reap it", and
#: precisely the collision the reap then resolves by destroying the other lane's run.
_FINISHED_STATES = frozenset({"exited", "dead"})


def _inspect_field(docker: DockerFn, name: str, fmt: str) -> str | None:
    """One `-f` field off `docker inspect`, or `None` when the daemon answered non-zero.

    The rc/stdout contract of an inspect, in ONE place, because both reap decisions rest on
    it: `_container_status` asks what state this name holds and `_start_token` asks whose
    container it is, and two copies of "rc means absent, stdout stripped means the answer" is
    two places a later correction — a whitespace-only reply, a timeout, an rc-2 case — can be
    applied to only one, leaving the pre-create sweep and the create-fault arm disagreeing
    about the same daemon reply. What each answer MEANS stays with its own caller."""
    proc = _call(docker, ["docker", "inspect", "-f", fmt, name])
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip()


def _container_status(docker: DockerFn, name: str) -> str | None:
    """Docker's own word for what this name holds, or `None` for no such container.

    An answer we cannot read — rc 0 with nothing parseable — is reported as the empty string
    rather than `None`, which keeps it OUT of `_FINISHED_STATES` and therefore unreapable. A
    daemon we cannot understand is not evidence that the container is done with."""
    return _inspect_field(docker, name, "{{.State.Status}}")


#: Stamped on every box at create, so a fault arm can tell OUR container from another lane's
#: under the same name. A name alone cannot: `docker run --detach` is create-then-start, so a
#: non-zero rc means EITHER "we created it and the task would not start" or "the name was
#: already taken", and no liveness test can discriminate either — a concurrent lane's container
#: is itself in `created` for the whole conflict window. Minted per START, never per run id: a
#: reused run-cycle name is exactly where the run id would answer yes for somebody else's box.
START_TOKEN_LABEL = "defender.start-token"

#: Docker's own text for a label the container does not carry, which `-f {{index …}}` prints
#: rather than failing. It means "not ours" as surely as a mismatch does.
_NO_LABEL = "<no value>"


def _start_token(docker: DockerFn, name: str) -> str | None:
    # `None` from the helper is "no such container" — nothing to own, and nothing to reap.
    token = _inspect_field(
        docker, name, f'{{{{index .Config.Labels "{START_TOKEN_LABEL}"}}}}',
    )
    return None if not token or token == _NO_LABEL else token


def _reap_stale_before_create(docker: DockerFn, name: str) -> None:
    """The pre-create sweep, which MAY raise — the one reap in this module that should.

    Nothing has been created yet and no fault is being carried, so an unreachable daemon has
    no signal to trample and every reason to abort the start: proceeding to `docker run`
    against a daemon that just refused `rm -f` would fail again, or collide with the stale
    container this call exists to clear. Contrast `_reap_on_fault`.

    Ownership is decided by STATE here, not by the start token `_reap_on_fault` reads, and the
    difference is not an inconsistency: the token is minted per start, so at this point in the
    call there is no token that could be ours, and every container under this name would read
    as foreign. What can be established is whether anyone can still be USING it. A finished
    container is nobody's; anything else may be a lane mid-start, and this arm refuses rather
    than reap it (#955 F-49) — the same trade `_reap_on_fault` states, decided the same way.
    An unreapable leak costs one stale container and a loud fault an operator can clear by
    hand; reaping the wrong box costs another run its artifacts and reports the loss as a
    mount error."""
    status = _container_status(docker, name)
    if status is None:
        return
    if status not in _FINISHED_STATES:
        described = status or "in a state this daemon would not name"
        raise BoxFault(
            f"a container named {name} already exists and is {described} — refusing rather "
            "than reaping it, because a container that is not finished may belong to another "
            "lane still writing its artifacts. If it is a leak, "
            f"`docker rm -f {name}` clears it."
        )
    _call(docker, ["docker", "rm", "-f", name])


def _reap_on_fault(docker: DockerFn, name: str, *, owned_token: str | None = None) -> None:
    """Reap a box on a path ALREADY unwinding a startup fault — best-effort on BOTH halves,
    which is the point of routing every such reap through here. `_call` raises `BoxFault`
    whenever docker cannot be invoked (the CORRELATED case: the same sick daemon is often why
    create failed), and unsuppressed it would replace the create's own stderr — the only
    account of why the box never started — and cost the tree its §7 D2 verdict.

    `owned_token` is for the CREATE-fault arms, where the container under this name may not be
    ours: reaped only if it carries the token THIS call stamped on it. Absent the label, or on
    any daemon answer we cannot read, nothing is reaped — an unreapable leak costs one stale
    container, reaping the wrong box costs another run its artifacts. The startup-fault arms
    pass nothing: they faulted THROUGH a create that returned rc 0, so the box is theirs."""
    with contextlib.suppress(BoxFault):
        if owned_token is not None and _start_token(docker, name) != owned_token:
            return
        _call(docker, ["docker", "rm", "-f", name])


def _own_container_ids(
    hostname_path: Path = _HOSTNAME_PATH, mountinfo_path: Path = _MOUNTINFO_PATH,
) -> tuple[str, ...]:
    """Candidate identifiers for THIS container, most specific first; empty off-container.

    `/etc/hostname` is the container's short id only by DEFAULT — `--hostname`, compose and
    Kubernetes override it, and then `docker inspect <hostname>` fails and the C46 translation
    silently degrades to the identity. `/proc/self/mountinfo` carries the full 64-hex id, so
    it survives a renamed host. `read_text_soft`, not a bare `except OSError`: an undecodable
    file raises UnicodeDecodeError, a ValueError, which would escape `start_box` past both
    `_opt_out_or_raise` and core/faults.py's SYSTEMIC_FAULTS.
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
    """This process's own mounts as `(destination, source)`, longest destination first. Empty
    when we are not in a container or no candidate id resolves on the daemon — both of which
    make `_daemon_source` the identity.
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
    reach the translation through. A seam because the discovery half is not injectable any
    other way: `_own_container_ids` reads `/etc/hostname` and `/proc/self/mountinfo`, which
    answer differently on a devcontainer and a bare CI runner, so a test feeding a table
    through the `docker=` fake alone would pass vacuously on one of them.
    """
    return _own_container_mounts(docker, _own_container_ids())


SharedMountsFn = Callable[[DockerFn], Sequence[tuple[Path, Path]]]


def _covering_mount(
    path: Path, mounts: Sequence[tuple[Path, Path]],
) -> tuple[Path, Path] | None:
    """The most specific `(destination, source)` whose destination contains `path`, else None.

    `os.path.normpath` FIRST: `PurePath` does not collapse a `..` component, so a path that
    walks out of a mount destination still reports it among its parents — passing the coverage
    check and then translating to a daemon-side source OUTSIDE the shared mount.
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
    `source=<our path>` names a directory the daemon cannot resolve. Only the bind SOURCE is
    translated: `target=`, `--workdir` and `infra_env` keep the path this process uses, which
    is the path the agent records into investigation.md, orient's workspace map and
    `raw_command`, read back by the learning loop and visualizer through this same namespace.
    Identity when no mapping covers `path`.

    A wrong mapping is caught at startup wherever a sentinel covers the mount. The two-arg
    tier's READ-ONLY defender_dir bind is the one gap — a sentinel there would write into the
    tree it declares read-only — so a wrong mapping of that mount surfaces on first use, as an
    unresolvable `defender.runtime.bash_exec`.
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
    Otherwise it surfaces as docker's "bind source path does not exist", which reads like a
    bug rather than a topology mismatch and sends the operator straight to
    DEFENDER_ALLOW_UNSANDBOXED, trading away the boundary O10 guarantees.
    """
    return BoxFault(
        f"the {subject} {path} is not on any path this container shares with the docker "
        "daemon, so the box's bind source cannot be resolved (C46: docker-outside-of-Docker). "
        f"{remedy} under one of {', '.join(str(d) for d, _ in mounts)}, or run the driver "
        "where it shares a path namespace with the daemon."
    )


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
