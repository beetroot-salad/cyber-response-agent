"""Talking to the daemon: naming, env, status, reaping, and which mounts are shared.

Every call to `docker` in the runtime goes through here.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import weakref
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, NamedTuple

import shlex

from defender._io import read_text_soft
from defender.records.formats import RUN_ID_ALLOWED, is_valid_run_id
from defender.execution.box_codec import (
    BOX_ENV_ALLOWLIST,
    BOX_MARK_ENV,
    REQUEST_MAGIC,  # noqa: F401 — re-exported: test_exec_seam.py imports it as `box.REQUEST_MAGIC`
    RESPONSE_MAGIC,  # noqa: F401 — re-exported: test_exec_seam.py imports it as `box.RESPONSE_MAGIC`
    BoxFault,
)
from defender.box._scrub import (  # noqa: F401 — re-exported: run.py/drains.py/tests import `box.scrub`, `box.RunTainted`
    Finding,
    RunTainted,
    scrub,
    verdict_path,
    write_did_not_run,
)
from ._image import ImageInputError, image_tag


_ALLOW_UNSANDBOXED = "DEFENDER_ALLOW_UNSANDBOXED"

#: The build script every missing-image fault names, relative to the tree root.
_BUILD_SCRIPT_TAIL = "defender/box/image_cli.py"


class Rootfs(NamedTuple):
    """The box's root filesystem image, and what to tell an operator whose daemon lacks it."""

    image: str
    #: The build command for a tree-derived image; `None` for an explicit rootfs.
    remedy: str | None


class Create(NamedTuple):
    """A rendered `docker run` (the run box's: `docker create`): the argv, plus the rootfs by
    name so no caller reads it off an argv position."""

    argv: list[str]
    rootfs: Rootfs


def build_remedy(tree: Path) -> str:
    """The sentence every missing-image fault ends with: the build command for `tree`
    (absolute, `shlex.quote`d)."""
    quoted_tree = shlex.quote(str(Path(tree).resolve()))
    return f"build it first: `python3 {quoted_tree}/{_BUILD_SCRIPT_TAIL} build`"


def resolve_rootfs(rootfs: str | None, tree: Path) -> Rootfs:
    """An explicit `rootfs` is used verbatim with no remedy; unset resolves to
    `image_tag(tree)` with the build remedy. Raises `BoxFault` rather than
    `ImageInputError` so every `docker run` site sees one fault type."""
    if rootfs is not None:
        return Rootfs(rootfs, None)
    try:
        return Rootfs(image_tag(tree), build_remedy(tree.parent))
    except ImageInputError as e:
        raise BoxFault(str(e)) from e


def carries_build_remedy(fault: BaseException) -> bool:
    """Whether a fault's message ends with the `build_remedy` command."""
    return f"/{_BUILD_SCRIPT_TAIL} build" in str(fault)


def require_image(docker: DockerFn, rootfs: Rootfs) -> None:
    """Ask the daemon whether it holds the image (`docker image inspect`, by exit code)
    before any create names it; raise `BoxFault` with the build remedy if not.

    Decided by exit code, never by error text, which varies across docker CLI versions. A
    non-zero rc also means "daemon unreachable", so the daemon is probed and that case is
    reported without a build remedy."""
    probe = _call(docker, ["docker", "image", "inspect", "--format", "{{.Id}}", rootfs.image])
    if probe.returncode == 0:
        return
    detail = (probe.stderr or "").strip()
    alive = _call(docker, ["docker", "version", "-f", "{{.Server.Version}}"])
    if alive.returncode != 0:
        raise BoxFault(
            f"docker could not say whether the daemon holds {rootfs.image}, and could not "
            f"answer for the daemon either ({(alive.stderr or '').strip()[:200]!r})"
        )
    message = f"the daemon holds no image {rootfs.image}: {detail}"
    raise BoxFault(message if rootfs.remedy is None else f"{message} — {rootfs.remedy}")


#: What to do when the daemon has no runtime a box asks for, by runtime (#1484).
_RUNTIME_REMEDY = {
    "runsc": ("install gVisor and register it with Docker (`runsc install -- --oci-seccomp --host-uds=open`, then "
              "restart Docker; defender/CLAUDE.md, \"Upgrade from before #1170\", step 2), or set "
              "DEFENDER_BOX_RUNTIME=runc to run boxes under Docker's default runtime, with weaker isolation"),
}


#: The runtimes each daemon was seen to have registered, by its `docker` seam (#1484): a daemon's runtimes change only
#: when it restarts, so a process asks once per runtime. Only a runtime found is kept: a missing one is asked again,
#: so a host fixed while a worker runs is seen at its next start.
_FOUND_RUNTIMES: weakref.WeakKeyDictionary[Any, set[str]] = weakref.WeakKeyDictionary()


def require_runtime(docker: DockerFn, runtime: str) -> None:
    """Confirm the daemon has `runtime` registered before any create names it (#1484); raise `BoxFault` with its
    remedy if not. Like `require_image`, decided by asking the daemon, never by a create's error text. A daemon that
    cannot say (no answer, or an answer naming no runtime: a daemon always has its default) is not refused here: a
    create then faults in docker's own words."""
    try:
        if runtime in _FOUND_RUNTIMES.get(docker, ()):
            return
    except TypeError:  # a seam that cannot be weakly referenced is asked every time
        pass
    try:
        proc = _call(docker, ["docker", "info", "--format", "{{json .Runtimes}}"])
        runtimes = json.loads(proc.stdout or "") if proc.returncode == 0 else None
    except (BoxFault, ValueError):
        return
    if not isinstance(runtimes, dict) or not runtimes:
        return
    if runtime in runtimes:
        with contextlib.suppress(TypeError):
            _FOUND_RUNTIMES.setdefault(docker, set()).add(runtime)
        return
    remedy = _RUNTIME_REMEDY.get(runtime, "register it with Docker, or set DEFENDER_BOX_RUNTIME to another box runtime")
    raise BoxFault(f"Docker on this host has no runtime {runtime!r} registered: {remedy}")


def require_startable(docker: DockerFn, rootfs: Rootfs, runtime: str) -> None:
    """What a box needs of its host before its create: its image (`require_image`) and its runtime
    (`require_runtime`), each a refusal of its own with its remedy."""
    require_image(docker, rootfs)
    require_runtime(docker, runtime)


# The full container id as docker writes it into every container's own mount table.
_CONTAINER_ID_RE = re.compile(r"/containers/([0-9a-f]{64})")
_HOSTNAME_PATH = Path("/etc/hostname")
_MOUNTINFO_PATH = Path("/proc/self/mountinfo")
_BOX_PATH = "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
_NAME_PREFIX = "defender-run-"

# A `C` locale inside the box would decode a granted program's UTF-8 output differently
# than the host does.
_LOCALE_ENV: dict[str, str] = {"LANG": "C.UTF-8", "TZ": "UTC"}


def container_name(run_id: str) -> str:
    if not is_valid_run_id(run_id):
        raise ValueError(
            f"run id {run_id!r} cannot name a container (allowed: {RUN_ID_ALLOWED})"
        )
    return f"{_NAME_PREFIX}{run_id}"


def infra_env(defender_dir: Path, run_dir: Path) -> dict[str, str]:
    """The infra env every box needs: the shims and package location. `DEFENDER_RUNS_BASE` is
    the run folder's own hand-out from the layout owner (`RunPaths.runs_base_export`), never read
    from the environment and never composed here (#1105 PR 2, #1210)."""
    from defender.records import RunPaths

    env: dict[str, str] = {}
    env["DEFENDER_DIR"] = str(defender_dir)
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    env["DEFENDER_RUNS_BASE"] = RunPaths(run_dir).runs_base_export()
    env["PATH"] = f"{defender_dir / 'bin'}:{_BOX_PATH}"
    env["PYTHONPATH"] = str(defender_dir.parent)
    return env


def _derived_infra_env(workdir: Path, *, defender_dir: Path | None = None) -> dict[str, str]:
    """Infra keys from the explicit product root, or a legacy checkout workdir."""
    from ._spec import _code_dir

    defender_dir = _code_dir(workdir, defender_dir)
    return {
        "DEFENDER_DIR": str(defender_dir),
        "PATH": f"{defender_dir / 'bin'}:{_BOX_PATH}",
        "PYTHONPATH": str(defender_dir.parent),
    }


def _render_env(request_env: Mapping[str, str], workdir: Path, *, defender_dir: Path | None = None) -> dict[str, str]:
    """Render the box env from a key allowlist. Derived infra keys override the request;
    `LANG`/`TZ` are defaults the request may override; the `DEFENDER_BOX` mark goes last so
    no request env can switch it off."""
    merged = dict(_LOCALE_ENV)
    merged.update({k: v for k, v in request_env.items() if k in BOX_ENV_ALLOWLIST})
    merged.update(_derived_infra_env(workdir, defender_dir=defender_dir))
    merged.update(BOX_MARK_ENV)
    return merged


class _RealDocker:
    """The real docker CLI. Called: one command, run to completion. `.popen`: a docker process
    left running, a box's attached start (the run box's, #1343 B10; each of a request-lane box's
    windows, #1344 amendment 2), whose input its holder keeps open while the box may run.
    Every attached start asks for it of the docker object it was handed (r5 item 15),
    so a docker double carries its own and the real daemon is never reached around it."""

    def __call__(self, argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.run(
            argv, capture_output=True, text=True, check=False, timeout=120,
            encoding="utf-8",
            errors="replace",
        )

    @staticmethod
    def popen(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        return subprocess.Popen(argv, **kwargs)


run_docker = _RealDocker()


DockerFn = Callable[..., subprocess.CompletedProcess]


def _call(docker: DockerFn, argv: list[str]) -> subprocess.CompletedProcess:
    try:
        return docker(argv)
    except (OSError, subprocess.SubprocessError) as e:
        # SubprocessError covers TimeoutExpired, which is not an OSError and would otherwise
        # escape the unsandboxed fallback and the SYSTEMIC_FAULTS classification.
        raise BoxFault(f"could not invoke docker ({argv[:2]}): {e}") from e


def _inspect_field(docker: DockerFn, name: str, fmt: str) -> str | None:
    """One `-f` field off `docker inspect`, or `None` when the daemon answered non-zero.
    Callers decide what `None` means. Only the newline docker ends its answer with is dropped:
    a label padded with whitespace is not the token it pads (#1342 r5 C1)."""
    proc = _call(docker, ["docker", "inspect", "-f", fmt, name])
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").removesuffix("\n")


def _container_status(docker: DockerFn, name: str) -> str | None:
    """Docker's word for what this name holds, or `None` for no such container.

    An unparseable answer is `""`: something holds the name, so a start refuses (#1279 O6).
    A non-zero rc means either "no such object" or "daemon unreachable"; since `None` here
    licenses a create, the daemon is probed and an unreachable one raises."""
    status = _inspect_field(docker, name, "{{.State.Status}}")
    if status is not None:
        return status
    probe = _call(docker, ["docker", "version", "-f", "{{.Server.Version}}"])
    if probe.returncode != 0:
        raise BoxFault(
            f"docker could not say what the name {name} holds, and could not answer for the "
            f"daemon either ({(probe.stderr or '').strip()[:200]!r}) — refusing rather than "
            "reading that as a free name, because a create against a name another lane holds "
            "is the collision the ownership check exists to prevent"
        )
    return None


#: Stamped on every box at create so a fault arm can tell our container from another lane's
#: under the same name (a failed create-then-start is ambiguous otherwise). Minted per start,
#: not per run id, since run ids can be reused.
START_TOKEN_LABEL = "defender.start-token"
#: The label naming the tenant a box works for (#1214 O4): the tenant's teardown stops its
#: containers by it.
TENANT_LABEL = "defender.tenant"

#: The label naming the worker child a box was started under (#1446 review): the worker hands
#: each child a fresh claim token in `CLAIM_ENV`, every box started anywhere in that child's
#: process tree is stamped with it, and once the child is gone the worker removes every
#: container carrying it (`remove_claimed_containers`). A box started outside a worker child
#: carries none.
CLAIM_LABEL = "defender.claim"
CLAIM_ENV = "DEFENDER_BOX_CLAIM"
#: A claim token as the worker mints it (`uuid4().hex`).
_CLAIM_TOKEN = re.compile(r"[0-9a-f]{32}")


def claim_label(environ: Mapping[str, str] | None = None) -> list[str]:
    """The create flags stamping the box with its worker child's claim (`CLAIM_ENV` in
    `environ`, by default this process's): none outside a worker child. A value that is not a
    claim token is refused, never dropped: a box the worker cannot find would outlive the child
    it was started for. The refusal is a `BoxStartConflict`, a configuration fault the
    unsandboxed opt-out never degrades."""
    token = (os.environ if environ is None else environ).get(CLAIM_ENV)
    if token is None:
        return []
    if not _CLAIM_TOKEN.fullmatch(token):
        raise BoxStartConflict(f"{CLAIM_ENV} is not a claim token the worker mints; the box is not created")
    return ["--label", f"{CLAIM_LABEL}={token}"]


#: Docker's own text for a label the container does not carry, which `-f {{index …}}` prints
#: rather than failing. It means "not ours" as surely as a mismatch does.
_NO_LABEL = "<no value>"


def _start_token(docker: DockerFn, name: str) -> str | None:
    token = _inspect_field(
        docker, name, f'{{{{index .Config.Labels "{START_TOKEN_LABEL}"}}}}',
    )
    return None if not token or token == _NO_LABEL else token


def _remove_container(docker: DockerFn, name: str) -> str | None:
    """Remove the container `name`, paused or not: `None` once it is gone, else why not.

    Under runsc a PAUSED container's `rm -f` kills it but answers "PID … is zombie and can not
    be killed" and leaves it behind (#1202). `docker wait` then proves it exited, and a second
    `rm -f` removes it. Never thaws the box to remove it (#1178). The one removal step every
    site uses: `stop_box` and both reaps. A container the daemon is already removing counts as
    gone, for every caller: its removal is under way (a run box, `--rm`, removing itself once it
    stopped, #1343 B10, or a teardown racing a worker's sweep), and a second `rm` cannot hasten it."""
    argv = ["docker", "rm", "-f", name]
    first = _call(docker, argv)
    if first.returncode == 0:
        return None
    _call(docker, ["docker", "wait", name])
    second = _call(docker, argv)
    if second.returncode == 0:
        return None
    # Removed by someone else meanwhile (a teardown racing a worker's sweep): it is gone.
    with contextlib.suppress(BoxFault):
        status = _container_status(docker, name)
        if status in (None, "removing"):
            return None
    return f"{(first.stderr or '').strip()}; after waiting: {(second.stderr or '').strip()}"


def remove_labelled_containers(label: str, value: str | None = None, *, docker: DockerFn = run_docker,
                               whose: str = "the labelled") -> str | None:
    """Remove every container carrying the label `label` (with the value `value`, or any value when `value` is
    None), each through `_remove_container`, paused or not: `None` once none is left, else why not, naming
    `whose` containers. A host with no docker binary has no box to remove."""
    try:
        listed = labelled_containers(label, value, docker=docker)
    except BoxFault as e:
        return str(e)
    return remove_containers([name for name, _ in listed], docker=docker, whose=whose)


def labelled_containers(label: str, value: str | None = None, *, read: str | None = None,
                        docker: DockerFn = run_docker) -> list[tuple[str, str]]:
    """Every container carrying the label `label` (with the value `value`, or any value when `value` is None), as
    `(id, the value of its label `read`)`, that value empty when it lacks the label or `read` is None; `BoxFault` when
    docker cannot list them. A host with no docker binary has none."""
    selector = label if value is None else f"{label}={value}"
    argv = ["docker", "ps", "-aq", "--filter", f"label={selector}"] if read is None else [
        "docker", "ps", "-a", "--filter", f"label={selector}", "--format", '{{.ID}} {{.Label "' + read + '"}}']
    try:
        listed = docker(argv)
    except FileNotFoundError:
        return []
    except (OSError, subprocess.SubprocessError) as e:
        raise BoxFault(f"could not invoke docker: {e}") from None
    if listed.returncode != 0:
        raise BoxFault(f"docker could not list the containers labelled {selector}: {(listed.stderr or '').strip()}")
    rows = [line.split(None, 1) for line in (listed.stdout or "").splitlines() if line.strip()]
    return [(row[0], row[1].strip() if len(row) > 1 else "") for row in rows]


def remove_containers(names: list[str], *, docker: DockerFn = run_docker, whose: str = "the") -> str | None:
    """Remove each named container through `_remove_container`, paused or not: `None` once all are gone, else why not,
    naming `whose` containers."""
    faults = [f"{name}: {why}" for name in names if (why := _remove_container(docker, name)) is not None]
    return f"docker could not remove {whose} containers: {'; '.join(faults)}" if faults else None


def remove_tenant_containers(tenant_id: str, *, docker: DockerFn = run_docker) -> str | None:
    """Remove every container labelled with the tenant (`TENANT_LABEL`): `None` once none is
    left, else why not. A host with no docker binary has no box to remove (the offboarding of a
    tenant on a host that never ran one)."""
    return remove_labelled_containers(TENANT_LABEL, tenant_id, docker=docker, whose="the tenant's")


def remove_claimed_containers(token: str, *, docker: DockerFn = run_docker) -> str | None:
    """Remove every container a worker child's process tree started (`CLAIM_LABEL`): `None`
    once none is left, else why not. Running, stopped or never started, each is removed: the
    child that held it is gone."""
    if not _CLAIM_TOKEN.fullmatch(token):
        raise ValueError(f"not a claim token: {token!r}")
    return remove_labelled_containers(CLAIM_LABEL, token, docker=docker, whose="the child's")


class BoxStartConflict(BoxFault):
    """A start refused for what it would collide with, never degraded by the unsandboxed opt-out
    (#1279 A2): a mount that overlaps the publish root (O3), or a container that already holds
    the box's name (O6). These are configuration and collision faults, not "no sandbox here"."""


class BoxStartFault(BoxFault):
    """The run box did not start (#1342 M3): raised by a job-lane run's lifecycle at its start
    arm, chaining the start's own fault, so the job entry can tell a box that never started from
    one whose teardown faulted (a plain `BoxFault` out of the same lifecycle)."""


def _refuse_an_existing_container(docker: DockerFn, name: str) -> None:
    """The pre-create check (#1279 O6): every box name is fresh, so a container already holding
    it is never legitimate, whatever its state, and is neither named as ours nor removed.

    Unlike `_reap_on_fault` it may raise: no fault is being carried, so an unreachable daemon
    aborts the start (a plain `BoxFault`, which the opt-out may degrade: only the daemon's
    answer "a container with this name exists" is a `BoxStartConflict`)."""
    status = _container_status(docker, name)
    if status is None:
        return
    described = status or "in a state this daemon would not name"
    raise BoxStartConflict(
        f"a container named {name} already exists and is {described} — refusing, and removing "
        "nothing, because every box name is fresh and this one may belong to another run still "
        f"writing its artifacts. If it is a leak, `docker rm -f {name}` clears it."
    )


def container_present(name: str, *, docker: DockerFn = run_docker) -> bool:
    """Whether a container holds the name `name`, in any state. A daemon that cannot answer is a
    `BoxFault`, never "absent"."""
    return _container_status(docker, name) is not None


def _reap_on_fault(docker: DockerFn, name: str, *, owned_token: str | None = None) -> None:
    """Best-effort reap on a path already unwinding a startup fault. A `BoxFault` here (often
    the same sick daemon) is suppressed so it cannot replace the original fault.

    `owned_token` is for create-fault arms, where the container may not be ours: reap only if
    it carries our token. Startup-fault arms pass nothing, since their create succeeded."""
    with contextlib.suppress(BoxFault):
        if owned_token is not None and _start_token(docker, name) != owned_token:
            return
        _remove_container(docker, name)


def _own_container_ids(
    hostname_path: Path = _HOSTNAME_PATH, mountinfo_path: Path = _MOUNTINFO_PATH,
) -> tuple[str, ...]:
    """Candidate identifiers for this container; empty off-container.

    `/etc/hostname` is the short id only by default (`--hostname`, compose and Kubernetes
    override it), so the full id from `/proc/self/mountinfo` is added. `read_text_soft`
    also absorbs a `UnicodeDecodeError`, which would otherwise escape `start_box`.
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
    """This process's own mounts as `(destination, source)`, longest destination first;
    empty off-container or when no candidate id resolves.
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
            # Longest first, so `_covering_mount` picks the most specific.
            return tuple(sorted(pairs, key=lambda p: len(str(p[0])), reverse=True))
    return ()


def _shared_mounts(docker: DockerFn) -> tuple[tuple[Path, Path], ...]:
    """This container's mount table. A seam so tests can inject it: the id discovery reads
    host files that differ between a devcontainer and a CI runner.
    """
    return _own_container_mounts(docker, _own_container_ids())


SharedMountsFn = Callable[[DockerFn], Sequence[tuple[Path, Path]]]


def _covering_mount(
    path: Path, mounts: Sequence[tuple[Path, Path]],
) -> tuple[Path, Path] | None:
    """The most specific `(destination, source)` whose destination contains `path`, else None.

    Normalized first: `PurePath` keeps `..`, so an escaping path would otherwise pass the
    coverage check and translate to a source outside the mount.
    """
    resolved = Path(os.path.normpath(path))
    for dest, source in mounts:
        if resolved.is_relative_to(dest):
            return dest, source
    return None


def _daemon_source(path: Path, mounts: Sequence[tuple[Path, Path]]) -> Path:
    """Translate a path this process sees into the bind source the daemon must be given
    (docker-outside-of-Docker: the namespaces differ). Identity when no mount covers it.

    Only the source is translated; `target=`, `--workdir` and `infra_env` keep this process's
    path, which is what the agent records and the learning loop reads back.

    A startup sentinel catches a wrong run-dir mapping. The tenant agent bind uses its
    existing identity marker: planting into that source would dirty the clone. The product
    bind is checked on first use.
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
    """The refusal for a bind source on no shared mount. Without it docker reports "bind
    source path does not exist", which tempts the operator into DEFENDER_ALLOW_UNSANDBOXED.
    """

    return BoxFault(
        f"the {subject} {path} is not on any path this container shares with the docker "
        "daemon, so the box's bind source cannot be resolved (C46: docker-outside-of-Docker). "
        f"{remedy} under one of {', '.join(str(d) for d, _ in mounts)}, or run the driver "
        "where it shares a path namespace with the daemon."
    )
