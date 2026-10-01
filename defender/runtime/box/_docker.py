"""Talking to the daemon: naming, env, status, reaping, and which mounts are shared.

Every call to `docker` in the runtime goes through here.
"""
from __future__ import annotations

import contextlib
import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import NamedTuple

import shlex

from defender._io import read_text_soft
from defender._run_id import RUN_ID_ALLOWED, is_valid_run_id
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
from ._image import ImageInputError, image_tag


_ALLOW_UNSANDBOXED = "DEFENDER_ALLOW_UNSANDBOXED"

#: The build script every missing-image fault names, relative to the tree root.
_BUILD_SCRIPT_TAIL = "defender/scripts/box_image.py"


class Rootfs(NamedTuple):
    """The box's root filesystem image, and what to tell an operator whose daemon lacks it."""

    image: str
    #: The build command for a tree-derived image; `None` for an explicit rootfs.
    remedy: str | None


class Create(NamedTuple):
    """A rendered `docker run`: the argv, plus the rootfs by name so no caller reads it off
    an argv position."""

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
    derived from the run dir, never read from the environment."""
    env: dict[str, str] = {}
    env["DEFENDER_DIR"] = str(defender_dir)
    env["DEFENDER_RUN_DIR"] = str(run_dir)
    env["DEFENDER_RUNS_BASE"] = str(run_dir.parent)
    env["PATH"] = f"{defender_dir / 'bin'}:{_BOX_PATH}"
    env["PYTHONPATH"] = str(defender_dir.parent)
    return env


def _derived_infra_env(workdir: Path) -> dict[str, str]:
    """The infra keys derived off the request's workdir (`defender_dir.parent`)."""
    defender_dir = Path(workdir) / "defender"
    return {
        "DEFENDER_DIR": str(defender_dir),
        "PATH": f"{defender_dir / 'bin'}:{_BOX_PATH}",
        "PYTHONPATH": str(workdir),
    }


def _render_env(request_env: Mapping[str, str], workdir: Path) -> dict[str, str]:
    """Render the box env from a key allowlist. Derived infra keys override the request;
    `LANG`/`TZ` are defaults the request may override; the `DEFENDER_BOX` mark goes last so
    no request env can switch it off."""
    merged = dict(_LOCALE_ENV)
    merged.update({k: v for k, v in request_env.items() if k in BOX_ENV_ALLOWLIST})
    merged.update(_derived_infra_env(workdir))
    merged.update(_BOX_MARK_ENV)
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
        # SubprocessError covers TimeoutExpired, which is not an OSError and would otherwise
        # escape the unsandboxed fallback and the SYSTEMIC_FAULTS classification.
        raise BoxFault(f"could not invoke docker ({argv[:2]}): {e}") from e


#: States in which nothing can still be starting or running, so reaping is safe. `created`
#: is excluded: `docker run --detach` is create-then-start, so a concurrent lane's box sits
#: in `created` during exactly the window two lanes can collide on one name.
_FINISHED_STATES = frozenset({"exited", "dead"})


def _inspect_field(docker: DockerFn, name: str, fmt: str) -> str | None:
    """One `-f` field off `docker inspect`, or `None` when the daemon answered non-zero.
    Callers decide what `None` means."""
    proc = _call(docker, ["docker", "inspect", "-f", fmt, name])
    if proc.returncode != 0:
        return None
    return (proc.stdout or "").strip()


def _container_status(docker: DockerFn, name: str) -> str | None:
    """Docker's word for what this name holds, or `None` for no such container.

    An unparseable answer is `""`, which is not in `_FINISHED_STATES` and so never reaped.
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

#: Docker's own text for a label the container does not carry, which `-f {{index …}}` prints
#: rather than failing. It means "not ours" as surely as a mismatch does.
_NO_LABEL = "<no value>"


def _start_token(docker: DockerFn, name: str) -> str | None:
    token = _inspect_field(
        docker, name, f'{{{{index .Config.Labels "{START_TOKEN_LABEL}"}}}}',
    )
    return None if not token or token == _NO_LABEL else token


def _reap_stale_before_create(docker: DockerFn, name: str) -> None:
    """The pre-create sweep. Unlike `_reap_on_fault` it may raise: no fault is being carried,
    so an unreachable daemon should abort the start.

    Ownership is decided by state, since no start token exists yet. Only a finished container
    is reaped; anything else may be another lane mid-start and is refused. A leaked container
    is cheap to clear by hand; reaping another lane's box loses its artifacts."""
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
    """Best-effort reap on a path already unwinding a startup fault. A `BoxFault` here (often
    the same sick daemon) is suppressed so it cannot replace the original fault.

    `owned_token` is for create-fault arms, where the container may not be ours: reap only if
    it carries our token. Startup-fault arms pass nothing, since their create succeeded."""
    with contextlib.suppress(BoxFault):
        if owned_token is not None and _start_token(docker, name) != owned_token:
            return
        _call(docker, ["docker", "rm", "-f", name])


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

    A startup sentinel catches a wrong mapping, except on the read-only binds: `defender_dir`
    fails on first use, but a wrong mapping of the tenant `agent/` half goes unnoticed (the box
    just sees a different or empty dir).
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
