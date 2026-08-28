"""Talking to the daemon: naming, env, status, reaping, and which mounts are shared.

Split out of `box.py` at 1077 lines. Every call to `docker` in the runtime goes through
here.
"""
from __future__ import annotations

import contextlib
import os
import re
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from defender._io import read_text_soft
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
from ._spec import BOX_ENV_ALLOWLIST


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
    daemon we cannot understand is not evidence that the container is done with.

    A NON-ZERO rc IS TWO ANSWERS, and they are opposite. `docker inspect` exits non-zero both
    for "no such object" and for "cannot connect to the daemon" — and only THIS caller reads
    `None` as "the name is free", which licenses a create against a name another lane may
    hold: the collision the ownership check exists to make impossible. So the rc alone is not
    taken as absence here; the daemon is asked whether it is answering at all. The daemon is
    PROBED rather than the stderr text matched, because the text is a UI string and liveness
    is the actual question.

    `_start_token`'s `None` needs no such probe: there it means "nothing to own, reap
    nothing", which is the safe direction on a path already unwinding a fault. Same rc, two
    readings, and the difference is what each caller does with it — which is why
    `_inspect_field` reports the rc and declines to interpret it."""
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
