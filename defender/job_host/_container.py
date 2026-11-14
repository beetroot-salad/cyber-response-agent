"""The job container (#1170 H3, O1-O4, A5, A7, A8, H9; #1469 D0): its socket, its environment, its runtime and its
`docker run`.

One container per job, the helper's child: started attached (`docker run -i`), its input a pipe the helper holds, so it
ends when the helper does (A5); labelled with its tenant, its claim and the job-container label; running as the uid
that owns the data root (H9), with exactly three binds, each at its own path: the tenant's folder (read-write), the
code the helper runs from (read-only, A7: the worker's code copy, holding no `.env`) and the job socket's folder
(read-write, holding only the socket). Its
environment is every setting the job reads minus secrets and cross-tenant addresses (A8), plus the provider keys the
helper resolved (N2)."""
from __future__ import annotations

import logging
import os
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NamedTuple

from defender.job_socket import HELPER_LABEL, IMAGE_ENV, JOB_LABEL, NETWORK_ENV, SOCKET_ENV

from ._session import Session, StartFailed

_logger = logging.getLogger(__name__)

#: Where under the data root each claim's socket folder lives: outside every tenant's folder and outside `/tmp` (H9).
SOCKETS = ".job-sockets"
SOCKET_NAME = "job.sock"
#: A unix socket's path holds at most this many bytes, its terminating NUL included (`sun_path`).
_SUN_PATH = 108
#: The image when the setting names none (A7).
DEFAULT_IMAGE = "defender-job:latest"
#: Seconds the container is given to unwind on a graceful stop (A2: learning siblings' 20 < this < the worker's 30,
#: leaving the rest of the worker's grace for the removal).
STOP_GRACE = 22
#: Settings the job never gets, whatever their prefix: the database address, the shared publish folder (A10), the
#: provider key's file, the unsandboxed opt-out, the code-tree override (the job runs the mounted code).
_DENIED = frozenset({
    "DEFENDER_DATABASE_DSN", "DEFENDER_RUN_VISUALIZATIONS_DIR", "DEFENDER_ENV_FILE", "DEFENDER_ALLOW_UNSANDBOXED",
    "DEFENDER_DIR", SOCKET_ENV,
})
#: Words in a setting's name that mark a secret or a login (an OpenBao or vault address included).
_SECRET_WORDS = re.compile(r"DSN|PASSWORD|PASSWD|SECRET|TOKEN|OPENBAO|VAULT|LOGIN|PRIVATE")
#: Values that carry a database address.
_DATABASE_VALUE = re.compile(r"postgres(?:ql)?://", re.IGNORECASE)


def socket_folder(session: Session) -> Path:
    return session.root_folder / SOCKETS / session.claim


def socket_path(session: Session) -> Path:
    """The claim's socket path, or `StartFailed` when it cannot fit a unix socket (r4.1)."""
    path = socket_folder(session) / SOCKET_NAME
    if len(os.fsencode(str(path))) >= _SUN_PATH:
        raise StartFailed(f"the job socket's path {path} is longer than a unix socket's {_SUN_PATH - 1} bytes: "
                          "the data root is too deep for a job to be served")
    return path


def owner(session: Session) -> tuple[int, int]:
    """The uid and gid that own the data root: the job container's (H9)."""
    st = os.stat(session.root_folder)
    return st.st_uid, st.st_gid


def make_socket_folder(session: Session) -> Path:
    """`<root>/.job-sockets/<claim>/`, mode 0700, owned by the data root's owner (the container's uid)."""
    folder = socket_folder(session)
    parent = folder.parent
    # Both folders are under the data root, outside every tenant's folder, and made before the job's container
    # exists: no box mounts the parent, and the claim's folder (the container's socket bind) is made here, exclusively,
    # in the parent judged no-follow first; the helper writes nothing else there while the container runs.
    parent.mkdir(mode=0o711, exist_ok=True)  # lint-unguarded-tree-write: ok — no box or job mounts it (H9)
    if parent.is_symlink() or not parent.is_dir():
        raise StartFailed(f"{parent} is not a folder the helper made")
    folder.mkdir(mode=0o700)  # lint-unguarded-tree-write: ok — exclusive, made before its container exists
    os.chmod(folder, 0o700)
    uid, gid = owner(session)
    if os.geteuid() == 0 and (uid, gid) != (0, 0):
        os.chown(folder, uid, gid)
    return folder


def _setting(name: str, value: str, denied_values: tuple[str, ...]) -> bool:
    if name in _DENIED or _SECRET_WORDS.search(name) or name.endswith(("_FILE", "_KEY")):
        return False
    if _DATABASE_VALUE.search(value):
        return False
    return not any(d and d in value for d in denied_values)


def _denied_values(environ: Mapping[str, str]) -> tuple[str, ...]:
    """Values no variable of the job may carry: the database address, OpenBao's address, the publish folder."""
    from defender.configuration.issuer import DEPLOYMENT_ISSUER

    named = (environ.get("DEFENDER_DATABASE_DSN"), environ.get("DEFENDER_RUN_VISUALIZATIONS_DIR"),
             DEPLOYMENT_ISSUER.openbao_url)
    return tuple(v for v in named if v)


def provider_keys(environ: Mapping[str, str]) -> dict[str, str]:
    """Each provider's key as a run resolves it (N2): the `.env` file's (`DEFENDER_ENV_FILE` first), else the
    ambient one. The job never reads `.env` itself. Read once per launch (`container_launch`)."""
    from defender import providers
    from defender._first_party_key import resolve_first_party_key

    keys: dict[str, str] = {}
    for var in sorted(providers.api_key_vars()):
        key, _source = resolve_first_party_key(var=var)
        if key:
            keys[var] = key
        elif environ.get(var):
            keys[var] = environ[var]
    return keys


def job_environment(session: Session, socket: Path, keys: Mapping[str, str],
                    environ: Mapping[str, str] = os.environ) -> dict[str, str]:
    """The job's environment (A8): the `DEFENDER_*` settings minus secrets and cross-tenant addresses, the provider
    keys `keys`, the code on the path, a writable home, and the socket."""
    from defender.box import CLAIM_ENV

    denied = _denied_values(environ)
    env = {k: v for k, v in environ.items() if k.startswith("DEFENDER_") and _setting(k, v, denied)}
    for k in ("TZ", "LANG", "LC_ALL"):
        if environ.get(k):
            env[k] = environ[k]
    env.update(keys)
    env.update({
        "DEFENDER_DATA_ROOT": str(session.root_folder),
        CLAIM_ENV: session.claim,
        SOCKET_ENV: str(socket),
        "PYTHONPATH": str(session.defender_dir.parent),
        "HOME": "/tmp",
    })
    return env


#: The job container's runtime by the box runtime the deployment sets (#1469 D0): gVisor's job registration (the same
#: binary as `runsc`, registered with host-socket access, which the job's socket needs), or `runc` as the boxes are. The
#: job runtime is derived, never set, so a sandboxed box can never run beside an unsandboxed job container; it is no
#: box runtime, so no box can be started under it. The code never reads how it is registered.
JOB_RUNTIMES = {"runsc": "runsc-job", "runc": "runc"}


def job_runtime(box_runtime: str) -> str:
    """The runtime the job container starts under, derived from the box runtime `box_runtime`."""
    try:
        return JOB_RUNTIMES[box_runtime]
    except KeyError:
        raise ValueError(f"{box_runtime!r} is not a known box runtime: no job runtime derives from it") from None


def job_container_name(session: Session) -> str:
    return f"defender-job-{session.claim}"


def job_network(environ: Mapping[str, str] = os.environ) -> str:
    """The network the job container joins (N5), as `NETWORK_ENV` names it: the worker judged it at its start
    (`worker._start.check_job_network`), so the helper only refuses an unset name, which no worker it serves leaves."""
    name = (environ.get(NETWORK_ENV) or "").strip()
    if not name:
        raise StartFailed(f"{NETWORK_ENV} is not set; the worker refuses to start without it")
    return name


class Launch(NamedTuple):
    """The job container's attached `docker run`: its command line, the docker command's own environment, which
    alone carries the provider keys the command line names without their values, and the job runtime it names."""

    argv: list[str]
    env: dict[str, str]
    runtime: str


def container_launch(session: Session, socket: Path, command: list[str], environ: Mapping[str, str] = os.environ
                     ) -> Launch:
    """The job container's attached `docker run` (module doc), built in one step so its command line and its
    environment name the same provider keys, read once. The runtime it names is asked of the daemon here
    (#1484, `box.require_runtime`), while a stop still unwinds the helper's setup, so a host without it refuses naming
    the remedy rather than in docker's words."""
    from defender.box import CLAIM_LABEL, TENANT_LABEL, BoxFault, BoxSpec, require_runtime

    try:
        runtime = job_runtime(BoxSpec.from_env(environ).runtime)
    except ValueError as unknown:
        raise StartFailed(str(unknown)) from None
    try:
        require_runtime(session.docker, runtime)
    except BoxFault as missing:
        raise StartFailed(str(missing)) from None
    if session.tenant_folder is None:
        raise StartFailed("the job's tenant was not accepted: there is no tenant folder to bind")
    from defender.tenancy import process_mark

    network = job_network(environ)
    try:
        helper = process_mark()
    except OSError as unreadable:
        raise StartFailed(f"the helper cannot name itself on its container: {unreadable}") from None
    uid, gid = owner(session)
    tenant = str(session.tenant_folder)
    code = str(session.defender_dir)
    sockets = str(socket.parent)
    argv = [
        "docker", "run", "-i", "--rm", "--init", "--name", session.container,
        "--user", f"{uid}:{gid}",
        "--label", f"{TENANT_LABEL}={session.tenant_id}", "--label", f"{CLAIM_LABEL}={session.claim}",
        "--label", f"{JOB_LABEL}={session.kind}", "--label", f"{HELPER_LABEL}={helper}",
        "--pull=never", "--runtime", runtime, "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=256m",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
    ]
    argv += [
        "--network", network,
        "--mount", f"type=bind,source={tenant},target={tenant}",
        "--mount", f"type=bind,source={code},target={code},readonly",
        # Read-write (a connect needs no write on the folder, but the code bind is the one read-only bind, A7);
        # the folder holds only the socket, made and removed by the helper.
        "--mount", f"type=bind,source={sockets},target={sockets}",
        "--workdir", str(session.defender_dir.parent),
    ]
    keys = provider_keys(environ)
    for key, value in sorted(job_environment(session, socket, keys, environ).items()):
        argv += ["--env", key if key in keys else f"{key}={value}"]
    argv += [environ.get(IMAGE_ENV) or DEFAULT_IMAGE, *command]
    return Launch(argv, {**environ, **keys}, runtime)


def start(session: Session, launch: Launch) -> Any:
    """The container, attached: its input a pipe this helper holds and never writes (A5); its output the helper's."""
    popen = getattr(session.docker, "popen", None)
    if popen is None:
        raise StartFailed("the docker seam has no attached start (`popen`)")
    try:
        return popen(launch.argv, stdin=subprocess.PIPE, env=launch.env)
    except (OSError, subprocess.SubprocessError) as cannot:
        raise StartFailed(f"docker could not be run to start the job container: {cannot}") from None
