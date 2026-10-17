"""Bearer authentication for git, held in a sealed in-memory git config only."""

from __future__ import annotations

import ctypes
import fcntl
import math
import os
from collections.abc import Sequence
from pathlib import Path

from defender import _git

from .auth import CLOCK_SKEW, ForgejoIdentity
from .forgejo import ForgeAddress

#: Linux UAPI (include/uapi/linux/{memfd,fcntl}.h). Standalone Python builds can omit
#: os.memfd_create, its flags, or fcntl's seal names, depending on their build headers.
#: Always call libc with the stable Linux ABI; creation and sealing remain mandatory.
_MEMFD_FLAGS = 0x0001 | 0x0002  # MFD_CLOEXEC | MFD_ALLOW_SEALING
_F_ADD_SEALS = 1033
_F_SEAL_ALL = 0x0001 | 0x0002 | 0x0004 | 0x0008  # seal, shrink, grow, write


def _sealed(data: bytes) -> int:
    """A sealed in-memory file holding exactly `data` (amendment 3, C4): no name on any file
    system, and once sealed it can be neither written, grown, shrunk nor unsealed, so the
    child a descriptor of it is handed to can only read it. Close-on-exec: only a child it is
    passed to (`pass_fds`) inherits it."""
    create = ctypes.CDLL(None, use_errno=True).memfd_create
    create.argtypes, create.restype = [ctypes.c_char_p, ctypes.c_uint], ctypes.c_int
    fd = int(create(b"tenant-forge-credential", _MEMFD_FLAGS))
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        fcntl.fcntl(fd, _F_ADD_SEALS, _F_SEAL_ALL)
    except BaseException:
        os.close(fd)
        raise
    return fd


def network_git(
    args: Sequence[str],
    *,
    repo: Path,
    address: ForgeAddress,
    identity: ForgejoIdentity,
    env: dict[str, str],
    timeout: float,
) -> str:
    """Put the Bearer header in a URL-scoped, sealed config inherited by this git call.
    The command line and environment name only its descriptor, never the JWT. Redirects
    are refused, hooks disabled and ambient credential helpers cleared. Rewrites to any
    other repository or server do not match this config's URL scope.
    """
    token = identity.token(min_validity=timeout + CLOCK_SKEW)
    # Use the configured spelling: git URL matching treats repository path case literally.
    origin = _git.git(["config", "--get", "remote.origin.url"], cwd=repo, env=env)
    if ForgeAddress.parse(origin) != address:
        raise ValueError("The git origin changed before authentication")
    config = f'[http "{origin}"]\nextraHeader = Authorization: Bearer {token}\n'
    fd = _sealed(config.encode("utf-8"))
    try:
        return _git.git_network(
            [
                "-c",
                "credential.helper=",
                "-c",
                "core.askPass=",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "http.followRedirects=false",
                "-c",
                "http.extraHeader=",
                "-c",
                f"http.{origin}.extraHeader=",
                "-c",
                f"include.path=/dev/fd/{fd}",
                "-c",
                "http.lowSpeedLimit=1",
                "-c",
                f"http.lowSpeedTime={max(1, math.ceil(timeout))}",
                *args,
            ],
            cwd=repo,
            env=env,
            timeout=timeout,
            pass_fds=(fd,),
        )
    finally:
        os.close(fd)
