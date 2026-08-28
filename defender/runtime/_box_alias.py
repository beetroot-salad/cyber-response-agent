"""The alias-ban probe: refuse a box whose shell could rename a banned program back into
reach.

Split out of `box.py` at 1077 lines. This gate fails CLOSED — an inconclusive probe is a
refusal, not a pass.
"""
from __future__ import annotations

import uuid
from pathlib import Path

from defender.runtime.box_codec import (
    REQUEST_MAGIC,  # noqa: F401 — re-exported: test_540_exec_seam.py imports it as `box.REQUEST_MAGIC`
    RESPONSE_MAGIC,  # noqa: F401 — re-exported: test_540_exec_seam.py imports it as `box.RESPONSE_MAGIC`
    )
from defender.runtime.scrub import (  # noqa: F401 — re-exported: run.py/drains.py/tests import `box.scrub`, `box.RunTainted`
    Finding,
    RunTainted,
    scrub,
    verdict_path,
    write_did_not_run,
)
from ._box_spec import _OCI_SECCOMP_FLAG, _RUNSC_INSTALL_CMD
from ._box_docker import DockerFn, _call


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
