"""The sandbox the agent's commands run in.

Split into four modules when this file reached 1077 lines:

  * `_spec`      — what a box IS: the request, the mounts, the executor, and the two
                       transports that carry a command to one.
  * `_alias`     — the alias-ban probe, which refuses a box whose shell could rename
                       a banned program back into reach.
  * `_docker`    — talking to the daemon: naming, env, status, reaping, mount shapes.
  * `_lifecycle` — start, stop, scrub, and the faults each step can raise.

Every name below is a re-export; this module is the door the runtime knocks on.
"""

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
from ._spec import (
    ALIAS_PROFILE_PATH,
    BANNED_SHAPES,
    BOX_ENV_ALLOWLIST,
    BoxExecutor,
    BoxRequest,
    BoxSpec,
    DEFAULT_SPEC,
    Mount,
    Transport,
    _DockerTransport,
    _HostTransport,
    _OCI_SECCOMP_FLAG,
    _RUNSC_INSTALL_CMD,
    _text,
    _unattached,
)
from ._alias import (
    AliasBanNotInForce,
    DockerFn,
    _CONTROL_FAILED_MARKER,
    _alias_ban_fault_message,
    _alias_probe_argv,
    _alias_probe_inconclusive_message,
    _alias_probe_script,
    _call,
    _probe_alias_ban,
)
from ._docker import (
    START_TOKEN_LABEL,
    SharedMountsFn,
    _ALLOW_UNSANDBOXED,
    _BOX_PATH,
    _CONTAINER_ID_RE,
    _FINISHED_STATES,
    _HOSTNAME_PATH,
    _LOCALE_ENV,
    _MOUNTINFO_PATH,
    _NAME_PREFIX,
    _NO_LABEL,
    _container_status,
    _covered,
    _covering_mount,
    _daemon_source,
    _derived_infra_env,
    _docker,
    _inspect_field,
    _own_container_ids,
    _own_container_mounts,
    _reap_on_fault,
    _reap_stale_before_create,
    _render_env,
    _shared_mounts,
    _start_token,
    _uncovered_fault,
    container_name,
    infra_env,
)
from ._lifecycle import (
    _check_mount_sentinel,
    _create_argv,
    _did_not_run_for_request,
    _host_fallback_env,
    _opt_out_or_raise,
    _plant,
    _plant_sentinel,
    _probe_cwd_for_request,
    _probe_sentinel,
    _render_argv,
    _start_boxed,
    _start_boxed_request,
    start_box,
    stop_and_scrub,
    stop_box,
    unboxed_executor,
)


#: Everything imported above is a RE-EXPORT: the name's real home is the module it
#: comes from. Kept because a reader already imports it from here.
__all__ = [
    "ALIAS_PROFILE_PATH",
    "AliasBanNotInForce",
    "BANNED_SHAPES",
    "BOX_ENV_ALLOWLIST",
    "BoxExecutor",
    "BoxFault",
    "BoxRequest",
    "BoxResult",
    "BoxSpec",
    "Callable",
    "ClassVar",
    "DEFAULT_SPEC",
    "DockerFn",
    "Finding",
    "Mapping",
    "Mount",
    "Path",
    "Protocol",
    "REQUEST_MAGIC",
    "RESPONSE_MAGIC",
    "RUN_ID_ALLOWED",
    "RawExec",
    "RunTainted",
    "START_TOKEN_LABEL",
    "Sequence",
    "SharedMountsFn",
    "Transport",
    "_ALLOW_UNSANDBOXED",
    "_BOX_PATH",
    "_CONTAINER_ID_RE",
    "_CONTROL_FAILED_MARKER",
    "_DockerTransport",
    "_FINISHED_STATES",
    "_HOSTNAME_PATH",
    "_HostTransport",
    "_LOCALE_ENV",
    "_MOUNTINFO_PATH",
    "_NAME_PREFIX",
    "_NO_LABEL",
    "_OCI_SECCOMP_FLAG",
    "_RUNSC_INSTALL_CMD",
    "_alias_ban_fault_message",
    "_alias_probe_argv",
    "_alias_probe_inconclusive_message",
    "_alias_probe_script",
    "_call",
    "_check_mount_sentinel",
    "_container_status",
    "_covered",
    "_covering_mount",
    "_create_argv",
    "_daemon_source",
    "_derived_infra_env",
    "_did_not_run_for_request",
    "_docker",
    "_host_fallback_env",
    "_inspect_field",
    "_opt_out_or_raise",
    "_own_container_ids",
    "_own_container_mounts",
    "_plant",
    "_plant_sentinel",
    "_probe_alias_ban",
    "_probe_cwd_for_request",
    "_probe_sentinel",
    "_reap_on_fault",
    "_reap_stale_before_create",
    "_render_argv",
    "_render_env",
    "_shared_mounts",
    "_start_boxed",
    "_start_boxed_request",
    "_start_token",
    "_text",
    "_unattached",
    "_uncovered_fault",
    "bash_exec",
    "container_name",
    "contextlib",
    "dataclass",
    "decode_request",
    "decode_response",
    "encode_request",
    "encode_response",
    "field",
    "infra_env",
    "is_valid_run_id",
    "os",
    "re",
    "read_text_soft",
    "scrub",
    "start_box",
    "stop_and_scrub",
    "stop_box",
    "subprocess",
    "sweep_staged",
    "sys",
    "unboxed_executor",
    "uuid",
    "verdict_path",
    "write_did_not_run",
    "write_guarded",
]
