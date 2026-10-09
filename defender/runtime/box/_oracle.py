"""The branching oracle's own box (#1224, M18): a sandboxed container per sibling that binds the
checkout read-only and a fresh scratch folder, and nothing of the investigator's (no run dir, no
tenant agent half). It never yields an unsandboxed executor, whatever
`DEFENDER_ALLOW_UNSANDBOXED` says: a start that is not sandboxed raises `BoxStartRefused`.
"""
from __future__ import annotations

import os
import secrets
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import _lifecycle
from ._spec import BoxRequest, BoxSpec, Mount

#: The checkout the in-box Python runs from (`python3 -m defender.runtime.bash_exec`).
CHECKOUT = Path(__file__).resolve().parents[3]

#: Each started oracle box's scratch folder, by box name: where its frames run.
SCRATCH: dict[str, Path] = {}


class BoxStartRefused(RuntimeError):
    """The oracle's box did not start sandboxed."""


def start_oracle_box(*, env: Mapping[str, str]) -> Any:
    """Start the oracle's sandboxed box; `env` is the process environment handed in (its
    `PATH` finds the `docker` binary, its box knobs size the container)."""
    scratch = Path(tempfile.mkdtemp(prefix="defender-oracle-"))
    request = BoxRequest(
        name=f"defender-oracle-{secrets.token_hex(6)}",
        mounts=(Mount(source=CHECKOUT, target=CHECKOUT, writable=False),
                Mount(source=scratch, target=scratch, writable=True)),
        # The checkout is the workdir: the start path reads its `box.Dockerfile`, and in-box
        # Python runs `python3 -m defender.runtime.bash_exec` from it. Frames run in `scratch`.
        workdir=CHECKOUT, env={}, spec=BoxSpec.from_env(env),
    )
    path = env.get("PATH")

    def docker(argv: Any, **kw: Any) -> Any:
        merged = dict(kw.pop("env", None) or os.environ)
        if path:
            merged["PATH"] = path
        return _lifecycle._docker(argv, env=merged, **kw)

    try:
        box = _lifecycle._start_boxed_request(request, docker)
    except Exception as exc:
        shutil.rmtree(scratch, ignore_errors=True)
        raise BoxStartRefused(f"the oracle's box could not start sandboxed: {exc}") from exc
    if not getattr(box, "sandboxed", False):
        shutil.rmtree(scratch, ignore_errors=True)
        raise BoxStartRefused("the oracle's box is not sandboxed")
    SCRATCH[box.name] = scratch
    return box


def start_process_oracle_box() -> Any:
    """`start_oracle_box` over this process's environment."""
    return start_oracle_box(env=os.environ)
