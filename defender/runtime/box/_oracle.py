"""The branching oracle's own box (#1224, M18): a sandboxed container per sibling that binds a
fresh runner folder read-only and a fresh scratch folder, and nothing else — nothing of the
investigator's (no run dir, no tenant agent half) and nothing of the checkout. It never yields an
unsandboxed executor, whatever `DEFENDER_ALLOW_UNSANDBOXED` says: a start that is not sandboxed
raises `BoxStartRefused`.

The box's only in-box code is the transport's entry point, `python3 -m
defender.runtime.bash_exec`, which imports the stdlib and `box_codec` alone. So the runner folder
holds copies of exactly those modules (`RUNNER_FILES`), bound at the checkout's path: the
request's workdir stays the checkout (the start path reads its `box.Dockerfile` on the host to
name the image, and the box's `PYTHONPATH` is that path), but inside the box that path holds the
runner and nothing more. The repository root, its `.env` and the rest of the tree are never a
bind source, so oracle Python cannot read them.
"""
from __future__ import annotations

import os
import secrets
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from defender._io import guarded_mkdir, read_bytes_capped, write_guarded

from . import _lifecycle
from ._spec import BoxExecutor, BoxRequest, BoxSpec, Mount

#: The checkout: the request's workdir (the host reads its image recipe) and the in-box path the
#: runner is bound at. Never itself a bind source.
CHECKOUT = Path(__file__).resolve().parents[3]

#: Everything the in-box transport imports (`bash_exec` and the stdlib-only `box_codec` it
#: decodes frames with; `defender` is a namespace package), relative to the checkout.
RUNNER_FILES: tuple[str, ...] = (
    "defender/runtime/__init__.py",
    "defender/runtime/bash_exec.py",
    "defender/runtime/box_codec.py",
)


@dataclass
class OracleBox(BoxExecutor):
    """A started oracle box, the host scratch folder bound into it (where its frames run) and
    the runner folder it runs the transport from. The folders live exactly as long as the box:
    `stop_oracle_box` removes all three."""

    scratch: Path | None = None
    runner: Path | None = None


class BoxStartRefused(RuntimeError):
    """The oracle's box did not start sandboxed."""


def _make_runner() -> Path:
    """A fresh folder holding copies of `RUNNER_FILES` under their checkout-relative paths:
    the whole tree the box's bind at the checkout's path exposes."""
    runner = Path(tempfile.mkdtemp(prefix="defender-oracle-runner-"))
    try:
        for rel in RUNNER_FILES:
            dest = runner / rel
            guarded_mkdir(dest.parent, base=runner)
            write_guarded(dest, read_bytes_capped(CHECKOUT / rel))
    except BaseException:
        shutil.rmtree(runner, ignore_errors=True)
        raise
    return runner


def oracle_box_request(scratch: Path, runner: Path, *, env: Mapping[str, str]) -> BoxRequest:
    """The oracle box's request: the runner read-only at the checkout's path, the scratch
    folder writable, no env of the caller's."""
    return BoxRequest(
        name=f"defender-oracle-{secrets.token_hex(6)}",
        mounts=(Mount(source=runner, target=CHECKOUT, writable=False),
                Mount(source=scratch, target=scratch, writable=True)),
        workdir=CHECKOUT, env={}, spec=BoxSpec.from_env(env),
    )


def start_oracle_box(*, env: Mapping[str, str]) -> Any:
    """Start the oracle's sandboxed box; `env` is the process environment handed in (its
    `PATH` finds the `docker` binary, its box knobs size the container)."""
    runner = _make_runner()
    try:
        scratch = Path(tempfile.mkdtemp(prefix="defender-oracle-"))
    except BaseException:
        shutil.rmtree(runner, ignore_errors=True)
        raise

    def discard() -> None:
        shutil.rmtree(scratch, ignore_errors=True)
        shutil.rmtree(runner, ignore_errors=True)

    request = oracle_box_request(scratch, runner, env=env)
    path = env.get("PATH")

    def docker(argv: Any, **kw: Any) -> Any:
        merged = dict(kw.pop("env", None) or os.environ)
        if path:
            merged["PATH"] = path
        return _lifecycle._docker(argv, env=merged, **kw)

    try:
        box = _lifecycle._start_boxed_request(request, docker)
    except Exception as exc:
        discard()
        raise BoxStartRefused(f"the oracle's box could not start sandboxed: {exc}") from exc
    if not getattr(box, "sandboxed", False):
        discard()
        raise BoxStartRefused("the oracle's box is not sandboxed")
    return OracleBox(**{f.name: getattr(box, f.name) for f in fields(BoxExecutor)},
                     scratch=scratch, runner=runner)


def stop_oracle_box(box: Any) -> None:
    """Remove the box's container, then its scratch and runner folders (they go even when the
    container's removal fails: nothing runs in them once the box is being torn down)."""
    try:
        _lifecycle.stop_box(box)
    finally:
        for folder in (getattr(box, "scratch", None), getattr(box, "runner", None)):
            if folder is not None:
                shutil.rmtree(folder, ignore_errors=True)


def start_process_oracle_box() -> Any:
    """`start_oracle_box` over this process's environment."""
    return start_oracle_box(env=os.environ)
