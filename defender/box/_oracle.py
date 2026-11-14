"""The branching oracle's own box (#1224, M18): a sandboxed container per sibling that binds a
fresh runner folder read-only and a fresh scratch folder, and nothing else — nothing of the
investigator's (no run dir, no tenant agent half) and nothing of the checkout. It never yields an
unsandboxed executor, whatever `DEFENDER_ALLOW_UNSANDBOXED` says: a start that is not sandboxed
raises `BoxStartRefused`."""
from __future__ import annotations

import functools
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
from ._docker import DockerFn
from ._spec import CODE_CHECK_FILE, BoxExecutor, BoxRequest, BoxSpec, Mount

#: The checkout: the request's workdir (the host reads its image recipe) and the in-box path the
#: runner is bound at. Never itself a bind source.
CHECKOUT = Path(__file__).resolve().parents[2]

#: Everything the in-box transport imports (`bash_exec` and the stdlib-only `box_codec` it
#: decodes frames with; `defender` is a namespace package), plus the code check file box start
#: reads back through the runner's `code` mount (#1108 D7), relative to the checkout.
RUNNER_FILES: tuple[str, ...] = (
    "defender/execution/__init__.py",
    "defender/execution/bash_exec.py",
    "defender/execution/box_codec.py",
    f"defender/{CODE_CHECK_FILE}",
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


def _make_runner(folder: Path | None = None) -> Path:
    """A fresh folder (under `folder`, else the host's temporary folder) holding copies of
    `RUNNER_FILES` under their checkout-relative paths: the whole tree the box's bind at the
    checkout's path exposes."""
    runner = Path(tempfile.mkdtemp(prefix="defender-oracle-runner-", dir=folder))
    try:
        for rel in RUNNER_FILES:
            dest = runner / rel
            guarded_mkdir(dest.parent, base=runner)
            write_guarded(dest, read_bytes_capped(CHECKOUT / rel))
    except BaseException:
        shutil.rmtree(runner, ignore_errors=True)
        raise
    return runner


def oracle_box_request(scratch: Path, runner: Path, *, env: Mapping[str, str],
                       tenant_id: str, data_root: Path) -> BoxRequest:
    """The oracle box's request: the runner read-only at the checkout's path as the box's
    `code` mount, the scratch folder writable, no env of the caller's, labelled with the tenant
    it serves (`tenant_id`, #1214 O4: the tenant's teardown removes it), and carrying the data root its box check runs
    under (`data_root`, #1469). It requires a sandbox
    (#1108 amendment 3, C3): a start fault raises, never an unsandboxed fallback, and leaves
    no did-not-run marker beside the scratch folder."""
    return BoxRequest(
        name=f"defender-oracle-{secrets.token_hex(6)}",
        mounts=(Mount(source=runner, target=CHECKOUT, writable=False, kind="code"),
                Mount(source=scratch, target=scratch, writable=True)),
        workdir=CHECKOUT, env={}, spec=BoxSpec.from_env(env), require_sandbox=True,
        tenant_id=tenant_id, data_root=data_root,
    )


@functools.lru_cache(maxsize=8)
def _on_path(path: str | None) -> DockerFn:
    """The real docker seam with `path` as its `PATH`: one per `PATH`, so a process's oracle boxes share a seam and the
    box check's pass (kept per seam, #1469 D2) is paid once, not at every box."""
    def on_path(argv: Any, **kw: Any) -> Any:
        merged = dict(kw.pop("env", None) or os.environ)
        if path:
            merged["PATH"] = path
        return _lifecycle.run_docker(argv, env=merged, **kw)

    return on_path


def start_oracle_box(*, env: Mapping[str, str], tenant_id: str, data_root: Path, folder: Path | None = None,
                     docker: DockerFn | None = None) -> Any:
    """Start the oracle's sandboxed box for `tenant_id`; `data_root` is the data root its entry point resolved, where the
    box check runs (#1469); `env` is the process environment handed
    in (its `PATH` finds the `docker` binary, its box knobs size the container). `folder` is
    where its runner and scratch folders are made (#1170 C21: a per-claim folder under the data
    root, for a job's helper), else the host's temporary folder. `docker` is the docker seam the
    box is started and run through, used as given (a job's helper passes its own); None, the
    real one with `env`'s `PATH`."""
    runner = _make_runner(folder)
    try:
        scratch = Path(tempfile.mkdtemp(prefix="defender-oracle-", dir=folder))
    except BaseException:
        shutil.rmtree(runner, ignore_errors=True)
        raise

    def discard() -> None:
        shutil.rmtree(scratch, ignore_errors=True)
        shutil.rmtree(runner, ignore_errors=True)

    request = oracle_box_request(scratch, runner, env=env, tenant_id=tenant_id, data_root=data_root)
    if docker is None:
        docker = _on_path(env.get("PATH"))
    try:
        # The one entry for a `BoxRequest`; the request requires a sandbox, so a start fault
        # raises whatever the operator's opt-out says.
        box = _lifecycle.start_box(request, docker=docker)
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


def start_process_oracle_box(tenant_id: str, data_root: Path) -> Any:
    """`start_oracle_box` over this process's environment."""
    return start_oracle_box(env=os.environ, tenant_id=tenant_id, data_root=data_root)
